"""Scripted OpenAI-compatible fake provider (plan 19).

The local protocol server for conversational-agent acceptance: it is the
SAME fixture the agent gate uses, so fast regressions and required-mode
gates exercise the real HTTP wire, the real Authorization header policy
and the real pydantic-AI request encoding — never a monkeypatched
stand-in for the model layer. It is NOT a model-competence claim: every
response is scripted by the test.

Capabilities: scripted responses (text / native tool calls / parallel
calls / forged names), truncation (finish_reason=length), empty
content, SSE streaming, per-request auth enforcement, injected hangs
(bounded sleeps that make the client time out) and CONCURRENT-REQUEST
tracking so a test can prove the single admission slot with the
provider itself, not just in-process counters.
"""
from __future__ import annotations

import json
import threading
import time
import http.server
import socketserver
from dataclasses import dataclass, field


def tool_call(call_id: str, name: str, arguments: dict) -> dict:
    return {"id": call_id, "type": "function",
            "function": {"name": name, "arguments": json.dumps(arguments)}}


def text_response(text: str, *, finish: str = "stop",
                  usage: dict | None = None) -> dict:
    return {"index": 0, "message": {"role": "assistant", "content": text},
            "finish_reason": finish, "usage": usage}


def tool_response(calls: list[dict], *, finish: str = "tool_calls",
                  usage: dict | None = None, content: str | None = None) -> dict:
    return {"index": 0, "message": {"role": "assistant", "content": content,
                                    "tool_calls": calls},
            "finish_reason": finish, "usage": usage}


def check_wire(body: dict) -> str | None:
    """STRICT OpenAI-protocol validation of one chat.completions request
    (review round 2, finding 1): every tool message must answer a tool
    call the assistant actually made, call ids may never duplicate or
    go unanswered-then-orphaned, and the message list must be a legal
    sequence. Returns None when the request is protocol-complete, else
    the violation description. The real provider (and the reviewer's
    strict local provider) REJECT orphan tool results with HTTP 400 —
    the scripted fake must too, or compaction defects stay invisible."""
    messages = body.get("messages") or []
    issued: list[str] = []
    answered: set[str] = set()
    for m in messages:
        role = m.get("role")
        if role == "assistant":
            for tc in m.get("tool_calls") or []:
                cid = tc.get("id")
                if not cid:
                    return "assistant tool call without an id"
                if cid in issued:
                    return f"duplicate tool call id {cid!r}"
                issued.append(cid)
        elif role == "tool":
            cid = m.get("tool_call_id")
            if not cid:
                return "tool message without tool_call_id"
            if cid not in issued:
                return f"orphan tool result {cid!r}: no assistant call " \
                       f"asked for it"
            if cid in answered:
                return f"tool result {cid!r} answered twice"
            answered.add(cid)
    unresolved = [c for c in issued if c not in answered]
    if unresolved:
        # an unanswered call is legal only as the LAST assistant turn
        # (the answer arrives next request); older gaps mean the middle
        # of the conversation was compacted away — protocol-broken
        last_assistant = next((m for m in reversed(messages)
                               if m.get("role") == "assistant"), None)
        last_ids = [tc.get("id") for tc in
                    (last_assistant or {}).get("tool_calls") or []]
        if any(c not in last_ids for c in unresolved):
            return f"tool call(s) {unresolved} lost their results " \
                   "(compaction split a call from its return)"
    return None


@dataclass
class _State:
    script: list = field(default_factory=list)
    auth: str | None = None          # required Authorization value
    hang_s: float = 0.0              # sleep BEFORE responding (client timeout)
    strict: bool = False             # reject protocol-broken requests 400
    echo_auth_errors: bool = False   # error bodies echo the Authorization
    #                                  header (leaky-provider realism)
    requests: list = field(default_factory=list)
    violations: list = field(default_factory=list)
    live: int = 0
    max_live: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)


class FakeModelServer:
    def __init__(self):
        outer = self
        state = _State()
        self.state = state

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802
                self._handle(post=True)

            def do_GET(self):  # noqa: N802
                self._handle(post=False)

            def _handle(self, *, post):
                if not post:
                    # model discovery: GET {base}/v1/models — auth-checked
                    # like everything else; returns the model catalog only
                    if state.auth is not None and \
                            self.headers.get("Authorization") != state.auth:
                        self.send_response(401)
                        self.end_headers()
                        return
                    with state.lock:
                        state.requests.append({"path": self.path, "body": {},
                                               "auth": self.headers.get(
                                                   "Authorization"),
                                               "ts": time.monotonic()})
                    if self.path.rstrip("/").endswith("/models"):
                        payload = json.dumps({
                            "object": "list",
                            "data": [{"id": "gpt-4o", "object": "model"},
                                     {"id": "coach-mini",
                                      "object": "model"}]}).encode()
                    else:
                        payload = b'{"error": "not found"}'
                    self.send_response(200 if payload != b'{"error": "not found"}' else 404)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                n = int(self.headers.get("Content-Length") or 0)
                try:
                    body = json.loads(self.rfile.read(n))
                except ValueError:
                    body = {}
                with state.lock:
                    state.live += 1
                    state.max_live = max(state.max_live, state.live)
                    state.requests.append({
                        "path": self.path, "body": body,
                        "auth": self.headers.get("Authorization"),
                        "ts": time.monotonic()})
                try:
                    self._respond(body)
                except (BrokenPipeError, ConnectionResetError):
                    # the hang script makes clients abandon mid-response;
                    # a dead socket is the test's doing, not a defect
                    pass
                finally:
                    with state.lock:
                        state.live -= 1

            def _respond(self, body):
                if state.auth is not None and \
                        self.headers.get("Authorization") != state.auth:
                    # leaky-provider realism: some 401 diagnostics echo
                    # the presented credential — the redaction layer must
                    # survive exactly this
                    payload = json.dumps({"error": {"message":
                        "invalid api key; presented: "
                        f"{self.headers.get('Authorization')}"}}).encode()
                    self.send_response(401)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                if state.strict and self.path.rstrip("/").endswith(
                        "/chat/completions"):
                    problem = check_wire(body)
                    if problem is not None:
                        with state.lock:
                            state.violations.append(problem)
                        payload = json.dumps({"error": {
                            "message": f"invalid messages: {problem}",
                            "type": "invalid_request_error"}}).encode()
                        self.send_response(400)
                        self.send_header("Content-Type",
                                         "application/json")
                        self.send_header("Content-Length", str(len(payload)))
                        self.end_headers()
                        self.wfile.write(payload)
                        return
                if state.script:
                    item = state.script[0]
                    if len(state.script) > 1:
                        state.script.pop(0)
                else:
                    item = None
                if item is None:
                    outer_err = json.dumps({"error": {"message":
                        "fake model script exhausted"}}).encode()
                    self.send_response(500)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(outer_err)))
                    self.end_headers()
                    self.wfile.write(outer_err)
                    return
                if state.hang_s:
                    time.sleep(state.hang_s)
                if item.get("_delay"):
                    time.sleep(float(item["_delay"]))
                status = item.get("_status", 200)
                if item.get("_error_echo"):
                    # leaky provider on ANY status: the diagnostic body
                    # echoes the Authorization header and (optionally) a
                    # caller-chosen slice of the request — the redaction
                    # and status-only-diagnostic layers must survive it
                    leaked = {"auth": self.headers.get("Authorization")}
                    if state.echo_auth_errors:
                        leaked["messages"] = str(body.get("messages"))[:400]
                    payload = json.dumps({"error": {
                        "message": "provider diagnostic", **leaked}}).encode()
                    self.send_response(item.get("_status", 500))
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return
                if item.get("_stream"):
                    self._sse(item["_stream"], body)
                    return
                choice = dict(item.get("_choice", item))
                # on the real wire, usage is TOP-LEVEL on the completion,
                # not inside the choice — script authors pass it per-item
                # and it is lifted here so the SDK sees real shapes
                usage = choice.pop("usage", None)
                envelope = {
                    "id": "chatcmpl-fake", "object": "chat.completion",
                    "created": 0, "model": body.get("model", "fake"),
                    "choices": [choice]}
                if usage:
                    envelope["usage"] = usage
                payload = json.dumps(envelope).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def _sse(self, chunks, body):
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                for chunk in chunks:
                    envelope = {"id": "chatcmpl-stream",
                                "object": "chat.completion.chunk",
                                "created": 0,
                                "model": body.get("model", "fake"),
                                "choices": [chunk]}
                    self.wfile.write(
                        b"data: " + json.dumps(envelope).encode() + b"\n\n")
                    self.wfile.flush()
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()

            def log_message(self, *a):  # silence
                pass

        self._server = socketserver.ThreadingTCPServer(("127.0.0.1", 0),
                                                        Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)

    # -- lifecycle ----------------------------------------------------------
    def start(self) -> "FakeModelServer":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}/v1"

    # -- scripting -----------------------------------------------------------
    def script(self, items: list, *, auth: str | None = None,
               hang_s: float = 0.0) -> None:
        self.state.script = list(items)
        self.state.auth = auth
        self.state.hang_s = hang_s

    def set_strict(self, enabled: bool = True, *,
                   echo_error_bodies: bool = False) -> None:
        """STRICT provider mode: every chat request is protocol-checked
        (see check_wire) and violations answer HTTP 400 — the way a real
        strict provider behaves. echo_error_bodies additionally makes
        error diagnostics echo request message content (hostile-provider
        realism for the spoiler-leak regressions)."""
        self.state.strict = enabled
        self.state.echo_auth_errors = echo_error_bodies

    @property
    def violations(self) -> list:
        with self.state.lock:
            return list(self.state.violations)

    @property
    def requests(self) -> list:
        with self.state.lock:
            return list(self.state.requests)

    @property
    def max_concurrent(self) -> int:
        with self.state.lock:
            return self.state.max_live

    def request_bodies(self) -> list:
        return [r["body"] for r in self.requests]
