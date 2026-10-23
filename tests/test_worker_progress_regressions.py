"""Progress failures must remain truthful within the existing worker capability."""
from __future__ import annotations

import hashlib
import uuid
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import httpx
import pytest

from srplatform.red_agent.loop import RedAgentLoop
from srplatform import worker_supervisor as ws


class Transport:
    def __init__(self):
        self.events = []
        self.state = {"summary": "known facts [1]", "summary_upto": 0}

    def scenario_spec(self, session_id):
        return {"id": "test", "red": {"objectives": []}}

    def log_event(self, event):
        # Enforce the actual runner ingest allowlist, not a permissive fake.
        assert event["actor"] == "red"
        assert event["action_type"] in {"action_intent", "action_result", "agent_note"}
        self.events.append({**event, "event_id": len(self.events) + 1})

    def events_since(self, session_id, cursor):
        return [e for e in self.events if e["event_id"] > cursor]

    def get_agent_state(self, session_id):
        return dict(self.state)

    def save_agent_state(self, session_id, summary, summary_upto, phase):
        self.state = dict(summary=summary, summary_upto=summary_upto, current_phase=phase)


def make_loop(replies, **kwargs):
    transport = Transport()
    model = SimpleNamespace(complete=Mock(side_effect=replies))
    runner = SimpleNamespace(run=Mock(return_value=(0, "ok")))
    loop = RedAgentLoop(str(uuid.uuid4()), "test", transport, model, runner,
                        max_steps=1, **kwargs)
    return loop, transport, model, runner


def test_twice_malformed_output_uses_runner_permitted_note():
    loop, transport, _, runner = make_loop(["not JSON", "still not JSON"])
    result = loop.run()
    assert result["outcome"] == "incomplete"
    assert result["steps"] == 1
    runner.run.assert_not_called()
    assert "rejected twice" in transport.events[0]["payload"]["error"]


def test_attacker_prompt_does_not_assume_kali_tools():
    loop, _, model, _ = make_loop(['{"tool":"shell","args":{"command":"command -v curl"}}'])
    loop.run()
    prompt = model.complete.call_args.args[0]
    assert "isolated Linux attacker VM" in prompt
    assert "Do not assume Kali" in prompt
    assert "command -v" in prompt
    assert "There is no internet" in prompt


def test_missing_tool_then_malformed_turn_does_not_kill_next_dispatch():
    loop, transport, _, runner = make_loop([
        '{"tool":"shell","args":{"command":"fixture-missing"}}',
        "not JSON", "still not JSON",
        '{"tool":"shell","args":{"command":"command -v curl"}}',
    ])
    loop.max_steps = 3
    runner.run.side_effect = [(127, "fixture-missing: command not found"), (0, "/usr/bin/curl")]
    result = loop.run()
    assert result["steps"] == 3
    assert runner.run.call_count == 2
    assert sum(e["action_type"] == "action_result" for e in transport.events) == 2
    assert any("rejected twice" in (e["payload"].get("error") or "") for e in transport.events)


@pytest.mark.parametrize("replies", [
    [RuntimeError("model unavailable")],
    ["bad JSON", RuntimeError("empty/truncated response")],
    ["bad JSON", httpx.ConnectError("gateway down")],
    ["bad JSON", ValueError("gateway response invalid")],
])
def test_model_failures_on_either_attempt_are_explicit(replies):
    loop, transport, _, runner = make_loop(replies)
    result = loop.run()
    assert result["outcome"] == "model_unavailable"
    assert transport.events[-1]["payload"].get("model_error")
    runner.run.assert_not_called()


@pytest.mark.parametrize("summary", ["", " \n\t", None, 7, {}, RuntimeError("outage")])
def test_failed_compression_preserves_checkpoint_and_emits_bounded_progress(summary):
    loop, transport, _, _ = make_loop([summary])
    before = dict(transport.state)
    events = [{"event_id": 1, "actor": "red", "action_type": "action_result",
               "payload": {"output": "x" * 4000}}]
    assert loop.compress("known facts [1]", 1, events) is None
    assert transport.state == before
    assert [e["payload"]["state"] for e in transport.events] == ["started", "failed"]
    assert all(len(str(e["payload"])) < 450 for e in transport.events)


def test_valid_compression_keeps_facts_and_excludes_own_telemetry():
    loop, transport, model, _ = make_loop(["updated facts [1]"])
    events = [
        {"event_id": 1, "actor": "red", "action_type": "action_result",
         "payload": {"output": "target evidence"}},
        {"event_id": 2, "actor": "red", "action_type": "agent_note",
         "payload": {"activity": "compression", "error": "recursive sentinel"}},
    ]
    assert loop.compress("prior facts [0]", 2, events) == ("updated facts [1]", 2)
    prompt = model.complete.call_args.args[0]
    assert "prior facts [0]" in prompt and "target evidence" in prompt
    assert "recursive sentinel" not in prompt
    assert transport.events[-1]["payload"]["state"] == "completed"


def test_blank_compression_does_not_advance_durable_loop_state():
    loop, transport, _, runner = make_loop(
        ['{"tool":"shell","args":{"command":"synthetic"}}', "  "],
        compress_after=1, keep_recent=1)
    assert loop.run()["steps"] == 1
    assert transport.state["summary_upto"] == 0
    assert transport.state["summary"] == "known facts [1]"
    runner.run.assert_called_once()


def test_compression_requests_are_bounded_without_skipping_history():
    loop, transport, model, _ = make_loop(
        ['{"tool":"shell","args":{"command":"synthetic"}}', "facts [64]"],
        compress_after=1, keep_recent=1)
    for i in range(100):
        transport.log_event(dict(actor="red", action_type="agent_note", payload={"index": i}))
    loop.run()
    assert transport.state["summary_upto"] == 64
    summary_prompt = model.complete.call_args.args[0]
    assert "[64]" in summary_prompt and "[65]" not in summary_prompt


@pytest.mark.parametrize("status", [200, 403, 409, 422, 503])
def test_worker_completion_requires_success_status(monkeypatch, status):
    from srplatform.red_agent import worker
    response = httpx.Response(status, request=httpx.Request("POST", "http://api/complete"))
    monkeypatch.setattr(worker.httpx, "post", Mock(return_value=response))
    assert worker._report("http://api", "run", "token", {"outcome": "incomplete"}) is (status == 200)


def test_supervisor_retains_assignment_across_transport_and_status_failures(monkeypatch):
    sup = ws.Supervisor("http://api", "secret", 0.25, 1)
    assignment = ws.Assignment("run", "claim")
    sup.current = assignment
    request = httpx.Request("POST", "http://api/failed")
    bad = httpx.HTTPStatusError("unavailable", request=request,
                                response=httpx.Response(503, request=request))
    post = Mock(side_effect=[httpx.ConnectError("offline"), bad, {"ok": True}])
    monkeypatch.setattr(ws, "_post", post)
    waits = []

    def wait(delay):
        assert sup.current is assignment
        waits.append(delay)
        return False

    monkeypatch.setattr(sup.stop, "wait", wait)
    assert sup._resolve_assignment(object(), assignment, "child exited") is True
    assert sup.current is None
    assert waits == [0.25, 0.5]
    assert post.call_count == 3
    assert all(call.args[3]["claim_token"] == "claim" for call in post.call_args_list)


def test_generic_conflict_does_not_discard_assignment(monkeypatch):
    request = httpx.Request("POST", "http://api/failed")
    conflict = httpx.HTTPStatusError("conflict", request=request,
                                    response=httpx.Response(409, request=request))
    monkeypatch.setattr(ws, "_post", Mock(side_effect=conflict))
    sup = ws.Supervisor("http://api", "secret", 1, 1)
    assignment = ws.Assignment("run", "claim")
    sup.current = assignment
    assert sup._report(object(), assignment, "gone") is False
    assert sup.current is assignment


@pytest.mark.parametrize("reply", [
    {"ok": True},
    {"ok": False, "detail": "claim credential does not match — refused (obsolete claimant)"},
    {"ok": False, "detail": "worker exit recorded; remote cessation UNCONFIRMED"},
    {"ok": False, "detail": "unknown run"},
])
def test_supervisor_accepts_recorded_or_definitively_fenced_reply(monkeypatch, reply):
    monkeypatch.setattr(ws, "_post", Mock(return_value=reply))
    sup = ws.Supervisor("http://api", "secret", 1, 1)
    assert sup._report(object(), ws.Assignment("run", "claim"), "gone") is True


@pytest.mark.parametrize("path", ["exit", "spawn", "assign"])
def test_supervisor_run_never_claims_again_while_failure_report_is_pending(monkeypatch, path):
    sup = ws.Supervisor("http://api", "secret", 0.25, 1)
    child = SimpleNamespace(pid=123, wait=Mock(return_value=1))
    popen = Mock(side_effect=OSError("spawn failed")) if path == "spawn" else Mock(return_value=child)
    monkeypatch.setattr(ws.subprocess, "Popen", popen)
    monkeypatch.setattr(ws.os, "getpgid", lambda pid: pid)
    monkeypatch.setattr(ws, "_pstart", lambda pid: 99)
    monkeypatch.setattr(sup, "_terminate_child", Mock(return_value="child gone"))
    monkeypatch.setattr(ws.threading, "Thread", Mock())
    monkeypatch.setattr(ws.httpx, "Client", MagicMock())
    calls = []
    reports = 0

    def post(client, url, headers, body=None):
        nonlocal reports
        calls.append(url)
        if url.endswith("/claim"):
            assert calls.count(url) == 1, "pending assignment was discarded"
            return {"assignment": {"run_id": "run", "claim_token": "claim", "env": {}}}
        if url.endswith("/assign"):
            if path == "assign":
                raise httpx.ConnectError("assign reply lost")
            return {"ok": True}
        assert url.endswith("/failed")
        assert body["claim_token"] == "claim"
        assert sup.current.run_id == "run"
        reports += 1
        if reports == 1:
            raise httpx.ConnectError("callback reply lost")
        sup.stop.set()
        return {"ok": True}

    monkeypatch.setattr(ws, "_post", post)
    monkeypatch.setattr(sup.stop, "wait", Mock(return_value=False))
    assert sup.run() == 0
    assert sup.current is None
    assert reports == 2
    assert popen.call_count == 1


def test_supervisor_retry_backoff_is_capped(monkeypatch):
    sup = ws.Supervisor("http://api", "secret", 1, 1)
    assignment = ws.Assignment("run", "claim")
    sup.current = assignment
    monkeypatch.setattr(ws, "_post", Mock(side_effect=[{}] * 10 + [{"ok": True}]))
    wait = Mock(return_value=False)
    monkeypatch.setattr(sup.stop, "wait", wait)
    assert sup._resolve_assignment(object(), assignment, "gone")
    assert [c.args[0] for c in wait.call_args_list] == [1, 2, 4, 8, 16, 30, 30, 30, 30, 30]


@pytest.mark.parametrize("reply", [{}, {"ok": False, "detail": "try again"}])
def test_unacknowledged_report_at_shutdown_retains_assignment(monkeypatch, reply):
    monkeypatch.setattr(ws, "_post", Mock(return_value=reply))
    sup = ws.Supervisor("http://api", "secret", 1, 1)
    assignment = ws.Assignment("run", "claim")
    sup.current = assignment
    sup.stop.set()
    assert sup._resolve_assignment(object(), assignment, "gone") is False
    assert sup.current is assignment


@pytest.mark.db
def test_malformed_retry_and_compression_notes_pass_actual_runner_ingest(client, users):
    """Real authenticated ingest + append-only DB; no permissions broadened."""
    from srplatform.db.models import Run
    from srplatform.db.session import db

    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    token = f"wk-{uuid.uuid4().hex}"
    with db() as session:
        session.add(Run(session_id=uuid.UUID(sid), scenario_id="quick-win-01",
                        status="running", worker_token=hashlib.sha256(token.encode()).hexdigest()))
    loop, transport, _, _ = make_loop(["malformed", "malformed again", " "])
    loop.run()
    loop.compress("facts", 1, [])
    for event in transport.events:
        response = client.post("/events", json={**event, "session_id": sid},
                               headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 201, response.text
        assert response.json()["actor"] == "red"
    denied = client.post("/events", json={"action_type": "tool_call", "payload": {}},
                         headers={"Authorization": f"Bearer {token}"})
    assert denied.status_code == 422
