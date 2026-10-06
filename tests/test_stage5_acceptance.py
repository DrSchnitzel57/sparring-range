"""Stage 5 regressions (second follow-up review).

ONE shared model scheduler across processes (worker red turns vs interactive
hints), honest coach evidence labels (unattributed activity earns no defender
credit; remediation is a claim until verified), and the full safe practice
loop (capture -> verification -> score -> report -> cleanup) end to end.
"""
from __future__ import annotations

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from tests.helpers import tool


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class SlowFakeModel:
    """OpenAI-compatible endpoint with a per-request delay and a call log."""

    def __init__(self, delay=0.35, reply=None):
        self.delay = delay
        self.log = []
        self.reply = reply or tool("recon", "DONE")
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("content-length", 0))
                body = json.loads(self.rfile.read(n) or b"{}")
                outer.log.append(("req", time.monotonic()))
                time.sleep(outer.delay)
                outer.log.append(("done", time.monotonic()))
                content = outer.reply if callable(outer.reply) is False else outer.reply(body)
                out = json.dumps({"id": "f", "object": "chat.completion", "created": 0,
                                  "model": "f", "choices": [{"index": 0,
                                      "message": {"role": "assistant", "content": content},
                                      "finish_reason": "stop"}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def log_message(self, *a):
                pass

        self.port = _free_port()
        self.server = HTTPServer(("127.0.0.1", self.port), H)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        self.server.shutdown()


# --------------------------------------------------------------------------- #
# Stage 5 item 1 — ONE shared scheduler across processes                        #
# --------------------------------------------------------------------------- #

@pytest.mark.db
def test_hint_jumps_queued_red_turns_across_processes(migrated_db, test_db_url_owner,
                                                      tmp_path, monkeypatch):
    """ACROSS ACTUAL PROCESSES: a separate process posts red turns to the
    API's model endpoint (the worker's path); an interactive hint requested
    while red turns are queued must overtake them in the ONE shared
    gateway."""
    import subprocess
    import sys

    import httpx
    import uvicorn

    from infra.proxmox_client import FakePVEHttp, ProxmoxClient
    from srplatform import settings as st
    from srplatform.api import deps
    from srplatform.api.app import app
    from srplatform.model_gateway import set_model_gateway

    model = SlowFakeModel(delay=0.6)
    monkeypatch.setenv("SR_ENV", "dev")
    monkeypatch.setenv("LLM_BASE_URL", f"http://127.0.0.1:{model.port}/v1")
    monkeypatch.setenv("LLM_API_KEY", "fake")
    monkeypatch.setenv("SAFETY_STATE_FILE", str(tmp_path / "safety.json"))
    monkeypatch.setenv("RECORDINGS_DIR", str(tmp_path / "rec"))
    st.get_settings.cache_clear()
    set_model_gateway(None)

    httpd = FakePVEHttp()
    for vmid in (9001, 9002, 9003, 9004):
        httpd.vms[vmid] = {"name": f"tpl{vmid}", "template": vmid, "status": "stopped"}
    from tests.conftest import wipe_data
    wipe_data(test_db_url_owner)
    deps.set_proxmox(ProxmoxClient(api=httpd))

    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port,
                                           log_level="error"))
    threading.Thread(target=server.run, daemon=True).start()
    deadline = time.time() + 15
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    base = f"http://127.0.0.1:{port}"
    monkeypatch.setenv("API_BASE_URL", base)
    st.get_settings.cache_clear()
    set_model_gateway(None)

    try:
        httpx.post(f"{base}/auth/bootstrap",
                   json={"username": "drew", "password": "operator-testpw-9"})
        tok = httpx.post(f"{base}/auth/login",
                         json={"username": "drew", "password": "operator-testpw-9"}
                         ).json()["token"]
        H = {"Authorization": f"Bearer {tok}"}
        sid = httpx.post(f"{base}/sessions", json={"scenario_id": "quick-win-01"},
                         headers=H).json()["session_id"]
        assert httpx.post(f"{base}/sessions/{sid}/launch", headers=H).status_code == 200
        runner_token = _mint_runner_token(sid)

        # Warm the coach endpoint probe OUTSIDE the measured window (the
        # liveness probe is deliberately not gateway-scheduled).
        httpx.post(f"{base}/sessions/{sid}/hint", json={"question": "warm"},
                   headers=H, timeout=120)
        warm_calls = len([x for x in model.log if x[0] == "req"])

        # SEPARATE PROCESS: four CONCURRENT red turns — one occupies the
        # single slot, three genuinely queue behind it
        script = f"""
import sys, json, threading
import httpx
base = {base!r}
tok = {runner_token!r}
def red(i):
    r = httpx.post(f"{{base}}/internal/model/complete",
                   json={{"name": f"red-{{i}}", "system": "s", "user": f"u{{i}}"}},
                   headers={{"Authorization": f"Bearer {{tok}}"}}, timeout=120)
    print(json.dumps({{"red": i, "status": r.status_code}}), flush=True)
ts = [threading.Thread(target=red, args=(i,)) for i in range(4)]
for t in ts: t.start()
for t in ts: t.join()
print("ALL-DONE", flush=True)
"""
        proc = subprocess.Popen([sys.executable, "-c", script],
                                stdout=subprocess.PIPE, text=True,
                                env={"PATH": "/usr/bin:/bin",
                                     "PYTHONPATH": str(__import__("pathlib").Path(__file__).resolve().parents[1])})
        # let red0 occupy the slot and red1..3 queue up
        time.sleep(0.25)
        t0 = time.monotonic()
        hint = httpx.post(f"{base}/sessions/{sid}/hint", json={"question": "now?"},
                          headers=H, timeout=120)
        hint_wait = time.monotonic() - t0
        outs = []
        while True:
            line = proc.stdout.readline()
            if not line:
                break
            outs.append(line.strip())
            if "ALL-DONE" in line:
                break
        proc.wait(timeout=30)

        assert hint.status_code == 200, hint.text
        reds = [json.loads(x) for x in outs if x.startswith("{")]
        assert len(reds) == 4 and all(r["status"] == 200 for r in reds), outs
        # Timing proof: the hint was submitted while 3 red turns (0.6s each)
        # were queued behind one in flight. WITHOUT priority it would wait
        # ~4*delay; WITH cross-process priority it runs right after the
        # in-flight request.
        assert hint_wait < 3 * model.delay, (
            f"hint waited {hint_wait:.2f}s (>= {3 * model.delay:.1f}s) — it did "
            "not jump the queued red turns from the other process")
        # one scheduler served all scheduled calls (4 red + hint)
        assert len([x for x in model.log if x[0] == "req"]) == warm_calls + 5
    finally:
        server.should_exit = True
        model.stop()
        deps.set_proxmox(None)
        set_model_gateway(None)
        st.get_settings.cache_clear()


def _mint_runner_token(session_id) -> str:
    """Create an active run row + capability exactly like the run manager."""
    import uuid as _u

    from srplatform.db.models import Run
    from srplatform.db.session import db
    token = f"wk-{_u.uuid4().hex}"
    import hashlib
    with db() as s:
        s.add(Run(session_id=session_id, scenario_id="quick-win-01",
                  status="running", worker_token=hashlib.sha256(token.encode()).hexdigest()))
    return token


@pytest.mark.db
def test_worker_env_has_no_model_credential(client, users):
    """The worker holds NO model endpoint credential: red turns are scheduled
    through the API (the shared scheduler is the only model entry point)."""
    from srplatform.api.runs import _worker_env
    from srplatform.settings import get_settings
    run = type("R", (), {"run_id": __import__("uuid").uuid4()})()
    env = _worker_env(get_settings(), "tok", __import__("uuid").uuid4(), "quick-win-01", run)
    assert not any(k.startswith("LLM_") or k == "MODEL_QUEUE_MAX" for k in env)


@pytest.mark.db
def test_model_endpoint_requires_runner_capability(client, users):
    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    r = client.post("/internal/model/complete",
                    json={"system": "s", "user": "u"}, headers=users["member"])
    assert r.status_code == 403   # members cannot drive the model endpoint


# --------------------------------------------------------------------------- #
# Stage 5 item 2 — honest coach evidence labels                                 #
# --------------------------------------------------------------------------- #

def _ev(eid, ts, actor, kind, host=None, payload=None):
    return {"event_id": eid, "ts": f"2026-01-01T12:{ts:02d}:00+00:00", "actor": actor,
            "action_type": kind, "host": host, "payload": payload or {}, "phase": None,
            "mitre_technique": None}


def test_attacker_telemetry_cannot_earn_defender_credit():
    """Same-host auditd activity AFTER a passed objective is UNATTRIBUTED —
    it must not correlate as a defender response (the attacker's own `cat
    /etc/shadow` on the host is not the blue team responding)."""
    from srplatform.coach.timeline import compress_timeline
    events = [
        _ev(1, 0, "system", "verifier", "web01", {"objective": "flaggrab", "passed": True}),
        _ev(2, 5, "telemetry", "command", "web01",
            {"argv": "cat /etc/shadow", "comm": "sh"}),          # attacker activity!
    ]
    text, idx = compress_timeline(events)
    assert len(idx["misses"]) == 1, "unattributed activity must NOT count as a response"
    assert "unattributed" in text


def test_defender_attributed_response_does_correlate():
    from srplatform.coach.timeline import compress_timeline
    events = [
        _ev(1, 0, "system", "verifier", "web01", {"objective": "flaggrab", "passed": True}),
        _ev(2, 5, "blue:amy", "command", "web01", {"command": "ps aux"}),
    ]
    _, idx = compress_timeline(events)
    assert idx["misses"] == []


def test_remediation_is_labeled_a_claim():
    from srplatform.coach.timeline import compress_timeline
    events = [_ev(1, 0, "blue:amy", "remediation", "web01", {"action": "removed cron"})]
    text, idx = compress_timeline(events)
    assert len(idx["wins"]) == 1
    assert "claim" in text and "scorecard" in text


def test_detection_events_are_rendered():
    from srplatform.coach.timeline import compress_timeline
    events = [_ev(1, 0, "telemetry", "detection", "web01",
                  {"audit_key": "sparring_persistence", "argv": "echo x"})]
    text, _ = compress_timeline(events)
    assert "DETECT web01" in text and "sparring_persistence" in text


# --------------------------------------------------------------------------- #
# Stage 5 item 5 — full safe practice loop                                      #
# --------------------------------------------------------------------------- #

@pytest.mark.db
def test_full_practice_loop_capture_verify_score_report_cleanup(client, users):
    """Capture -> deterministic verification -> score -> report -> cleanup,
    asserting each artifact carries its honest provenance."""
    from srplatform import verification_service

    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    assert client.post(f"/sessions/{sid}/launch", headers=users["member"]).status_code == 200

    # CAPTURE: telemetry under the enrolled session-bound capability
    from srplatform.db.models import ServiceToken
    from srplatform.db.session import db
    with db() as s:
        tok = s.query(ServiceToken).filter_by(session_id=sid, scope="telemetry").first()
    assert tok is not None
    r = client.post("/ingest/auditd", json={"events": [
        {"kind": "command", "argv": "id", "uid": "0", "comm": "bash",
         "exe": "/usr/bin/bash", "source_id": "41", "boot_id": "b1"}]},
        headers={"Authorization": f"Bearer {tok.token}"})
    assert r.status_code == 201

    # VERIFICATION: controlled true host state passes deterministically
    def true_state(host, command):
        if "cat" in command and "flag" in command:
            return 0, "FLAG{quick-win}\n"
        if "awk" in command:
            return 0, ""
        if "list-unit-files" in command:
            return 0, "sshd.service enabled enabled\nnginx.service enabled enabled\n"
        return 1, ""
    verification_service.set_verifier_exec(true_state)
    try:
        v = client.post(f"/sessions/{sid}/verifier_checks",
                        json={"objective_id": "flaggrab"}, headers=users["member"])
        assert v.json()["status"] == "passed"

        # SCORE
        sc = client.post(f"/sessions/{sid}/score", headers=users["member"]).json()
        assert sc["earned"] == 15 and sc["status"] == "scored"
        assert sc["deployment"]["deployment_id"]      # identity recorded

        # REPORT
        aar = client.post(f"/sessions/{sid}/aar", json={"narrative": False},
                          headers=users["member"])
        assert aar.status_code == 200
        body = aar.json()
        assert body["persisted"] and body["evidence_cutoff_event_id"] > 0

        # CLEANUP: end (final trusted score while hosts live) + teardown
        assert client.post(f"/sessions/{sid}/end",
                           headers=users["member"]).status_code == 200
    finally:
        verification_service.set_verifier_exec(None)
    assert client.post(f"/sessions/{sid}/teardown",
                       headers=users["member"]).status_code == 200
    # capabilities revoked; rescore refused
    r = client.post("/ingest/auditd", json={"events": [
        {"kind": "command", "argv": "id", "source_id": "42", "boot_id": "b1"}]},
        headers={"Authorization": f"Bearer {tok.token}"})
    assert r.status_code in (401, 403)
    assert client.post(f"/sessions/{sid}/score",
                       headers=users["member"]).status_code == 503
    # historical score remains readable
    hist = client.get(f"/sessions/{sid}/score", headers=users["member"]).json()
    assert hist["earned"] == 15
