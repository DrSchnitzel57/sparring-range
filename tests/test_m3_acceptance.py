"""M3 acceptance tests — Part 5/M3 'Accept when':

  * `run` drives the agent to the foothold objective
  * the FLAG VERIFIER (backend-executed, not the model's claim) confirms
    compromise — DONE without verifier truth is REFUSED (F15)
  * every red step is in `events` with a `phase` tag; intents precede execution (F14)
  * restart mid-run resumes from agent_state and NEVER blindly replays an
    intent whose outcome is unknown

The loop is the real one over the real API (TestClient transport) and the real
DB; the model is scripted, Kali is a scripted sandbox, and the target hosts
are an exec-channel double wired into the trusted verification service.
"""
import hashlib
import json

import pytest

from srplatform import verification_service
from srplatform.red_agent.loop import RedAgentLoop
from srplatform.red_agent.sandbox import FakeSandbox
from srplatform.red_agent.transport import TestClientTransport
from tests.helpers import FakeLLM, make_runner_token, tool
from tests.conftest import launch_and_wait


pytestmark = pytest.mark.db


def _setup(client, users):
    """Launch a session and wire scripted host state into the verifier exec."""
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    launch_and_wait(client, users["member"], sid)

    state = {"flag": None, "cron_files": ["e2scrub_all"], "crontab": ""}

    def host_exec(host: str, command: str):
        assert host == "10.66.0.10", f"verifier must exec against the DEPLOYED ip, got {host}"
        if command.startswith("cat "):
            if state["flag"] is None:
                return 1, "cat: No such file or directory"
            return 0, state["flag"]
        if command.startswith("python3 -c ") and "crontab" in command:
            files = {name: {"uid": 0, "gid": 0, "mode": 0o644,
                            "sha256": hashlib.sha256(name.encode()).hexdigest()}
                     for name in state["cron_files"]}
            return 0, json.dumps({"files": files, "crontab": state["crontab"]})
        return 127, "no route"

    verification_service.set_verifier_exec(host_exec)
    return sid, state


def _plant_pwn(state):
    def pwn(cmd):
        state["flag"] = "FLAG{web01-root}"
        return 0, "pwned"
    return pwn


def _persist(state):
    def go(cmd):
        state["cron_files"].append("backdoor")
        return 0, "ok"
    return go


def test_m3_loop_completes_only_via_backend_verifiers(client, users):
    sid, state = _setup(client, users)
    tr = TestClientTransport(client, make_runner_token(sid))
    sandbox = FakeSandbox(script={
        "nmap": (0, "Nmap report: 80/tcp open http"),
        "exploit.py": _plant_pwn(state),
        "persist.sh": _persist(state),
        "maintain": (0, "still in"),
    })
    # SUSTAINED MATCH (pilot step 3): objective completion does NOT end the
    # loop — the 4th action is dispatched AFTER everything is confirmed.
    result = RedAgentLoop(sid, "web-foothold-01", tr, FakeLLM([
        tool("recon", "nmap -sV 10.66.0.10"),
        tool("pwn", "python3 exploit.py --target 10.66.0.10"),
        tool("persist", "bash persist.sh"),
        tool("maintain", "bash maintain.sh"),
    ]), sandbox, max_steps=4, compress_after=50).run()

    assert result["complete"] is True and result["outcome"] == "incomplete"
    events = client.get("/events", params={"session_id": sid, "tail": 200},
                        headers=users["member"]).json()
    types = [e["action_type"] for e in events]
    # every step paired intent→result BEFORE/AFTER execution, phase-tagged
    assert types.count("action_intent") >= 4 and types.count("action_result") >= 4
    assert any(e["payload"].get("command", "").startswith("bash maintain")
               for e in events if e["action_type"] == "action_intent"), \
        "sustained match must keep acting after all objectives are confirmed"
    for e in events:
        if e["action_type"] in ("action_intent", "action_result"):
            assert e["phase"], "red steps must carry the phase tag"
    # the CONFIRMATION events are the backend's (actor=system), not the agent's
    verifs = [e for e in events if e["action_type"] == "verifier"]
    passed = {(e["payload"]["objective"], e["payload"]["passed"]) for e in verifs}
    assert ("foothold", True) in passed and ("persistence", True) in passed
    assert all(e["actor"] == "system" for e in verifs)
    assert any(e["payload"].get("verifier_version") for e in verifs)


def test_m3_done_claim_without_verifier_truth_is_refused(client, users):
    sid, state = _setup(client, users)
    tr = TestClientTransport(client, make_runner_token(sid))
    result = RedAgentLoop(sid, "web-foothold-01", tr,
                          FakeLLM([tool("i win", "DONE")] * 4),
                          FakeSandbox(), max_steps=10).run()
    assert result["complete"] is False and result["outcome"] == "no_progress"
    notes = [e for e in client.get("/events", params={"session_id": sid, "tail": 100},
                                   headers=users["member"]).json()
             if e["action_type"] == "agent_note"]
    assert any("verifiers did not confirm" in e["payload"].get("note", "") for e in notes)


def test_m3_partial_progress_not_marked_complete(client, users):
    """Model does the exploit but never persistence, then claims DONE."""
    sid, state = _setup(client, users)
    tr = TestClientTransport(client, make_runner_token(sid))
    sandbox = FakeSandbox(script={"exploit.py": _plant_pwn(state)})
    result = RedAgentLoop(sid, "web-foothold-01", tr, FakeLLM([
        tool("pwn", "python3 exploit.py --target 10.66.0.10"),
        tool("lie", "DONE"), tool("lie2", "DONE"), tool("lie3", "DONE"),
    ]), sandbox, max_steps=12).run()
    assert result["complete"] is False
    assert "foothold" in result["achieved"] and "persistence" not in result["achieved"]


def test_m3_restart_does_not_blindly_replay_unresolved_intent(client, users):
    sid, state = _setup(client, users)
    tr = TestClientTransport(client, make_runner_token(sid))
    # a previous worker died AFTER logging an intent but BEFORE its result
    tr.log_event({"session_id": sid, "actor": "red", "action_type": "action_intent",
                  "phase": "recon", "payload": {"op_id": 77, "command": "rm -rf / --preserve",
                                                "thought": "ghost intent"}})
    sandbox = FakeSandbox()
    result = RedAgentLoop(sid, "web-foothold-01", tr, FakeLLM([
        tool("pwn", "python3 exploit.py --target 10.66.0.10"),
    ]), sandbox, max_steps=1, compress_after=50).run()
    events = client.get("/events", params={"session_id": sid, "tail": 100},
                        headers=users["member"]).json()
    notes = [e for e in events if e["action_type"] == "agent_note"]
    assert any("NOT replayed" in e["payload"].get("note", "") and
               e["payload"].get("op_id") == 77 for e in notes)
    # the ghost command was never executed
    assert not [e for e in events if e["action_type"] == "action_result"
                and "rm -rf" in e["payload"].get("command", "")]
    # the resumed loop re-derived op_seq from history — its NEW intent is
    # numbered above the ghost (77), so ids never collide across restarts
    ints = [e for e in events if e["action_type"] == "action_intent"]
    new_intents = [e for e in ints if "rm -rf" not in e["payload"]["command"]]
    assert new_intents and new_intents[-1]["payload"]["op_id"] > 77


def test_m3_agent_state_checkpoint_and_summary_carries_forward(client, users):
    sid, state = _setup(client, users)
    tr = TestClientTransport(client, make_runner_token(sid))
    sandbox = FakeSandbox(script={
        "exploit.py": _plant_pwn(state), "persist.sh": _persist(state),
        "noise": (0, "x" * 10),
    })
    llm = FakeLLM([tool("a", "noise"), tool("b", "noise"), tool("c", "noise"),
                   tool("pwn", "python3 exploit.py --target 10.66.0.10"),
                   tool("persist", "bash persist.sh")])
    result = RedAgentLoop(sid, "web-foothold-01", tr, llm, sandbox,
                          max_steps=5, compress_after=4, keep_recent=2).run()
    assert result["complete"] is True
    st = tr.get_agent_state(sid)
    assert st["summary"], "compression must have persisted a summary"
    assert st["summary_upto"] > 0
    # every compression carried the PREVIOUS summary forward (F14)
    summarize_calls = [c for c in llm.calls if "situation report" in c[0]]
    assert len(summarize_calls) >= 2
    # second call's prompt includes the FIRST canned summary (carried, not dropped)
    assert "SUMMARY: web01 discovered" in summarize_calls[1][0]


def test_m3_run_endpoint_guards(client, users, monkeypatch):
    """API-level: /run refuses before launch; safety latch refuses with 423."""
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    r = client.post("/run/web-foothold-01", json={"session_id": sid},
                    headers=users["member"])
    assert r.status_code == 409  # not launched yet

    launch_and_wait(client, users["member"], sid)
    # engage the latch: /run must now refuse with reasons (423), never spawn
    client.post("/safety/killswitch", headers=users["op"])
    r = client.post("/run/web-foothold-01", json={"session_id": sid},
                    headers=users["member"])
    assert r.status_code == 423
    assert any("LATCH" in x.upper() for x in r.json()["detail"]["reasons"])
    client.post("/safety/killswitch-release", headers=users["op"])


def test_m3_run_endpoint_supervises_worker_lifecycle(client, users, monkeypatch):
    """Durable run state + process-group supervision, with the worker command
    replaced by `sleep` (the API-side contract is what's under test)."""
    import subprocess as sp
    import types

    from srplatform.api import runs as runs_mod

    launched = []

    def fake_popen(cmd, **kw):
        p = sp.Popen(["sleep", "120"], start_new_session=True,
                     stdout=sp.PIPE, stderr=sp.STDOUT, text=True)
        launched.append(p)
        return p

    monkeypatch.setattr(runs_mod, "subprocess",
                        types.SimpleNamespace(Popen=fake_popen, PIPE=sp.PIPE, STDOUT=sp.STDOUT))
    try:
        sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                          headers=users["member"]).json()["session_id"]
        launch_and_wait(client, users["member"], sid)

        r = client.post("/run/quick-win-01", json={"session_id": sid},
                        headers=users["member"])
        assert r.status_code == 202, r.text
        run_id = r.json()["run_id"]
        assert len(launched) == 1

        # duplicate /run never spawns a second worker while one is active
        r2 = client.post("/run/quick-win-01", json={"session_id": sid},
                         headers=users["member"])
        assert r2.json()["run_id"] == run_id and len(launched) == 1

        st = client.get(f"/runs/{run_id}", headers=users["member"]).json()
        assert st["status"] == "running"

        out = client.post(f"/runs/{run_id}/stop", headers=users["member"]).json()
        assert out["status"] == "cancelled"
        # the whole process GROUP is gone (killpg), not just marked
        deadline = __import__("time").time() + 5
        while launched[0].poll() is None and __import__("time").time() < deadline:
            __import__("time").sleep(0.05)
        assert launched[0].poll() is not None
    finally:
        for p in launched:
            if p.poll() is None:
                p.kill()
