"""M3 acceptance tests — Part 5/M3 'Accept when':

  * `run web-foothold-01` drives the agent to the foothold objective
  * the FLAG VERIFIER (not the model's claim) confirms compromise
  * every red step is in `events` with a `phase` tag
  * killing and restarting the agent mid-run resumes correctly from agent_state

The loop is the real one; only the model (scripted) and Kali (fake sandbox with
an in-memory range filesystem) are simulated. Drew's live model + Kali box are
the human gate, but the harness contract is pinned here.
"""
import json

import pytest
from fastapi.testclient import TestClient

from srplatform.api.app import app
from srplatform.red_agent.loop import RedAgentLoop
from srplatform.red_agent.sandbox import FakeSandbox
from srplatform.red_agent.transport import TestClientTransport

SCENARIO = "web-foothold-01"


def tool(thought: str, command: str) -> str:
    return json.dumps({"thought": thought, "propose_phase": None, "tool": "shell",
                       "args": {"command": command}})


class FakeLLM:
    """Scripted model. Summarization requests (recognizable system prompt) always
    get a canned compressed report."""

    def __init__(self, script: list):
        self.script = list(script)
        self.calls: list[tuple[str, str]] = []

    def complete(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        if "situation report" in system:
            return "SUMMARY: web01 discovered; exploit pending."
        if not self.script:
            raise AssertionError("FakeLLM script exhausted")
        item = self.script.pop(0)
        if isinstance(item, BaseException):  # KeyboardInterrupt is BaseException
            raise item
        return item


@pytest.fixture()
def session(migrated_db):
    c = TestClient(app)
    sid = c.post("/sessions", json={"scenario_id": SCENARIO, "username": "drew"}).json()["session_id"]
    return c, sid


def make_loop(c, sid, script, sandbox):
    return RedAgentLoop(sid, SCENARIO, TestClientTransport(c), FakeLLM(script), sandbox,
                        max_steps=12, compress_after=3, keep_recent=2)


def test_m3_agent_reaches_objectives_confirmed_by_verifier(session):
    c, sid = session
    sb = FakeSandbox(script={
        "nmap": (0, "Nmap scan report for 10.66.0.10\n80/tcp open http"),
        "exploit.py": lambda cmd: (0, "root shell obtained") if _plant(sb) else (1, "exploit failed"),
        "persist.sh": lambda cmd: (0, "cron installed") if _cron(sb) else (1, "nope"),
    })

    result = make_loop(c, sid, [
        tool("recon the web server", "nmap -sV 10.66.0.10"),
        tool("run the webapp exploit", "python3 exploit.py --target 10.66.0.10"),
        tool("install cron persistence", "bash persist.sh"),
        tool("believe we are done", "DONE"),
    ], sb).run()

    assert result["complete"] is True
    assert set(result["achieved"]) == {"foothold", "persistence"}

    # the FLAG VERIFIER (actor 'system', action 'verifier') — not the model —
    # is what marks compromise; red claims alone never count
    logged = c.get("/events", params={"session_id": sid}).json()
    vpass = [e for e in logged if e["action_type"] == "verifier" and e["payload"].get("passed")]
    assert {v["payload"]["objective"] for v in vpass} == {"foothold", "persistence"}

    # every red step carries a phase tag (acceptance: 'every red step is in
    # events with a phase tag')
    red_steps = [e for e in logged if e["actor"] == "red"]
    assert red_steps and all(e["phase"] for e in red_steps)
    assert any(e["payload"].get("command") == "nmap -sV 10.66.0.10" for e in red_steps)

    # rolling memory lives in agent_state, and it compressed at least once
    st = c.get(f"/agent_state/{sid}").json()
    assert st["summary"] and "SUMMARY" in st["summary"]
    assert st["summary_upto"] and st["summary_upto"] > 0


def test_m3_no_self_reported_success_without_verifier_proof(session):
    """Hallucinated success must NOT complete the scenario (constraint #3)."""
    c, sid = session
    sb = FakeSandbox(script={"nmap": (0, "80/tcp open")})
    result = make_loop(c, sid, [
        tool("recon", "nmap -p80 10.66.0.10"),
        tool("claim victory with no exploit run", "DONE"),
        tool("claim again", "DONE"),
        tool("again", "DONE"),
    ], sb).run()

    assert result["complete"] is False
    assert result["achieved"] == []
    logged = c.get("/events", params={"session_id": sid}).json()
    claims = [e for e in logged if e["action_type"] == "verifier"
              and "verifiers did not confirm" in str(e["payload"].get("note", ""))]
    assert claims, "unconfirmed DONE claims must be logged"


def test_m3_kill_and_restart_resumes_from_agent_state(session):
    c, sid = session
    sb = FakeSandbox(script={
        "nmap": (0, "Nmap report 10.66.0.10"),
        "exploit.py": lambda cmd: (0, "root shell") if _plant(sb) else (1, "fail"),
        "persist.sh": lambda cmd: (0, "cron") if _cron(sb) else (1, "fail"),
    })

    # --- first life: recon + exploit, then the process dies mid-run
    with pytest.raises(KeyboardInterrupt):
        make_loop(c, sid, [
            tool("recon", "nmap -sV 10.66.0.10"),
            tool("exploit", "python3 exploit.py --target 10.66.0.10"),
            KeyboardInterrupt(),  # <- kill arrives on the 3rd model call
        ], sb).run()

    st_mid = c.get(f"/agent_state/{sid}").json()
    assert st_mid["current_phase"], "phase must be persisted before the kill"
    events_before = len(c.get("/events", params={"session_id": sid}).json())

    # --- second life: resumes, does NOT redo achieved objectives, finishes
    res = make_loop(c, sid, [
        tool("install persistence", "bash persist.sh"),
        tool("done", "DONE"),
    ], sb).run()
    assert res["complete"] is True, "resumed agent must finish from agent_state"

    # resume re-derived achieved objectives from verifier EVENTS (not memory)
    logged = c.get("/events", params={"session_id": sid}).json()
    assert len(logged) > events_before  # append-only: history grows, never shrinks
    foothold_verifs = [e for e in logged if e["action_type"] == "verifier"
                       and e["payload"].get("objective") == "foothold"]
    # after resume the loop re-checks objectives; that's fine — but it must not
    # have re-run the exploit command
    red_cmds = [e["payload"]["command"] for e in logged if e["actor"] == "red"]
    assert red_cmds.count("python3 exploit.py --target 10.66.0.10") == 1


# --------------------------------------------------------------------- helpers
def _plant(sb: FakeSandbox) -> bool:
    sb.fs.setdefault("web01", {})["/root/flag_foothold.txt"] = "FLAG{foothold-confirmed}"
    return True


def _cron(sb: FakeSandbox) -> bool:
    sb.fs.setdefault("web01", {})["/etc/cron.d/backup-sync"] = "*/5 * * * * root /usr/local/bin/sync.sh"
    return True
