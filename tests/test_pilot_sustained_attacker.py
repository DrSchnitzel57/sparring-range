"""Pilot step 3: sustained attacker loop + bounded gateway retry policy.

Fast-layer tests (no DB, no model, no SSH): the REAL RedAgentLoop against an
in-memory transport double, and the REAL ModelGateway with a patched sleep.
Proves: runs to the deadline (not to objective completion), per-action
throttle from the snapshot, strictly sequential dispatch (no overlap), and
the three-attempt/5-15s gateway policy that fails truthfully.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import pytest

from srplatform.model_gateway import ModelGateway
from srplatform.red_agent.loop import RedAgentLoop
from tests.helpers import FakeLLM, tool


class MemTransport:
    """Minimal in-memory transport: events, agent_state, objective truth."""

    def __init__(self, scenario, objective_state: dict):
        self._scenario = scenario
        self.events: list[dict] = []
        self.state: dict = {}
        self.objective_state = objective_state
        self.operations: dict = {}
        self._eid = 0

    def scenario_spec(self, session_id):
        return self._scenario

    def log_event(self, ev):
        self._eid += 1
        self.events.append({"event_id": self._eid, **ev})

    def events_since(self, session_id, after):
        return [e for e in self.events if e["event_id"] > after]

    def get_agent_state(self, session_id):
        return dict(self.state)

    def save_agent_state(self, session_id, summary, upto, phase):
        self.state = {"summary": summary, "summary_upto": upto,
                      "current_phase": phase}

    def verify_objective(self, session_id, objective_id):
        return {"passed": bool(self.objective_state.get(objective_id))}

    def register_operation(self, op_uuid, kind):
        self.operations[op_uuid] = "active"

    def complete_operation(self, op_uuid, state, detail=None):
        self.operations[op_uuid] = state


class SeqRunner:
    """Runner double that FAILS if two commands ever overlap."""

    def __init__(self, on_run=None):
        self.calls: list[tuple[str, float]] = []
        self._live = False
        self.on_run = on_run

    def run(self, command, op_id=None):
        assert not self._live, "OVERLAPPING ACTIONS — dispatch must be sequential"
        self._live = True
        try:
            self.calls.append((command, time.monotonic()))
            if self.on_run:
                self.on_run(command)
            return 0, "ok"
        finally:
            self._live = False


def _scenario(objectives):
    return {
        "id": "sustain-01", "name": "sustain test",
        "red": {"start_phase": "recon", "objectives": objectives},
        "topology": {"hosts": [{"name": "web01", "ip": "10.66.0.10",
                                "services": ["http"]}]},
    }


def _one_objective_scenario():
    return _scenario([{"id": "foothold", "phase": "initial-access",
                       "description": "own it", "verifier": "flag_file_present",
                       "args": {}}])


def test_sustained_loop_continues_past_objective_completion():
    obj = [{"id": "foothold", "phase": "initial-access", "description": "own it",
            "verifier": "flag_file_present", "args": {}}]
    truth = {"foothold": False}

    def on_run(cmd):
        if "exploit" in cmd:
            truth["foothold"] = True

    tr = MemTransport(_scenario(obj), truth)
    runner = SeqRunner(on_run=on_run)
    llm = FakeLLM([
        tool("pwn", "python3 exploit.py"),
        tool("claim", "DONE"),        # true claim — must NOT end the match
        tool("press", "curl http://10.66.0.10/admin"),  # sustained pressure
    ])
    result = RedAgentLoop("s1", "sustain-01", tr, llm, runner,
                          max_steps=3).run()
    assert result["complete"] is True          # objective IS achieved
    assert result["outcome"] == "incomplete"   # but the loop ran to its cap
    commands = [c for c, _ in runner.calls]
    assert any("admin" in c for c in commands), \
        "a confirmed-DONE must not end a sustained match"
    notes = [e for e in tr.events if e["action_type"] == "agent_note"]
    assert any("sustained match continues" in e["payload"].get("note", "")
               for e in notes)


def test_deadline_terminates_the_loop():
    tr = MemTransport(_one_objective_scenario(), {})
    runner = SeqRunner()
    past = datetime.now(timezone.utc) - timedelta(seconds=1)
    result = RedAgentLoop("s1", "sustain-01", tr, FakeLLM([]), runner,
                          deadline_utc=past).run()
    assert result["outcome"] == "deadline"
    assert not runner.calls, "no dispatch after the deadline"


def test_deadline_stops_during_throttle():
    tr = MemTransport(_one_objective_scenario(), {})
    runner = SeqRunner()
    soon = datetime.now(timezone.utc) + timedelta(milliseconds=30)
    llm = FakeLLM([tool("a", "whoami"), tool("b", "id")])
    result = RedAgentLoop("s1", "sustain-01", tr, llm, runner,
                          throttle_s=5.0, deadline_utc=soon).run()
    assert result["outcome"] == "deadline"
    assert len(runner.calls) == 1  # second action never dispatched


def test_throttle_spaces_actions_and_stays_sequential():
    tr = MemTransport(_one_objective_scenario(), {})
    runner = SeqRunner()
    llm = FakeLLM([tool("a", "one"), tool("b", "two"), tool("c", "three")])
    RedAgentLoop("s1", "sustain-01", tr, llm, runner,
                 max_steps=3, throttle_s=0.05).run()
    assert len(runner.calls) == 3
    gaps = [runner.calls[i + 1][1] - runner.calls[i][1]
            for i in range(len(runner.calls) - 1)]
    assert all(g >= 0.04 for g in gaps), f"throttle not applied: {gaps}"


def test_zero_throttle_dispatches_without_intentional_delay():
    tr = MemTransport(_one_objective_scenario(), {})
    runner = SeqRunner()
    llm = FakeLLM([tool("a", "one"), tool("b", "two")])
    t0 = time.monotonic()
    RedAgentLoop("s1", "sustain-01", tr, llm, runner,
                 max_steps=2, throttle_s=0).run()
    assert time.monotonic() - t0 < 1.0


def test_model_exhaustion_is_a_truthful_outcome():
    tr = MemTransport(_one_objective_scenario(), {})
    runner = SeqRunner()

    class DeadLLM:
        def complete(self, system, user):
            raise RuntimeError("model down")

    result = RedAgentLoop("s1", "sustain-01", tr, DeadLLM(), runner).run()
    assert result["outcome"] == "model_unavailable"
    notes = [e for e in tr.events if e["action_type"] == "agent_note"]
    assert any("model_error" in e["payload"] for e in notes)


# ------------------------------------------------------- gateway retry policy
def test_gateway_three_attempts_with_5_15_delays(monkeypatch):
    import srplatform.model_gateway as mg
    sleeps: list[float] = []
    monkeypatch.setattr(mg, "_sleep", lambda s: sleeps.append(s))
    gw = ModelGateway(max_queue=4)
    calls = {"n": 0}

    def flaky():
        calls["n"] += 1
        if calls["n"] < 3:
            raise RuntimeError("transient")
        return "recovered"

    fut = gw.submit(5, "red-turn", flaky)
    assert gw.wait(fut, timeout=5) == "recovered"
    assert sleeps == [5.0, 15.0]
    assert calls["n"] == 3
    assert gw.metrics["completed"] == 1 and gw.metrics["failed"] == 0


def test_gateway_exhaustion_raises_the_real_error(monkeypatch):
    import srplatform.model_gateway as mg
    sleeps: list[float] = []
    monkeypatch.setattr(mg, "_sleep", lambda s: sleeps.append(s))
    gw = ModelGateway(max_queue=4)

    def down():
        raise RuntimeError("endpoint gone")

    fut = gw.submit(5, "red-turn", down)
    with pytest.raises(RuntimeError, match="endpoint gone"):
        gw.wait(fut, timeout=5)
    assert sleeps == [5.0, 15.0]           # exactly three attempts
    assert gw.metrics["failed"] == 1       # counted once, truthfully
    assert "endpoint gone" in gw.metrics["last_error"]


def test_worker_pace_and_deadline_env(monkeypatch):
    from srplatform.red_agent import worker
    monkeypatch.delenv("SR_ATTACK_PACE_S", raising=False)
    assert worker._pace_seconds() == 30.0          # snapshot default
    monkeypatch.setenv("SR_ATTACK_PACE_S", "0")
    assert worker._pace_seconds() == 0.0           # no-delay option
    monkeypatch.setenv("SR_ATTACK_PACE_S", "15")
    assert worker._pace_seconds() == 15.0
    monkeypatch.setenv("SR_ATTACK_PACE_S", "garbage")
    assert worker._pace_seconds() == 30.0          # never crash on bad input
    monkeypatch.delenv("SR_MATCH_DEADLINE_UTC", raising=False)
    assert worker._match_deadline() is None
    monkeypatch.setenv("SR_MATCH_DEADLINE_UTC", "2026-10-13T20:00:00+00:00")
    assert worker._match_deadline().year == 2026
    monkeypatch.setenv("SR_MATCH_DEADLINE_UTC", "not-a-date")
    assert worker._match_deadline() is None
