"""The journey's evidence must be real (milestone 15, review rounds).

The journey claims three things that a green run must actually show: that
the member's browser can log in (without leaking the password), that a
service break is OBSERVED through the API's trusted checks and then
repaired, and that a submission decides exactly once.

These are unit-level proofs of the helpers' contracts: the live proof
belongs to the journey gate against the installed appliance.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from infra.dev import journey


def test_the_browser_diagnostics_never_echo_the_password(tmp_path):
    """`fill` carries the password as its VALUE: the diagnostics hide it."""
    secret = "SYNTHETIC-PASSWORD-DO-NOT-LOG"
    fake = tmp_path / "fake-playwright"
    # the browser opens, then the FILL fails and echoes every argument it
    # was given (including the password).
    fake.write_text("#!/bin/sh\n"
                    "case \"$2\" in\n"
                    "  fill) echo \"fill failed with: $*\"; exit 3;;\n"
                    "  *) exit 0;;\n"
                    "esac\n")
    fake.chmod(0o755)
    with pytest.raises(journey.JourneyError) as bad:
        journey._browser_check("https://appliance.invalid", "alice", secret,
                               cli=str(fake), timeout=10)
    text = str(bad.value)
    assert secret not in text, text
    assert "***" in text, text


def test_the_redactor_hides_the_value_not_the_selector():
    hidden = journey._redact_args(("fill", 'input[placeholder="password"]',
                                   "hunter2"))
    assert hidden == ("fill", 'input[placeholder="password"]', "***")
    assert "hunter2" not in " ".join(hidden)


class _Resp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status
        self.text = json.dumps(payload)

    def json(self):
        return self._payload


class _ScoreClient:
    """A client whose scorecard flips from broken to repaired."""

    def __init__(self, states):
        self.states = list(states)
        self.calls = 0

    def post(self, url, **kw):
        self.calls += 1
        state = self.states[min(self.calls - 1, len(self.states) - 1)]
        return _Resp({"status": "scored", "items": [
            {"verifier": "http_content", "domain": "recover",
             "points": 15, "awarded": 15 if state == "pass" else 0,
             "status": "passed" if state == "pass" else "failed"},
            {"verifier": "service_present", "domain": "recover",
             "points": 5, "awarded": 5 if state == "pass" else 0,
             "status": "passed" if state == "pass" else "failed"},
        ]})


def test_the_break_repair_transition_is_observed(monkeypatch):
    """A real break must FAIL the availability checks and the real repair
    must make them pass again."""
    commands: list[str] = []

    async def _fake_exec(conn, key, known_hosts, command):
        commands.append(command)
        return {"exit_status": 0, "stdout": "ok", "stderr": ""}

    monkeypatch.setattr(journey, "_ssh_exec", _fake_exec)
    operator = _ScoreClient(["fail", "pass"])
    out = journey._break_repair(None, operator, "sid-1", conn={}, ssh_key="k",
                                known_hosts="h")
    assert out["verified"] is True
    assert any("systemctl stop" in c for c in commands)
    assert any("systemctl start" in c for c in commands)
    # the score was taken twice: once broken, once repaired
    assert operator.calls >= 2


def test_a_break_that_is_not_observed_fails_the_journey(monkeypatch):
    """The service stayed available: the break was not real, so the journey
    must not claim it proved a break/repair."""

    async def _fake_exec(conn, key, known_hosts, command):
        return {"exit_status": 0, "stdout": "ok", "stderr": ""}

    monkeypatch.setattr(journey, "_ssh_exec", _fake_exec)
    operator = _ScoreClient(["pass"])
    with pytest.raises(journey.JourneyError) as bad:
        journey._break_repair(None, operator, "sid-1", conn={}, ssh_key="k",
                              known_hosts="h")
    assert "break was not observed" in str(bad.value)


def test_a_repair_that_is_not_verified_fails_the_journey(monkeypatch):
    async def _fake_exec(conn, key, known_hosts, command):
        return {"exit_status": 0, "stdout": "ok", "stderr": ""}

    monkeypatch.setattr(journey, "_ssh_exec", _fake_exec)
    operator = _ScoreClient(["fail", "fail"])
    with pytest.raises(journey.JourneyError) as bad:
        journey._break_repair(None, operator, "sid-1", conn={}, ssh_key="k",
                              known_hosts="h", repair_timeout_s=2)
    assert "repair was not verified" in str(bad.value)
