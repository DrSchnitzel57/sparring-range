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
    # the USERNAME fill succeeds; the PASSWORD fill fails and echoes every
    # argument it was given (including the password).
    # $1=-s=<session> $2=fill $3=<selector> $4=<value>
    fake.write_text("#!/bin/sh\n"
                    "case \"$3\" in\n"
                    "  *password*) echo \"fill failed with: $*\"; exit 3;;\n"
                    "  *) exit 0;;\n"
                    "esac\n")
    fake.chmod(0o755)
    with pytest.raises(journey.JourneyError) as bad:
        journey._browser_check("https://appliance.invalid", "alice", secret,
                               cli=str(fake), timeout=10)
    text = str(bad.value)
    assert secret not in text, text
    assert "***" in text, text


def test_a_password_fill_timeout_does_not_disclose_the_password(tmp_path):
    """A TIMEOUT escapes before the exit-status redaction.

    The original exception carries the whole command line — with the
    password in it — so it is caught and replaced by a sanitized message.
    """
    secret = "SYNTHETIC-PASSWORD-DO-NOT-LOG"
    fake = tmp_path / "stalling-playwright"
    fake.write_text("#!/bin/sh\n"
                    "case \"$3\" in\n"
                    "  *password*) sleep 30;;\n"
                    "  *) exit 0;;\n"
                    "esac\n")
    fake.chmod(0o755)
    with pytest.raises(journey.JourneyError) as bad:
        journey._browser_check("https://appliance.invalid", "alice", secret,
                               cli=str(fake), timeout=2)
    text = str(bad.value)
    assert secret not in text, text
    assert "***" in text, text
    assert "timed out" in text, text


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


def _exec_recorder(states: list[str], *, failing: bool = False):
    """A fake exec: the state answers come from `states` (in order)."""
    commands: list[str] = []
    remaining = list(states)

    async def _fake_exec(conn, key, known_hosts, command):
        commands.append(command)
        if "is-active" in command:
            if failing:
                return {"exit_status": 255, "stdout": "", "stderr": "ssh: fail"}
            state = remaining.pop(0) if remaining else remaining_last(states)
            return {"exit_status": 0, "stdout": state, "stderr": ""}
        return {"exit_status": 0, "stdout": "ok", "stderr": ""}

    def remaining_last(seq):
        return seq[-1] if seq else ""

    return _fake_exec, commands


def test_the_break_repair_transition_is_observed(monkeypatch):
    """A real break must FAIL the liveness check and the real repair must
    make it pass again — and the service's OWN state must confirm both."""
    fake, commands = _exec_recorder(["inactive", "active"])
    monkeypatch.setattr(journey, "_ssh_exec", fake)
    operator = _ScoreClient(["fail", "pass"])
    out = journey._break_repair(None, operator, "sid-1", conn={}, ssh_key="k",
                                known_hosts="h")
    assert out["verified"] is True
    assert out["broken_state"] == "inactive"
    assert out["repaired_state"] == "active"
    assert any("systemctl stop" in c for c in commands)
    assert any("systemctl start" in c for c in commands)
    # the score was taken twice: once broken, once repaired
    assert operator.calls >= 2


def test_a_stopped_service_is_observed_by_the_liveness_check(monkeypatch):
    """`service_present` asks whether the unit EXISTS.

    A stopped unit still exists, so the break must be observed by the
    LIVENESS check (http_content): with the service present but not
    serving, the break is real and the journey must accept it.
    """

    fake, _commands = _exec_recorder(["inactive", "active"])
    monkeypatch.setattr(journey, "_ssh_exec", fake)
    operator = _ScoreClient(["fail", "pass"])
    out = journey._break_repair(None, operator, "sid-1", conn={}, ssh_key="k",
                                known_hosts="h")
    assert out["verified"] is True


def test_a_break_that_is_not_observed_fails_the_journey(monkeypatch):
    """The service stayed available: the break was not real, so the journey
    must not claim it proved a break/repair."""

    # the service never stopped: the check passes and the service says so
    fake, _commands = _exec_recorder(["active", "active"])
    monkeypatch.setattr(journey, "_ssh_exec", fake)
    operator = _ScoreClient(["pass"])
    with pytest.raises(journey.JourneyError) as bad:
        journey._break_repair(None, operator, "sid-1", conn={}, ssh_key="k",
                              known_hosts="h")
    assert "break was not observed" in str(bad.value)


def test_an_unavailable_verification_is_not_a_broken_service(monkeypatch):
    """`unknown` is not evidence of a stopped service.

    The reviewer's probe: the management channel fails (exit 255), the
    check reports `unknown`, a later probe succeeds — that is probe
    recovery, not an observed outage.  The journey must not accept it.
    """
    fake, _commands = _exec_recorder([], failing=True)
    monkeypatch.setattr(journey, "_ssh_exec", fake)
    operator = _ScoreClient(["unknown", "pass"])
    with pytest.raises(journey.JourneyError):
        journey._break_repair(None, operator, "sid-1", conn={}, ssh_key="k",
                              known_hosts="h")


def test_a_probe_recovery_without_an_observed_outage_fails(monkeypatch):
    """The checks went unknown -> passed, but the service never stopped."""
    fake, _commands = _exec_recorder(["active", "active"])
    monkeypatch.setattr(journey, "_ssh_exec", fake)
    operator = _ScoreClient(["unknown", "pass"])
    with pytest.raises(journey.JourneyError) as bad:
        journey._break_repair(None, operator, "sid-1", conn={}, ssh_key="k",
                              known_hosts="h")
    assert "break was not observed" in str(bad.value)


def test_a_repair_that_is_not_verified_fails_the_journey(monkeypatch):
    # the service comes back, but the API's verification stays unavailable
    fake, _commands = _exec_recorder(["inactive", "active"])
    monkeypatch.setattr(journey, "_ssh_exec", fake)
    operator = _ScoreClient(["fail", "unknown"])
    with pytest.raises(journey.JourneyError) as bad:
        journey._break_repair(None, operator, "sid-1", conn={}, ssh_key="k",
                              known_hosts="h", repair_timeout_s=2)
    assert "repair was not verified" in str(bad.value)
