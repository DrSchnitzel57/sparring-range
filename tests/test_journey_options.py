"""The journey must cover the documented match options (plan 15, criterion 6).

The journey drives the INSTALLED appliance, so it cannot run in a developer
environment.  What CAN be proven here is that the journey asks for every
documented option — both presets, the three durations, both modes, both start
conditions and the inject toggle — and that the request it builds carries
them, so a missing option is a failed test rather than an untested path.
"""
from __future__ import annotations

import inspect
import json

import pytest

from infra.dev import journey


def test_option_matrix_covers_every_documented_option():
    opts = journey.SESSION_OPTIONS
    assert {o["duration_minutes"] for o in opts} == {30, 60, 120}
    assert {o["mode"] for o in opts} == {"practice", "evaluation"}
    assert {o["start_condition"] for o in opts} == {"network-entry",
                                                   "assumed-breach"}
    assert {o["injects_enabled"] for o in opts} == {True, False}
    assert journey.PRESETS == ("mojang-web-01", "mojang-web-db-01")


def test_journey_creates_a_session_for_every_option(monkeypatch):
    """The runner must POST the options, and it must walk the whole matrix."""
    seen: list[dict] = []

    class _Resp:
        def __init__(self, payload, status=200):
            self._payload = payload
            self.status_code = status
            self.text = json.dumps(payload)

        def json(self):
            return self._payload

    class _Client:
        def post(self, url, json=None, **kw):
            seen.append({"url": url, "body": json or {}})
            if url == "/sessions":
                return _Resp({"session_id": "sid-1", "status": "preparing"})
            if url.endswith("/launch"):
                return _Resp({"ok": True}, status=202)
            if url.endswith("/begin"):
                return _Resp({"ok": True, "status": "running",
                              "started_at": "2026-10-21T00:00:00Z"})
            if url.endswith("/end"):
                return _Resp({"ok": True, "status": "complete"})
            if url.endswith("/score"):
                return _Resp({"status": "unscored"})
            return _Resp({"ok": True})

        def get(self, url, **kw):
            if url.startswith("/sessions?mine=false"):
                return _Resp([{"session_id": "sid-1"}])
            if url.endswith("/connections"):
                return _Resp({"connections": [
                    {"host": "web01", "ip": "10.66.0.10",
                     "login_token": "tok-abc",
                     "ssh": "ssh 10.66.0.2 -p 2222 -l tok-abc"}]})
            if url.endswith("/operation"):
                return _Resp({"state": "succeeded"})
            if url.endswith("/score"):
                return _Resp({"status": "unscored"})
            if url.endswith("/replay"):
                # plan 20: the page only counts; casts moved to /casts
                return _Resp({"casts_total": 1, "operations_total": 0,
                              "sealed": False, "timeline": [],
                              "has_more": False, "next_after_event_id": None})
            if "/casts" in url:
                # the member's SSH transcript exists after the rehearsal
                return _Resp({"casts": [{"frames": [[0, "o", "hello"]],
                                         "header": {"timestamp": 1},
                                         "frame_count": 1}],
                              "has_more": False, "next_after": None})
            return _Resp({"session_id": "sid-1", "status": "complete",
                           "deployment_status": "ready",
                           "match": {"state": "ready", "snapshot_version": 7,
                                     "snapshot": {}}})

        def close(self):
            pass

    monkeypatch.setattr(journey, "_client", lambda *a, **k: _Client())
    # The live steps (SSH, the browser, the incident workflow) are proven by
    # the journey gate against the INSTALLED appliance; here they are
    # stubbed so this test can check the option matrix in isolation.
    async def _fake_ssh(*a, **k):
        return {"output": "ok"}

    monkeypatch.setattr(journey, "_ssh_check", _fake_ssh)
    monkeypatch.setattr(journey, "_browser_check",
                        lambda *a, **k: {"logged_in": True, "library": True})
    monkeypatch.setattr(journey, "_inject_workflow",
                        lambda *a, **k: {"submission_status": "incorrect"})
    monkeypatch.setattr(journey, "_refusal_paths", lambda *a, **k: {})
    monkeypatch.setattr(journey, "_break_repair",
                        lambda *a, **k: {"verified": True})
    journey.run_journey(base_url="https://appliance.invalid",
                        operator_token="op", member_token="member",
                        ssh_key="/tmp/member.key",
                        bastion_known_hosts="/tmp/known_hosts",
                        browser_url="https://appliance.invalid",
                        browser_user="member", browser_password="secret")
    bodies = [e["body"] for e in seen if e["url"] == "/sessions"]
    # both presets, the whole option matrix, and the reuse session
    assert len(bodies) == (len(journey.PRESETS) + len(journey.SESSION_OPTIONS)
                           + 1)
    for body in bodies:
        assert body["scenario_id"] in journey.PRESETS
        assert body["duration_minutes"] in (30, 60, 120)
        assert body["mode"] in ("practice", "evaluation")
        assert body["start_condition"] in ("network-entry", "assumed-breach")
        assert isinstance(body["injects_enabled"], bool)
    # every option combination is asked for at least once
    asked = {(b["duration_minutes"], b["mode"], b["start_condition"],
              b["injects_enabled"]) for b in bodies}
    for options in journey.SESSION_OPTIONS:
        assert (options["duration_minutes"], options["mode"],
                options["start_condition"],
                options["injects_enabled"]) in asked


def test_journey_refuses_a_session_that_ignored_its_options(monkeypatch):
    """A session that did not record the options it was created with is a
    failed journey."""
    class _Resp:
        def __init__(self, payload, status=200):
            self._payload = payload
            self.status_code = status
            self.text = json.dumps(payload)

        def json(self):
            return self._payload

    class _Client:
        def post(self, url, json=None, **kw):
            if url == "/sessions":
                return _Resp({"session_id": "sid-1"})
            if url.endswith("/launch"):
                return _Resp({"ok": True}, status=202)
            if url.endswith("/begin"):
                return _Resp({"ok": True, "status": "running",
                              "started_at": "2026-10-21T00:00:00Z"})
            if url.endswith("/end"):
                return _Resp({"ok": True, "status": "complete"})
            if url.endswith("/score"):
                return _Resp({"status": "unscored"})
            return _Resp({"ok": True})

        def get(self, url, **kw):
            if url.startswith("/sessions?mine=false"):
                return _Resp([{"session_id": "sid-1"}])
            if url.endswith("/connections"):
                return _Resp({"connections": [
                    {"host": "web01", "ip": "10.66.0.10",
                     "login_token": "tok-abc",
                     "ssh": "ssh 10.66.0.2 -p 2222 -l tok-abc"}]})
            if url.endswith("/operation"):
                return _Resp({"state": "succeeded"})
            if url.endswith("/score"):
                return _Resp({"status": "unscored"})
            if url.endswith("/replay"):
                # plan 20: the page only counts; casts moved to /casts
                return _Resp({"casts_total": 1, "operations_total": 0,
                              "sealed": False, "timeline": [],
                              "has_more": False, "next_after_event_id": None})
            if "/casts" in url:
                # the member's SSH transcript exists after the rehearsal
                return _Resp({"casts": [{"frames": [[0, "o", "hello"]],
                                         "header": {"timestamp": 1},
                                         "frame_count": 1}],
                              "has_more": False, "next_after": None})
            return _Resp({"session_id": "sid-1", "status": "ready",
                           "deployment_status": "ready",
                           "match": {"state": "ready", "snapshot_version": 7,
                                     "snapshot": {"duration_minutes": 999}}})

        def close(self):
            pass

    monkeypatch.setattr(journey, "_client", lambda *a, **k: _Client())
    async def _fake_ssh(*a, **k):
        return {"output": "ok"}

    monkeypatch.setattr(journey, "_ssh_check", _fake_ssh)
    monkeypatch.setattr(journey, "_browser_check",
                        lambda *a, **k: {"logged_in": True, "library": True})
    monkeypatch.setattr(journey, "_inject_workflow",
                        lambda *a, **k: {"submission_status": "incorrect"})
    monkeypatch.setattr(journey, "_refusal_paths", lambda *a, **k: {})
    monkeypatch.setattr(journey, "_break_repair",
                        lambda *a, **k: {"verified": True})
    with pytest.raises(journey.JourneyError):
        journey.run_journey(base_url="https://appliance.invalid",
                            operator_token="op", member_token="member",
                            ssh_key="/tmp/member.key",
                            bastion_known_hosts="/tmp/known_hosts",
                            browser_url="https://appliance.invalid",
                            browser_user="member", browser_password="secret")
