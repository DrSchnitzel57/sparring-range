"""Plan 20 replay projections + sessions list — pagination, filters,
provenance honesty and sealed visibility, all through the REAL API.

* the replay timeline is cursor-paged and filterable; casts are
  summaries (list rendering never downloads a cast);
* the operations track pairs ONLY the red agent's own intent/result
  events — telemetry commands, verifier traffic and bastion noise are
  NEVER attacker attribution;
* a sealed competition member gets no red commands through replay, the
  operations track or the chunk endpoint — enforcement is in the API;
* the sessions list paginates and marks interrupted / unscored /
  cleanup-pending truthfully, members see only their own.
"""
from __future__ import annotations

import uuid as U
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from srplatform.db.models import Event, RunOperation
from srplatform.db.session import db as db_ctx

pytestmark = pytest.mark.db

NOW = datetime.now(timezone.utc)


def _sid(client, users, mode="practice"):
    return client.post("/sessions", json={"scenario_id": "web-foothold-01",
                                          "mode": mode},
                       headers=users["member"]).json()["session_id"]


def _mk_events(sid, rows):
    with db_ctx() as s:
        for r in rows:
            s.add(Event(session_id=U.UUID(sid), ts=r.get("ts", NOW),
                        actor=r["actor"], action_type=r["action_type"],
                        payload=r.get("payload") or {}, host=r.get("host")))
        s.commit()


def _op_pair(sid, op_uuid, command="id", output_capture=None):
    _mk_events(sid, [
        {"actor": "red", "action_type": "action_intent",
         "payload": {"op_id": 1, "op_uuid": op_uuid, "command": command,
                     "thought": "t"}},
        {"actor": "red", "action_type": "action_result",
         "payload": {"op_id": 1, "op_uuid": op_uuid, "command": command,
                     "exit_code": 0, "timed_out": False,
                     "output_capture": output_capture}},
    ])


# --- replay timeline pagination + filters -------------------------------------
def test_replay_paging_and_filters(client, users):
    sid = _sid(client, users)
    rows = []
    for i in range(12):
        rows.append({"actor": "blue", "action_type": "note",
                     "payload": {"i": i},
                     "ts": NOW + timedelta(seconds=i)})
    _mk_events(sid, rows)
    rp = client.get(f"/sessions/{sid}/replay",
                    params={"limit": 5},
                    headers=users["member"]).json()
    assert len(rp["timeline"]) == 5
    full = client.get(f"/sessions/{sid}/replay", params={"limit": 100},
                      headers=users["member"]).json()
    assert rp["has_more"] is True
    assert rp["total_events"] == len(full["timeline"])
    assert rp["total_events"] >= 12   # 12 notes + the session's own events
    nxt = rp["next_after_event_id"]
    rp2 = client.get(f"/sessions/{sid}/replay",
                     params={"limit": 5, "after_event_id": nxt},
                     headers=users["member"]).json()
    ids1 = [e["event_id"] for e in rp["timeline"]]
    ids2 = [e["event_id"] for e in rp2["timeline"]]
    assert set(ids1).isdisjoint(ids2) and min(ids2) > max(ids1)

    f = client.get(f"/sessions/{sid}/replay",
                   params={"actor": "red"},
                   headers=users["member"]).json()
    assert f["timeline"] == [] and f["total_events"] == 0


def test_collapsed_noise_and_operation_track(client, users):
    sid = _sid(client, users)
    op = U.uuid4().hex
    _mk_events(sid, [
        {"actor": "blue", "action_type": "bastion_session_start"},
        {"actor": "blue", "action_type": "bastion_session_end"},
        {"actor": "blue", "action_type": "bastion_session_start"},
        {"actor": "blue", "action_type": "bastion_session_end",
         "ts": NOW + timedelta(seconds=9)},
        {"actor": "blue", "action_type": "detection",
         "payload": {"objective": "foothold"},
         "ts": NOW + timedelta(seconds=10)},
    ])
    _op_pair(sid, op, command="ss -tlnp",
             output_capture={"chunks": 2, "bytes_captured": 90,
                             "complete": True})
    rp = client.get(f"/sessions/{sid}/replay", headers=users["member"]).json()
    noise = [e for e in rp["timeline"]
             if e["action_type"] == "connection_noise"]
    assert noise and noise[0]["collapsed"] == 4       # honest count, folded
    assert noise[0]["last_event_id"] > noise[0]["first_event_id"]
    expanded = client.get(f"/sessions/{sid}/replay",
                          params={"collapsed": False},
                          headers=users["member"]).json()
    assert not any(e["action_type"] == "connection_noise"
                   for e in expanded["timeline"])

    ops = rp["operations"]
    assert len(ops) == 1 and ops[0]["op_uuid"] == op
    assert ops[0]["command"] == "ss -tlnp" and ops[0]["exit_code"] == 0
    assert ops[0]["end_ts"] is not None
    assert ops[0]["capture"]["chunks"] == 2

    # output chunk endpoint: no rows yet -> honest command-only fallback
    out = client.get(f"/sessions/{sid}/operations/{op}/output",
                     headers=users["member"]).json()
    assert out["chunks"] == [] and out.get("hidden") is None

    with db_ctx() as s:
        run_id = s.execute(text(
            "INSERT INTO runs (run_id, session_id, scenario_id, status)"
            " VALUES (gen_random_uuid(), :s, 'web-foothold-01', 'complete')"
            " RETURNING run_id"), {"s": sid}).scalar()
        s.execute(text(
            "INSERT INTO operation_outputs (run_id, session_id, op_id, seq,"
            " kind, text) VALUES (:r, :s, :op, 0, 'output', 'listing a'),"
            " (:r, :s, :op, 1, 'gap', 'capture hiccup')"),
            {"r": str(run_id), "s": sid, "op": op})
        s.commit()
    rp = client.get(f"/sessions/{sid}/replay", headers=users["member"]).json()
    assert rp["operations"][0]["has_output"] is True
    out = client.get(f"/sessions/{sid}/operations/{op}/output",
                     headers=users["member"]).json()
    assert [c["kind"] for c in out["chunks"]] == ["output", "gap"]
    page = client.get(f"/sessions/{sid}/operations/{op}/output",
                      params={"after_seq": 0, "limit": 1},
                      headers=users["member"]).json()
    assert [c["seq"] for c in page["chunks"]] == [1]


def test_operations_track_is_attacker_by_construction_not_guessing(client, users):
    """Verifier, telemetry (host audit) and bastion/MOTD-noise events are
    NEVER attacker attribution: only the red worker's own intent/result
    events pair onto the track. Host telemetry stays unattributed — the
    identity of who ran a host command cannot come from the payload."""
    sid = _sid(client, users)
    _mk_events(sid, [
        {"actor": "system", "action_type": "verifier",
         "payload": {"objective": "foothold", "passed": True,
                     "source": "scenario verifier"}},
        {"actor": "telemetry", "action_type": "command", "host": "web01",
         "payload": {"source": "auditd", "uid": 0, "comm": "sshd",
                     "argv": "motd-shim"}},
        {"actor": "blue", "action_type": "bastion_session_start",
         "payload": {"note": "management login banner noise"}},
    ])
    rp = client.get(f"/sessions/{sid}/replay", headers=users["member"]).json()
    assert rp["operations"] == []        # NOTHING pairs onto attacker track
    actors = {e["actor"] for e in rp["timeline"]}
    assert "red" not in actors
    # and the un-collapsed projection keeps their REAL provenance
    kinds = {(e["actor"], e["action_type"]) for e in rp["timeline"]}
    assert ("telemetry", "command") in kinds
    assert ("system", "verifier") in kinds
    assert all(not e.get("command") for e in rp["operations"])


# --- sealed visibility at every new door ---------------------------------------
def test_sealed_member_gets_no_commands_anywhere(client, users):
    sid = _sid(client, users, mode="competition")
    op = U.uuid4().hex
    _op_pair(sid, op, command="cat /root/SEALCMD",
             output_capture={"chunks": 1, "complete": True})
    with db_ctx() as s:
        run_id = s.execute(text(
            "INSERT INTO runs (run_id, session_id, scenario_id, status)"
            " VALUES (gen_random_uuid(), :s, 'web-foothold-01', 'running')"
            " RETURNING run_id"), {"s": sid}).scalar()
        s.execute(text(
            "INSERT INTO operation_outputs (run_id, session_id, op_id,"
            " seq, kind, text) VALUES (:r, :s, :op, 0, 'output',"
            " 'SEALED-OUTPUT-TEXT')"),
            {"r": str(run_id), "s": sid, "op": op})
        s.commit()

    rp = client.get(f"/sessions/{sid}/replay", headers=users["member"]).json()
    assert rp["sealed"] is True
    assert rp["operations"] == []
    assert "SEALCMD" not in str(rp)
    out = client.get(f"/sessions/{sid}/operations/{op}/output",
                     headers=users["member"]).json()
    assert out["chunks"] == [] and out["hidden"] is True
    # operator sees the same session's track fully
    rp_op = client.get(f"/sessions/{sid}/replay", headers=users["op"]).json()
    assert rp_op["operations"][0]["command"] == "cat /root/SEALCMD"
    out_op = client.get(f"/sessions/{sid}/operations/{op}/output",
                        headers=users["op"]).json()
    assert out_op["chunks"][0]["text"] == "SEALED-OUTPUT-TEXT"


# --- sessions list envelope -----------------------------------------------------
def test_sessions_list_pagination_and_flags(client, users):
    mine = [client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                        headers=users["member"]).json()["session_id"]
            for _ in range(3)]
    with db_ctx() as s:
        s.execute(text(
            "UPDATE sessions SET status = 'complete', outcome = 'complete',"
            " ended_at = now() WHERE session_id = :s"),
            {"s": mine[0]})
        s.execute(text(
            "UPDATE sessions SET status = 'failed',"
            " outcome = 'worker_failure', ended_at = now()"
            " WHERE session_id = :s"), {"s": mine[1]})
        # session 2 stays active (running status probe below)
        s.execute(text("UPDATE sessions SET status = 'running' "
                       "WHERE session_id = :s"), {"s": mine[2]})
        s.commit()
    # finished-but-unscored vs scored: score_snapshot event only on session 0
    _mk_events(mine[0], [{"actor": "system", "action_type": "score_snapshot",
                          "payload": {"scorecard": {"status": "scored"}}}])
    # cleanup-pending on the completed session: unresolved operation row
    with db_ctx() as s:
        run_id = s.execute(text(
            "INSERT INTO runs (run_id, session_id, scenario_id, status)"
            " VALUES (gen_random_uuid(), :s, 'web-foothold-01', 'stopped')"
            " RETURNING run_id"), {"s": mine[0]}).scalar()
        s.add(RunOperation(run_id=U.UUID(str(run_id)),
                           session_id=U.UUID(mine[0]),
                           op_id="op-" + "c" * 12, kind="remote",
                           state="cancel-unknown"))
        s.commit()

    lst = client.get("/sessions", params={"limit": 2},
                     headers=users["member"]).json()
    assert lst["total"] == 3 and len(lst["sessions"]) == 2
    assert lst["has_more"] is True
    page2 = client.get("/sessions", params={"limit": 2, "offset": 2},
                       headers=users["member"]).json()
    ids = {s["session_id"] for s in lst["sessions"]} | \
          {s["session_id"] for s in page2["sessions"]}
    assert ids == set(mine)

    by_id = {s["session_id"]: s for s in
             client.get("/sessions", headers=users["member"]).json()["sessions"]}
    assert by_id[mine[0]]["unscored"] is False      # has score_snapshot
    assert by_id[mine[0]]["cleanup_pending"] is True
    assert by_id[mine[0]]["interrupted"] is False
    assert by_id[mine[1]]["interrupted"] is True    # worker_failure
    assert by_id[mine[1]]["unscored"] is False      # failed, not completed
    assert by_id[mine[2]]["interrupted"] is False   # still active

    act = client.get("/sessions", params={"view": "active"},
                     headers=users["member"]).json()
    assert [s["session_id"] for s in act["sessions"]] == [mine[2]]
    his = client.get("/sessions", params={"view": "history"},
                     headers=users["member"]).json()
    assert {s["session_id"] for s in his["sessions"]} == {mine[0], mine[1]}


def test_sessions_list_membership_is_enforced(client, users):
    sid = _sid(client, users)
    other = client.post("/users", headers=users["op"],
                        json={"username": "p20other",
                              "password": "an0ther-testpw-9",
                              "role": "member"})
    assert other.status_code == 201, other.text
    tok = client.post("/auth/login", json={"username": "p20other",
                                           "password": "an0ther-testpw-9"})
    headers = {"Authorization": f"Bearer {tok.json()['token']}"}
    lst = client.get("/sessions", headers=headers).json()
    assert all(s["session_id"] != sid for s in lst["sessions"])
    # an ordinary member asking for the all-session view still sees only
    # their own (mine is not a trust boundary — authorization is)
    all_view = client.get("/sessions", params={"mine": False},
                          headers=headers).json()
    assert all(s["session_id"] != sid for s in all_view["sessions"])
    ops = client.get("/sessions", params={"mine": False},
                     headers=users["op"]).json()
    assert any(s["session_id"] == sid for s in ops["sessions"])
