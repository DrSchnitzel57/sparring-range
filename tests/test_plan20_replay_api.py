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

    ops = client.get(f"/sessions/{sid}/operations",
                     headers=users["member"]).json()["operations"]
    assert len(ops) == 1 and ops[0]["op_uuid"] == op
    assert ops[0]["command"] == "ss -tlnp" and ops[0]["exit_code"] == 0
    assert ops[0]["end_ts"] is not None
    assert ops[0]["capture"]["chunks"] == 2
    assert ops[0]["registered"] is False      # no run_operations row here
    assert ops[0]["incomplete"] is False      # intent + result pair

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
    ops = client.get(f"/sessions/{sid}/operations",
                     headers=users["member"]).json()["operations"]
    assert ops[0]["has_output"] is True
    out = client.get(f"/sessions/{sid}/operations/{op}/output",
                     headers=users["member"]).json()
    assert [c["kind"] for c in out["chunks"]] == ["output", "gap"]
    page = client.get(f"/sessions/{sid}/operations/{op}/output",
                      params={"after_seq": 0, "limit": 1},
                      headers=users["member"]).json()
    assert [c["seq"] for c in page["chunks"]] == [1]


def test_operations_track_is_attacker_by_construction_not_guessing(client, users):
    """Verifier, telemetry (host audit) and bastion/MOTD events are NEVER
    attacker attribution (review finding 5): not through their action
    names, not through a matching or forged ``op_uuid`` at the top of
    their payload, and not through a nested payload either. ONLY the
    red plane's own intent/result events (``actor='red'``, set from the
    authenticated session-bound worker token) pair onto the track."""
    sid = _sid(client, users)
    real_op = U.uuid4().hex
    _op_pair(sid, real_op, command="id")           # genuine red pair
    shared_op = U.uuid4().hex
    _mk_events(sid, [
        {"actor": "system", "action_type": "action_result",
         "payload": {"op_uuid": shared_op, "command": "system-maintenance",
                     "exit_code": 0}},
        {"actor": "system", "action_type": "action_intent",
         "payload": {"op_uuid": shared_op, "command": "system-maintenance"}},
        {"actor": "verifier", "action_type": "action_result",
         "payload": {"op_uuid": U.uuid4().hex, "command": "verifier-probe",
                     "exit_code": 0}},
        {"actor": "telemetry", "action_type": "action_result", "host": "web01",
         "payload": {"op_uuid": U.uuid4().hex, "command": "motd-shim",
                     "exit_code": 0}},
        {"actor": "blue", "action_type": "bastion_session_start",
         "payload": {"note": "management login banner noise",
                     "op_uuid": U.uuid4().hex,
                     "command": "MOTD-banner-command"}},
        # nested spoof: a management event whose INNER payload carries a
        # full forged intent — top-level extraction never descends, and
         # the actor filter rejects it regardless
        {"actor": "system", "action_type": "config_update",
         "payload": {"nested": {"action_type": "action_intent",
                                "op_uuid": U.uuid4().hex,
                                "command": "NESTED-SPOOF-COMMAND"}}},
    ])
    ops = client.get(f"/sessions/{sid}/operations",
                     headers=users["member"]).json()["operations"]
    uuids = {o["op_uuid"] for o in ops}
    assert uuids == {real_op}, f"non-red events promoted: {uuids - {real_op}}"
    assert all(o["provenance"] == "red" for o in ops)
    rendered = str(ops)
    for banned in ("system-maintenance", "verifier-probe", "motd-shim",
                   "MOTD-banner-command", "NESTED-SPOOF-COMMAND"):
        assert banned not in rendered
    # the replay timeline still shows those events with their REAL
    # provenance (they are not deleted — just never attacker-attributed)
    rp = client.get(f"/sessions/{sid}/replay", headers=users["member"]).json()
    kinds = {(e["actor"], e["action_type"]) for e in rp["timeline"]}
    assert ("system", "action_result") in kinds
    assert ("telemetry", "action_result") in kinds
    assert rp["operations_total"] == 1          # only the genuine red op


# --- review finding 6: orphans, order and duplicates --------------------------------
def test_orphan_and_out_of_order_evidence_stays_honest_never_500(client,
                                                                 users):
    sid = _sid(client, users)
    orphan = U.uuid4().hex
    dup = U.uuid4().hex
    only_intent = U.uuid4().hex
    _mk_events(sid, [
        {"actor": "red", "action_type": "action_result",
         "payload": {"op_uuid": orphan, "command": "legacy-only-result",
                     "exit_code": 3}},
        {"actor": "red", "action_type": "action_intent",
         "payload": {"op_uuid": dup, "command": "twice", "op_id": 7}},
        {"actor": "red", "action_type": "action_result",
         "payload": {"op_uuid": dup, "command": "twice", "exit_code": 0}},
        {"actor": "red", "action_type": "action_result",
         "payload": {"op_uuid": dup, "command": "twice", "exit_code": 0}},
        {"actor": "red", "action_type": "action_intent",
         "payload": {"op_uuid": only_intent, "command": "still running",
                     "op_id": 8}},
    ])
    r = client.get(f"/sessions/{sid}/operations", headers=users["member"])
    assert r.status_code == 200, r.text
    ops = {o["op_uuid"]: o for o in r.json()["operations"]}
    assert ops[orphan]["incomplete"] is True
    assert ops[orphan].get("orphan_result") is True
    assert ops[orphan]["command"] == "legacy-only-result"
    assert ops[orphan]["intent_event_id"] is None      # nothing invented
    assert ops[orphan]["exit_code"] == 3               # the real fact kept
    assert ops[dup]["incomplete"] is False             # paired once
    assert ops[only_intent]["incomplete"] is True      # no result yet
    assert ops[only_intent]["result_event_id"] is None
    # a chunk request for the orphan op answers, never crashes
    out = client.get(f"/sessions/{sid}/operations/{orphan}/output",
                     headers=users["member"])
    assert out.status_code == 200 and out.json()["chunks"] == []


# --- review finding 11: bounded pages, honest raw cursor -----------------------------
def test_replay_pages_are_bounded_and_cursors_are_raw_server_positions(client,
                                                                       users):
    sid = _sid(client, users)
    _mk_events(sid, [pair for i in range(20) for pair in (
        {"actor": "red", "action_type": "action_intent",
         "payload": {"op_uuid": f"op-{i}", "op_id": i,
                     "command": f"cmd-{i}"}},
        {"actor": "red", "action_type": "action_result",
         "payload": {"op_uuid": f"op-{i}", "op_id": i,
                     "command": f"cmd-{i}", "exit_code": 0}})])
    _mk_events(sid, [{"actor": "blue", "action_type": "bastion_session_start"}
                     for _ in range(10)])

    # replay page: NO operations, NO cast bodies, bounded timeline
    rp = client.get(f"/sessions/{sid}/replay", params={"limit": 7},
                    headers=users["member"]).json()
    assert len(rp["timeline"]) <= 7
    assert "operations" not in rp and "casts" not in rp
    assert rp["operations_total"] == 20 and rp["casts_total"] == 0

    # collapsed noise: the cursor is the RAW last consumed id — the
    # displayed collapsed entry cannot make the next page re-consume
    expanded = client.get(f"/sessions/{sid}/replay",
                          params={"collapsed": False, "limit": 200},
                          headers=users["member"]).json()
    all_ids = [e["event_id"] for e in expanded["timeline"]]
    noise_at = next(i for i, e in enumerate(expanded["timeline"])
                    if e["action_type"] == "bastion_session_start")
    mid = client.get(f"/sessions/{sid}/replay",
                     params={"limit": noise_at + 3},
                     headers=users["member"]).json()
    raw_consumed = all_ids[noise_at + 2]
    assert mid["next_after_event_id"] == raw_consumed
    assert mid["timeline"][-1]["collapsed"] == 3
    # the LAST DISPLAYED id of a collapsed run is its FIRST event —
    # trusting it would re-consume the noise range; the server cursor
    # never does
    assert mid["timeline"][-1]["event_id"] < raw_consumed

    rp_all = client.get(f"/sessions/{sid}/replay", params={"limit": 100},
                        headers=users["member"]).json()
    noise_rows = [e for e in rp_all["timeline"]
                  if e["action_type"] == "connection_noise"]
    assert noise_rows and noise_rows[0]["collapsed"] >= 10

    # operations page: bounded, cursor advances, no overlap, no refetch
    # loop: keep paging until exhausted and assert monotonicity
    seen_cursors, collected = [], {}
    cursor = None
    for _ in range(30):
        params = {"limit": 5}
        if cursor is not None:
            params["after_event_id"] = cursor
        page = client.get(f"/sessions/{sid}/operations", params=params,
                          headers=users["member"]).json()
        for op in page["operations"]:
            collected[op["op_uuid"]] = op
        if not page["has_more"]:
            break
        assert page["next_after_event_id"] is not None
        assert not seen_cursors or page["next_after_event_id"] > \
            seen_cursors[-1]
        seen_cursors.append(page["next_after_event_id"])
        cursor = page["next_after_event_id"]
    assert len(collected) == 20
    assert seen_cursors, "expected multiple pages"


def test_casts_endpoint_is_paged(client, users, tmp_path):
    import json as jsonlib
    sid = _sid(client, users)
    recs_dir = tmp_path / "recordings"
    recs_dir.mkdir(exist_ok=True)
    hdr = {"version": 2, "width": 80, "height": 24,
           "timestamp": int(NOW.timestamp())}
    for i in range(3):
        cast = recs_dir / f"cast-{i}.cast"
        cast.write_text(jsonlib.dumps(hdr) + "\n" +
                        jsonlib.dumps([0.1, "o", f"cast-{i}\n"]) + "\n")
        btok = client.post("/admin/service_tokens",
                           json={"scope": "bastion", "session_id": sid},
                           headers=users["op"]).json()["token"]
        r = client.post(f"/sessions/{sid}/recordings",
                        json={"cast_path": str(cast)},
                        headers={"Authorization": f"Bearer {btok}"})
        assert r.status_code == 201, r.text
    page1 = client.get(f"/sessions/{sid}/casts", params={"limit": 2},
                       headers=users["member"]).json()
    assert len(page1["casts"]) == 2 and page1["has_more"] is True
    assert page1["next_after"] is not None
    page2 = client.get(f"/sessions/{sid}/casts",
                       params={"limit": 2, "after": page1["next_after"]},
                       headers=users["member"]).json()
    ids1 = {c["recording_id"] for c in page1["casts"]}
    ids2 = {c["recording_id"] for c in page2["casts"]}
    assert ids1.isdisjoint(ids2) and len(ids1 | ids2) == 3
    assert page2["has_more"] is False


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
    assert rp["operations_total"] >= 1        # facts exist…
    ops = client.get(f"/sessions/{sid}/operations",
                     headers=users["member"]).json()
    assert ops["operations"] == [] and ops["hidden"] is True
    assert "SEALCMD" not in str(rp) and "SEALCMD" not in str(ops)
    out = client.get(f"/sessions/{sid}/operations/{op}/output",
                     headers=users["member"]).json()
    assert out["chunks"] == [] and out["hidden"] is True
    # operator sees the same session's track fully
    ops_op = client.get(f"/sessions/{sid}/operations",
                        headers=users["op"]).json()
    assert ops_op["operations"][0]["command"] == "cat /root/SEALCMD"
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


# --- review finding 7: dashboard warnings from durable facts --------------------
def _set_match_state(sid, state):
    with db_ctx() as s:
        s.execute(text("UPDATE matches SET state = :st WHERE session_id = :s"),
                  {"st": state, "s": sid})
        s.commit()


def test_interrupted_match_and_incomplete_outcome_are_flagged(client, users):
    """The reviewer's exact repro: a session whose run ended with
    outcome 'incomplete', whose MATCH is 'interrupted' and which holds
    the durable teardown_incomplete fact used to render as fully
    healthy. Flags now come from the durable lifecycle state, and
    prose alone neither adds nor removes a warning."""
    sid = _sid(client, users)
    with db_ctx() as s:
        s.execute(text(
            "UPDATE sessions SET status = 'complete', outcome = 'incomplete',"
            " ended_at = now() WHERE session_id = :s"), {"s": sid})
        s.commit()
    _set_match_state(sid, "interrupted")
    _mk_events(sid, [{"actor": "system", "action_type": "teardown_incomplete",
                      "payload": {"reason": "VM still exists"}}])

    row = next(s for s in client.get("/sessions", headers=users["member"])
               .json()["sessions"] if s["session_id"] == sid)
    assert row["interrupted"] is True       # interrupted match: said so
    assert row["cleanup_pending"] is True   # obligations unresolved
    assert row["unscored"] is True          # completed without scorecard:
    #    UNSCORED stays a DISTINCT fact — the AI failure never folds it


def test_finalizing_and_resolved_cleanup_track_across_history(client, users):
    """finalizing = durable cleanup intent (pending); a completed match
    with resolved operations clears the flags; a NEWER obligation sets
    cleanup again — history pagination shows the same truth."""
    sid = _sid(client, users)
    with db_ctx() as s:
        s.execute(text("UPDATE sessions SET status = 'complete',"
                       " outcome = 'complete', ended_at = now()"
                       " WHERE session_id = :s"), {"s": sid})
        s.commit()
    _set_match_state(sid, "finalizing")
    row = next(s for s in client.get("/sessions", headers=users["member"])
               .json()["sessions"] if s["session_id"] == sid)
    assert row["cleanup_pending"] is True and row["interrupted"] is False

    _set_match_state(sid, "completed")
    row = next(s for s in client.get("/sessions", headers=users["member"])
               .json()["sessions"] if s["session_id"] == sid)
    assert row["cleanup_pending"] is False and row["interrupted"] is False

    # a newer obligation: unresolved operation re-raises cleanup only
    with db_ctx() as s:
        run_id = s.execute(text(
            "INSERT INTO runs (run_id, session_id, scenario_id, status)"
            " VALUES (gen_random_uuid(), :s, 'web-foothold-01', 'stopped')"
            " RETURNING run_id"), {"s": sid}).scalar()
        s.add(RunOperation(run_id=U.UUID(str(run_id)), session_id=U.UUID(sid),
                           op_id="op-" + "d" * 12, kind="remote",
                           state="active"))
        s.commit()
    row = next(s for s in client.get("/sessions",
                                     params={"view": "history"},
                                     headers=users["member"]).json()["sessions"]
               if s["session_id"] == sid)
    assert row["cleanup_pending"] is True


def test_unconfirmed_run_cessation_is_interrupted_and_unclean(client, users):
    sid = _sid(client, users)
    with db_ctx() as s:
        s.execute(text("UPDATE sessions SET status = 'complete',"
                       " outcome = 'complete', ended_at = now()"
                       " WHERE session_id = :s"), {"s": sid})
        s.execute(text(
            "INSERT INTO runs (run_id, session_id, scenario_id, status)"
            " VALUES (gen_random_uuid(), :s, 'web-foothold-01',"
            " 'cancel-unknown')"), {"s": sid})
        s.commit()
    row = next(s for s in client.get("/sessions", headers=users["member"])
               .json()["sessions"] if s["session_id"] == sid)
    assert row["interrupted"] is True and row["cleanup_pending"] is True


def test_prose_alone_never_moves_a_flag(client, users):
    """An agent_note that merely MENTIONS 'worker failure' — or any other
    wording — never flips interrupted (the old LIKE probe is gone); and
    its absence never hides a genuine interruption (covered above)."""
    sid = _sid(client, users)
    with db_ctx() as s:
        s.execute(text("UPDATE sessions SET status = 'complete',"
                       " outcome = 'complete', ended_at = now()"
                       " WHERE session_id = :s"), {"s": sid})
        s.commit()
    _mk_events(sid, [{"actor": "red", "action_type": "agent_note",
                      "payload": {"note": "no worker failure happened here"}}])
    row = next(s for s in client.get("/sessions", headers=users["member"])
               .json()["sessions"] if s["session_id"] == sid)
    assert row["interrupted"] is False and row["cleanup_pending"] is False
