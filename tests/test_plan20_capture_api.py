"""Plan 20 internal output plane — worker-authenticated, idempotent,
server-enforced quotas. Real API endpoints, real PostgreSQL, real worker
token hashing: forged op ids and bad tokens are refused; chunk
re-delivery is deduplicated on unique (run_id, op_id, seq) with the
server DISTINGUISHING a matching duplicate from a content conflict
(review finding 9); the SERVER independently enforces the per-operation
AND per-session quota over EVERY stored payload byte — gap text and
truncation markers included — with an atomic row cap and exactly ONE
honest ``truncated`` marker row per operation (review finding 3); and
observed read timestamps are stored apart from persist time (finding
10).
"""
from __future__ import annotations

import hashlib
import uuid as U

import pytest
from sqlalchemy import text

from srplatform.db.models import Run
from srplatform.db.session import db as db_ctx

pytestmark = pytest.mark.db


def _running_session(client, users):
    return client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                       headers=users["member"]).json()["session_id"]


def _run_with_token(sid) -> tuple[str, str]:
    token = f"wk-{uuid4hex()}"
    with db_ctx() as s:
        run = Run(session_id=U.UUID(sid), scenario_id="web-foothold-01",
                  status="running",
                  worker_token=hashlib.sha256(token.encode()).hexdigest())
        s.add(run)
        s.flush()
        rid = str(run.run_id)
    return rid, token


def uuid4hex() -> str:
    import uuid
    return uuid.uuid4().hex


def _register(client, rid, token, op="op-" + "a" * 12):
    r = client.post(f"/internal/runs/{rid}/operations",
                    json={"op_id": op, "kind": "local"},
                    headers={"X-Worker-Token": token})
    assert r.status_code == 201, r.text
    return op


def _append(client, rid, token, op, **body):
    return client.post(f"/internal/runs/{rid}/operations/{op}/output",
                       json=body, headers={"X-Worker-Token": token})


def _rows(rid, where="", args=None):
    with db_ctx() as s:
        return s.execute(text(
            "SELECT kind, text, dropped_bytes, read_ts, read_ts_claim, "
            "read_ts_status FROM operation_outputs"
            " WHERE run_id = :r " + where + " ORDER BY seq"),
            {"r": rid, **(args or {})}).fetchall()


def test_output_append_requires_worker_and_registered_op(client, users):
    sid = _running_session(client, users)
    rid, token = _run_with_token(sid)
    op = _register(client, rid, token)

    r = _append(client, rid, token, op, seq=0, kind="output", text="hello")
    assert r.status_code == 201 and r.json()["status"] == "stored"
    assert _append(client, rid, "wrong-token", op, seq=1,
                   text="x").status_code == 403
    forged = "op-" + "f" * 12
    assert _append(client, rid, token, forged, seq=0,
                   text="orphan").status_code == 404
    assert _append(client, rid, token, op, seq=1,
                   kind="silently-missing", text=None).status_code == 422
    # empty output text and oversized chunks are protocol violations, not
    # silently-stored rows (finding 3: every payload is bounded)
    assert _append(client, rid, token, op, seq=2,
                   text="").status_code == 422
    assert _append(client, rid, token, op, seq=3,
                   text="x" * 70_000).status_code == 422

    rows = _rows(rid)
    assert [(r[0], r[1]) for r in rows] == [("output", "hello")]


def test_chunk_redelivery_distinguishes_duplicate_from_conflict(client,
                                                                users):
    """Finding 9's server half + plan 22 F8: an idempotent re-delivery
    (same seq, kind, text AND timing/drop metadata) answers ``duplicate``
    (200); ANY divergence at a known seq answers ``conflict`` with HTTP
    409 — never silently stored, never overwritten, never a silent 200."""
    sid = _running_session(client, users)
    rid, token = _run_with_token(sid)
    op = _register(client, rid, token)
    import time as _t
    ts_now = _t.time()
    first = _append(client, rid, token, op, seq=0, text="first delivery",
                    read_ts=ts_now, dropped_bytes=7)
    assert first.json()["status"] == "stored"

    same = _append(client, rid, token, op, seq=0, text="first delivery",
                   read_ts=ts_now, dropped_bytes=7)
    assert same.status_code == 200 and same.json()["status"] == "duplicate"
    clash = _append(client, rid, token, op, seq=0, text="different bytes")
    assert clash.status_code == 409 and clash.json()["status"] == "conflict"
    # F8: same text but a divergent timing/drop claim is STILL a conflict
    ts_clash = _append(client, rid, token, op, seq=0, text="first delivery",
                       read_ts=ts_now + 0.5, dropped_bytes=7)
    assert ts_clash.status_code == 409, ts_clash.text
    drop_clash = _append(client, rid, token, op, seq=0, text="first delivery",
                         read_ts=ts_now, dropped_bytes=8)
    assert drop_clash.status_code == 409, drop_clash.text
    rows = _rows(rid)
    assert len(rows) == 1 and rows[0][1] == "first delivery"


def test_server_enforces_quota_with_one_marker(client, users, monkeypatch):
    import srplatform.api.app as app_mod
    from srplatform.settings import get_settings
    small = get_settings().model_copy(update={"runner_op_capture_bytes": 80})
    monkeypatch.setattr(app_mod, "get_settings", lambda: small)

    sid = _running_session(client, users)
    rid, token = _run_with_token(sid)
    op = _register(client, rid, token)
    assert _append(client, rid, token, op, seq=0,
                   text="1234567890").json()["status"] == "stored"
    over = _append(client, rid, token, op, seq=1, text="overflow")
    assert over.json()["status"] == "quota"
    # later chunks also refuse, but the marker exists exactly ONCE
    assert _append(client, rid, token, op, seq=2,
                   text="more").json()["status"] == "quota"
    kinds = [(r[0], r[1]) for r in _rows(rid)]
    assert kinds == [("output", "1234567890"),
                     ("truncated",
                      "server capture quota reached — further chunks were "
                      "not stored")]


def test_quota_charges_every_payload_not_just_output_text(client, users,
                                                          monkeypatch):
    """Finding 3's exact repro: with an 80-byte budget (the 63-byte reserved marker
    included), ten authenticated
    400-byte gap requests used to store 4000 uncharged bytes (and TWO
    truncation markers). Now gap text counts against the same operation
    and session budgets, and the marker stays exactly one."""
    import srplatform.api.app as app_mod
    from srplatform.settings import get_settings
    small = get_settings().model_copy(update={
        "runner_op_capture_bytes": 80, "runner_session_capture_bytes": 4096,
        "runner_op_capture_rows": 1000})
    monkeypatch.setattr(app_mod, "get_settings", lambda: small)

    sid = _running_session(client, users)
    rid, token = _run_with_token(sid)
    op = _register(client, rid, token)
    assert _append(client, rid, token, op, seq=0,
                   text="1234567890").json()["status"] == "stored"
    for i in range(1, 11):
        r = _append(client, rid, token, op, seq=i, kind="gap",
                    text="x" * 400)
        assert r.json()["status"] == "quota", f"gap row {i} was charged 0"
    rows = _rows(rid)
    stored_bytes = sum(len((r[1] or "").encode()) for r in rows)
    # 10 charged bytes + exactly one server-authored marker (its own
    # short fixed text is the only other stored payload)
    assert stored_bytes <= 10 + 128
    assert sum(1 for r in rows if r[0] == "truncated") == 1


def test_session_budget_bounds_gap_rows_across_operations(client, users,
                                                          monkeypatch):
    """Gap rows are NOT free: with a tiny SESSION budget and generous
    per-op quotas, a second operation's gap text still hits the wall."""
    import srplatform.api.app as app_mod
    from srplatform.settings import get_settings
    small = get_settings().model_copy(update={
        "runner_op_capture_bytes": 100_000,
        "runner_session_capture_bytes": 83,
        "runner_op_capture_rows": 1000})
    monkeypatch.setattr(app_mod, "get_settings", lambda: small)

    sid = _running_session(client, users)
    rid, token = _run_with_token(sid)
    op1 = _register(client, rid, token, op="op-" + "7" * 12)
    op2 = _register(client, rid, token, op="op-" + "8" * 12)
    assert _append(client, rid, token, op1, seq=0, kind="gap",
                   text="g" * 15).json()["status"] == "stored"
    assert _append(client, rid, token, op2, seq=0, kind="gap",
                   text="g" * 5).json()["status"] == "stored"
    assert _append(client, rid, token, op2, seq=1, kind="gap",
                   text="g").json()["status"] == "quota"


def test_row_cap_admits_at_most_the_reserved_marker(client, users,
                                                    monkeypatch):
    """Finding 3: row COUNTS are a server fact too — an operation cannot
    outlive its byte quota with an endless stream of tiny rows, and the
    row cap reserves exactly one truncation marker."""
    import srplatform.api.app as app_mod
    from srplatform.settings import get_settings
    small = get_settings().model_copy(update={
        "runner_op_capture_bytes": 100_000,
        "runner_session_capture_bytes": 100_000,
        "runner_op_capture_rows": 5})
    monkeypatch.setattr(app_mod, "get_settings", lambda: small)

    sid = _running_session(client, users)
    rid, token = _run_with_token(sid)
    op = _register(client, rid, token)
    statuses = [_append(client, rid, token, op, seq=i,
                        text="x" * 8).json()["status"]
                for i in range(9)]
    assert statuses[:5] == ["stored"] * 5
    assert statuses[5:] == ["quota"] * 4
    rows = _rows(rid)
    assert len(rows) == 6                      # 5 stored + 1 reserved marker
    assert rows[-1][0] == "truncated"


def test_session_budget_spans_operations(client, users, monkeypatch):
    """Finding 3: the SESSION is the authoritative outer budget — many
    operations under generous per-op quotas still cannot out-store the
    appliance's disk."""
    import srplatform.api.app as app_mod
    from srplatform.settings import get_settings
    small = get_settings().model_copy(update={
        "runner_op_capture_bytes": 1000, "runner_session_capture_bytes": 83,
        "runner_op_capture_rows": 1000})
    monkeypatch.setattr(app_mod, "get_settings", lambda: small)

    sid = _running_session(client, users)
    rid, token = _run_with_token(sid)
    op1 = _register(client, rid, token, op="op-" + "1" * 12)
    op2 = _register(client, rid, token, op="op-" + "2" * 12)
    assert _append(client, rid, token, op1, seq=0,
                   text="1234567890").json()["status"] == "stored"
    assert _append(client, rid, token, op2, seq=0,
                   text="1234567890").json()["status"] == "stored"
    over = _append(client, rid, token, op2, seq=1, text="z")
    assert over.json()["status"] == "quota"
    stored = _rows(rid)
    total = sum(len((r[1] or "").encode()) for r in stored
                if r[0] == "output")
    assert total <= 20


def test_concurrent_admission_cannot_double_marker_or_overshoot(client,
                                                                users,
                                                                monkeypatch):
    """Finding 3: admission must be atomic, never read-count-then-insert.
    Eight real concurrent POSTs against an 80-byte budget (63 of
    them permanently reserved for the marker) land at most one
    stored output row and EXACTLY ONE truncated marker."""
    import concurrent.futures

    import srplatform.api.app as app_mod
    from srplatform.settings import get_settings
    small = get_settings().model_copy(update={"runner_op_capture_bytes": 80})
    monkeypatch.setattr(app_mod, "get_settings", lambda: small)

    sid = _running_session(client, users)
    rid, token = _run_with_token(sid)
    op = _register(client, rid, token)

    def post(i):
        return _append(client, rid, token, op, seq=i,
                       text="x" * 9).json()["status"]

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        statuses = list(pool.map(post, range(8)))
    assert statuses.count("stored") <= 1
    rows = _rows(rid)
    assert sum(1 for r in rows if r[0] == "truncated") == 1
    assert sum(1 for r in rows if r[0] == "output") <= 1


def test_untrusted_dropped_claims_are_clamped(client, users):
    sid = _running_session(client, users)
    rid, token = _run_with_token(sid)
    op = _register(client, rid, token)
    r = _append(client, rid, token, op, seq=0, kind="gap",
                text="capture hiccup", dropped_bytes=10**18)
    assert r.status_code == 201
    rows = _rows(rid)
    assert rows[0][2] == 1_000_000_000       # clamped, never stored verbatim


def test_read_ts_stored_apart_from_persist_time(client, users):
    """Finding 10: the observed pipe-read instant is a first-class
    column; a row without one stays NULL (persist-time fallback is
    labelled by absence, never silently rewritten)."""
    sid = _running_session(client, users)
    rid, token = _run_with_token(sid)
    op = _register(client, rid, token)
    import time as _t
    now = _t.time()
    assert _append(client, rid, token, op, seq=0, text="early",
                   read_ts=now - 1.25).json()["status"] == "stored"
    assert _append(client, rid, token, op, seq=1, text="no ts").json()[
        "status"] == "stored"
    rows = _rows(rid)
    assert abs(rows[0][3] - (now - 1.25)) < 0.001
    assert rows[0][5] == "accepted"
    assert rows[1][3] is None and rows[1][4] is None
    assert rows[1][5] == "absent"


# ------------------------------------------------- item 8: per-operation --- #
# The review counterexample: a claim from 180 days ago on a FRESH op was
# accepted by the old 400-day wall window. Under the per-operation
# interval it is refused — kept verbatim for honesty, never used for
# placement — while claims inside the operation's lifetime (± the
# documented 300 s skew) are accepted.
def test_stale_and_future_claims_are_rejected_but_kept(client, users):
    import time as _t

    sid = _running_session(client, users)
    rid, token = _run_with_token(sid)
    op = _register(client, rid, token)
    now = _t.time()
    DAY = 86400.0

    # the counterexample: 180 days ago — inside the OLD 400-day window,
    # outside the operation's lifetime
    r = _append(client, rid, token, op, seq=0, text="ancient",
                read_ts=now - 180 * DAY)
    assert r.json()["status"] == "stored"      # bytes are never refused
    # a future claim beyond the skew allowance
    _append(client, rid, token, op, seq=1, text="future",
            read_ts=now + 400)
    # absurd epoch (the old docstring's own example)
    _append(client, rid, token, op, seq=2, text="epoch-one", read_ts=1.0)
    rows = _rows(rid)
    assert [(r[3], r[5]) for r in rows] == [
        (None, "rejected-out-of-interval")] * 3
    assert rows[0][4] == now - 180 * DAY        # claim kept VERBATIM
    assert rows[1][4] == now + 400 and rows[2][4] == 1.0

    # the honest surface: placement is persist time, and it SAYS the
    # claim was rejected rather than hiding it
    r = client.get(f"/sessions/{sid}/operations/{op}/output",
                   headers=users["member"])
    body = r.json()
    assert "REJECTED" in body["timing_provenance"]
    assert [c["read_ts_status"] for c in body["chunks"]] == [
        "rejected-out-of-interval"] * 3
    assert all(c["read_ts"] is None for c in body["chunks"])


def test_interval_boundaries_follow_the_operation_lifetime(client, users):
    """Boundaries are INCLUSIVE at registration-300 and at end+300; after
    the operation ends the run end (not "now") bounds the window."""
    import time as _t

    sid = _running_session(client, users)
    rid, token = _run_with_token(sid)
    op = _register(client, rid, token)
    now = _t.time()

    # registration is seconds ago: 299 s before it is inside, 301 s is not
    _append(client, rid, token, op, seq=0, text="in", read_ts=now - 299)
    _append(client, rid, token, op, seq=1, text="out", read_ts=now - 301)
    # and a near-future worker clock inside the skew is accepted
    _append(client, rid, token, op, seq=2, text="skew", read_ts=now + 299)
    rows = _rows(rid)
    assert [r[5] for r in rows] == [
        "accepted", "rejected-out-of-interval", "accepted"]

    # end the operation: a claim near the END is still accepted, a claim
    # beyond end+skew is not — the window CLOSES, it does not ride "now"
    done = client.post(f"/internal/runs/{rid}/operations/{op}/done",
                       json={"state": "completed"},
                       headers={"X-Worker-Token": token})
    assert done.status_code == 200
    with db_ctx() as s:
        ended = s.execute(text(
            "SELECT ended_at FROM run_operations WHERE run_id = :r"),
            {"r": rid}).scalar_one()
    e = ended.timestamp()
    _append(client, rid, token, op, seq=3, text="just-after",
            read_ts=e + 200)
    _append(client, rid, token, op, seq=4, text="much-later",
            read_ts=e + 400)
    rows = _rows(rid, "AND seq >= 3")
    assert [r[5] for r in rows] == [
        "accepted", "rejected-out-of-interval"]


def test_idempotence_compares_the_raw_claim(client, users):
    """Plan 22 item 8: a REJECTED claim's retry answers duplicate (the
    worker sent what we have), but a DIFFERENT rejected claim at the same
    seq is a conflict — two different rejected claims normalizing to the
    same NULL used to smuggle a silent duplicate. Accepted-side clash
    semantics are unchanged."""
    import time as _t

    sid = _running_session(client, users)
    rid, token = _run_with_token(sid)
    op = _register(client, rid, token)
    now = _t.time()
    DAY = 86400.0
    stale = now - 180 * DAY

    r = _append(client, rid, token, op, seq=0, text="t", read_ts=stale)
    assert r.json()["status"] == "stored"
    same = _append(client, rid, token, op, seq=0, text="t", read_ts=stale)
    assert same.status_code == 200 and same.json()["status"] == "duplicate"
    other = _append(client, rid, token, op, seq=0, text="t",
                    read_ts=stale - 5)
    assert other.status_code == 409 and other.json()["status"] == "conflict"
    absent = _append(client, rid, token, op, seq=0, text="t")
    assert absent.status_code == 409, "a dropped claim is still a change"
    # and nothing moved
    rows = _rows(rid)
    assert len(rows) == 1 and rows[0][4] == stale


def test_capture_survives_ordinary_completion(client, users):
    """A worker completing its operation does not erase the captured
    chunks — output rows are append-only evidence on their own."""
    sid = _running_session(client, users)
    rid, token = _run_with_token(sid)
    op = _register(client, rid, token)
    _append(client, rid, token, op, seq=0, text="a")
    _append(client, rid, token, op, seq=1, kind="gap", text="capture hiccup",
            dropped_bytes=4096)
    r = client.post(f"/internal/runs/{rid}/operations/{op}/done",
                    json={"state": "completed"},
                    headers={"X-Worker-Token": token})
    assert r.status_code == 200
    rows = _rows(rid)
    assert [(r[0], r[2]) for r in rows] == [("output", None), ("gap", 4096)]


def test_real_loop_captures_timed_output_through_the_api(client, users):
    """FULL worker path, no doubles between loop and DB: the real
    RedAgentLoop dispatches a real command through the LocalDevRunner,
    the chunks travel over the transport to the internal endpoint and
    land in operation_outputs; the action_result event carries the
    capture SUMMARY. Legacy shape is preserved: the event's output is
    still the bounded first-4000-char fact, capture is additive. The
    rows now carry observed READ times."""
    import json as _json

    from srplatform.red_agent.loop import RedAgentLoop
    from srplatform.red_agent.runner import LocalDevRunner
    from srplatform.red_agent.transport import TestClientTransport
    from srplatform.settings import Settings
    from tests.helpers import FakeLLM

    sid = _running_session(client, users)
    rid, token = _run_with_token(sid)
    tr = TestClientTransport(client, token, run_id=rid)
    runner = LocalDevRunner(Settings(sr_env="dev",
                                     runner_transport="local-dev"))
    llm = FakeLLM([_json.dumps({"thought": "capture probe",
                                "propose_phase": None, "tool": "shell",
                                "args": {"command":
                                         "echo TIMED-CAPTURE-MARKER-42; "
                                         "echo second line"}})])
    RedAgentLoop(sid, "web-foothold-01", tr, llm, runner,
                 max_steps=1, compress_after=50).run()

    events = client.get("/events", params={"session_id": sid, "tail": 200},
                        headers=users["member"]).json()
    ar = [e for e in events if e["action_type"] == "action_result"]
    assert len(ar) == 1
    summary = ar[0]["payload"]["output_capture"]
    assert summary and summary["complete"] is True
    assert summary["chunks"] >= 1
    assert summary["read_timed"] is True
    op_uuid = ar[0]["payload"]["op_uuid"]
    rows = _rows(rid, "AND op_id = :o", {"o": op_uuid})
    assert [r[0] for r in rows] == ["output"]
    assert "TIMED-CAPTURE-MARKER-42" in rows[0][1]
    assert "second line" in rows[0][1]
    assert rows[0][3] is not None           # a real read time, not persist
    # the event's own output stayed the honest bounded fact
    assert "TIMED-CAPTURE-MARKER-42" in ar[0]["payload"]["output"]
