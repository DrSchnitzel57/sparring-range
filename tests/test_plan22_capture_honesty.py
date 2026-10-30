"""Plan 22 F8 + F9: capture idempotence INCLUDING metadata, and bounded,
labelled worker timing.

F8 (with the 409 change on the conflict answer): duplicate suppression is
exact-equality on (seq, kind, text, read_ts, dropped_bytes); a divergent
re-delivery is a 409-classified conflict, never a silent 200.

F9 (plan 22 review sharpened it): a worker-claimed pipe-read instant is a
CLAIM adjudicated against the OPERATION's server-trusted lifetime ± 300 s
skew — not a 400-day wall window. Out-of-interval claims (read_ts=1, 180
days ago on a fresh op) are refused while the bytes are still stored (the
row honestly degrades to persist time, the claim is kept verbatim, and
the surface says so); in-lifetime claims survive; and the member-facing
output projection labels which placement replay is looking at, because a
timing only the worker vouches for is advisory, not verified.

F6 server half: the replay surface carries ONE canonical session-clock
anchor (the session's first event, unfiltered) so client-side filters can
no longer move the cast offset.
"""
from __future__ import annotations

import time

from tests.test_plan20_capture_api import (  # noqa: F401 — shared helpers
    _append, _register, _rows, _run_with_token, _running_session)


def test_absurd_worker_read_ts_is_dropped_but_bytes_survive(client, users):
    sid = _running_session(client, users)
    rid, token = _run_with_token(sid)
    op = _register(client, rid, token, op="op-" + "1" * 12)
    r = _append(client, rid, token, op, seq=0, text="real bytes", read_ts=1)
    assert r.status_code == 201 and r.json()["status"] == "stored"
    rows = _rows(rid, "AND seq = 0")
    assert rows[0][1] == "real bytes"          # completeness preserved
    assert rows[0][3] is None                  # the bogus claim was refused
    assert rows[0][4] == 1.0                   # …kept verbatim, un-laundered
    assert rows[0][5] == "rejected-out-of-interval"

    now = time.time()
    r2 = _append(client, rid, token, op, seq=1, text="kept", read_ts=now)
    assert r2.json()["status"] == "stored"
    rows = _rows(rid, "AND seq = 1")
    assert abs(rows[0][3] - now) < 0.001       # in-lifetime claim accepted
    assert rows[0][5] == "accepted"


def test_output_projection_labels_timing_provenance(client, users):
    sid = _running_session(client, users)
    rid, token = _run_with_token(sid)
    op = _register(client, rid, token, op="op-" + "2" * 12)
    _append(client, rid, token, op, seq=0, text="plain")
    body = client.get(f"/sessions/{sid}/operations/{op}/output",
                      headers=users["member"]).json()
    assert body["timing_provenance"].startswith("server persist time")
    _append(client, rid, token, op, seq=1, text="timed",
            read_ts=time.time())
    body = client.get(f"/sessions/{sid}/operations/{op}/output",
                      headers=users["member"]).json()
    assert body["timing_provenance"].startswith("worker-claimed")


def test_replay_carries_canonical_session_t0(client, users):
    sid = _running_session(client, users)
    d = client.get(f"/sessions/{sid}/replay?limit=10",
                   headers=users["member"]).json()
    assert d["session_t0"]
    first = min(e["ts"] for e in d["timeline"])
    assert d["session_t0"] <= first            # THE anchor precedes everything
    d2 = client.get(f"/sessions/{sid}/replay?limit=10&actor=red",
                    headers=users["member"]).json()
    # F6: the anchor is the SAME under any filter — filters change what is
    # shown, never where the session clock starts.
    assert d2["session_t0"] == d["session_t0"]
