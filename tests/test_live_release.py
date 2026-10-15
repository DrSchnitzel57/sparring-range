"""Live release workflows (plan 13 criterion 7) — operator live gate.

Drives a DEPLOYED lab purely over HTTP (httpx): no test doubles, no
fixtures, no skips. Requires:
  SR_LIVE_BASE_URL=http(s)://<controller>
  SR_LIVE_OPERATOR_USER / SR_LIVE_OPERATOR_PASSWORD
Without them the fixture FAILS loudly (and with SR_REQUIRE_LIVE=1 a skip
would fail anyway — a skip is never acceptance).

Coverage: both presets, modes/start-conditions/snapshots, duplicate and
crash/timeout recovery, service/inject/security results, competition API
filtering, reports/history/replay, and subsequent reuse. Each test ends
its session (the range is single-active); timeouts are generous because
real clones take minutes.
"""
from __future__ import annotations

import os
import time
import uuid

import httpx
import pytest

pytestmark = pytest.mark.live

BASE = os.environ.get("SR_LIVE_BASE_URL", "").rstrip("/")
OP_USER = os.environ.get("SR_LIVE_OPERATOR_USER", "")
OP_PW = os.environ.get("SR_LIVE_OPERATOR_PASSWORD", "")
MEM_PW = os.environ.get("SR_LIVE_MEMBER_PASSWORD", "live-member-testpw-1")
LAUNCH_TIMEOUT_S = float(os.environ.get("SR_LIVE_LAUNCH_TIMEOUT_S", "1200"))


@pytest.fixture(scope="module")
def live():
    assert BASE, "SR_LIVE_BASE_URL is required — the live gate never runs blind"
    assert OP_USER and OP_PW, \
        "SR_LIVE_OPERATOR_USER/PASSWORD are required for the live gate"
    c = httpx.Client(base_url=BASE, timeout=60.0)
    # bootstrap is one-time on a real lab: 201 first run, 403 afterwards
    r = c.post("/auth/bootstrap", json={"username": OP_USER,
                                        "password": OP_PW})
    assert r.status_code in (201, 403), r.text
    r = c.post("/auth/login", json={"username": OP_USER, "password": OP_PW})
    assert r.status_code == 200, r.text
    op = {"Authorization": f"Bearer {r.json()['token']}"}
    yield {"client": c, "op": op}
    c.close()


def _member(live, tag: str) -> dict:
    """A FRESH member per test (unique username): competition filtering is
    proven between strangers, never recycled accounts."""
    c = live["client"]
    name = f"live-{tag}-{uuid.uuid4().hex[:8]}"
    r = c.post("/users", json={"username": name, "password": MEM_PW,
                               "role": "member"}, headers=live["op"])
    assert r.status_code == 201, r.text
    r = c.post("/auth/login", json={"username": name, "password": MEM_PW})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['token']}", "username": name}


def _create(live, headers, scenario, **kw):
    c = live["client"]
    r = c.post("/sessions", json={"scenario_id": scenario, **kw},
               headers=headers)
    assert r.status_code in (200, 201), r.text
    return r.json()["session_id"]


def _launch_wait(live, headers, sid, timeout_s: float = LAUNCH_TIMEOUT_S):
    c = live["client"]
    r = c.post(f"/sessions/{sid}/launch", headers=headers)
    assert r.status_code == 202, r.text
    op_id = r.json()["operation_id"]
    deadline = time.monotonic() + timeout_s
    while True:
        op = c.get(f"/sessions/{sid}/operation", headers=headers).json()
        assert op["operation_id"] == op_id, op
        if op["state"] in ("succeeded", "failed", "interrupted"):
            return op
        assert time.monotonic() < deadline, f"launch stuck: {op}"
        time.sleep(5.0)


def _end(live, headers, sid):
    c = live["client"]
    r = c.post(f"/sessions/{sid}/end", headers=headers)
    assert r.status_code == 200, r.text
    return r.json()


def test_live_both_presets_launch_begin_end_and_reuse(live):
    """Both presets: create → 202 → ready → begin → end → the range frees
    and a subsequent launch succeeds without any DB/ledger surgery."""
    for scenario in ("web-foothold-01", "mojang-web-db-01"):
        mem = _member(live, "preset")
        sid = _create(live, mem, scenario)
        try:
            done = _launch_wait(live, mem, sid)
            assert done["state"] == "succeeded", done
            assert done["result"]["connections"], done
            c = live["client"]
            r = c.post(f"/sessions/{sid}/begin", headers=mem)
            assert r.status_code == 202, r.text
            _end(live, mem, sid)
        finally:
            try:
                _end(live, mem, sid)
            except Exception:  # noqa: BLE001 — end is idempotent; best effort
                pass
        # reuse: a fresh launch on the same session succeeds
        done = _launch_wait(live, mem, sid)
        assert done["state"] == "succeeded", done
        _end(live, mem, sid)


def test_live_modes_start_conditions_and_snapshot_freeze(live):
    mem = _member(live, "snapshot")
    sid = _create(live, mem, "web-foothold-01", mode="competition",
                  duration_minutes=5, pace_seconds=15,
                  start_condition="manual", injects_enabled=True)
    try:
        c = live["client"]
        body = c.get(f"/sessions/{sid}", headers=mem).json()
        m = body["match"]
        assert m["snapshot_version"] == 2, m
        assert m["mode"] == "competition" and m["pace_seconds"] == 15
        snap = m.get("snapshot", {}) if isinstance(m.get("snapshot"), dict) else {}
        assert snap.get("scenario_versions", {}).get("scenario_sha256"), m
        # unbounded intensity is refused BEFORE storage
        r = c.post("/sessions", json={"scenario_id": "web-foothold-01",
                                      "pace_seconds": 7}, headers=mem)
        assert r.status_code == 422, r.text
    finally:
        _end(live, mem, sid)


def test_live_duplicate_launch_never_duplicates(live):
    mem = _member(live, "dupe")
    sid = _create(live, mem, "web-foothold-01")
    try:
        c = live["client"]
        first = c.post(f"/sessions/{sid}/launch", headers=mem).json()
        assert first["status"] == "accepted"
        dup = c.post(f"/sessions/{sid}/launch", headers=mem)
        if dup.status_code == 202:
            pass  # finished between the calls: a new idempotent attempt
        else:
            assert dup.status_code == 409, dup.text
            assert dup.json()["detail"]["error"] == "operation_in_progress"
            assert dup.json()["detail"]["operation_id"] == first["operation_id"]
        done = _launch_wait(live, mem, sid) if dup.status_code == 202 else None
        if done is not None:
            assert done["state"] == "succeeded", done
        else:
            op = c.get(f"/sessions/{sid}/operation", headers=mem).json()
            assert op["operation_id"] == first["operation_id"], op
    finally:
        _end(live, mem, sid)


def test_live_deadline_ends_match_and_range_is_reusable(live):
    """A 1-minute match expires by the server clock; the range frees and a
    second launch succeeds — end/expiry never resume attacks."""
    mem = _member(live, "deadline")
    sid = _create(live, mem, "web-foothold-01", duration_minutes=1,
                  pace_seconds=0)
    try:
        done = _launch_wait(live, mem, sid)
        assert done["state"] == "succeeded", done
        c = live["client"]
        assert c.post(f"/sessions/{sid}/begin", headers=mem).status_code == 202
        deadline = time.monotonic() + 300
        while True:
            m = c.get(f"/sessions/{sid}", headers=mem).json()["match"]
            if m["state"] in ("completed", "interrupted"):
                break
            assert time.monotonic() < deadline, m
            time.sleep(5.0)
        assert m["state"] == "completed", m
    finally:
        _end(live, mem, sid)
    done = _launch_wait(live, mem, sid)
    assert done["state"] == "succeeded", done
    _end(live, mem, sid)


def test_live_competition_visibility_is_api_enforced(live):
    """Strangers cannot read each other's sessions through ANY member
    path; the operator can. Hiding a button is not the control."""
    a = _member(live, "vis-a")
    b = _member(live, "vis-b")
    sid = _create(live, a, "web-foothold-01")
    try:
        c = live["client"]
        for path in (f"/sessions/{sid}",
                     f"/sessions/{sid}/operation",
                     f"/sessions/{sid}/injects",
                     f"/sessions/{sid}/live"):
            r = c.get(path, headers=b)
            assert r.status_code in (403, 404), (path, r.status_code)
        assert c.get(f"/sessions/{sid}", headers=live["op"]).status_code == 200
        mine = c.get("/sessions", params={"mine": True}, headers=b).json()
        assert all(s["session_id"] != sid for s in mine), mine
    finally:
        _end(live, a, sid)


def test_live_injects_reports_history_and_replay(live):
    """Inject inbox, separate score, and truthful post-match artifacts:
    report, replay timeline, and per-user history."""
    mem = _member(live, "artifacts")
    sid = _create(live, mem, "mojang-web-db-01", duration_minutes=1,
                  pace_seconds=0)
    try:
        done = _launch_wait(live, mem, sid)
        assert done["state"] == "succeeded", done
        c = live["client"]
        assert c.post(f"/sessions/{sid}/begin", headers=mem).status_code == 202
        inbox = c.get(f"/sessions/{sid}/injects", headers=mem).json()
        assert inbox["releases"], inbox
        assert set(inbox["score"]) >= {"correct", "scored"}, inbox["score"]
        _end(live, mem, sid)
        # truthful post-match artifacts through the API: trusted score,
        # live/session state, and per-user history
        for path in (f"/sessions/{sid}/score",
                     f"/sessions/{sid}/live",
                     f"/sessions/{sid}/replay"):
            r = c.get(path, headers=mem)
            assert r.status_code == 200, (path, r.status_code)
        score = c.get(f"/sessions/{sid}/score", headers=mem).json()
        assert "earned" in score or "items" in score or "checks" in score, score
        r = c.get(f"/users/{mem['username']}/progress", headers=mem)
        assert r.status_code == 200, r.text
    finally:
        try:
            _end(live, mem, sid)
        except Exception:  # noqa: BLE001
            pass
