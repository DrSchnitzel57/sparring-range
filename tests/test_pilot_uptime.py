"""Pilot step 5: web uptime scoring.

Fast layer: the scoring MATH (score = % up among VALID checks; unknown
awards nothing; zero valid => unscored) and probe classification, plus the
prober loop's truthful behavior (infrastructure failure INTERRUPTS the
match instead of fabricating downtime). DB layer: identity-bound append-only
samples, dashboard/end reporting, and the grant-level proof that samples
are history (the app role cannot UPDATE or DELETE them).
"""
import time
from datetime import datetime, timedelta, timezone

import pytest

from srplatform import uptime
from tests.conftest import launch_and_wait



def _s(state, secs_ago=0, latency=None):
    return {"state": state,
            "ts": datetime.now(timezone.utc) - timedelta(seconds=secs_ago),
            "latency_ms": latency, "detail": None}


# ------------------------------------------------------------------- math ----
def test_summarize_scores_only_valid_checks():
    sm = uptime.summarize([_s("up", 20, 10), _s("down", 10), _s("up", 5, 12)])
    assert sm["scored"] and sm["pct_up"] == 66.7
    assert sm["valid_checks"] == 3 and sm["coverage_pct"] == 100.0


def test_unknown_never_counts_and_never_downtime():
    sm = uptime.summarize([_s("up", 20), _s("unknown", 10), _s("unknown", 5)])
    assert sm["scored"] and sm["pct_up"] == 100.0
    assert sm["down"] == 0 and sm["unknown"] == 2
    assert sm["coverage_pct"] == 33.3


def test_zero_valid_is_unscored_not_zero_or_hundred():
    sm = uptime.summarize([_s("unknown", 5)])
    assert not sm["scored"] and sm["pct_up"] is None
    empty = uptime.summarize([])
    assert not empty["scored"] and empty["latest"] is None and empty["stale"]


def test_freshness_and_staleness():
    now = datetime.now(timezone.utc)
    fresh = uptime.summarize([_s("up", 5)], now=now)
    assert 4 <= fresh["freshness_s"] <= 6
    assert not fresh["stale"]
    assert uptime.summarize([_s("up", 120)], now=now)["stale"]


# --------------------------------------------------------------- classify ----
class _Resp:
    def __init__(self, status_code=200, text=""):
        self.status_code, self.text = status_code, text


def _raises(exc):
    def _f(url, timeout):
        raise exc
    return _f


def test_probe_once_up_down_unknown():
    up = uptime.probe_once("http://h/", _get=lambda url, timeout:
                           _Resp(200, "the Minecraft Legends catalogue"))
    assert up[0] == "up" and up[1] is not None
    assert uptime.probe_once("http://h/", _get=_raises(TimeoutError()))[0] == "unknown"
    assert uptime.probe_once("http://h/", _get=_raises(ConnectionRefusedError()))[0] == "down"
    # 200 but wrong content, or an error status, is CONFIRMED not-serving
    assert uptime.probe_once("http://h/", _get=lambda url, timeout:
                             _Resp(200, "502 bad gateway"))[0] == "down"
    assert uptime.probe_once("http://h/", _get=lambda url, timeout:
                             _Resp(500, "boom"))[0] == "down"


def test_probe_once_httpx_classes_are_classified():
    import httpx
    assert uptime.probe_once("http://h/", _get=_raises(
        httpx.ConnectTimeout("t")))[0] == "unknown"
    assert uptime.probe_once("http://h/", _get=_raises(
        httpx.ConnectError("refused")))[0] == "down"


# ------------------------------------------------------------------ loop -----
def test_prober_interrupts_on_infra_failure_without_fabricating_samples():
    recorded, interrupted = [], []
    p = uptime.Prober("s", [("web01", "http://10.66.0.10/")],
                      record=lambda h, st, l, d: recorded.append((h, st)),
                      interrupt=interrupted.append,
                      get=_raises(uptime.ProbeInfraError("client exploded")),
                      interval_s=0.01)
    p.run_once()
    assert interrupted and recorded == []  # no fake downtime rows
    p.start()
    p.stop()
    assert len(interrupted) == 1  # loop stopped after the interruption


def test_prober_loop_records_samples():
    calls = []
    p = uptime.Prober("s", [("web01", "http://h/")],
                      record=lambda h, st, l, d: calls.append(st),
                      interrupt=lambda r: calls.append("interrupted"),
                      get=lambda url, timeout: _Resp(200, "Minecraft Legends"),
                      interval_s=0.01)
    p.start()
    time.sleep(0.08)
    p.stop()
    assert calls and all(c == "up" for c in calls)


# -------------------------------------------------------------------- db -----
def _db():
    from srplatform.db.session import db
    return db()


@pytest.mark.db
def test_begin_starts_prober_and_samples_are_identity_bound(client, users,
                                                            fake_pve, monkeypatch):
    from sqlalchemy import text
    from srplatform import settings as st
    monkeypatch.setenv("UPTIME_SCORING_ENABLED", "1")
    st.get_settings.cache_clear()
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    launch_and_wait(client, users["member"], sid)
    assert client.post(f"/sessions/{sid}/begin",
                       headers=users["member"]).status_code == 202
    rows = []
    deadline = time.time() + 25  # first sample is immediate; probe may wait timeout
    while time.time() < deadline:
        with _db() as s:
            rows = s.execute(text(
                "SELECT host, state, deployment_id FROM uptime_samples "
                "WHERE session_id = :s"), {"s": str(sid)}).fetchall()
        if rows:
            break
        time.sleep(0.5)
    assert rows, "the prober never recorded a sample"
    assert rows[0][0] == "web01" and rows[0][2]  # bound to host + generation
    assert all(r[1] in ("up", "down", "unknown") for r in rows)
    # END stops the prober and reports the summary
    r = client.post(f"/sessions/{sid}/end", headers=users["member"])
    assert r.status_code == 200 and r.json()["uptime"]["samples"] >= 1
    assert uptime._probers.get(str(sid)) is None  # loop stopped with the match


@pytest.mark.db
def test_uptime_samples_append_only_and_displayed(client, users, fake_pve,
                                                  test_db_url_app):
    from sqlalchemy import create_engine, text
    from sqlalchemy.exc import ProgrammingError
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    launch_and_wait(client, users["member"], sid)
    with _db() as s:  # the app role may INSERT (prober path) — proven here
        for state in ("up", "up", "down", "unknown"):
            s.execute(text("INSERT INTO uptime_samples (session_id, "
                           "deployment_id, host, state) VALUES (:s, 'dep-t', "
                           "'web01', :st)"), {"s": str(sid), "st": state})
        s.commit()
    live = client.get(f"/sessions/{sid}/live", headers=users["member"]).json()
    u = live["uptime"]
    assert u["scored"] and u["pct_up"] == 66.7 and u["unknown"] == 1
    assert u["down"] == 1 and u["coverage_pct"] == 75.0
    # samples are HISTORY: the app role holds SELECT+INSERT only
    eng = create_engine(test_db_url_app)
    with pytest.raises(ProgrammingError):
        with eng.begin() as c:
            c.execute(text("UPDATE uptime_samples SET state='up'"))
    with pytest.raises(ProgrammingError):
        with eng.begin() as c:
            c.execute(text("DELETE FROM uptime_samples"))
    eng.dispose()
    # the end response carries the same honest summary (separate score)
    r = client.post(f"/sessions/{sid}/end", headers=users["member"])
    assert r.status_code == 200 and r.json()["uptime"]["pct_up"] == 66.7
