"""Plan 13 phase 6 — match contract (fast layer): bounded snapshot choices
and schedule-aware observation coverage."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest


# --------------------------------------------------------------------------- #
# bounded, versioned snapshot choices
# --------------------------------------------------------------------------- #

def test_bounded_choices_accepted():
    from srplatform.lifecycle import MATCH_MODES, PACE_CHOICES, START_CONDITIONS
    assert set(MATCH_MODES) == {"practice", "competition"}
    assert set(START_CONDITIONS) == {"network-entry", "assumed-breach"}
    assert set(PACE_CHOICES) == {0, 15, 30, 60}  # 60/30/15 max cadence + fixture 0


def test_create_match_validates_before_storing():
    """create_match raises BEFORE db.add on any unbounded choice (the route
    maps ValueError to 422; nothing is stored)."""
    from unittest.mock import MagicMock

    from srplatform.lifecycle import create_match
    db = MagicMock()
    with pytest.raises(ValueError, match="mode"):
        create_match(db, "sid", "web-foothold-01", mode="anything")
    with pytest.raises(ValueError, match="start_condition"):
        create_match(db, "sid", "web-foothold-01", start_condition="auto")
    with pytest.raises(ValueError, match="pace_seconds"):
        create_match(db, "sid", "web-foothold-01", pace_seconds=5)
    db.add.assert_not_called()


def test_snapshot_freezes_versioned_choices():
    from unittest.mock import MagicMock

    from srplatform.lifecycle import create_match
    db = MagicMock()
    m = create_match(db, "sid", "mojang-web-db-01", duration_minutes=45,
                     pace_seconds=15, mode="competition",
                     start_condition="assumed-breach", injects_enabled=False,
                     actor="drew")
    snap = m.snapshot
    assert snap["snapshot_version"] == 2
    assert snap["mode"] == "competition"
    assert snap["start_condition"] == "assumed-breach"
    assert snap["injects_enabled"] is False
    assert snap["pace_seconds"] == 15 and snap["duration_minutes"] == 45


def test_snapshot_freezes_scenario_and_effective_versions():
    """History can never be re-scored against a later library state."""
    from unittest.mock import MagicMock

    from srplatform.lifecycle import create_match
    db = MagicMock()
    m = create_match(db, "sid", "mojang-web-db-01",
                     scenario_versions={"scenario_version": 3,
                                        "image_version": "noble-20260926",
                                        "scenario_sha256": "ab" * 32},
                     effective_settings={"uptime_scoring_enabled": True})
    assert m.snapshot["scenario_versions"]["image_version"] == "noble-20260926"
    assert m.snapshot["scenario_versions"]["scenario_sha256"] == "ab" * 32
    assert m.snapshot["effective_settings"]["uptime_scoring_enabled"] is True


# --------------------------------------------------------------------------- #
# schedule-aware coverage
# --------------------------------------------------------------------------- #

def _t(mins=0):
    return datetime(2026, 10, 14, 12, tzinfo=timezone.utc) + timedelta(minutes=mins)


def test_coverage_gaps_are_visible_never_fabricated():
    from srplatform.uptime import coverage
    # 10 minutes at 10 s cadence => 60 expected; only 10 arrived
    c = coverage(["up"] * 8 + ["unknown"] * 2, started_at=_t(0), ended_at=_t(10))
    assert c["expected_checks"] == 60 and c["received"] == 10
    assert c["missed"] == 50 and c["unknown"] == 2
    assert c["coverage_pct"] == 16.7
    assert c["scored"] and c["pct_up"] == 100.0  # unknown awarded nothing


def test_coverage_zero_valid_is_unscored_and_down_is_not_unknown():
    from srplatform.uptime import coverage
    c = coverage(["unknown"] * 5, started_at=_t(0), ended_at=_t(1))
    assert not c["scored"] and c["pct_up"] is None
    assert c["down"] == 0  # ambiguous transport NEVER counts as downtime
    c2 = coverage(["up", "down"], started_at=_t(0),
                  ended_at=_t(0) + timedelta(seconds=20))
    assert c2["pct_up"] == 50.0 and c2["expected_checks"] == 2


def test_coverage_open_clock_and_empty_window():
    from srplatform.uptime import coverage
    now = datetime.now(timezone.utc)
    c = coverage([], started_at=now - timedelta(seconds=100), ended_at=None)
    assert c["expected_checks"] == 10 and c["missed"] == 10
    assert not c["scored"] and c["received"] == 0


# --------------------------------------------------------------------------- #
# MySQL business probe (plan 13 phase 6)
# --------------------------------------------------------------------------- #

def test_mysql_probe_command_is_select_only_with_in_guest_password():
    from srplatform.uptime import mysql_probe_command
    cmd = mysql_probe_command()
    assert "SELECT COUNT(*)" in cmd and "INSERT" not in cmd.upper().replace(
        "SELECT", "")
    # credential never crosses the channel: read INSIDE the guest
    assert "--password=\"$(cat /etc/mojang-web/reader-pw)\"" in cmd
    assert "--host=127.0.0.1" in cmd


def test_mysql_probe_three_truths_separate():
    from srplatform.uptime import ProbeInfraError, probe_mysql

    def runner(rc, out):
        return lambda ip, cmd: (rc, out)

    assert probe_mysql(runner(0, "12\n"), "10.0.0.5")[0] == "up"
    # reachable DB, WRONG business answer => down (not up, not unknown)
    assert probe_mysql(runner(0, "9\n"), "10.0.0.5")[0] == "down"
    # session never established => cannot tell whether the query ran
    assert probe_mysql(runner(255, "ssh: connect"), "10.0.0.5")[0] == "unknown"
    # refused connection => target down
    assert probe_mysql(runner(1, "ERROR 2002: Can't connect to "
                                 "local MySQL server (111)"),
                       "10.0.0.5")[0] == "down"
    # OUR credential broken => probe infrastructure, never target downtime
    try:
        probe_mysql(runner(1, "ERROR 1045: Access denied for user"),
                    "10.0.0.5")
        raise AssertionError("expected ProbeInfraError")
    except ProbeInfraError:
        pass
    # channel machinery itself failing => infrastructure too
    def broken(ip, cmd):
        raise OSError("ssh binary vanished")
    try:
        probe_mysql(broken, "10.0.0.5")
        raise AssertionError("expected ProbeInfraError")
    except ProbeInfraError:
        pass


def test_prober_dispatches_http_and_mysql_targets():
    from srplatform.uptime import Prober
    seen = []
    p = Prober("s1", [("web01", "http://x/"), ("db01", "mysql",
                                                 lambda: ("up", 5, "rows"))],
               record=lambda h, s, l, d: seen.append((h, s)),
               interrupt=lambda r: seen.append(("interrupt", r)))
    p._get = lambda url, timeout: type("R", (), {"status_code": 200,
                                                 "text": "Minecraft Legends"})()
    p.run_once()
    assert ("web01", "up") in seen and ("db01", "up") in seen
    assert len(seen) == 2


# --------------------------------------------------------------------------- #
# injects (plan 13 phase 6)
# --------------------------------------------------------------------------- #

def test_inject_catalog_is_versioned_and_typed():
    from srplatform.injects import CATALOG
    assert all(k.endswith("@1") for k in CATALOG)
    kinds = {k: v["kind"] for k, v in CATALOG.items()}
    assert kinds["incident-report@1"] == "written"
    assert sum(1 for v in CATALOG.values() if v["kind"] == "technical") == 3
    # written work can never carry a verifier (advisory only)
    assert CATALOG["incident-report@1"]["verifier"] is None


def test_inject_schedule_derives_from_frozen_duration():
    from datetime import datetime, timezone
    from srplatform.injects import schedule_times
    start = datetime(2026, 10, 14, 12, tzinfo=timezone.utc)
    times = schedule_times(start, 60)
    assert len(times) == 4
    # 20/40/60/80% release, each open 20% of the clock
    assert times[0][0] == start + timedelta(minutes=12)
    assert times[0][1] == start + timedelta(minutes=24)
    assert times[3][1] == start + timedelta(minutes=60)


def test_disabled_inject_set_releases_nothing():
    """injects_enabled=false: schedule returns [] BEFORE touching the db."""
    from unittest.mock import MagicMock
    from srplatform.injects import schedule
    db = MagicMock()
    match = MagicMock()
    match.snapshot = {"injects_enabled": False}
    assert schedule(db, "sid", match, {"topology": {"hosts": []}}) == []
    db.add.assert_not_called()
    db.commit.assert_not_called()


# --------------------------------------------------------------------------- #
# probe infrastructure failure (plan 13 phase 6: DB failure + dead threads)
# --------------------------------------------------------------------------- #

def test_prober_survives_db_failure_and_records_unknown_truth():
    from srplatform.uptime import Prober
    recorded = []
    p = Prober("s1", [("web01", "http://x/"), ("db01", "mysql",
                                                 lambda: ("up", 1, ""))],
               record=lambda h, s, l, d: recorded.append((h, s, d)),
               interrupt=lambda r: None)

    def record_then_stop(host, state, latency, detail):
        recorded.append((host, state, detail))
        p._stop.set()          # end the loop after the first fallback record

    p.run_once = lambda: (_ for _ in ()).throw(
        RuntimeError("db connection lost"))
    p._record = record_then_stop
    p.interval_s = 0.01
    p.loop()                    # must NOT raise: a DB hiccup is survivable
    assert recorded[0][0] == "web01"
    assert recorded[0][1] == "unknown"      # never fabricated downtime
    assert "prober error" in recorded[0][2]

    # DB FULLY down: the loop keeps running (no crash), samples just stop —
    # the schedule gap shows the truth instead.
    p2 = Prober("s2", [("web01", "http://x/")],
                record=lambda *a: None, interrupt=lambda r: None)

    def dead_record(*a):
        p2._stop.set()
        raise RuntimeError("db gone")

    p2.run_once = lambda: (_ for _ in ()).throw(RuntimeError("db gone"))
    p2._record = dead_record
    p2.interval_s = 0.01
    p2.loop()                   # one full failing iteration, no exception


def test_dead_prober_is_detectable_never_fakes_coverage():
    from srplatform.uptime import Prober, coverage
    p = Prober("s1", [("web01", "http://x/")],
               record=lambda *a: None, interrupt=lambda r: None)
    assert p.alive() is False          # never started: NOT alive
    p._get = lambda url, timeout: type("R", (), {"status_code": 200,
                                                 "text": "Minecraft Legends"})()
    p.start()
    assert p.alive() is True
    p.stop()
    assert p.alive() is False          # dead thread is detectable
    # and a dead prober shows as schedule GAPS, never as downtime:
    now = datetime.now(timezone.utc)
    c = coverage(["up"] * 3, started_at=now - timedelta(seconds=100),
                 ended_at=now)
    assert c["missed"] == 7 and c["down"] == 0


def test_filter_scorecard_keeps_totals_seals_items():
    from srplatform.api.visibility import filter_scorecard
    card = {"status": "scored", "earned": 10, "total": 25, "items": [
        {"verifier": "flag_file_present", "host": "web01", "domain": "x",
         "points": 10, "awarded": 10, "status": "passed",
         "evidence": {"path": "/root/flag"}, "error": None}]}
    out = filter_scorecard(card)
    assert out["earned"] == 10 and out["total"] == 25
    assert out["items"] == [{"verifier": "flag_file_present", "host": "web01",
                             "domain": "x", "points": 10, "sealed":
                             "competition — sealed until the match completes"}]
