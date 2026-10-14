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
    assert set(START_CONDITIONS) == {"manual", "auto-on-ready"}
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
                     start_condition="auto-on-ready", injects_enabled=False,
                     actor="drew")
    snap = m.snapshot
    assert snap["snapshot_version"] == 2
    assert snap["mode"] == "competition"
    assert snap["start_condition"] == "auto-on-ready"
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
