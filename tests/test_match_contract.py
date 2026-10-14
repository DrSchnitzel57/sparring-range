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
