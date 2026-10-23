"""Fast schedule projections: no DB, network, or live-operation prerequisites."""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest


def test_registry_failure_cannot_reuse_old_generation_availability(monkeypatch):
    from datetime import datetime, timezone
    from types import SimpleNamespace
    from srplatform import lifecycle, uptime
    monkeypatch.setattr(uptime, "summarize_for_session", lambda *args: {
        "scored": True, "pct_up": 100.0, "up": 65, "samples": 65})
    monkeypatch.setattr(lifecycle, "get_match", lambda *args: SimpleNamespace(
        started_at=datetime.now(timezone.utc), state="running"))
    def unavailable(*args, **kwargs):
        raise RuntimeError("fixture registry failure")
    monkeypatch.setattr(uptime, "coverage_for_session", unavailable)
    monkeypatch.setattr(uptime, "mysql_integrity", lambda *args: None)
    result = uptime.live_projection(object(), "fixture-session")
    assert result["scored"] is False and result["pct_up"] is None
    assert result["samples"] == 0 and result["up"] == 0
    assert result["coverage_error"] == "service coverage registry unavailable"

from srplatform import uptime


START = datetime(2026, 10, 23, tzinfo=timezone.utc)


def sample(seconds=0, host="web", state="up", generation="current"):
    return dict(ts=START + timedelta(seconds=seconds), host=host,
                state=state, deployment_id=generation)


def project(samples, seconds=0, targets=None):
    return uptime.scheduled_coverage(
        samples, targets=targets if targets is not None else ["web"],
        deployment_id="current", started_at=START,
        ended_at=START + timedelta(seconds=seconds))


def test_immediate_first_slot_is_due_at_start():
    empty = project([])
    assert empty["expected_checks"] == empty["missed"] == 1
    assert empty["coverage_pct"] == 0
    assert not empty["scored"]
    full = project([sample()])
    assert full["expected_checks"] == full["received"] == 1
    assert full["coverage_pct"] == 100


@pytest.mark.parametrize("seconds,expected", [(9.999, 1), (10, 2), (20, 3)])
def test_exact_boundary_includes_new_due_slot(seconds, expected):
    c = project([sample()], seconds=seconds)
    assert c["expected_checks"] == expected
    assert c["missed"] == expected - 1


def test_multiple_services_have_independent_slots_and_denominators():
    hosts = ["web", "db", "db:direct", "db:banner", "web:db-path"]
    c = project([sample(t, host=h) for t in (0, 10, 20) for h in hosts],
                seconds=20, targets=hosts)
    assert c["expected_checks"] == c["received"] == 15
    assert c["target_count"] == 5
    assert c["coverage_pct"] == 100
    assert c["missed"] == c["duplicate_samples"] == 0


def test_duplicates_cannot_fill_other_slots_or_overwrite_down():
    c = project([sample(0, state="down"), sample(1), sample(2)], seconds=20)
    assert c["raw_samples"] == 3
    assert c["received"] == 1
    assert c["duplicate_samples"] == 2
    assert c["missed"] == 2
    assert c["coverage_pct"] == 33.3
    assert c["down"] == 1 and c["pct_up"] == 0


def test_missing_target_samples_never_shrink_denominator():
    c = project([sample(0), sample(10), sample(20)], seconds=20,
                targets=["web", "db"])
    assert c["expected_checks"] == 6
    assert c["received"] == c["missed"] == 3
    assert c["coverage_pct"] == 50


def test_prior_generation_unknown_host_and_out_of_window_are_excluded():
    c = project([sample(-1), sample(21), sample(0, generation="old"),
                 sample(0, host="unexpected"), sample(0, host=None),
                 sample(10, state="unknown")], seconds=20)
    assert c["excluded_samples"] == 5
    assert c["received"] == c["unknown"] == 1
    assert c["missed"] == 2
    assert c["valid_checks"] == 0 and not c["scored"]
    assert c["pct_up"] is None


def test_no_expected_targets_is_unscored_not_inferred_from_observations():
    c = project([sample()], targets=[])
    assert c["expected_checks"] == c["received"] == 0
    assert c["excluded_samples"] == 1
    assert c["coverage_pct"] is None and not c["scored"]


def test_reversed_window_has_no_slots_and_excludes_all_samples():
    c = project([sample()], seconds=-1)
    assert c["expected_checks"] == c["received"] == 0
    assert c["excluded_samples"] == 1


@pytest.mark.parametrize("interval", [0, -1, float("inf"), float("nan")])
def test_invalid_interval_is_rejected(interval):
    with pytest.raises(ValueError):
        uptime.scheduled_coverage([], targets=["web"], deployment_id="current",
                                  started_at=START, interval_s=interval)


def test_inventory_keeps_service_types_distinct_and_missing_probes_expected():
    spec = {"topology": {"hosts": [
        {"name": "mixed", "services": ["http", "mysql"], "db_ref": "mixed"}]}}
    resources = [{"host": "mixed", "ip": "192.0.2.1", "mysql_probe": True,
                  "db_reader_password": "synthetic"}]
    assert uptime._coverage_targets(spec, resources) == [
        "mixed", "mixed:banner", "mixed:db-path", "mixed:direct", "mixed:mysql"]


def test_naive_timestamps_and_unsorted_input_are_supported():
    first = sample(0, state="down")
    first["ts"] = START.replace(tzinfo=None)
    c = project([sample(1), first], seconds=10)
    assert c["down"] == 1 and c["up"] == 0
    assert c["duplicate_samples"] == 1


def test_live_projection_uses_slot_score_and_never_received_only_fallback(monkeypatch):
    from srplatform import lifecycle
    monkeypatch.setattr(uptime, "summarize_for_session",
                        lambda *_: {"coverage_pct": 100, "samples": 99})
    monkeypatch.setattr(lifecycle, "get_match", lambda *_: SimpleNamespace(
        started_at=START, ended_at=START, state="finished"))
    monkeypatch.setattr(uptime, "mysql_integrity", lambda *_: None)
    monkeypatch.setattr(uptime, "coverage_for_session", lambda *a, **kw:
                        project([sample(), sample(0)]))
    result = uptime.live_projection(None, "session")
    assert result["samples"] == 1 and result["duplicate_samples"] == 1
    assert result["coverage_pct"] == 100

    def broken(*a, **kw):
        raise RuntimeError("registry unavailable")

    monkeypatch.setattr(uptime, "coverage_for_session", broken)
    assert uptime.live_projection(None, "session")["coverage_pct"] is None
