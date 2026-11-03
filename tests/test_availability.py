"""Dependency-aware availability evidence (Underpressure availability lane).

Pure decision table over the REAL underpressure check registry: a sampled
check is never downtime while the target or a carrying dependency is down,
a scorer-side error is never downtime either, and unknown evidence never
awards points.
"""
from __future__ import annotations

import pytest

from srplatform.availability import Observation, evaluate_check, \
    evaluate_registry
from srplatform.environment_specs import load_environment


def _registry():
    return load_environment("underpressure-range").checks


def _all_up():
    registry = _registry()
    guests = {g.name for g in load_environment(
        "underpressure-range").blueprint.guests}
    return {name: "ready" for name in guests}


def _all_ok(registry):
    return {c.id: Observation("ok", latency_ms=40) for c in registry.checks}


# ------------------------------------------------------------------ checks ---
def test_a_completed_failed_transaction_is_real_downtime():
    registry = _registry()
    states = _all_up()
    check = registry.check("store-catalog-https")
    row = evaluate_check(check, observation=Observation("failed"),
                         guest_states=states)
    assert row["state"] == "failed"
    assert "expectation failed" in row["reason"]


def test_a_down_router_makes_every_carried_check_unknown():
    """The firewall/router carry every public path: their outage is
    infrastructure, so even a FAILED observation becomes UNKNOWN."""
    registry = _registry()
    states = _all_up()
    states["opnsense-fw"] = "failed"
    check = registry.check("store-catalog-https")
    row = evaluate_check(check, observation=Observation("failed"),
                         guest_states=states)
    assert row["state"] == "unknown"
    assert "opnsense-fw: failed" in row["reason"]


def test_a_scorer_error_is_never_downtime():
    registry = _registry()
    check = registry.check("mail-roundtrip")
    row = evaluate_check(check,
                         observation=Observation("error", detail="timeout"),
                         guest_states=_all_up())
    assert row["state"] == "unknown"
    assert "scorer error" in row["reason"]


def test_an_unsampled_check_is_unknown_not_a_pass():
    check = _registry().check("dns-authoritative")
    row = evaluate_check(check, observation=None, guest_states=_all_up())
    assert row["state"] == "unknown"
    assert "no sample" in row["reason"]


def test_a_guest_without_inventory_poisons_its_checks():
    check = _registry().check("store-catalog-https")
    states = _all_up()
    states.pop("ecomm")
    row = evaluate_check(check, observation=Observation("ok"),
                         guest_states=states)
    assert row["state"] == "unknown"
    assert "no durable inventory" in row["reason"]


# --------------------------------------------------------------- registry ---
def test_all_ok_and_all_up_is_the_only_way_to_be_ok():
    registry = _registry()
    out = evaluate_registry(registry, observations=_all_ok(registry),
                            guest_states=_all_up())
    assert out["ok"] is True
    assert out["coverage"]["unknown"] == 0
    assert all(t["awarded"] == t["points"] for t in out["tasks"].values())


def test_any_unknown_makes_the_whole_window_not_ok():
    registry = _registry()
    observations = _all_ok(registry)
    observations.pop(registry.checks[0].id)
    out = evaluate_registry(registry, observations=observations,
                            guest_states=_all_up())
    assert out["ok"] is False
    assert out["coverage"]["unknown"] == 1
    assert out["checks"][registry.checks[0].id]["state"] == "unknown"


def test_task_rollup_never_awards_points_on_unknown_evidence():
    registry = _registry()
    states = _all_up()
    states["vyos-edge"] = "creating"
    out = evaluate_registry(registry, observations=_all_ok(registry),
                            guest_states=states)
    for task in out["tasks"].values():
        if task["service_checks"]:
            assert task["state"] == "unknown"
            assert task["awarded"] == 0


def test_observation_rejects_a_state_the_vantage_cannot_report():
    with pytest.raises(ValueError, match="unknown observation state"):
        Observation("maybe")
