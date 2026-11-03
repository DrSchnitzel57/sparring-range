"""Dependency-aware availability evidence for environment labs.

The service-check REGISTRY (`environment_specs/checks.py`) defines REAL
availability transactions. This module decides what one sample MEANS — a
pure decision table, so the same rules apply to scheduled samples, defender
views and the final score:

  * the TARGET's guests (itself + `depends_on_guests`) must be up, or the
    sample is UNKNOWN (infrastructure, not defense): an outage of the
    router/firewall that carries every path can never award or deduct
    points for a check it could not reach;
  * a SCORER-side error (timeout, auth material, DB error from the vantage)
    is UNKNOWN too, never downtime — the plan says "distinguish scorer/auth/
    DB faults from target outage";
  * only an observation the vantage really completed (it reached the
    service and the transaction's expectation did not hold) is FAILED;
  * a check nobody sampled is UNKNOWN, never a silent pass.

Nothing here samples the network: callers provide observations; the
transactions themselves run from the trusted scoring vantage.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .environment_specs.checks import ServiceCheck, ServiceCheckRegistry

#: Guest states that positively mean "the machine is up and owned". A guest
#: in any other state (pending, failed, unknown, foreign…) cannot make a
#: check's failure meaningful to a defender.
UP_GUEST_STATES = frozenset({"ready", "running", "stopped-up"})

#: Observation verdicts a vantage can REPORT. `error` is about the SCORER
#: (timeout, credential material, client crash) and never becomes downtime.
OBSERVATION_STATES = frozenset({"ok", "failed", "error"})


@dataclass(frozen=True)
class Observation:
    """One vantage sample. `error` carries the scorer-side reason."""
    state: str
    latency_ms: int | None = None
    detail: str = field(default="")

    def __post_init__(self) -> None:
        if self.state not in OBSERVATION_STATES:
            raise ValueError(f"unknown observation state {self.state!r}; "
                             f"expected one of {sorted(OBSERVATION_STATES)}")


def _dependency_state(check: ServiceCheck,
                      guest_states: dict[str, str]) -> str | None:
    """The first guest this check depends on that is not verifiably UP."""
    for guest in [check.guest, *check.depends_on_guests]:
        state = guest_states.get(guest)
        if state is None:
            return f"{guest}: no durable inventory"
        if state not in UP_GUEST_STATES:
            return f"{guest}: {state}"
    return None


def evaluate_check(check: ServiceCheck, *,
                   observation: Observation | None,
                   guest_states: dict[str, str]) -> dict:
    """One check's availability evidence: ok | failed | unknown."""
    reason = _dependency_state(check, guest_states)
    if reason is not None:
        return {"check": check.id, "state": "unknown",
                "reason": f"dependency unavailable ({reason})",
                "latency_ms": None, "detail": observation.detail
                if observation else ""}
    if observation is None:
        return {"check": check.id, "state": "unknown",
                "reason": "no sample in this window",
                "latency_ms": None, "detail": ""}
    if observation.state == "error":
        return {"check": check.id, "state": "unknown",
                "reason": f"scorer error: {observation.detail or 'unknown'}",
                "latency_ms": observation.latency_ms,
                "detail": observation.detail}
    return {"check": check.id, "state": observation.state,
            "reason": ("target answered the transaction"
                       if observation.state == "ok"
                       else "transaction completed but its expectation failed"),
            "latency_ms": observation.latency_ms,
            "detail": observation.detail}


def evaluate_registry(registry: ServiceCheckRegistry, *,
                      observations: dict[str, Observation],
                      guest_states: dict[str, str]) -> dict:
    """Project a whole window: per-check evidence, per-task rollup and
    coverage. A task with any unknown check is UNKNOWN (its failure cannot
    be attributed); `points` are never awarded for unknown evidence."""
    checks: dict[str, dict] = {}
    for check in registry.checks:
        checks[check.id] = evaluate_check(
            check,
            observation=observations.get(check.id),
            guest_states=guest_states)
    tasks: dict[str, dict] = {}
    for task in registry.tasks:
        states = [checks[cid]["state"] for cid in task.service_checks
                  if cid in checks]
        if not task.service_checks:
            state = "verified-elsewhere"  # deterministic verifier task
        elif any(s == "failed" for s in states):
            state = "failed"
        elif any(s == "unknown" for s in states) or not states:
            state = "unknown"
        else:
            state = "ok"
        tasks[task.id] = {
            "task": task.id, "state": state,
            "points": task.points, "domain": task.domain,
            # verified-elsewhere tasks are graded by deterministic
            # verifiers, not by availability transactions; their points are
            # simply not availability evidence, never zero because unknown.
            "awarded": task.points
            if state in ("ok", "verified-elsewhere") else 0,
            "service_checks": list(task.service_checks),
        }
    by_state = {"ok": 0, "failed": 0, "unknown": 0}
    for row in checks.values():
        by_state[row["state"]] += 1
    return {
        "environment": registry.environment,
        "checks_version": registry.version,
        "checks": checks,
        "tasks": tasks,
        "coverage": {
            "total": len(checks),
            "sampled": sum(1 for cid in observations if cid in checks),
            **by_state,
        },
        "ok": by_state["failed"] == 0 and by_state["unknown"] == 0,
    }
