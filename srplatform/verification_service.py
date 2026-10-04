"""Trusted verification service (F04/F10/F11).

The ONLY code path that runs verifiers and appends their results (actor
'system'). The red worker, the browser and the CLI can REQUEST a check; they
cannot supply a result. Host resolution comes from the session's OWNED
deployment inventory — never from user input — and the exec channel is the
management SSH path built here (never mounted into the attacker runner).

Test hook: `set_verifier_exec()` swaps the exec channel (used with scripted
host-state doubles); production uses SSH with the management key.
"""
from __future__ import annotations

import shlex
import subprocess
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from srplatform.db.models import Deployment, Event
from srplatform.scenario_engine.loader import load_scenario
from srplatform.settings import get_settings
from verifiers import registry
from verifiers.base import Context

VerifierExec = Callable[[str, str], tuple[int, str]]

_exec_override: VerifierExec | None = None


def set_verifier_exec(fn: VerifierExec | None) -> None:
    """Test/operator hook: replace the management exec channel."""
    global _exec_override
    _exec_override = fn


def _ssh_exec(host: str, command: str) -> tuple[int, str]:
    s = get_settings()
    if not s.verifier_ssh_key_path:
        return 126, "[verifier-exec] management key not configured (VERIFIER_SSH_KEY_PATH)"
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
           "-o", "StrictHostKeyChecking=no",  # lab inventory, pinned via inventory freshness
           "-i", s.verifier_ssh_key_path, f"{s.verifier_ssh_user}@{host}", command]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=s.verifier_exec_timeout_s)
        return p.returncode, (p.stdout + p.stderr)[:8000]
    except (subprocess.TimeoutExpired, OSError) as e:
        return 124, f"[verifier-exec] {e}"


def host_map_for(db: Session, session_id) -> dict[str, str]:
    """Logical scenario hostname -> concrete address, from the session's owned
    deployment resources (F19: never depend on accidental DNS)."""
    if session_id is None:
        return {}
    dep = db.execute(select(Deployment).where(Deployment.session_id == session_id)
                     .order_by(Deployment.created_at.desc())).scalars().first()
    if not dep:
        return {}
    return {r["host"]: r["ip"] for r in (dep.resources or []) if r.get("host") and r.get("ip")}


def _resolve(exec_fn: VerifierExec, hmap: dict[str, str]) -> VerifierExec:
    def resolved(host: str, command: str) -> tuple[int, str]:
        return exec_fn(hmap.get(host, host), command)
    return resolved


def check_objective(db: Session, session_id, objective_id: str) -> dict:
    """Run ONE red objective's verifier and append the trusted event.
    Returns {objective, status, passed, evidence, event_id}."""
    spec = scenario_spec(db, session_id)
    obj = next((o for o in spec.get("red", {}).get("objectives", []) if o["id"] == objective_id), None)
    if obj is None:
        return {"error": f"unknown objective '{objective_id}'"}
    exec_fn = _exec_override or _ssh_exec
    ctx = Context(exec=_resolve(exec_fn, host_map_for(db, session_id)),
                  hosts=host_map_for(db, session_id))
    v = registry.get(obj["verifier"])
    outcome = v.evaluate(ctx, **(obj.get("args") or {}))   # typed: passed/failed/unknown
    ev = Event(session_id=session_id, ts=datetime.now(timezone.utc), actor="system",
               host=(obj.get("args") or {}).get("host"), action_type="verifier",
               payload={"objective": objective_id, "verifier": obj["verifier"],
                        "verifier_version": v.version,
                        "status": outcome.status, "passed": outcome.status == "passed",
                        "expected": outcome.expected,
                        "args_digest": outcome.args_digest,
                        "evidence": outcome.evidence, "error": outcome.error,
                        "points": 0, "domain": "red-objective"})
    db.add(ev)
    db.flush()
    return {"objective": objective_id, "status": outcome.status,
            "passed": outcome.status == "passed", "evidence": outcome.evidence,
            "event_id": ev.event_id}


def build_scorecard(db: Session, session_id) -> dict:
    """Deterministic blue scorecard from scenario rubric + live host state.
    Unavailable checks follow the documented policy (unknown scores 0 and
    REMAINS VISIBLE); no fabrication, no implicit penalties. Uses the
    session's SNAPSHOT of the scenario so post-hoc YAML edits cannot change
    historical meaning (F19)."""
    scenario_id = _session_scenario(db, session_id)
    spec = scenario_spec(db, session_id)
    checks = (spec.get("scoring") or {}).get("blue_checks", [])
    exec_fn = _exec_override or _ssh_exec
    hmap = host_map_for(db, session_id)
    ctx = Context(exec=_resolve(exec_fn, hmap), hosts=hmap)

    items, earned, total = [], 0, 0
    status_seen = []
    for chk in checks:
        points = int(chk.get("points", 0))
        total += points
        v = registry.get(chk["verifier"])
        args = {k: val for k, val in chk.items()
                if k not in ("verifier", "points", "domain", "expect", "description")}
        outcome = v.evaluate(ctx, **args)
        awarded = points if outcome.status == "passed" else 0
        earned += awarded
        status_seen.append(outcome.status)
        items.append({"verifier": chk["verifier"], "verifier_version": v.version,
                      "host": chk.get("host"), "domain": chk.get("domain", "general"),
                      "description": chk.get("description", ""),
                      "points": points, "awarded": awarded,
                      "status": outcome.status, "expected": outcome.expected,
                      "args_digest": outcome.args_digest,
                      "evidence": outcome.evidence, "error": outcome.error})

    scorecard_status = "scored"
    if not checks:
        scorecard_status = "unscored"
    elif any(s == "unknown" for s in status_seen):
        scorecard_status = "partial"

    snapshot = {"scenario_id": scenario_id, "earned": earned, "total": total,
                "status": scorecard_status, "items": items,
                "rubric_version": spec.get("rubric_version", spec.get("version", 1))}
    ev = Event(session_id=session_id, ts=datetime.now(timezone.utc), actor="system",
               action_type="score_snapshot", payload={"scorecard": snapshot,
                                                      "scorecard_status": scorecard_status})
    db.add(ev)
    db.flush()
    return {"event_id": ev.event_id, **snapshot}


def latest_scorecard(db: Session, session_id) -> dict | None:
    ev = db.execute(select(Event).where(Event.session_id == session_id,
                                         Event.action_type == "score_snapshot")
                    .order_by(Event.event_id.desc())).scalars().first()
    if not ev:
        return None
    return {"event_id": ev.event_id, "ts": ev.ts.isoformat(), **(ev.payload or {}).get("scorecard", {})}


def _session_scenario(db: Session, session_id) -> str:
    from srplatform.db.models import Session as SessionModel

    sess = db.get(SessionModel, session_id)
    if sess is None:
        raise ValueError("session not found")
    return sess.scenario_id


def scenario_spec(db: Session, session_id) -> dict:
    """Snapshot-first scenario resolution (F19): the YAML captured at session
    creation defines what this session's checks MEAN; live-file edits cannot
    rewrite history. Falls back to the current file for pre-remediation
    sessions."""
    import yaml

    from srplatform.scenario_engine.loader import parse_scenario

    ev = db.execute(select(Event).where(Event.session_id == session_id,
                                         Event.action_type == "session_start")
                    .order_by(Event.event_id.desc())).scalars().first()
    payload = (ev.payload or {}) if ev else {}
    if payload.get("scenario_yaml"):
        return parse_scenario(payload["scenario_yaml"], where="session-snapshot")
    return load_scenario(_session_scenario(db, session_id))
