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

import os
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
    if not s.verifier_ssh_known_hosts:
        # audit N11: no TOFU for management SSH — an unpinned channel can be
        # silently redirected and its output would be indistinguishable from
        # truth. Missing pin file is a VISIBLE unavailable, never an attempt.
        return 125, ("[verifier-exec] VERIFIER_SSH_KNOWN_HOSTS not configured — "
                     "refusing unpinned management SSH (unknown, not attempted)")
    if not os.path.exists(s.verifier_ssh_known_hosts):
        return 125, (f"[verifier-exec] known-hosts file {s.verifier_ssh_known_hosts} "
                     "missing — unknown, not attempted")
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
           # PINNED host keys (audit N11): a changed or missing key makes ssh
           # fail LOUDLY (exit 255 + offending key message) — the verifier
           # maps that to `unknown`, never to a pass.
           "-o", "StrictHostKeyChecking=yes",
           "-o", f"UserKnownHostsFile={s.verifier_ssh_known_hosts}",
           "-i", s.verifier_ssh_key_path, f"{s.verifier_ssh_user}@{host}", command]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=s.verifier_exec_timeout_s)
        return p.returncode, (p.stdout + p.stderr)[:8000]
    except (subprocess.TimeoutExpired, OSError) as e:
        return 124, f"[verifier-exec] {e}"


def active_deployment(db: Session, session_id) -> Deployment | None:
    """The session's CURRENT generation deployment: the newest one that is
    `ready`. A failed/torn-down deployment is a different generation and its
    (possibly reused, possibly foreign) resources must not be verified."""
    if session_id is None:
        return None
    return db.execute(select(Deployment)
                      .where(Deployment.session_id == session_id,
                             Deployment.status == "ready")
                      .order_by(Deployment.created_at.desc())).scalars().first()


def host_map_for(db: Session, session_id) -> dict[str, str]:
    """Logical scenario hostname -> concrete address, from ACTIVE, POSITIVELY
    OWNED resources of the correct deployment generation only (audit N11):
    `state == created` rows of the ready deployment. Pending intents, failed
    destructions and foreign/uncertain entries are filtered; a missing or
    stale inventory yields an EMPTY map — verification then reports unknown
    with NO DNS fallback and NO SSH attempt."""
    dep = active_deployment(db, session_id)
    if not dep:
        return {}
    return {r["host"]: r["ip"] for r in (dep.resources or [])
            if r.get("host") and r.get("ip") and r.get("state") == "created"}


_NOT_OWNED = "[verifier-exec] target not in the session's owned active inventory — " \
             "no DNS fallback, no SSH attempt (unknown)"


def _resolve(exec_fn: VerifierExec, hmap: dict[str, str]) -> VerifierExec:
    def resolved(host: str, command: str) -> tuple[int, str]:
        addr = hmap.get(host)
        if addr is None:
            # audit N11: the OLD `hmap.get(host, host)` fell back to the RAW
            # name — a DNS lookup of a stale/foreign name and an SSH attempt
            # at whatever answered. Resolution is now inventory-only.
            return 254, _NOT_OWNED
        return exec_fn(addr, command)
    return resolved


def _deployment_identity(db: Session, session_id) -> dict:
    dep = active_deployment(db, session_id)
    return {"deployment_id": str(dep.deployment_id) if dep else None,
            "deployment_status": dep.status if dep else None,
            "deployment_created_at": dep.created_at.isoformat() if dep else None}


def readiness_checks(db: Session, session_id) -> dict:
    """Service-readiness gate for the provisioning contract (audit N10 item
    4): every service declared by the session's snapshot topology must be
    PRESENT (service_present against the owned active inventory) before the
    session reaches `ready`. When the management exec channel is not
    configured (dev mode), enforcement is skipped but VISIBLE — it never
    silently passes as 'ready without readiness'."""
    from srplatform.scenario_engine.loader import SUPPORTED_SERVICES
    spec = scenario_spec(db, session_id)
    hosts = (spec.get("topology") or {}).get("hosts", [])
    declared = [(h["name"], svc) for h in hosts for svc in h.get("services", [])]
    if not declared:
        return {"enforced": True, "ok": True, "checks": [],
                "reason": "no services declared"}
    hmap = host_map_for(db, session_id)
    exec_fn = _exec_override or _ssh_exec
    if _exec_override is None:
        s = get_settings()
        if (not s.verifier_ssh_key_path or not s.verifier_ssh_known_hosts
                or not os.path.exists(s.verifier_ssh_known_hosts)):
            return {"enforced": False, "ok": True, "checks": [],
                    "reason": "management exec channel not configured — dev-mode "
                              "relaxation, visible in this response (production "
                              "refuses `ready` without readiness)"}
    v = registry.get("service_present")
    ctx = Context(exec=_resolve(exec_fn, hmap), hosts=hmap)
    items, ok = [], True
    for host, svc in declared:
        unit = SUPPORTED_SERVICES.get(svc, svc)
        outcome = v.evaluate(ctx, host=host, service=unit)
        if outcome.status != "passed":
            ok = False
        items.append({"host": host, "service": svc, "unit": unit,
                      "status": outcome.status, "evidence": outcome.evidence,
                      "error": outcome.error})
    return {"enforced": True, "ok": ok, "checks": items,
            "reason": None if ok else "declared services not ready on the owned inventory"}


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
                        # audit N11: evidence records WHICH deployment/target
                        # was addressed — a later report can be attributed.
                        "deployment": _deployment_identity(db, session_id),
                        "target": host_map_for(db, session_id).get(
                            (obj.get("args") or {}).get("host", "")),
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
    # LIVE RESCORE GUARD (audit N11): scoring addresses live hosts — it is
    # only meaningful while the session still owns an ACTIVE deployment.
    # After teardown (or with a stale/foreign inventory) refuse explicitly
    # rather than SSH at whatever answers the reused addresses.
    if checks and not hmap:
        raise RuntimeError("no active owned deployment inventory for this session — "
                           "live rescore refused (historical score_snapshot remains "
                           "read-only available); no SSH attempted")
    ctx = Context(exec=_resolve(exec_fn, hmap), hosts=hmap)

    items, earned, total = [], 0, 0
    status_seen = []
    for chk in checks:
        points = int(chk.get("points", 0))
        total += points
        v = registry.get(chk["verifier"])
        # `expect` (polarity) MUST reach the verifier: an `expect: absent`
        # check scores the INVERSE condition; dropping it silently would
        # reward the vulnerability and penalize its removal (audit R09).
        args = {k: val for k, val in chk.items()
                if k not in ("verifier", "points", "domain", "description")}
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
                "deployment": _deployment_identity(db, session_id),
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
