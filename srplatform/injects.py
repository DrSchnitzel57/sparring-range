"""Versioned injects (plan 13 phase 6).

Trusted SERVER scheduling: release/deadline times derive from the SNAP-
SHOTTED duration at Begin — clients can never move them. Submissions are
identity-bound and idempotent (the FIRST submission decides; duplicates
are counted, never re-decided), technical verification is deterministic
through the same verifier registry the scorecard uses, and written
feedback (incident report) is ADVISORY ONLY: it can never award verified
points. Inject score stays SEPARATE from availability (uptime) and the
final security scorecard — no invented combined grade.

Outcomes are explicit: pending, correct, incorrect, late (first answer
after deadline), duplicate (after a decision), advisory (written work).
A disabled inject set releases NOTHING; submissions to unknown or
unreleased injects are refused, not queued.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import select, update

#: Versioned catalog. ``host_role`` resolves at schedule time against the
#: scenario topology (owned hosts only); verification re-reads the live
#: deployment inventory, so a release can only ever be proven against the
#: generation the session owns.
CATALOG: dict[str, dict] = {
    "restricted-account@1": {
        "kind": "technical",
        "host_role": "web",
        "description": ("Incident: an unauthorized privileged account appeared on "
                        "the web tier. Remove it (restore least privilege)."),
        "verifier": "rogue_account",
        "args": {"table": None},
    },
    "web-restoration@1": {
        "kind": "technical",
        "host_role": "web",
        "description": "Incident: the shop stopped serving. Restore the catalogue page.",
        "verifier": "http_content",
        "args": {"path": "/", "expected_text": "Minecraft Legends"},
    },
    "db-data-recovery@1": {
        "kind": "technical",
        "host_role": "db",
        "description": "Incident: purchase data was damaged. Restore the seeded rows.",
        "verifier": "mysql_rows",
        "args": {"table": "purchases", "expected_count": 12},
    },
    "incident-report@1": {
        "kind": "written",
        "host_role": "web",
        "description": ("Write the incident report (timeline, impact, containment). "
                        "Advisory feedback only — never verified points."),
        "verifier": None,
        "args": {},
    },
}

#: release cadence as a fraction of the snapshotted duration: four injects
#: open at 20/40/60/80 % and each stays open for 20 %.
_RELEASE_FRACTIONS = (0.2, 0.4, 0.6, 0.8)
_OPEN_FRACTION = 0.2

#: maximum retained submission text (incident reports stay readable;
#: the store is evidence, not a file drop)
MAX_SUBMISSION_CHARS = 4000


def _content_preview(content) -> str | None:
    if content is None:
        return None
    text = content if isinstance(content, str) else str(content)
    return text[:MAX_SUBMISSION_CHARS]


def schedule_times(start: datetime, duration_minutes: int):
    """Pure schedule computation (testable): [(offset, deadline)] as
    datetimes derived from the frozen duration."""
    dur = timedelta(minutes=int(duration_minutes))
    return [(start + dur * f, start + dur * (f + _OPEN_FRACTION))
            for f in _RELEASE_FRACTIONS]


def _role_hosts(spec: dict) -> dict[str, str]:
    web = next((h["name"] for h in (spec.get("topology") or {}).get("hosts", [])
                if "http" in (h.get("services") or [])), None)
    db = next((h["name"] for h in (spec.get("topology") or {}).get("hosts", [])
               if "mysql" in (h.get("services") or [])), None)
    return {"web": web, "db": db}


def schedule(db, session_id, match, spec: dict, *, actor: str = "system") -> list:
    """Create the session's releases from the catalog (idempotent: a second
    Begin never duplicates or re-times them). ``injects_enabled: false`` in
    the snapshot releases NOTHING — that is the disabled-inject outcome."""
    from srplatform.db.models import InjectRelease
    snap = match.snapshot or {}
    if not snap.get("injects_enabled", True):
        return []
    existing = db.execute(select(InjectRelease).where(
        InjectRelease.session_id == session_id)).scalars().all()
    if existing:
        return list(existing)
    hosts = _role_hosts(spec)
    start = match.started_at or datetime.now(timezone.utc)
    times = schedule_times(start, match.duration_minutes)
    out = []
    for (inject_id, defn), (rel_at, deadline) in zip(CATALOG.items(), times):
        host = hosts.get(defn["host_role"])
        if defn["host_role"] == "db" and not host:
            continue  # scenario has no DB tier: that inject simply does not exist
        if not host:
            continue
        r = InjectRelease(session_id=session_id, inject_id=inject_id,
                          kind=defn["kind"], status="pending",
                          scheduled_at=rel_at, deadline_at=deadline,
                          evidence={"host": host})
        db.add(r)
        out.append(r)
    db.commit()
    return out


#: Versioned image user baseline for the restricted-account inject
#: (web tier). Accounts the untouched guest ships: noble cloud-image
#: system set + the tier's service accounts. Anything else present is the
#: incident. Supersets are safe (extras never match); omissions
#: false-positive on untouched guests. NOTE: there is deliberately no
#:`mgmt` unix account — the mgmt principal administers as root per the
#: role-key policy, so a `mgmt` user on the guest would itself be rogue.
#: Conformance against RECORDED build data is enforced by
#: test_mojang_images.py::test_images_rogue_baselines_match_recorded_users.
IMAGE_BASELINE_USERS = [
    "root", "daemon", "bin", "sys", "sync", "games", "man", "lp", "mail",
    "news", "uucp", "proxy", "www-data", "backup", "list", "irc", "nobody",
    "systemd-network", "systemd-resolve", "systemd-timesync", "systemd-oom",
    "messagebus", "syslog", "_apt", "uuidd", "tcpdump", "sshd", "tss",
    "defender", "web-user", "mysql", "srshipper",
]


def verify_release(db, release, *, exec_fn=None):
    """Deterministic technical verification through the shared registry.
    Returns 'correct' | 'incorrect' | 'pending' (unknown keeps the release
    open — an unverifiable moment is never scored as failure)."""
    from srplatform import verification_service
    from srplatform.db.models import Event
    from verifiers import registry
    from verifiers.base import Context

    defn = CATALOG[release.inject_id]
    if defn["kind"] == "written":
        return "advisory"
    host = (release.evidence or {}).get("host")
    hmap = verification_service.host_map_for(db, release.session_id)
    if host not in hmap:
        return "pending"  # owned inventory does not (yet) carry the host
    args = {k: v for k, v in defn["args"].items() if v is not None}
    if defn["verifier"] == "rogue_account":
        args = {"known_users": IMAGE_BASELINE_USERS}
    v = registry.get(defn["verifier"])
    exec_ = exec_fn or verification_service.management_exec
    ctx = Context(exec=verification_service._resolve(exec_, hmap),
                  hosts=hmap)
    outcome = v.evaluate(ctx, host=host, **args)
    if outcome.status == "unknown":
        return "pending"
    release.evidence = {**(release.evidence or {}),
                        "verifier": defn["verifier"],
                        "verifier_version": v.version,
                        "predicate": outcome.status,
                        "evidence": {k: str(x)[:200] for k, x in
                                     (outcome.evidence or {}).items()}}
    return "correct" if outcome.status == "passed" else "incorrect"


def submit(db, release, *, now: datetime | None = None, exec_fn=None,
           actor: str = "member", content=None) -> dict:
    """One identity-bound submission attempt. First answer decides;
    duplicates count but never re-decide; late-first answers are `late`;
    written work is advisory. The submission TEXT is persisted (bounded)
    into the release evidence BEFORE verification acknowledges anything —
    an incident report is evidence first, advisory second. The transition
    is appended as an event."""
    from sqlalchemy import select as _select
    from srplatform.db.models import InjectRelease as _IR
    # ATOMIC CLAIM (first answer decides): lock the row; a concurrent
    # submission arriving while this one verifies sees the decided state
    # instead of re-verifying and overwriting it.
    # populate_existing: the caller may already hold this row in the
    # session (stale snapshot) — the locked read must refresh to the
    # committed truth, or the increment below silently overwrites a
    # concurrent submission's count (lost update DESPITE the lock).
    release = db.execute(
        _select(_IR).where(_IR.release_id == release.release_id)
        .with_for_update()
        .execution_options(populate_existing=True)).scalars().one()
    now = now or datetime.now(timezone.utc)
    release.submissions = int(release.submissions or 0) + 1
    if release.status != "pending":
        db.commit()
        note = ("duplicate — the first submission decided this release"
                if release.status != "expired"
                else "window closed unanswered — expired, not scored")
        return {"status": release.status, "note": note, "decided_at":
                release.submitted_at.isoformat() if release.submitted_at else None}
    if now < release.scheduled_at:
        db.commit()
        return {"status": "not_released",
                "opens_at": release.scheduled_at.isoformat()}
    preview = _content_preview(content)
    if preview is not None:
        release.evidence = {**(release.evidence or {}),
                            "submission": preview,
                            "submission_chars": len(preview)}
    release.submitted_at = now
    if now > release.deadline_at:
        release.status = "late"
    else:
        outcome = verify_release(db, release, exec_fn=exec_fn)
        release.status = outcome  # pending stays open for a later retry
    from srplatform.db.models import Event
    db.add(Event(session_id=release.session_id, ts=now, actor=actor,
                 action_type="inject_submission",
                 payload={"release_id": str(release.release_id),
                          "inject_id": release.inject_id,
                          "status": release.status,
                          "submission_chars": len(preview)
                          if preview is not None else 0}))
    db.commit()
    return {"status": release.status,
                            "deadline_at": release.deadline_at.isoformat()}


def expire_releases(db, session_id, *, now: datetime | None = None) -> int:
    """Durable expiry: releases still pending past their deadline become
    `expired` (a closed, non-correct outcome) with an event — ignoring a
    release can never preserve a perfect score. Idempotent; called on
    every inbox read and every submission, so expiry never depends on a
    scheduler tick."""
    from srplatform.db.models import Event, InjectRelease
    now = now or datetime.now(timezone.utc)
    # ATOMIC conditional transition (single UPDATE … WHERE status =
    # 'pending'): a verify that committed `correct` a microsecond earlier
    # no longer matches the predicate, so expiry can never overwrite a
    # timely decision.
    ids = db.execute(
        update(InjectRelease)
        .where(InjectRelease.session_id == session_id,
               InjectRelease.status == "pending",
               InjectRelease.deadline_at <= now)
        .values(status="expired")
        .returning(InjectRelease.release_id, InjectRelease.inject_id)
    ).all()
    for release_id, inject_id in ids:
        db.add(Event(session_id=session_id, ts=now, actor="system",
                     action_type="inject_expired",
                     payload={"release_id": str(release_id),
                              "inject_id": inject_id}))
    if ids:
        db.commit()
    return len(ids)


def summary(db, session_id) -> dict:
    """SEPARATE inject score: correct / technical releases whose window
    closed (answered, late, or EXPIRED unanswered). Advisory items never
    enter it; availability and security stay their own reports. An
    unanswered release counts as closed-not-correct once its deadline
    passes — ignoring tasks cannot produce 100%."""
    from srplatform.db.models import InjectRelease
    rows = db.execute(select(InjectRelease).where(
        InjectRelease.session_id == session_id)).scalars().all()
    technical = [r for r in rows if r.kind == "technical"]
    closed = [r for r in technical if r.status != "pending"]
    correct = sum(1 for r in technical if r.status == "correct")
    expired = sum(1 for r in technical if r.status == "expired")
    return {"releases": len(rows),
            "technical_closed": len(closed),
            "correct": correct,
            "expired": expired,
            "scored": bool(closed),
            "pct": round(100.0 * correct / len(closed), 1) if closed else None,
            "advisory_only": [r.inject_id for r in rows if r.kind == "written"]}
