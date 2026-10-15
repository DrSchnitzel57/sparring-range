"""Minimal durable match lifecycle (pilot step 4).

Server clock is the ONLY match authority:

  * session creation SNAPSHOTS the effective preset, duration and attack
    pace into `matches` (never re-read live mid-match);
  * Begin (or the first /run) starts the clock: started_at/deadline_at;
  * ready-but-unstarted labs EXPIRE after READY_IDLE_EXPIRY_MINUTES and are
    safely cleaned up (worker stopped, evidence captured, capabilities
    revoked, owned VMs destroyed, lease released when teardown completes);
  * the deadline ends the match the same way — end/expiry is ONE durable
    path, never a best-effort request;
  * an API restart INTERRUPTS running matches and reconciles them — a match
    is never silently resumed;
  * 'finalizing' is the durable intent marker: cleanup retries until the
    range is genuinely resolved. Unknown is never success: a blocked stop,
    unresolved operation or failed destroy RETAINS the lease and stays
    visible for recovery.

The scheduler tick is a plain function (tests call it directly); the thread
is started only when SR_MATCH_SCHEDULER_ENABLED=1 (production control
plane), so shared-database test processes never run background cleanup.
"""
from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from srplatform.db.models import (
    Event, LoginToken, MatchModel, ServiceToken,
)
from srplatform.db.models import Session as SessionModel

READY_IDLE_EXPIRY_MINUTES = 15
#: reasons that end a match WITHOUT it having been played to a result
INTERRUPTING_REASONS = {"idle_expiry", "api_restart"}


def _now() -> datetime:
    return datetime.now(timezone.utc)


class MatchBlocked(RuntimeError):
    """Cleanup cannot complete safely right now (worker stop unconfirmed,
    unresolved operations). The caller keeps everything reserved and
    visible; the scheduler retries. NEVER swallowed into success."""

    def __init__(self, reason: str, detail=None):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


# ------------------------------------------------------------------ snapshot --
#: Bounded, versioned match choices (plan 13 phase 6). Historical snapshots
#: keep whatever they froze; new rows freeze these keys, and readers apply
#: DOCUMENTED defaults to pre-upgrade rows (forward migration, never
#: reinterpretation of history).
MATCH_MODES = ("practice", "competition")
#: Agreed attacker starting conditions (ARCHITECTURE, AI attack behavior):
#: network-entry starts with no target credentials against the seeded,
#: documented vulnerabilities; assumed-breach starts with an explicitly
#: disclosed limited guest foothold (the worker's start phase moves past
#: recon AND both sides see the disclosure — never silent seeding).
START_CONDITIONS = ("network-entry", "assumed-breach")
#: the foothold phase an assumed-breach match starts from (must be a real
#: PhaseMachine phase; recon is skipped, never revisited)
ASSUMED_BREACH_START_PHASE = "initial-access"
#: attack dispatch cadence (intensity): 60/30/15 s maximum; 0 is the
#: explicit no-delay fixture mode, never an operator default.
PACE_CHOICES = (0, 15, 30, 60)
SNAPSHOT_VERSION = 2


def create_match(db, session_id, preset: str, *, duration_minutes: int = 30,
                 pace_seconds: int = 30, mode: str = "practice",
                 start_condition: str = "network-entry",
                 injects_enabled: bool = True,
                 scenario_versions: dict | None = None,
                 effective_settings: dict | None = None,
                 actor: str = "system") -> MatchModel:
    """Snapshot the effective match parameters AT SESSION CREATION.
    Every choice is BOUNDED (plan 13 phase 6): an unbounded cadence or an
    unknown mode/start condition is refused before anything is stored.
    ``scenario_versions`` freezes the topology/template/rubric/seed versions
    and scenario digest in force NOW, so history can never be re-scored
    against a later library state."""
    if mode not in MATCH_MODES:
        raise ValueError(f"mode must be one of {MATCH_MODES}")
    if start_condition not in START_CONDITIONS:
        raise ValueError(f"start_condition must be one of {START_CONDITIONS}")
    if int(pace_seconds) not in PACE_CHOICES:
        raise ValueError(f"pace_seconds (intensity) must be one of "
                         f"{PACE_CHOICES} (0 = no-delay fixture mode)")
    duration_minutes = max(1, int(duration_minutes))
    pace_seconds = int(pace_seconds)
    m = MatchModel(
        session_id=session_id, preset=preset,
        duration_minutes=duration_minutes, pace_seconds=pace_seconds,
        state="provisioning",
        snapshot={"snapshot_version": SNAPSHOT_VERSION,
                  "preset": preset, "duration_minutes": duration_minutes,
                  "pace_seconds": pace_seconds, "mode": mode,
                  "start_condition": start_condition,
                  "injects_enabled": bool(injects_enabled),
                  "scenario_versions": dict(scenario_versions or {}),
                  "effective_settings": dict(effective_settings or {}),
                  "ready_idle_expiry_minutes": READY_IDLE_EXPIRY_MINUTES,
                  "snapshot_at": _now().isoformat(), "snapshotted_by": actor})
    db.add(m)
    db.flush()
    db.add(Event(session_id=session_id, ts=_now(), actor="system",
                 action_type="match_snapshot", payload=dict(m.snapshot)))
    db.flush()
    return m


def get_match(db, session_id) -> MatchModel | None:
    return db.get(MatchModel, session_id)


def mark_ready(db, session_id) -> None:
    """Lab is READY (launch/reset finalize succeeded): the idle-expiry clock
    starts now. A RUNNING match keeps its original clock (reset mid-match
    must not restart the deadline); FINALIZING stays blocked until cleanup
    resolves. A COMPLETED/INTERRUPTED match is RE-ARMED: relaunching a torn-
    down session begins a fresh period (every transition is evented)."""
    m = get_match(db, session_id)
    if m is None or m.state in ("running", "finalizing"):
        return
    m.state = "ready"
    m.ready_at = _now()
    m.started_at = m.deadline_at = m.ended_at = None
    m.expiry_reason = None
    db.add(Event(session_id=session_id, ts=_now(), actor="system",
                 action_type="match_ready",
                 payload={"expires_at": (m.ready_at
                                         + timedelta(minutes=READY_IDLE_EXPIRY_MINUTES)
                                         ).isoformat()}))
    db.flush()


def prove_assumed_breach(db, session_id) -> dict | None:
    """Establish the disclosed assumed-breach foothold (see start_clock).
    Returns the proof dict for network-entry (None — nothing to prove) or
    the disclosure+proof for assumed-breach. Raises MatchBlocked when a
    production match cannot establish its starting condition. Pure and
    idempotent: safe to call before spawning the worker AND inside
    start_clock."""
    from srplatform import verification_service
    m = get_match(db, session_id)
    if m is None or (m.snapshot or {}).get("start_condition") != "assumed-breach":
        return None
    try:
        spec = verification_service.scenario_spec(db, session_id)
        web_host = next(
            (h["name"] for h in (spec.get("topology") or {}).get("hosts", [])
             if "http" in (h.get("services") or [])), None)
    except Exception:  # noqa: BLE001 — disclosure names best-effort
        web_host = None
    proof: dict = {"user": "web-user", "host": web_host,
                   "method": "documented diagnostic flaw "
                             "(MOJANG_DIAG_ENABLED)",
                   "scope": "limited guest foothold; recon phase "
                            "skipped by snapshot"}
    from srplatform.scenario_engine import orchestrator as _orch
    from srplatform.settings import get_settings as _gs
    chan = _orch.management_runner()
    if chan is None:
        proof["established"] = False
        proof["reason"] = ("no management channel — foothold disclosed "
                           "but unproven")
        if _gs().sr_env == "production":
            raise MatchBlocked(
                "assumed_breach_unproven",
                "production assumed-breach requires a management "
                "channel to establish the disclosed foothold")
        return proof
    hmap = verification_service.host_map_for(db, session_id)
    addr = hmap.get(web_host) if web_host else None
    if addr is None:
        proof["established"] = False
        proof["reason"] = ("owned inventory has no address for "
                           f"{web_host}")
        return proof
    code, out = chan(addr, "runuser -u web-user -- id -u web-user")
    proof["established"] = (code == 0)
    proof["exit_code"] = code
    proof["output"] = str(out or "")[:200]
    if code != 0:
        raise MatchBlocked(
            "assumed_breach_unproven",
            f"foothold proof command failed (exit {code}): "
            f"{str(out or '')[:200]}")
    return proof


def start_clock(db, session_id, *, actor: str = "system") -> MatchModel | None:
    """Begin: bind the SERVER clock to the match. Idempotent — a match that
    is already running keeps its ORIGINAL deadline (a duplicate Begin can
    never extend the match)."""
    m = get_match(db, session_id)
    if m is None:
        return None
    if m.state == "running":
        return m
    if m.state != "ready":
        raise MatchBlocked("not_ready", f"match is {m.state}")
    m.state = "running"
    m.started_at = _now()
    m.deadline_at = m.started_at + timedelta(minutes=m.duration_minutes)
    m.ready_at = None  # idle timer no longer applies
    payload = {"started_at": m.started_at.isoformat(),
               "deadline_at": m.deadline_at.isoformat(),
               "duration_minutes": m.duration_minutes,
               "pace_seconds": m.pace_seconds}
    proof = prove_assumed_breach(db, session_id)
    if proof is not None:
        payload["disclosed_foothold"] = proof
        # SUPPLY the capability to the attacker: the red loop restores its
        # phase and prompt summary from agent_state at startup, so seed
        # both with the disclosed foothold. The worker demonstrably starts
        # informed (initial-access, flaw invocation in context) instead of
        # re-exploiting network entry. Server-side write (the member
        # endpoint is sealed in competition; the runner token reads it).
        from srplatform.db.models import AgentState as _AS
        st = db.get(_AS, session_id)
        if st is None:
            st = _AS(session_id=session_id)
            db.add(st)
        st.summary = (
            "ASSUMED BREACH (disclosed foothold): execute as web-user "
            f"on {proof.get('host')} through the documented diagnostic "
            "flaw (MOJANG_DIAG_ENABLED); recon is already complete, "
            "begin at initial-access.")
        st.current_phase = "initial-access"
        db.flush()
    db.add(Event(session_id=session_id, ts=_now(), actor=actor,
                 action_type="match_begin", payload=payload))
    db.flush()
    return m


# ------------------------------------------------------------------ finalize --
def finalize_match(db, session_id, reason: str, *, broker, actor: str = "system",
                   username: str | None = None) -> dict:
    """THE durable end/expiry path (user end, deadline, idle expiry, API
    restart): stop the worker and CONFIRM, capture final evidence, revoke
    capabilities, DESTROY owned VMs, release the lease when teardown is
    complete. Raises MatchBlocked (everything stays reserved + visible)
    when a step cannot be safely confirmed — the scheduler retries."""
    from srplatform import verification_service
    from srplatform.api import runs as runs_svc
    from srplatform.scenario_engine import orchestrator

    sess = db.get(SessionModel, session_id)
    if sess is None:
        raise MatchBlocked("no_session", str(session_id))
    # the probe loop belongs to the match — stop it FIRST so no sample is
    # recorded against a teardown in progress
    from srplatform import uptime as _uptime
    _uptime.stop_for_session(session_id)
    m = get_match(db, session_id)
    if m is not None and m.state == "completed":
        return {"ok": True, "status": "complete", "note": "already finalized",
                "outcome": sess.outcome, "lease_released": True}

    # DURABLE INTENT (own transaction, like the claim machinery): 'finalizing'
    # must survive a rolled-back request — a crash or a blocked step leaves
    # the marker for the scheduler to retry, never a silent 'running'.
    if m is not None:
        from sqlalchemy import update as sa_update
        from srplatform.db.session import db as db_ctx
        with db_ctx() as s2:
            s2.execute(sa_update(MatchModel).where(
                MatchModel.session_id == session_id).values(
                state="finalizing", expiry_reason=reason))
            s2.commit()
        db.expire(m)  # reload sees the committed 'finalizing' intent

    # 1. stop the worker and confirm (never finalize over a live attacker)
    active = runs_svc.active_run_for_session(db, session_id)
    if active:
        stopped = runs_svc.stop_run(db, active.run_id)
        if not stopped.get("ok"):
            db.add(Event(session_id=session_id, ts=_now(), actor="system",
                         action_type="match_finalize_blocked",
                         payload={"reason": reason, "stage": "worker_stop",
                                  "detail": stopped.get("detail")}))
            db.flush()
            raise MatchBlocked("worker_stop_failed", stopped.get("detail"))
    # 2. durable obligations must be genuinely resolved (audit F2)
    rows = runs_svc.unresolved_operations(db, session_id)
    for rid in {str(r.run_id) for r in rows}:
        try:
            runs_svc.stop_run(db, rid)
        except KeyError:
            pass
    rows = runs_svc.unresolved_operations(db, session_id)
    if rows:
        db.add(Event(session_id=session_id, ts=_now(), actor="system",
                     action_type="match_finalize_blocked",
                     payload={"reason": reason, "stage": "operations",
                              "operations": [{"op_id": r.op_id, "state": r.state}
                                             for r in rows][:10]}))
        db.flush()
        raise MatchBlocked("unresolved_operations",
                           [r.state for r in rows])

    # 3. final evidence (scorecard + trusted red reconstruction)
    try:
        scorecard = verification_service.build_scorecard(db, session_id)
    except Exception as e:  # noqa: BLE001 — unscored is visible, never fatal
        db.add(Event(session_id=session_id, ts=_now(), actor="system",
                     action_type="score_unavailable", payload={"error": str(e)[:500]}))
        scorecard = {"status": "unscored", "error": str(e)[:300]}
    red_complete = False
    try:
        spec = verification_service.scenario_spec(db, session_id)
        objective_ids = {o["id"] for o in spec.get("red", {}).get("objectives", [])}
        passed = set()
        for ev in db.execute(select(Event).where(
                Event.session_id == session_id,
                Event.action_type == "verifier")).scalars():
            pl = ev.payload or {}
            if pl.get("passed") and pl.get("objective"):
                passed.add(pl["objective"])
        red_complete = bool(objective_ids) and objective_ids.issubset(passed)
    except Exception:  # noqa: BLE001 — spec unreadable => cannot claim complete
        red_complete = False

    # 4. session terminal state + end evidence
    if sess.status != "complete":
        sess.status = "complete"
        sess.outcome = "red_complete" if red_complete else "incomplete"
        sess.ended_at = sess.finalized_at = _now()
    db.add(Event(session_id=session_id, ts=_now(), actor="system",
                 action_type="session_end",
                 payload={"score_status": scorecard.get("status"),
                          "earned": scorecard.get("earned"),
                          "total": scorecard.get("total"),
                          "red_verified_complete": red_complete,
                          "end_reason": reason,
                          "ended_by": username or actor}))

    # 5. revoke capabilities (tokens die with the match)
    for lt in db.execute(select(LoginToken).where(
            LoginToken.session_id == session_id,
            LoginToken.revoked_at.is_(None))).scalars():
        lt.revoked_at = _now()
    for st in db.execute(select(ServiceToken).where(
            ServiceToken.session_id == session_id,
            ServiceToken.revoked_at.is_(None))).scalars():
        st.revoked_at = _now()

    # 6. DESTROY owned VMs; release the lease ONLY on a complete teardown
    #    (audit R07: a machine that still exists keeps its address reserved).
    t = orchestrator.teardown(db, session_id, sess.scenario_id, broker)
    complete = bool(t.get("complete", True))
    if complete:
        orchestrator.release_lease(db, session_id)
    else:
        db.add(Event(session_id=session_id, ts=_now(), actor="system",
                     action_type="teardown_incomplete",
                     payload={"reason": reason, "detail": t,
                              "note": "range reservation RETAINED — recovery "
                                      "required; scheduler retries"}))
    if m is not None:
        m.ended_at = _now()
        m.state = "completed" if complete else "interrupted"
        m.expiry_reason = reason
        db.add(Event(session_id=session_id, ts=_now(), actor="system",
                     action_type="match_end",
                     payload={"reason": reason, "complete": complete,
                              "lease_released": complete}))
    db.flush()
    return {"ok": complete, "status": "complete",
            "outcome": sess.outcome,
            "scorecard_status": scorecard.get("status"),
            "earned": scorecard.get("earned"), "total": scorecard.get("total"),
            "uptime": _uptime.live_projection(db, session_id),
            "lease_released": complete,
            "end_reason": reason,
            "note": ("owned VMs destroyed, lease released" if complete
                     else "teardown INCOMPLETE — lease retained, recovery required"),
            "teardown": t}


# ------------------------------------------------------------------ scheduler --
def tick(db, *, broker, now: datetime | None = None) -> list[dict]:
    """One scheduler pass: expire idle-ready labs, end matches whose deadline
    passed, retry interrupted cleanup. Each match is independent and claim-
    serialized against concurrent API requests; results are returned for
    logging. Never raises for a single match — blocked cleanup is reported
    and retried next tick."""
    from srplatform.scenario_engine import orchestrator
    now = now or _now()
    results: list[dict] = []
    due = db.execute(select(MatchModel).where(
        (MatchModel.state == "ready")
        & (MatchModel.ready_at < now - timedelta(minutes=READY_IDLE_EXPIRY_MINUTES))
    )).scalars().all()
    due += db.execute(select(MatchModel).where(
        (MatchModel.state == "running") & (MatchModel.deadline_at <= now)
    )).scalars().all()
    due += db.execute(select(MatchModel).where(
        MatchModel.state.in_(("interrupted", "finalizing"))
    )).scalars().all()
    for m in due:
        sid = m.session_id
        reason = ("idle_expiry" if m.state == "ready"
                  else "deadline" if m.state == "running"
                  else m.expiry_reason or "recovery_retry")
        # DEFENSE IN DEPTH: never expire a "ready" lab that has a live worker
        # (a Begin//run in flight owns it — the clock, not idle expiry, ends it)
        if m.state == "ready":
            from srplatform.api import runs as _runs
            if _runs.active_run_for_session(db, sid) is not None:
                continue
        try:
            claim_owner = orchestrator.claim_operation(db, sid, "match-expire")
        except orchestrator.OperationInProgress:
            continue  # a live request owns this session right now
        ok = False
        try:
            db.expire_all()
            out = finalize_match(db, sid, reason, broker=broker,
                                 actor="match-scheduler")
            db.commit()
            ok = True
            results.append({"session_id": str(sid), "reason": reason, **out})
        except MatchBlocked as b:
            db.rollback()
            results.append({"session_id": str(sid), "reason": reason,
                            "blocked": b.reason})
        except Exception as e:  # noqa: BLE001 — one bad match never kills the tick
            db.rollback()
            results.append({"session_id": str(sid), "reason": reason,
                            "error": str(e)[:200]})
        finally:
            try:
                if ok:
                    orchestrator.release_operation(db, sid, claim_owner)
                    db.commit()
                else:
                    from srplatform.db.session import db as db_ctx
                    with db_ctx() as s2:
                        orchestrator.release_operation(s2, sid, claim_owner)
            except Exception:  # noqa: BLE001 — stale-claim window recovers
                pass
    return results


def reconcile_on_startup(db, *, broker) -> list[dict]:
    """API restart: matches that were RUNNING are INTERRUPTED — never
    silently resumed. Their workers died with the API (children of this
    process); runs_svc.reconcile_on_startup has already taken each run
    through its terminal protocol. Cleanup then runs through the same
    durable finalize path: unresolved cessation keeps the lease and stays
    visible. 'finalizing'/'interrupted' matches from before the crash get
    their cleanup retried. Ready/provisioning matches are untouched (their
    idle timer keeps running)."""
    from srplatform.scenario_engine import orchestrator
    results: list[dict] = []
    rows = db.execute(select(MatchModel).where(
        MatchModel.state.in_(("running", "finalizing", "interrupted"))
    )).scalars().all()
    for m in rows:
        sid = m.session_id
        reason = "api_restart" if m.state == "running" else (m.expiry_reason or "recovery_retry")
        try:
            out = finalize_match(db, sid, reason, broker=broker,
                                 actor="startup-reconcile")
            results.append({"session_id": str(sid), "reason": reason, **out})
        except MatchBlocked as b:
            # the 'finalizing' intent is already durable (own transaction);
            # startup must not crash — the scheduler retries the cleanup
            results.append({"session_id": str(sid), "reason": reason,
                            "blocked": b.reason})
    db.commit()
    return results


# -------------------------------------------------------------------- thread --
_thread: threading.Thread | None = None


def start_scheduler(interval_s: int = 15) -> threading.Thread | None:
    """Background scheduler for the control plane (opt-in:
    SR_MATCH_SCHEDULER_ENABLED=1). Ticks `tick()` every interval; all errors
    are contained — the API keeps serving even if the DB hiccups."""
    global _thread
    if _thread is not None and _thread.is_alive():
        return _thread

    def loop():
        from srplatform.db.session import db as db_ctx
        while True:
            time.sleep(interval_s)
            try:
                from srplatform.api.deps import get_broker
                broker = get_broker()
            except Exception:  # noqa: BLE001 — unconfigured broker: retry tick
                continue
            try:
                with db_ctx() as s:
                    tick(s, broker=broker)
            except Exception:  # noqa: BLE001 — never kill the thread
                continue

    _thread = threading.Thread(target=loop, daemon=True, name="match-scheduler")
    _thread.start()
    return _thread
