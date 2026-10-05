"""FastAPI app — THE single front door (Part 3). rangectl and the web app are
clients of this service; nothing else touches Postgres.

Remediation highlights (F04/F08/F11/F13):
  * Every mutating route requires an authenticated principal; the acting
    member comes from the credential, never from a request body.
  * Event ingest is PRODUCER-SCOPED: members get their own blue actor and
    their own sessions; bastion/telemetry/runner capabilities may append only
    their narrow event kinds. Verifier/scorecard/session/agent events are
    appended exclusively by backend code paths — there is NO client route
    that can forge evidence.
  * Sessions have a durable lifecycle (preparing→ready→running→...→complete)
    driven by idempotent backend workflows shared by CLI and browser.
  * The arbitrary-PID registration endpoint is gone; safety is operator-only.
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from srplatform.api import runs as runs_svc
from srplatform.api.auth import (Principal, hash_password, issue_user_token,
                                 make_auth_dependencies, require_session_access,
                                 revoke_token, verify_password)
from srplatform.db.models import (AgentState, Deployment, Event, LoginToken,
                                  Recording, Run, ServiceToken, Session as SessionModel,
                                  User, WebToken)
from srplatform.db.session import db
from srplatform.safety import get_supervisor

app = FastAPI(title="sparring-range API", version="0.2.0")

# LAN origins are EXPLICIT (F23) — never wildcard, never silently localhost.
from srplatform.settings import get_settings  # noqa: E402

_s = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=[o.strip() for o in _s.api_allowed_origins.split(",") if o.strip()],
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    with db() as s:
        yield s


principal, any_member, operator, service = make_auth_dependencies(get_db)

# M5 coach routes + M7 web routes (auth-wired there as well)
from srplatform.api.coach_routes import router as coach_router  # noqa: E402
from srplatform.api.web_routes import router as web_router      # noqa: E402

app.include_router(coach_router)
app.include_router(web_router)


# --- health: liveness vs readiness (F23) -------------------------------------
@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/readyz")
def readyz():
    import os

    from alembic.script import ScriptDirectory
    from alembic.config import Config

    from srplatform.settings import get_settings as _gs
    issues = []
    v = None
    try:
        with db() as s:
            v = s.execute(text("SELECT version_num FROM alembic_version LIMIT 1")).scalar()
        cfg = Config("alembic.ini")
        head = ScriptDirectory.from_config(cfg).get_current_head()
        if v and head and v != head:
            issues.append(f"schema {v} behind head {head}")
    except Exception as e:  # noqa: BLE001
        issues.append(f"db: {e}")
    s = _gs()
    runner_ok, runner_why = get_supervisor().runner_available()
    rec_dir = s.recordings_dir
    rec_ok = os.access(rec_dir, os.W_OK) if os.path.isdir(rec_dir) else False
    return {"ready": v is not None and not issues,
            "migration_version": v, "issues": issues,
            "runner": {"ok": runner_ok, "detail": runner_why},
            "recordings_writable": rec_ok,
            "safety": get_supervisor().verify()}


# --- auth (F04) ----------------------------------------------------------------
class BootstrapIn(BaseModel):
    username: str
    password: str = Field(min_length=10)


@app.post("/auth/bootstrap", status_code=201)
def bootstrap(body: BootstrapIn, db: Session = Depends(get_db)):
    """One-time operator self-provisioning — ONLY while no account holds a
    password. After that, users are created by the operator."""
    has_any = db.execute(select(User).where(User.password_hash.isnot(None))).scalars().first()
    if has_any:
        raise HTTPException(403, "bootstrap closed — accounts already provisioned")
    if body.username != get_settings().bootstrap_operator_username:
        raise HTTPException(403, "only the configured bootstrap operator may bootstrap")
    u = db.execute(select(User).where(User.username == body.username)).scalar_one_or_none()
    if u is None:
        u = User(username=body.username, role="operator", password_hash=hash_password(body.password))
        db.add(u)
    else:
        u.role, u.password_hash = "operator", hash_password(body.password)
    db.flush()
    return {"user_id": str(u.user_id), "role": u.role}


class LoginIn(BaseModel):
    username: str
    password: str


@app.post("/auth/login")
def login(body: LoginIn, db: Session = Depends(get_db)):
    u = db.execute(select(User).where(User.username == body.username)).scalar_one_or_none()
    if not u or not verify_password(body.password, u.password_hash):
        raise HTTPException(401, "invalid credentials")
    tok = issue_user_token(db, u, get_settings().web_token_ttl_hours)
    return {"token": tok, "user_id": str(u.user_id), "username": u.username,
            "role": u.role,
            "expires_in_h": get_settings().web_token_ttl_hours}


@app.post("/auth/logout")
def logout(p: Principal = Depends(principal),
           authorization: str | None = Header(default=None),
           x_token: str | None = Header(default=None),
           db: Session = Depends(get_db)):
    from srplatform.api.auth import extract_token
    revoke_token(db, extract_token(authorization, x_token))
    return {"ok": True}


@app.get("/users/me")
def whoami(p: Principal = Depends(any_member)):
    return {"user_id": str(p.user_id), "username": p.username, "role": p.kind}


class UserIn(BaseModel):
    username: str
    password: str = Field(min_length=10)
    display_name: str | None = None
    role: str = "member"


@app.post("/users", status_code=201)
def create_user(body: UserIn, p: Principal = Depends(operator), db: Session = Depends(get_db)):
    """Member accounts are created by the operator WITH a password (F04:
    username knowledge is not authentication)."""
    if db.execute(select(User).where(User.username == body.username)).scalar_one_or_none():
        raise HTTPException(409, "exists")
    u = User(username=body.username, display_name=body.display_name, role=body.role,
             password_hash=hash_password(body.password))
    db.add(u)
    db.flush()
    return {"user_id": str(u.user_id), "username": u.username, "role": u.role}


# --- sessions: create with scenario snapshot (F19) -----------------------------
class SessionCreate(BaseModel):
    scenario_id: str
    players: dict | None = None


def _scenario_snapshot(scenario_id: str) -> tuple[str, str]:
    from srplatform.scenario_engine.loader import scenarios_dir
    p = scenarios_dir() / f"{scenario_id}.yaml"
    if p.exists():
        raw = p.read_bytes()
        return hashlib.sha256(raw).hexdigest(), raw.decode(errors="replace")
    return "missing", ""


@app.post("/sessions", status_code=201)
def create_session(body: SessionCreate, p: Principal = Depends(any_member),
                   db: Session = Depends(get_db)):
    from srplatform.scenario_engine.loader import load_scenario
    load_scenario(body.scenario_id)  # validated before anything is stored
    sha, raw = _scenario_snapshot(body.scenario_id)
    sess = SessionModel(scenario_id=body.scenario_id, user_id=p.user_id, players=body.players,
                        status="preparing")
    db.add(sess)
    db.flush()
    db.add(Event(session_id=sess.session_id, ts=_now(), actor="system",
                 action_type="session_start",
                 payload={"scenario_id": body.scenario_id,
                          "scenario_sha256": sha,
                          "scenario_yaml": raw or None,
                          "created_by": p.username}))
    db.flush()
    return {"session_id": str(sess.session_id), "status": sess.status,
            "scenario_sha256": sha}


@app.get("/sessions")
def list_sessions(mine: bool = Query(True), p: Principal = Depends(any_member),
                  db: Session = Depends(get_db)):
    q = select(SessionModel).order_by(SessionModel.started_at, SessionModel.session_id)
    if mine or not p.is_operator:
        q = q.where(SessionModel.user_id == p.user_id)
    rows = db.execute(q).scalars().all()
    return [{"session_id": str(r.session_id), "scenario_id": r.scenario_id,
             "user_id": str(r.user_id) if r.user_id else None,
             "started_at": r.started_at.isoformat() if r.started_at else None,
             "ended_at": r.ended_at.isoformat() if r.ended_at else None,
             "status": r.status, "outcome": r.outcome} for r in rows]


def _get_session(db, p, session_id) -> SessionModel:
    sess = db.get(SessionModel, session_id)
    if not sess:
        raise HTTPException(404, "session not found")
    require_session_access(db, p, sess)
    return sess


@app.get("/sessions/{session_id}")
def get_session(session_id: uuid.UUID, p: Principal = Depends(any_member),
                db: Session = Depends(get_db)):
    sess = _get_session(db, p, session_id)
    dep = db.execute(select(Deployment).where(Deployment.session_id == session_id)
                     .order_by(Deployment.created_at.desc())).scalars().first()
    active = runs_svc.active_run_for_session(db, session_id)
    return {"session_id": str(sess.session_id), "scenario_id": sess.scenario_id,
            "status": sess.status, "outcome": sess.outcome,
            "started_at": sess.started_at.isoformat() if sess.started_at else None,
            "deployment_status": dep.status if dep else None,
            "active_run": str(active.run_id) if active else None}


# --- launch / end / reset / teardown (F08/F13) ----------------------------------
# ONE lifecycle policy for every entrypoint (audit N03):
#   * every mutating operation takes a DURABLE per-session operation claim
#     (survives the intent commits that release row locks — audit N02);
#   * teardown/reset stop and CONFIRM the worker before releasing machines
#     and the lease, or return a conflict;
#   * terminal sessions are refused except through the documented
#     reset/relaunch transitions;
#   * capabilities are revoked when their machines die.
def _now():
    return datetime.now(timezone.utc)


def _revoke_session_capabilities(db, session_id, reason: str) -> int:
    n = 0
    t = _now()
    for lt in db.execute(select(LoginToken).where(LoginToken.session_id == session_id,
                                                  LoginToken.revoked_at.is_(None))).scalars():
        lt.revoked_at = t
        n += 1
    for st in db.execute(select(ServiceToken).where(ServiceToken.session_id == session_id,
                                                    ServiceToken.revoked_at.is_(None))).scalars():
        st.revoked_at = t
        n += 1
    if n:
        db.add(Event(session_id=session_id, ts=t, actor="system",
                     action_type="capabilities_revoked",
                     payload={"count": n, "reason": reason}))
    return n


def _stop_active_run_or_conflict(db, sess):
    """Teardown/reset precondition (audit N03): the worker must be stopped and
    CONFIRMED dead before its machines/lease are released. A failed stop is a
    conflict, never a silent continue."""
    active = runs_svc.active_run_for_session(db, sess.session_id)
    if not active:
        return
    stopped = runs_svc.stop_run(db, active.run_id)
    if not stopped.get("ok"):
        raise HTTPException(409, {"error": "worker_stop_failed",
                                  "run_id": str(active.run_id),
                                  "detail": stopped.get("detail"),
                                  "note": "range NOT torn down; retry or engage killswitch"})


def _release_claim_safely(db, session_id, succeeded: bool) -> None:
    """Release the durable operation claim WITHOUT ever rolling back the
    request's own successful writes (the request transaction commits after
    the route returns).

    On SUCCESS the claim delete rides the request transaction — atomic and
    race-free. On FAILURE the transaction is discarded by the request
    handler anyway, so the claim is removed through a SEPARATE session:
    committing through the failed transaction would CLOBBER the durable
    failure evidence the orchestrator just stored (audit N02 item 7), and a
    crash before this point is recovered by startup reconciliation / the
    stale-claim window."""
    from srplatform.scenario_engine import orchestrator
    try:
        if succeeded:
            orchestrator.release_operation(db, session_id)
        else:
            from srplatform.db.session import db as db_ctx
            with db_ctx() as s2:
                orchestrator.release_operation(s2, session_id)
    except Exception:  # noqa: BLE001 — recovery is startup/stale-window anyway
        pass


@app.post("/sessions/{session_id}/launch")
def launch_session(session_id: uuid.UUID, p: Principal = Depends(any_member),
                   db: Session = Depends(get_db)):
    """Shared backend workflow for CLI and browser:
    authenticate → claim → reserve (lease) → validate → deploy → issue per-host
    connection capabilities → ready."""
    from srplatform.scenario_engine import orchestrator
    from srplatform.api.deps import get_proxmox

    sess = db.get(SessionModel, session_id)
    if sess is None:
        raise HTTPException(404, "session not found")
    require_session_access(db, p, sess)
    if sess.status in ("complete", "failed"):
        raise HTTPException(409, f"session is {sess.status}")
    # DURABLE OPERATION CLAIM (audit N02): replaces the row lock that the
    # lease/deploy commits used to surrender — two simultaneous launches can
    # no longer both pass the lease check.
    try:
        orchestrator.claim_operation(db, sess.session_id, "launch")
    except orchestrator.OperationInProgress as e:
        raise HTTPException(409, {"error": "operation_in_progress", "operation": e.operation})
    _ok = False
    try:
        try:
            orchestrator.acquire_lease(db, sess.session_id)
        except orchestrator.LeaseConflict as e:
            raise HTTPException(409, {"error": "range_busy", "holder_session": e.holder_session_id,
                                      "acquired_at": e.acquired_at})
        try:
            result = orchestrator.deploy(db, sess.session_id, sess.scenario_id, get_proxmox())
        except orchestrator.ForeignResourceError as e:
            raise HTTPException(409, {"error": "foreign_resource", "detail": str(e)[:500]})

        # member-specific host connection capabilities (F08)
        s = get_settings()
        instructions = []
        for r in result["hosts"]:
            tok = f"tok-{r['host']}-{uuid.uuid4().hex[:6]}"
            db.add(LoginToken(token=tok, session_id=sess.session_id, user_id=p.user_id,
                              target_host=r["ip"], target_port=22,
                              expires_at=_now() + timedelta(hours=s.web_token_ttl_hours)))
            instructions.append({"host": r["host"], "ip": r["ip"], "login_token": tok,
                                 "ssh": f"ssh {s.bastion_address} -p {s.bastion_listen_port} -l {tok}"})
        sess.status = "ready"
        db.add(Event(session_id=sess.session_id, ts=_now(), actor="system",
                     action_type="session_ready",
                     payload={"hosts": [i["host"] for i in instructions]}))
        db.flush()
        _ok = True
        return {"session_id": str(sess.session_id), "status": sess.status,
                "deployment": result, "connections": instructions}
    finally:
        _release_claim_safely(db, sess.session_id, _ok)


@app.post("/sessions/{session_id}/end")
def end_session(session_id: uuid.UUID, p: Principal = Depends(any_member),
                db: Session = Depends(get_db)):
    """Idempotent finalize (F11/F13): stop worker, collect TRUSTED final score,
    append snapshot + end evidence, revoke session capabilities. The lease is
    released ONLY when no owned machine remains (audit R07): VMs are retained
    unless teardown is explicitly requested, and while they hold the range's
    static addresses the reservation must stay with this session."""
    from srplatform import verification_service
    from srplatform.scenario_engine import orchestrator

    sess = _get_session(db, p, session_id)
    if sess.status == "complete":
        return {"ok": True, "status": "complete", "note": "already ended (idempotent)",
                "outcome": sess.outcome}
    try:
        orchestrator.claim_operation(db, sess.session_id, "end")
    except orchestrator.OperationInProgress as e:
        raise HTTPException(409, {"error": "operation_in_progress", "operation": e.operation})
    _ok = False
    try:
        out = _end_session_inner(db, sess, p, verification_service, orchestrator)
        _ok = True
        return out
    finally:
        _release_claim_safely(db, sess.session_id, _ok)


def _end_session_inner(db, sess, p, verification_service, orchestrator):
    active = runs_svc.active_run_for_session(db, sess.session_id)
    if active:
        stopped = runs_svc.stop_run(db, active.run_id)
        if not stopped.get("ok"):
            # cancellation FAILED — do not finalize as safely stopped (R07)
            raise HTTPException(409, {"error": "worker_stop_failed",
                                      "detail": stopped.get("detail"),
                                      "note": "session NOT ended; retry or engage killswitch"})

    try:
        scorecard = verification_service.build_scorecard(db, sess.session_id)
    except Exception as e:  # noqa: BLE001 — scoring unavailable is visible, never fatal
        db.add(Event(session_id=sess.session_id, ts=_now(), actor="system",
                     action_type="score_unavailable", payload={"error": str(e)[:500]}))
        scorecard = {"status": "unscored", "error": str(e)[:300]}

    # red_verified_complete is RECONSTRUCTED from trusted verifier events —
    # every objective of the session's snapshot must have a passed verifier
    # result. The worker's self-reported `complete` flag is never trusted (R07).
    red_complete = False
    try:
        spec = verification_service.scenario_spec(db, sess.session_id)
        objective_ids = {o["id"] for o in spec.get("red", {}).get("objectives", [])}
        passed = set()
        for ev in db.execute(select(Event).where(
                Event.session_id == sess.session_id,
                Event.action_type == "verifier")).scalars():
            pl = ev.payload or {}
            if pl.get("passed") and pl.get("objective"):
                passed.add(pl["objective"])
        red_complete = bool(objective_ids) and objective_ids.issubset(passed)
    except Exception:  # noqa: BLE001 — spec unreadable => cannot claim complete
        red_complete = False

    sess.status = "complete"
    sess.outcome = "red_complete" if red_complete else "incomplete"
    sess.ended_at = sess.finalized_at = _now()
    db.add(Event(session_id=sess.session_id, ts=_now(), actor="system",
                 action_type="session_end",
                 payload={"score_status": scorecard.get("status"),
                          "earned": scorecard.get("earned"), "total": scorecard.get("total"),
                          "red_verified_complete": red_complete,
                          "ended_by": p.username}))

    # revoke session capabilities (F04/F08)
    for lt in db.execute(select(LoginToken).where(LoginToken.session_id == sess.session_id,
                                                  LoginToken.revoked_at.is_(None))).scalars():
        lt.revoked_at = _now()
    for st in db.execute(select(ServiceToken).where(ServiceToken.session_id == sess.session_id,
                                                    ServiceToken.revoked_at.is_(None))).scalars():
        st.revoked_at = _now()

    # release the reservation ONLY when nothing owned remains (audit R07):
    # retained VMs keep the range reserved so the next launch cannot collide
    # with their static addresses.
    residual = orchestrator._residual_resources(db, sess.session_id)
    if residual:
        note = (f"{len(residual)} owned machine(s) still exist — range reservation "
                "RETAINED until teardown removes them")
    else:
        orchestrator.release_lease(db, sess.session_id)
        note = "lease released (no residual resources)"
    # COMMIT the finalize (status/outcome/evidence/revocations): the claim
    # release in the route's finally must never roll this back, and durable
    # end evidence must survive independently of the request transaction.
    db.commit()
    return {"ok": True, "status": sess.status, "outcome": sess.outcome,
            "scorecard_status": scorecard.get("status"),
            "earned": scorecard.get("earned"), "total": scorecard.get("total"),
            "lease_released": not residual, "note": note}


@app.post("/sessions/{session_id}/score")
def score_session(session_id: uuid.UUID, p: Principal = Depends(any_member),
                  db: Session = Depends(get_db)):
    """Trusted scoring endpoint (F11): the BACKEND runs the verifiers; CLI and
    browser are both plain HTTP callers."""
    from srplatform import verification_service
    sess = _get_session(db, p, session_id)
    try:
        card = verification_service.build_scorecard(db, sess.session_id)
    except Exception as e:  # noqa: BLE001
        return JSONResponse(status_code=503, content={"status": "unscored",
                                                      "error": str(e)[:300]})
    return card


@app.get("/sessions/{session_id}/score")
def get_score(session_id: uuid.UUID, p: Principal = Depends(any_member),
              db: Session = Depends(get_db)):
    from srplatform import verification_service
    sess = _get_session(db, p, session_id)
    card = verification_service.latest_scorecard(db, sess.session_id)
    if card is None:
        return {"status": "unscored"}
    return card


def _teardown_common(db, sess, p):
    from srplatform.scenario_engine import orchestrator
    from srplatform.api.deps import get_proxmox
    # WORKER FIRST (audit N03): machines and the lease are released only after
    # the session's worker is confirmed stopped — otherwise a later session
    # could acquire the same static addresses while the old worker still
    # operates against them.
    _stop_active_run_or_conflict(db, sess)
    t = orchestrator.teardown(db, sess.session_id, sess.scenario_id, get_proxmox())
    # capabilities die with their machines (audit N03 lifecycle policy)
    _revoke_session_capabilities(db, sess.session_id, "teardown")
    # release the reservation ONLY on a COMPLETE teardown (audit R07): failed
    # destroys keep the range reserved so the addresses cannot be reused while
    # the machines still exist.
    if t.get("complete", True):
        orchestrator.release_lease(db, sess.session_id)
        if sess.status in ("ready", "running", "preparing"):
            # documented terminal transition: torn-down sessions must go
            # through launch (a fresh deploy) before they can run again
            sess.status = "torn_down"
    db.flush()
    return t


@app.post("/sessions/{session_id}/teardown")
def teardown_session(session_id: uuid.UUID, p: Principal = Depends(any_member),
                     db: Session = Depends(get_db)):
    from srplatform.scenario_engine import orchestrator
    sess = _get_session(db, p, session_id)
    try:
        orchestrator.claim_operation(db, sess.session_id, "teardown")
    except orchestrator.OperationInProgress as e:
        raise HTTPException(409, {"error": "operation_in_progress", "operation": e.operation})
    _ok = False
    try:
        out = _teardown_common(db, sess, p)
        _ok = True
        return out
    finally:
        _release_claim_safely(db, sess.session_id, _ok)


@app.post("/sessions/{session_id}/reset")
def reset_session(session_id: uuid.UUID, p: Principal = Depends(any_member),
                  db: Session = Depends(get_db)):
    from srplatform.scenario_engine import orchestrator
    from srplatform.api.deps import get_proxmox
    sess = _get_session(db, p, session_id)
    try:
        orchestrator.claim_operation(db, sess.session_id, "reset")
    except orchestrator.OperationInProgress as e:
        raise HTTPException(409, {"error": "operation_in_progress", "operation": e.operation})
    _ok = False
    try:
        # stop the worker BEFORE anything is destroyed (audit N03)
        _stop_active_run_or_conflict(db, sess)
        # old machines are about to die — their capabilities must die first
        _revoke_session_capabilities(db, sess.session_id, "reset")
        try:
            # orchestrator.reset ACQUIRES/VERIFIES the global lease first (R07)
            out = orchestrator.reset(db, sess.session_id, sess.scenario_id, get_proxmox())
            _ok = True
            return out
        except orchestrator.LeaseConflict as e:
            raise HTTPException(409, {"error": "range_busy", "holder_session": e.holder_session_id})
        except RuntimeError as e:
            raise HTTPException(409, str(e))
    finally:
        _release_claim_safely(db, sess.session_id, _ok)


# --- deploy (legacy wrapper — SAME invariants as /launch, audit N03) -------------
class DeployIn(BaseModel):
    session_id: uuid.UUID


@app.post("/deploy/{scenario_id}")
def deploy_scenario(scenario_id: str, body: DeployIn, p: Principal = Depends(any_member),
                    db: Session = Depends(get_db)):
    from srplatform.scenario_engine import orchestrator
    from srplatform.api.deps import get_proxmox
    sess = _get_session(db, p, body.session_id)
    # the legacy route must not become a side door: URL scenario == session
    # scenario, no deployment under a terminal session, same claim/lease
    # serialization as /launch.
    if scenario_id != sess.scenario_id:
        raise HTTPException(422, f"session runs scenario '{sess.scenario_id}' — "
                                 f"refusing to deploy '{scenario_id}' under it")
    if sess.status in ("complete", "failed", "torn_down"):
        raise HTTPException(409, f"session is {sess.status} — use the documented "
                                 "reset/relaunch transitions, not raw deploy")
    try:
        orchestrator.claim_operation(db, sess.session_id, "deploy")
    except orchestrator.OperationInProgress as e:
        raise HTTPException(409, {"error": "operation_in_progress", "operation": e.operation})
    _ok = False
    try:
        try:
            orchestrator.acquire_lease(db, sess.session_id)
        except orchestrator.LeaseConflict as e:
            raise HTTPException(409, {"error": "range_busy", "holder_session": e.holder_session_id})
        out = orchestrator.deploy(db, sess.session_id, scenario_id, get_proxmox())
        _ok = True
        return out
    finally:
        _release_claim_safely(db, sess.session_id, _ok)


@app.get("/scenarios")
def scenarios_list():
    from srplatform.scenario_engine.loader import list_scenarios
    return list_scenarios()


# --- run (M3) — validated, supervised, single-active ----------------------------
class RunIn(BaseModel):
    session_id: uuid.UUID


@app.post("/run/{scenario_id}", status_code=202)
def run_scenario(scenario_id: str, body: RunIn, p: Principal = Depends(any_member),
                 db: Session = Depends(get_db)):
    from srplatform.scenario_engine import orchestrator
    sess = _get_session(db, p, body.session_id)
    if sess.scenario_id != scenario_id:
        raise HTTPException(422, f"session runs scenario '{sess.scenario_id}'")
    if sess.status not in ("ready", "running"):
        raise HTTPException(409, f"session is {sess.status} — launch it first")
    # DEPLOYMENT/RESERVATION checks come BEFORE the safety gate so clients see
    # the actionable 409 ("not launched / no reservation") rather than a
    # confusing 423 that mixes in dev-mode evidence relaxations (audit N03).
    lease = orchestrator.current_lease(db)
    if not lease or lease["session_id"] != str(sess.session_id):
        raise HTTPException(409, {"error": "no_current_reservation",
                                  "note": "the range lease is not held by this session — "
                                          "launch it again before starting a run"})
    dep = db.execute(select(Deployment).where(Deployment.session_id == sess.session_id,
                                              Deployment.scenario_id == sess.scenario_id,
                                              Deployment.status == "ready")
                     .order_by(Deployment.created_at.desc())).scalars().first()
    if dep is None:
        raise HTTPException(409, {"error": "no_ready_deployment",
                                  "note": "no ready owned deployment for this session — "
                                          "launch it first"})
    try:
        run = runs_svc.start_run(db, sess.session_id, scenario_id)
    except runs_svc.GateRefused as e:
        raise HTTPException(423, {"error": "safety_gate", "reasons": e.reasons})
    except runs_svc.RunConflict as e:
        raise HTTPException(409, str(e))
    sess.status = "running"
    db.flush()
    return {"ok": True, "run_id": str(run.run_id), "status": run.status,
            "session_id": str(body.session_id)}


@app.get("/runs/{run_id}")
def get_run(run_id: uuid.UUID, p: Principal = Depends(any_member), db: Session = Depends(get_db)):
    run = db.get(Run, run_id)
    if run is None:
        raise HTTPException(404, "run not found")
    _get_session(db, p, run.session_id)
    return {"run_id": str(run.run_id), "status": run.status, "outcome": run.outcome,
            "started_at": run.started_at.isoformat() if run.started_at else None,
            "ended_at": run.ended_at.isoformat() if run.ended_at else None,
            "result": run.result, "error": run.error}


@app.post("/runs/{run_id}/stop")
def stop_run(run_id: uuid.UUID, p: Principal = Depends(any_member), db: Session = Depends(get_db)):
    run = db.get(Run, run_id)
    if run is None:
        raise HTTPException(404, "run not found")
    _get_session(db, p, run.session_id)
    return runs_svc.stop_run(db, run_id)


@app.post("/internal/runs/{run_id}/complete")
def run_complete(run_id: uuid.UUID, result: dict,
                 x_worker_token: str | None = Header(default=None),
                 db: Session = Depends(get_db)):
    """Worker callback — authenticated by the one-shot run capability. A
    terminal run's state is FINAL: a late callback gets 409, never a rewrite."""
    try:
        run = runs_svc.complete_run(db, str(run_id), x_worker_token or "", result)
    except PermissionError:
        raise HTTPException(403, "bad worker token")
    except KeyError:
        raise HTTPException(404, "run not found")
    except runs_svc.RunStateError as e:
        raise HTTPException(409, str(e))
    return {"ok": True, "status": run.status}


# --- trusted verification (backend executes; request is not a result) ----------
class VerifierCheckIn(BaseModel):
    objective_id: str


@app.post("/sessions/{session_id}/verifier_checks")
def verifier_check(session_id: uuid.UUID, body: VerifierCheckIn,
                   p: Principal = Depends(principal), db: Session = Depends(get_db)):
    """Allowed: session owner, operator, or the run-scoped runner token bound
    to THIS session. The backend runs the verifier and appends the evidence —
    the caller can request a check, never supply an outcome (F04)."""
    from srplatform import verification_service
    if p.kind == "service":
        if p.scope != "runner" or str(p.session_id) != str(session_id):
            raise HTTPException(403, "runner token does not match this session")
    else:
        _get_session(db, p, session_id)
    try:
        return verification_service.check_objective(db, session_id, body.objective_id)
    except ValueError:
        raise HTTPException(404, "session not found")


# --- event ingest (append-only; PRODUCER-SCOPED — F04) ---------------------------
MEMBER_KINDS = {"blue_command", "remediation", "note"}
BASTION_KINDS = {"bastion_session_start", "bastion_session_end", "command"}
TELEMETRY_KINDS = {"command", "detection"}
RUNNER_KINDS = {"action_intent", "action_result", "agent_note"}
FORBIDDEN_KINDS = {"verifier", "score_snapshot", "scorecard", "session_start", "session_end",
                   "session_ready", "aar", "hint", "score_unavailable"}


class EventIn(BaseModel):
    session_id: uuid.UUID | None = None
    ts: datetime | None = None
    action_type: str
    payload: dict
    phase: str | None = None
    mitre_technique: str | None = None
    raw_ref: str | None = None
    raw_output_hash: str | None = None
    host: str | None = None


@app.post("/events", status_code=201)
def ingest_event(body: EventIn, p: Principal = Depends(principal),
                 db: Session = Depends(get_db)):
    """Server assigns actor + session association from the credential; the
    body carries content only. Verifier/score/system kinds are not accepted
    from ANY client — backend code appends those itself."""
    if body.action_type in FORBIDDEN_KINDS:
        raise HTTPException(422, f"event kind '{body.action_type}' is backend-only")

    if p.kind in ("member", "operator"):
        allowed = MEMBER_KINDS
        actor = f"blue:{p.username}"
        session_id = body.session_id
        if session_id is not None:
            sess = db.get(SessionModel, session_id)
            if sess is None or (not p.is_operator and str(sess.user_id) != str(p.user_id)):
                raise HTTPException(403, "not your session")
    elif p.scope == "bastion":
        allowed = BASTION_KINDS
        actor = f"blue:{p.username or 'bastion'}"
        session_id = p.session_id or body.session_id  # global bastion passes resolved session
    elif p.scope == "telemetry":
        allowed = TELEMETRY_KINDS
        actor, session_id = "telemetry", p.session_id
        if body.host not in (None, p.host):
            raise HTTPException(403, f"telemetry token is bound to host '{p.host}'")
    elif p.scope == "runner":
        allowed = RUNNER_KINDS
        actor, session_id = "red", p.session_id
    else:
        raise HTTPException(403, "capability cannot ingest events")

    if body.action_type not in allowed:
        raise HTTPException(422, f"kind '{body.action_type}' not allowed for this capability")
    if session_id is None and p.kind != "operator" and body.session_id and p.kind in ("member",):
        session_id = body.session_id

    ev = _log_event(db, session_id, actor, body.host, body.action_type, body.payload,
                    phase=body.phase, mitre_technique=body.mitre_technique,
                    raw_ref=body.raw_ref, raw_output_hash=body.raw_output_hash, ts=body.ts)
    return {"ok": True, "event_id": ev.event_id, "actor": actor}


@app.get("/events")
def query_events(session_id: uuid.UUID | None = None,
                 action_type: str | None = None,
                 actor: str | None = None,
                 after_event_id: int | None = None,
                 tail: int | None = None,
                 limit: int = 500,
                 p: Principal = Depends(principal),
                 db: Session = Depends(get_db)):
    """Cursor pagination in DETERMINISTIC INGESTION ORDER (event_id) — F14.
    after_event_id pages forward; tail=N returns the last N (CLI status/live).
    Source timestamps are data, never the checkpoint."""
    limit = min(limit, 5000)
    if p.kind == "service":
        # a run's worker may read its own session's log; nothing else
        if not (p.scope == "runner" and session_id and str(p.session_id) == str(session_id)):
            raise HTTPException(403, "capability cannot read events")
    q = select(Event)
    if session_id:
        sess = db.get(SessionModel, session_id)
        if sess is None:
            raise HTTPException(404, "session not found")
        if (p.kind in ("member", "operator") and not p.is_operator
                and str(sess.user_id) != str(p.user_id)):
            raise HTTPException(403, "not your session")
        q = q.where(Event.session_id == session_id)
    else:
        q = q.where(Event.session_id.in_(select(SessionModel.session_id)
                                          .where(SessionModel.user_id == p.user_id)))
    if after_event_id is not None:
        q = q.where(Event.event_id > after_event_id)
    if action_type:
        q = q.where(Event.action_type == action_type)
    if actor:
        q = q.where(Event.actor == actor)
    if tail:
        q = q.order_by(Event.event_id.desc()).limit(min(tail, 5000))
        rows = list(reversed(db.execute(q).scalars().all()))
    else:
        q = q.order_by(Event.event_id).limit(limit)
        rows = db.execute(q).scalars().all()
    return [_event_json(r) for r in rows]


def _event_json(r: Event) -> dict:
    return {"event_id": r.event_id, "session_id": str(r.session_id) if r.session_id else None,
            "ts": r.ts.isoformat() if r.ts else None,
            "ingested_at": r.ingested_at.isoformat() if r.ingested_at else None,
            "actor": r.actor, "host": r.host, "action_type": r.action_type,
            "phase": r.phase, "mitre_technique": r.mitre_technique, "payload": r.payload,
            "raw_ref": r.raw_ref, "raw_output_hash": r.raw_output_hash}


# --- safety (operator-only; no arbitrary PIDs) -----------------------------------
@app.post("/safety/killswitch")
def killswitch(p: Principal = Depends(operator)):
    from sqlalchemy import select as sa_select
    extra = []
    try:
        with db() as s:
            for r in s.execute(sa_select(Run).where(Run.status.in_(("queued", "running")))).scalars():
                if r.pgid:
                    extra.append((str(r.run_id), int(r.pgid), r.pgid_pstart))
    except Exception:
        pass  # the latch still engages; the DB problem is visible in the result below
    # recovered groups are PASSED TO THE KILL (audit R03) — reporting them as
    # "recovered_groups" without terminating them was the fail-open bug.
    return get_supervisor().engage(reason=f"killswitch by {p.username}",
                                   extra_groups=extra)


@app.post("/safety/killswitch-release")
def killswitch_release(p: Principal = Depends(operator)):
    return get_supervisor().release()


@app.get("/safety/status")
def safety_status(p: Principal = Depends(operator)):
    return get_supervisor().verify()


class BaselineCheckIn(BaseModel):
    ok: bool | None = None      # omitted => the controller's own live status


@app.post("/safety/baseline-check")
def safety_baseline_check(body: BaselineCheckIn, p: Principal = Depends(operator)):
    """Run the backend's baseline verification and record the outcome.

    Audit R04: an operator attestation may record a FAILED check honestly, but
    can never override a failed live backend check to `ok=True` — that turned
    the evidence trail into a rubber stamp."""
    sup = get_supervisor()
    live = sup.datapath.baseline_status()
    if body.ok and not live["ok"]:
        raise HTTPException(409, "cannot record a passed baseline check while the live "
                                 "verification FAILS — fix the datapath and re-check")
    ok = live["ok"] if body.ok is None else bool(body.ok)
    sup.record("baseline_check", ok, {"source": "operator", "live": live})
    return {"ok": ok, "live": live}


class DatapathProofIn(BaseModel):
    probes: dict  # e.g. {"ping_1_1_1_1": "100% packet loss", "dns": "fail", "ipv6": "no default route"}
    vm_hostname: str = Field(min_length=1)


@app.post("/safety/datapath-proof")
def safety_datapath_proof(body: DatapathProofIn, p: Principal = Depends(operator)):
    """RECORD the operator's live datapath proof. The schema requires the
    observations AND requires them to describe FAILED egress — an observation
    of reachable internet is structurally rejected (audit R04). The TRUTH of
    isolated observations remains the operator's trusted statement, which is
    why this endpoint is operator-only."""
    from srplatform.safety import probes_attest_isolation
    needed = {"ping", "dns"}
    if not needed.issubset({k.lower() for k in body.probes}):
        raise HTTPException(422, "probes must include ping and dns observations")
    ok, reasons = probes_attest_isolation(body.probes)
    if not ok:
        raise HTTPException(422, {"error": "probes do not attest isolation", "reasons": reasons})
    sup = get_supervisor()
    sup.record("datapath_proof", True, {"probes": body.probes, "vm": body.vm_hostname,
                                        "by": p.username})
    return {"ok": True, "ttl_h": sup.settings.safety_evidence_max_age_h}


class KillswitchTestIn(BaseModel):
    commands_stopped: bool
    datapath_isolated: bool
    detail: dict = Field(default_factory=dict)


@app.post("/safety/killswitch-test")
def safety_killswitch_test(body: KillswitchTestIn, p: Principal = Depends(operator)):
    """RECORD the operator's killswitch acceptance test (audit N07): during a
    real engagement the operator observed (a) model/worker commands CEASED
    (runner cancellation effective) and (b) datapath ISOLATION held (including
    same-bridge). Both observations are mandatory; a partial test records
    ok=false and therefore never authorizes a start. The record binds to the
    current config identity and is invalidated by the next engage/release —
    release can never reuse an old datapath proof."""
    ok = bool(body.commands_stopped and body.datapath_isolated)
    sup = get_supervisor()
    sup.record("killswitch_test", ok,
               {"commands_stopped": body.commands_stopped,
                "datapath_isolated": body.datapath_isolated,
                "detail": body.detail, "by": p.username})
    return {"ok": ok,
            "note": "recorded" if ok else "recorded as FAILED — starts stay denied "
                    "until a complete test passes"}


# --- agent_state (worker-scoped working memory) ---------------------------------
class AgentStateIn(BaseModel):
    summary: str | None = None
    summary_upto: int | None = None
    current_phase: str | None = None


@app.put("/agent_state/{session_id}")
def put_agent_state(session_id: uuid.UUID, body: AgentStateIn,
                    p: Principal = Depends(principal), db: Session = Depends(get_db)):
    if p.kind == "service" and not (p.scope == "runner" and str(p.session_id) == str(session_id)):
        raise HTTPException(403, "runner token mismatch")
    if p.kind in ("member", "operator"):
        _get_session(db, p, session_id)
    st = db.get(AgentState, session_id)
    if not st:
        st = AgentState(session_id=session_id)
        db.add(st)
        db.flush()
    if body.summary is not None:
        st.summary = body.summary
    if body.summary_upto is not None:
        st.summary_upto = body.summary_upto
    if body.current_phase is not None:
        st.current_phase = body.current_phase
    return {"ok": True}


@app.get("/agent_state/{session_id}")
def get_agent_state(session_id: uuid.UUID, p: Principal = Depends(principal),
                    db: Session = Depends(get_db)):
    st = db.get(AgentState, session_id)
    if not st:
        raise HTTPException(404, "no agent state")
    if p.kind == "service":
        if not (p.scope == "runner" and str(p.session_id) == str(session_id)):
            raise HTTPException(403, "runner token mismatch")
    else:
        _get_session(db, p, session_id)
    return {"session_id": str(st.session_id), "summary": st.summary,
            "summary_upto": st.summary_upto, "current_phase": st.current_phase}


# --- bastion target resolution (bastion capability only) -------------------------
class ServiceTokenIn(BaseModel):
    scope: str
    session_id: uuid.UUID | None = None
    host: str | None = None
    ttl_hours: int | None = None


@app.post("/admin/service_tokens", status_code=201)
def create_service_token(body: ServiceTokenIn, p: Principal = Depends(operator),
                         db: Session = Depends(get_db)):
    """Operator-provisioned capability issuance (bastion/telemetry). The
    plaintext is shown ONCE; only its value in the DB can authenticate."""
    if body.scope not in ("bastion", "telemetry"):
        raise HTTPException(422, "self-issuable scopes: bastion, telemetry (runner tokens are run-scoped)")
    if body.scope == "telemetry" and not body.host:
        raise HTTPException(422, "telemetry tokens must be bound to a host")
    token = f"svc-{body.scope}-{uuid.uuid4().hex}"
    db.add(ServiceToken(token=token, scope=body.scope, session_id=body.session_id,
                        host=body.host,
                        expires_at=_now() + timedelta(hours=body.ttl_hours)
                        if body.ttl_hours else None))
    return {"token": token, "scope": body.scope, "session_id": str(body.session_id)
            if body.session_id else None, "host": body.host}


@app.get("/tokens/{token}")
def get_token(token: str, p: Principal = Depends(service("bastion")),
              db: Session = Depends(get_db)):
    t = db.get(LoginToken, token)
    if not t or t.revoked_at is not None:
        raise HTTPException(404, "token not found")
    if t.expires_at is not None and t.expires_at < _now():
        raise HTTPException(404, "token expired")
    # The bastion must bind the login to the OWNER'S provisioned public key
    # (audit R02): resolve the member identity server-side. The keys file is
    # keyed by username, so the response carries the authenticated username,
    # never just an opaque id the bastion cannot map.
    owner = db.get(User, t.user_id) if t.user_id else None
    return {"token": t.token, "session_id": str(t.session_id) if t.session_id else None,
            "target_host": t.target_host, "target_port": int(t.target_port),
            "user_id": str(t.user_id) if t.user_id else None,
            "username": owner.username if owner else None}


# --- telemetry ingest (host-bound capability; source identity dedup) --------------
class AuditdRecord(BaseModel):
    ts: str | datetime | None = None
    kind: str = "command"          # command | detection (persistence/account watches)
    uid: str | int | None = None
    comm: str | None = None
    exe: str | None = None
    argv: str | None = None
    audit_key: str | None = None
    source_id: str | None = None
    boot_id: str | None = None
    raw: dict | None = None


class AuditdBatch(BaseModel):
    events: list[AuditdRecord] = Field(default_factory=list)


@app.post("/ingest/auditd", status_code=201)
def ingest_auditd(body: AuditdBatch, p: Principal = Depends(service("telemetry")),
                  db: Session = Depends(get_db)):
    """Host identity, session and actor come from the capability — never from
    the payload (F09). Duplicate source event ids are dropped; late records
    keep their source ts but never displace ingestion order."""
    accepted, dupes = 0, 0
    seen_sources = set()
    for rec in body.events[: get_settings().ingest_max_body_events]:
        sid = f"{rec.boot_id or 'nb'}:{rec.source_id}" if rec.source_id else None
        if sid and sid in seen_sources:
            dupes += 1
            continue
        if sid:
            existing = db.execute(text(
                "SELECT 1 FROM events WHERE host = :h AND payload->>'source_id' = :s LIMIT 1"),
                {"h": p.host, "s": sid}).first()
            if existing:
                dupes += 1
                continue
            seen_sources.add(sid)
        _log_event(db, p.session_id, "telemetry", p.host, rec.kind if rec.kind in TELEMETRY_KINDS else "command",
                   {"source": "auditd", "uid": rec.uid, "comm": rec.comm, "exe": rec.exe,
                    "argv": rec.argv, "audit_key": rec.audit_key, "source_id": sid, "raw": rec.raw},
                   ts=_parse_ts(rec.ts))
        accepted += 1
    return {"ok": True, "accepted": accepted, "duplicates": dupes}


def _parse_ts(v):
    if v is None:
        return None
    if isinstance(v, datetime):
        return v
    try:
        return datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None


# --- shared helper ----------------------------------------------------------------
def _log_event(db: Session, session_id, actor, host, action_type, payload, phase=None,
               mitre_technique=None, raw_ref=None, raw_output_hash=None, ts=None):
    ev = Event(session_id=session_id, ts=ts or datetime.now(timezone.utc), actor=actor,
               host=host, action_type=action_type, phase=phase,
               mitre_technique=mitre_technique, payload=payload, raw_ref=raw_ref,
               raw_output_hash=raw_output_hash)
    db.add(ev)
    db.flush()
    return ev


# --- startup reconciliation (F13) ----------------------------------------------------
@app.on_event("startup")
def _startup():
    try:
        runs_svc.reconcile_on_startup()
    except Exception:
        pass  # readiness endpoint reports DB problems; startup must not crash
    try:
        # durable operation claims only have meaning while THIS process serves;
        # anything left over belongs to a dead request (crash recovery).
        from srplatform.scenario_engine import orchestrator
        with db() as s:
            orchestrator.clear_operation_claims(s)
    except Exception:
        pass
