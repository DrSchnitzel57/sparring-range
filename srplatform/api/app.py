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
import os
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


class _StartupCORSMiddleware(CORSMiddleware):
    """Origins are read when the middleware stack is BUILT (app startup),
    not at module import: a test/dev process sets its own web origin via
    API_ALLOWED_ORIGINS before serving, and importing this module earlier
    (e.g. during pytest collection) must not freeze the defaults.
    Production behaviour is unchanged — settings are read once, at boot."""

    def __init__(self, asgi_app):
        s = get_settings()
        super().__init__(
            asgi_app,
            allow_origins=[o.strip() for o in s.api_allowed_origins.split(",") if o.strip()],
            allow_methods=["*"],
            allow_headers=["*"],
        )


app.add_middleware(_StartupCORSMiddleware)


#: The guest-facing telemetry listener (plan 13 phase 4): when this process
#: serves the controller's RANGE address it must expose ONLY the
#: authenticated enrollment/ingest routes — never the general API, web,
#: auth, scoring, model or operator surface. Enabled by SR_API_INGEST_ONLY=1
#: on that listener's unit only; the internal (loopback) and LAN listeners
#: keep the full app. Unknown paths answer 404 (not 401/403 — the listener
#: does not advertise what exists), and bodies are bounded at the header.
INGEST_ALLOWLIST = frozenset({("POST", "/enroll/confirm"),
                              ("POST", "/ingest/auditd")})


@app.middleware("http")
async def _ingest_only_guard(request, call_next):
    from srplatform.settings import get_settings as _gs
    s = _gs()
    if not s.api_ingest_only:
        return await call_next(request)
    if (request.method, request.url.path) not in INGEST_ALLOWLIST:
        return JSONResponse({"detail": "not_found"}, status_code=404)
    # Enforce on BYTES ACTUALLY RECEIVED, not on the header: a missing or
    # lying Content-Length (chunked encoding) must not bypass the bound.
    # The body is replayed downstream so routing/validation are unaffected.
    limit = s.ingest_max_body_bytes
    chunks: list[bytes] = []
    received = 0
    receive = request.receive
    while True:
        message = await receive()
        if message["type"] == "http.request":
            chunk = message.get("body", b"")
            received += len(chunk)
            if received > limit:
                return JSONResponse({"detail": "body_too_large"},
                                    status_code=413)
            chunks.append(chunk)
            if not message.get("more_body", False):
                break
        elif message["type"] == "http.disconnect":
            break
    body = b"".join(chunks)
    sent = False

    async def _replay():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body,
                    "more_body": False}
        return {"type": "http.disconnect"}

    request._receive = _replay  # noqa: SLF001 — bounded replay, same bytes
    return await call_next(request)


# The ONE shared request DB session (function scope — commit completes before
# the response is sent; see srplatform/api/deps.py for why) and the auth
# dependencies built on it.
from srplatform.api.deps import DbSession  # noqa: E402

principal, any_member, operator, service = make_auth_dependencies()

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


@app.get("/stages")
def release_stages(p: Principal = Depends(operator), db: DbSession = None):
    """Release-stage ladder (plan 13 phase 4), operator-authorized and
    redacted. install-ready: configuration valid, schema at head, state
    writable — NO clone or pin is required, so bootstrap cannot deadlock.
    lab-ready: install-ready AND the broker answers with its latch state
    (templates, pins and the range inventory are only resolvable through
    it). attack-authorized: lab-ready PLUS the explicit operator gate
    (SR_ATTACK_AUTHORIZED=1), set only after isolation and emergency-stop
    verification. No stage waives a later gate, and a successful
    deployment never implies authorization to attack."""
    from srplatform.api.deps import get_broker
    issues = []
    v = None
    try:
        v = db.execute(text("SELECT version_num FROM alembic_version "
                            "LIMIT 1")).scalar()
        from alembic.config import Config as _Acfg
        from alembic.script import ScriptDirectory as _SD
        head = _SD.from_config(_Acfg("alembic.ini")).get_current_head()
        if v and head and v != head:
            issues.append(f"schema {v} behind head {head}")
    except Exception as e:  # noqa: BLE001 — a stage report never 500s
        issues.append(f"db: {str(e)[:200]}")
    s = get_settings()
    rec_dir = s.recordings_dir
    if not os.path.isdir(rec_dir):
        try:  # state dirs are ours to create (idempotent, non-destructive)
            os.makedirs(rec_dir, exist_ok=True)
        except OSError:
            pass
    rec_ok = os.access(rec_dir, os.W_OK) if os.path.isdir(rec_dir) else False
    if not rec_ok:
        issues.append("recordings/state dir not writable")
    install_ready = v is not None and not issues
    broker = None
    if install_ready:
        try:
            broker = {"ok": True, "latch": get_broker().latch_status()}
        except Exception as e:  # noqa: BLE001
            broker = {"ok": False, "detail": str(e)[:200]}
    lab_ready = install_ready and bool(broker and broker.get("ok"))
    return {"install_ready": install_ready,
            "lab_ready": lab_ready,
            "attack_authorized": lab_ready and s.attack_authorized,
            "operator_gate": s.attack_authorized,
            "broker": broker,
            "issues": issues}


# --- auth (F04) ----------------------------------------------------------------
class BootstrapIn(BaseModel):
    username: str
    password: str = Field(min_length=10)


@app.post("/auth/bootstrap", status_code=201)
def bootstrap(body: BootstrapIn, db: DbSession = None):
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
def login(body: LoginIn, db: DbSession = None):
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
           db: DbSession = None):
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
def create_user(body: UserIn, p: Principal = Depends(operator), db: DbSession = None):
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
    # match parameters are SNAPSHOTTED at creation (pilot step 4); defaults
    # come from settings (30-minute match, 30 s attack pace, 0 = no delay)
    duration_minutes: int | None = None
    pace_seconds: int | None = None
    # plan 13 phase 6: bounded, versioned choices frozen into the snapshot
    mode: str = "practice"
    start_condition: str = "network-entry"
    injects_enabled: bool = True


def _scenario_snapshot(scenario_id: str) -> tuple[str, str]:
    from srplatform.scenario_engine.loader import scenarios_dir
    p = scenarios_dir() / f"{scenario_id}.yaml"
    if p.exists():
        raw = p.read_bytes()
        return hashlib.sha256(raw).hexdigest(), raw.decode(errors="replace")
    return "missing", ""


@app.post("/sessions", status_code=201)
def create_session(body: SessionCreate, p: Principal = Depends(any_member),
                   db: DbSession = None):
    from srplatform.scenario_engine.loader import load_scenario
    load_scenario(body.scenario_id)  # validated before anything is stored
    sha, raw = _scenario_snapshot(body.scenario_id)
    if body.start_condition == "assumed-breach":
        # The disclosed foothold is PART of the frozen history: rewrite the
        # snapshotted spec's start phase (the worker reads this snapshot, so
        # recon is skipped by construction) and re-digest — the sha always
        # covers exactly what the session runs.
        import yaml as _yaml
        from srplatform import lifecycle as _lc
        spec_doc = _yaml.safe_load(raw)
        try:
            spec_doc["red"]["start_phase"] = \
                _lc.ASSUMED_BREACH_START_PHASE
        except (KeyError, TypeError) as e:
            raise HTTPException(422, {"error": "invalid_match_parameters",
                                      "detail": "scenario has no red.start_phase "
                                                f"for assumed-breach: {e}"})
        raw = _yaml.safe_dump(spec_doc, sort_keys=True)
        sha = hashlib.sha256(raw.encode()).hexdigest()
    sess = SessionModel(scenario_id=body.scenario_id, user_id=p.user_id, players=body.players,
                        status="preparing")
    db.add(sess)
    db.flush()
    # MATCH SNAPSHOT (pilot step 4): effective preset/duration/pace are
    # frozen NOW — never re-read live mid-match.
    from srplatform import lifecycle
    s = get_settings()
    try:
        spec_v = load_scenario(body.scenario_id)
        lifecycle.create_match(
            db, sess.session_id, body.scenario_id,
            duration_minutes=body.duration_minutes or s.match_default_duration_minutes,
            pace_seconds=(s.match_default_pace_seconds if body.pace_seconds is None
                          else body.pace_seconds),
            mode=body.mode, start_condition=body.start_condition,
            injects_enabled=body.injects_enabled,
            scenario_versions={"scenario_version": spec_v.get("version"),
                               "rubric_version": spec_v.get("rubric_version"),
                               "seed_version": spec_v.get("seed_version"),
                               "image_version": spec_v.get("image_version"),
                               "scenario_sha256": sha},
            effective_settings={
                "uptime_scoring_enabled": s.uptime_scoring_enabled,
                "scheduler_enabled": s.match_scheduler_enabled},
            actor=p.username)
    except ValueError as e:
        raise HTTPException(422, {"error": "invalid_match_parameters",
                                  "detail": str(e)})
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
                  db: DbSession = None):
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
                db: DbSession = None):
    sess = _get_session(db, p, session_id)
    dep = db.execute(select(Deployment).where(Deployment.session_id == session_id)
                     .order_by(Deployment.created_at.desc())).scalars().first()
    active = runs_svc.active_run_for_session(db, session_id)
    from srplatform import lifecycle
    m = lifecycle.get_match(db, session_id)
    match = None
    if m is not None:
        def _iso(dt):
            return dt.isoformat() if dt else None
        match = {"state": m.state, "preset": m.preset,
                 "duration_minutes": m.duration_minutes,
                 "pace_seconds": m.pace_seconds,
                 "mode": (m.snapshot or {}).get("mode", "practice"),
                 "start_condition": (m.snapshot or {}).get(
                     "start_condition", "network-entry"),
                 "snapshot_version": (m.snapshot or {}).get(
                     "snapshot_version"),
                 "snapshot": m.snapshot or {},
                 "ready_at": _iso(m.ready_at), "started_at": _iso(m.started_at),
                 "deadline_at": _iso(m.deadline_at), "ended_at": _iso(m.ended_at),
                 "expiry_reason": m.expiry_reason,
                 "ready_expires_at": (
                     (m.ready_at + timedelta(
                         minutes=lifecycle.READY_IDLE_EXPIRY_MINUTES)).isoformat()
                     if m.ready_at else None)}
    return {"session_id": str(sess.session_id), "scenario_id": sess.scenario_id,
            "status": sess.status, "outcome": sess.outcome,
            "started_at": sess.started_at.isoformat() if sess.started_at else None,
            "deployment_status": dep.status if dep else None,
            "active_run": str(active.run_id) if active else None,
            "match": match}


@app.get("/sessions/{session_id}/connections")
def get_connections(session_id: uuid.UUID, p: Principal = Depends(any_member),
                    db: DbSession = None):
    """Connection instructions SERVED BY THE API (pilot step 4): members
    re-fetch their SSH instructions any time (refresh, another device) —
    never a browser sessionStorage secret that vanishes on reload. Only the
    caller's OWN unexpired, unrevoked login capabilities are returned."""
    sess = _get_session(db, p, session_id)
    s = get_settings()
    dep = db.execute(select(Deployment).where(Deployment.session_id == session_id,
                                              Deployment.status == "ready")
                     .order_by(Deployment.created_at.desc())).scalars().first()
    name_by_ip = {}
    if dep:
        for r in (dep.resources or []):
            if r.get("ip"):
                name_by_ip[r["ip"]] = r.get("host")
    out = []
    for lt in db.execute(select(LoginToken).where(
            LoginToken.session_id == session_id,
            LoginToken.user_id == p.user_id,
            LoginToken.revoked_at.is_(None),
            LoginToken.expires_at > _now())).scalars():
        out.append({"host": name_by_ip.get(lt.target_host, lt.target_host),
                    "ip": lt.target_host, "login_token": lt.token,
                    "ssh": f"ssh {s.bastion_address} -p {s.bastion_listen_port} -l {lt.token}",
                    "expires_at": lt.expires_at.isoformat() if lt.expires_at else None})
    return {"session_id": str(session_id), "connections": out}


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
    """Teardown/reset precondition (audit N03/T01): the worker AND its remote
    commands must be stopped and CONFIRMED dead before its machines/lease are
    released. 'stopping' and 'cancel-unknown' are NOT confirmed — a failed or
    unconfirmed stop is a conflict, never a silent continue. AUDIT F2: the
    durable operation inventory is checked INDEPENDENTLY of run status — a
    corrupt terminal row cannot hide an unresolved obligation from release."""
    active = runs_svc.active_run_for_session(db, sess.session_id)
    if active:
        stopped = runs_svc.stop_run(db, active.run_id)
        if not stopped.get("ok"):
            raise HTTPException(409, {"error": "worker_stop_failed",
                                      "run_id": str(active.run_id),
                                      "status": stopped.get("status"),
                                      "detail": stopped.get("detail"),
                                      "note": "range NOT torn down; retry or engage killswitch"})
    _require_session_operations_resolved(db, sess.session_id)


def _require_session_operations_resolved(db, session_id) -> None:
    """AUDIT F2: end/reset/teardown must check durable obligations even when
    no run is ACTIVE. Attempts genuine resolution through the owning run's
    terminal protocol; anything still unconfirmed BLOCKS the release —
    existing inconsistent rows are repaired or block, never bypassed."""
    rows = runs_svc.unresolved_operations(db, session_id)
    if not rows:
        return
    for rid in {str(r.run_id) for r in rows}:
        try:
            runs_svc.stop_run(db, rid)
        except KeyError:
            pass
    rows = runs_svc.unresolved_operations(db, session_id)
    if rows:
        raise HTTPException(409, {
            "error": "unresolved_operations",
            "operations": [{"op_id": r.op_id, "state": r.state,
                            "run_id": str(r.run_id)} for r in rows][:10],
            "note": "unresolved command operations exist on this session's runs — "
                    "release blocked until cessation is genuinely confirmed"})


def _fail_deploy_operation(session_id, fence: str | None, error: str) -> None:
    """Record the failed outcome through a SEPARATE session (the request
    transaction is discarded by the raise) and ONLY for the attempt this
    request still fences — a stale request never finalizes a replacement."""
    from srplatform.db.session import db as db_ctx
    from srplatform.scenario_engine import orchestrator
    try:
        with db_ctx() as s2:
            row = orchestrator.latest_deploy_operation(s2, session_id)
            if row is not None and row.fence == fence and row.state in (
                    "accepted", "running"):
                orchestrator.finish_deploy_operation(s2, row, "failed",
                                                     error=error)
    except Exception:  # noqa: BLE001 — evidence is best-effort, the raise is not
        pass


def _release_claim_safely(db, session_id, succeeded: bool, owner: str | None = None) -> None:
    """Release the durable operation claim WITHOUT ever rolling back the
    request's own successful writes (the request transaction commits after
    the route returns). The release is FENCED on the owner token (audit T02):
    a request whose claim was taken over cannot erase the replacement.

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
            orchestrator.release_operation(db, session_id, owner)
        else:
            from srplatform.db.session import db as db_ctx
            with db_ctx() as s2:
                orchestrator.release_operation(s2, session_id, owner)
    except Exception:  # noqa: BLE001 — recovery is startup/stale-window anyway
        pass


@app.post("/sessions/{session_id}/launch", status_code=202)
def launch_session(session_id: uuid.UUID, p: Principal = Depends(any_member),
                   db: DbSession = None):
    """Shared backend workflow for CLI and browser (plan 13 phase 5, 202
    refinement): authenticate → claim → reserve (lease) → DURABLE ACCEPT
    → 202 with the operation reference. The supervised executor performs
    deploy → readiness → capabilities → ready in the background; poll
    GET /sessions/{id}/operation. A duplicate while accepted/running is
    refused 409 with the live operation — it can never create a second
    deployment."""
    from srplatform.scenario_engine import orchestrator
    from srplatform.scenario_engine import deploy_executor
    from srplatform.api.deps import get_broker

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
        _claim_owner = orchestrator.claim_operation(db, sess.session_id, "launch")
    except orchestrator.OperationInProgress as e:
        row = orchestrator.latest_deploy_operation(db, sess.session_id)
        raise HTTPException(409, {"error": "operation_in_progress",
                                  "operation": e.operation,
                                  "operation_id": str(row.operation_id)
                                  if row is not None else None})
    # DURABLE ACCEPTANCE: the attempt's identity, fence, phase and deadline
    # are committed BEFORE any side effect; the lease is reserved in the
    # same request so conflict answers stay synchronous and deterministic.
    from srplatform.settings import get_settings as _gs_op
    deadline_s = _gs_op().deploy_operation_deadline_s
    op_row = orchestrator.begin_deploy_operation(
        db, sess.session_id, "launch", fence=_claim_owner,
        deadline_s=deadline_s)
    try:
        orchestrator.acquire_lease(db, sess.session_id)
    except orchestrator.LeaseConflict as e:
        _fail_deploy_operation(sess.session_id, _claim_owner,
                               f"range_busy holder={e.holder_session_id}")
        _release_claim_safely(db, sess.session_id, False, _claim_owner)
        raise HTTPException(409, {"error": "range_busy",
                                  "holder_session": e.holder_session_id,
                                  "acquired_at": e.acquired_at})
    try:
        broker = get_broker()
    except Exception as e:  # noqa: BLE001 — broker unresolvable pre-dispatch
        _fail_deploy_operation(sess.session_id, _claim_owner,
                               f"broker_unavailable: {str(e)[:200]}")
        _release_claim_safely(db, sess.session_id, False, _claim_owner)
        raise
    deploy_executor.submit(operation_id=op_row.operation_id,
                           session_id=sess.session_id,
                           user_id=str(p.user_id),
                           operation="launch",
                           scenario_id=sess.scenario_id,
                           broker=broker, owner=_claim_owner)
    return {"session_id": str(sess.session_id),
            "operation_id": str(op_row.operation_id),
            "status": "accepted",
            "deadline_at": op_row.deadline_at.isoformat()
            if op_row.deadline_at else None,
            "operation": "/sessions/%s/operation" % sess.session_id}


@app.post("/sessions/{session_id}/end")
def end_session(session_id: uuid.UUID, p: Principal = Depends(any_member),
                db: DbSession = None):
    """Idempotent durable finalize (F11/F13 + pilot step 4): stop the worker
    and CONFIRM, capture final evidence, revoke capabilities, DESTROY the
    owned VMs and release the lease when teardown completes. A blocked stop,
    unresolved operation or failed destroy is a conflict — everything stays
    reserved and visible, and the scheduler retries; a repeat end retries
    the cleanup. The lease is released ONLY on a complete teardown (R07)."""
    from srplatform import lifecycle
    from srplatform.api.deps import get_broker
    from srplatform.scenario_engine import orchestrator

    sess = _get_session(db, p, session_id)
    m = lifecycle.get_match(db, sess.session_id)
    if sess.status == "complete" and (m is None or m.state == "completed"):
        return {"ok": True, "status": "complete", "note": "already ended (idempotent)",
                "outcome": sess.outcome, "lease_released": True}
    try:
        _claim_owner = orchestrator.claim_operation(db, sess.session_id, "end")
    except orchestrator.OperationInProgress as e:
        raise HTTPException(409, {"error": "operation_in_progress", "operation": e.operation})
    _ok = False
    try:
        out = lifecycle.finalize_match(db, sess.session_id, "user_end",
                                       broker=get_broker(), username=p.username)
        db.commit()
        _ok = True
        return out
    except lifecycle.MatchBlocked as e:
        raise HTTPException(409, {"error": e.reason, "detail": e.detail,
                                  "note": "session NOT fully ended; range stays "
                                          "reserved, cleanup retried automatically"})
    finally:
        _release_claim_safely(db, sess.session_id, _ok, _claim_owner)



@app.post("/sessions/{session_id}/score")
def score_session(session_id: uuid.UUID, p: Principal = Depends(any_member),
                  db: DbSession = None):
    """Trusted scoring endpoint (F11): the BACKEND runs the verifiers; CLI and
    browser are both plain HTTP callers."""
    from srplatform import verification_service
    sess = _get_session(db, p, session_id)
    try:
        card = verification_service.build_scorecard(db, sess.session_id)
    except Exception as e:  # noqa: BLE001
        return JSONResponse(status_code=503, content={"status": "unscored",
                                                      "error": str(e)[:300]})
    return _filter_scorecard(db, sess, p, card)


@app.get("/sessions/{session_id}/score")
def get_score(session_id: uuid.UUID, p: Principal = Depends(any_member),
              db: DbSession = None):
    from srplatform import verification_service
    sess = _get_session(db, p, session_id)
    card = verification_service.latest_scorecard(db, sess.session_id)
    if card is None:
        return {"status": "unscored"}
    return _filter_scorecard(db, sess, p, card)


def _filter_scorecard(db, sess, p, card: dict) -> dict:
    """Competition scorecard filtering: members see totals and status, but
    per-check pass/fail/evidence would reveal exactly what the attacker
    achieved — sealed until the match completes. Operators see everything."""
    if not _competition_sealed(db, sess, p):
        return card
    return _filter_card(card)


def _teardown_common(db, sess, p):
    from srplatform.scenario_engine import orchestrator
    from srplatform.api.deps import get_broker
    # WORKER FIRST (audit N03): machines and the lease are released only after
    # the session's worker is confirmed stopped — otherwise a later session
    # could acquire the same static addresses while the old worker still
    # operates against them.
    _stop_active_run_or_conflict(db, sess)
    t = orchestrator.teardown(db, sess.session_id, sess.scenario_id, get_broker())
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
    # MATCH: an explicit teardown ends the match lifecycle too (the machines
    # it referred to are gone); incomplete cleanup stays retryable.
    from srplatform import lifecycle
    m = lifecycle.get_match(db, sess.session_id)
    if m is not None and m.state != "completed":
        m.state = "completed" if t.get("complete", True) else "interrupted"
        m.expiry_reason = m.expiry_reason or "teardown"
        m.ended_at = m.ended_at or _now()
        db.add(Event(session_id=sess.session_id, ts=_now(), actor="system",
                     action_type="match_end",
                     payload={"reason": "teardown", "complete": t.get("complete", True)}))
    db.flush()
    return t


@app.post("/sessions/{session_id}/teardown")
def teardown_session(session_id: uuid.UUID, p: Principal = Depends(any_member),
                     db: DbSession = None):
    from srplatform.scenario_engine import orchestrator
    sess = _get_session(db, p, session_id)
    try:
        _claim_owner = orchestrator.claim_operation(db, sess.session_id, "teardown")
    except orchestrator.OperationInProgress as e:
        raise HTTPException(409, {"error": "operation_in_progress", "operation": e.operation})
    _ok = False
    try:
        out = _teardown_common(db, sess, p)
        _ok = True
        return out
    finally:
        _release_claim_safely(db, sess.session_id, _ok, _claim_owner)


@app.post("/sessions/{session_id}/reset")
@app.post("/sessions/{session_id}/reset", status_code=202)
def reset_session(session_id: uuid.UUID, p: Principal = Depends(any_member),
                  db: DbSession = None):
    """Reset via the supervised executor (plan 13 phase 5, 202 refinement):
    the worker is stopped and old capabilities revoked synchronously (fast,
    durable, synchronous conflicts), then the redeploy + readiness work runs
    in the background. Returns 202; poll GET /sessions/{id}/operation."""
    from srplatform.scenario_engine import orchestrator
    from srplatform.scenario_engine import deploy_executor
    from srplatform.api.deps import get_broker
    sess = _get_session(db, p, session_id)
    try:
        _claim_owner = orchestrator.claim_operation(db, sess.session_id, "reset")
    except orchestrator.OperationInProgress as e:
        row = orchestrator.latest_deploy_operation(db, sess.session_id)
        raise HTTPException(409, {"error": "operation_in_progress",
                                  "operation": e.operation,
                                  "operation_id": str(row.operation_id)
                                  if row is not None else None})
    from srplatform.settings import get_settings as _gs_op
    deadline_s = _gs_op().deploy_operation_deadline_s
    op_row = orchestrator.begin_deploy_operation(
        db, sess.session_id, "reset", fence=_claim_owner,
        deadline_s=deadline_s)
    try:
        # stop the worker BEFORE anything is destroyed (audit N03)
        _stop_active_run_or_conflict(db, sess)
        # old machines are about to die — their capabilities must die first
        _revoke_session_capabilities(db, sess.session_id, "reset")
    except HTTPException as e:
        _fail_deploy_operation(sess.session_id, _claim_owner,
                               str(e.detail if isinstance(e.detail, (dict, str))
                                   else e.status_code))
        _release_claim_safely(db, sess.session_id, False, _claim_owner)
        raise
    # the lease is reserved synchronously so range_busy stays deterministic;
    # orchestrator.reset re-verifies it inside the executor (R07).
    try:
        orchestrator.acquire_lease(db, sess.session_id)
    except orchestrator.LeaseConflict as e:
        _fail_deploy_operation(sess.session_id, _claim_owner,
                               f"range_busy holder={e.holder_session_id}")
        _release_claim_safely(db, sess.session_id, False, _claim_owner)
        raise HTTPException(409, {"error": "range_busy",
                                  "holder_session": e.holder_session_id})
    try:
        reset_broker = get_broker()
    except Exception:  # noqa: BLE001 — broker unresolvable pre-dispatch
        _fail_deploy_operation(sess.session_id, _claim_owner,
                               "broker_unavailable")
        _release_claim_safely(db, sess.session_id, False, _claim_owner)
        raise
    deploy_executor.submit(operation_id=op_row.operation_id,
                           session_id=sess.session_id,
                           user_id=str(p.user_id),
                           operation="reset",
                           scenario_id=sess.scenario_id,
                           broker=reset_broker, owner=_claim_owner)
    return {"session_id": str(sess.session_id),
            "operation_id": str(op_row.operation_id),
            "status": "accepted",
            "deadline_at": op_row.deadline_at.isoformat()
            if op_row.deadline_at else None,
            "operation": "/sessions/%s/operation" % sess.session_id}


@app.get("/sessions/{session_id}/operation")
def get_session_operation(session_id: uuid.UUID,
                          p: Principal = Depends(any_member), db: DbSession = None):
    """Authorized, REDACTED polling of the session's latest lifecycle
    operation (plan 13 phase 5): state/phase/deadline/outcome only — never
    provisioning commands, tokens or full errors. A browser disconnect or a
    504 can consult this to learn what actually happened; the answer can
    never create a second deployment."""
    from srplatform.scenario_engine import orchestrator
    sess = _get_session(db, p, session_id)
    row = orchestrator.latest_deploy_operation(db, sess.session_id)
    if row is None:
        raise HTTPException(404, {"error": "no_operation"})
    return {"operation_id": str(row.operation_id), "operation": row.operation,
            "state": row.state, "phase": row.phase,
            "deadline_at": row.deadline_at.isoformat() if row.deadline_at else None,
            "error": row.error,
            "result": (row.progress or {}).get("result"),
            "created_at": row.created_at.isoformat(),
            "updated_at": row.updated_at.isoformat(),
            "completed_at": row.completed_at.isoformat() if row.completed_at else None}


# --- deploy (legacy wrapper — SAME invariants as /launch, audit N03) -------------
class DeployIn(BaseModel):
    session_id: uuid.UUID


@app.post("/deploy/{scenario_id}", status_code=202)
def deploy_scenario(scenario_id: str, body: DeployIn, p: Principal = Depends(any_member),
                    db: DbSession = None):
    from srplatform.scenario_engine import orchestrator
    from srplatform.scenario_engine import deploy_executor
    from srplatform.api.deps import get_broker
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
        _claim_owner = orchestrator.claim_operation(db, sess.session_id, "deploy")
    except orchestrator.OperationInProgress as e:
        row = orchestrator.latest_deploy_operation(db, sess.session_id)
        raise HTTPException(409, {"error": "operation_in_progress",
                                  "operation": e.operation,
                                  "operation_id": str(row.operation_id)
                                  if row is not None else None})
    from srplatform.settings import get_settings as _gs_op
    deadline_s = _gs_op().deploy_operation_deadline_s
    op_row = orchestrator.begin_deploy_operation(
        db, sess.session_id, "launch", fence=_claim_owner,
        deadline_s=deadline_s)
    try:
        orchestrator.acquire_lease(db, sess.session_id)
    except orchestrator.LeaseConflict as e:
        _fail_deploy_operation(sess.session_id, _claim_owner,
                               f"range_busy holder={e.holder_session_id}")
        _release_claim_safely(db, sess.session_id, False, _claim_owner)
        raise HTTPException(409, {"error": "range_busy",
                                  "holder_session": e.holder_session_id})
    try:
        legacy_broker = get_broker()
    except Exception:  # noqa: BLE001 — broker unresolvable pre-dispatch
        _fail_deploy_operation(sess.session_id, _claim_owner,
                               "broker_unavailable")
        _release_claim_safely(db, sess.session_id, False, _claim_owner)
        raise
    deploy_executor.submit(operation_id=op_row.operation_id,
                           session_id=sess.session_id,
                           user_id=str(p.user_id),
                           operation="launch",
                           scenario_id=scenario_id,
                           broker=legacy_broker, owner=_claim_owner)
    return {"session_id": str(sess.session_id),
            "operation_id": str(op_row.operation_id),
            "status": "accepted",
            "operation": "/sessions/%s/operation" % sess.session_id}


@app.get("/scenarios")
def scenarios_list():
    from srplatform.scenario_engine.loader import list_scenarios
    return list_scenarios()


# --- run (M3) — validated, supervised, single-active ----------------------------
class RunIn(BaseModel):
    session_id: uuid.UUID


def _start_red_run(db, p, session_id, scenario_id: str):
    """Shared attack-start workflow (the durable claim must be HELD by the
    caller — audit T02). Every precondition is re-read AFTER the claim:
    what was true before the claim says nothing about now. Used by /run and
    /begin so both enforce the identical lease/deployment/enrollment gate."""
    from srplatform.scenario_engine import orchestrator
    db.expire_all()
    sess = _get_session(db, p, session_id)
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
    # ENROLLMENT EVIDENCE GATE (audit F3): an already-`ready` session must
    # not let /run bypass the current enrollment requirements — readiness
    # derives from valid CURRENT-generation enrollment evidence, not from
    # a stale JSON phase alone.
    from srplatform.scenario_engine import orchestrator as _orch
    if _orch.enrollment_channel_available():
        stale = [r.get("host") for r in (dep.resources or [])
                 if r.get("state") == "created"
                 and not _orch.enrollment_evidence_current(db, sess.session_id,
                                                           r.get("host"),
                                                           dep.deployment_id)]
        if stale:
            raise HTTPException(409, {
                "error": "enrollment_evidence_missing", "hosts": stale,
                "note": "current-deployment enrollment evidence (authenticated "
                        "delivery + capture) is missing for these hosts — "
                        "relaunch/reset to re-enroll; /run cannot bypass "
                        "enrollment requirements"})
    try:
        run = runs_svc.start_run(db, sess.session_id, scenario_id)
    except runs_svc.GateRefused as e:
        raise HTTPException(423, {"error": "safety_gate", "reasons": e.reasons})
    except runs_svc.RunConflict as e:
        raise HTTPException(409, str(e))
    sess.status = "running"
    db.flush()
    return run


@app.post("/run/{scenario_id}", status_code=202)
def run_scenario(scenario_id: str, body: RunIn, p: Principal = Depends(any_member),
                 db: DbSession = None):
    """Start the attack worker. LIFECYCLE COORDINATION (audit T02): /run
    participates in the SAME durable operation claim as end/reset/teardown/
    begin — a run can never slip past teardown's "no active worker" check.
    A ready match's SERVER CLOCK starts with it (pilot step 4)."""
    from srplatform import lifecycle
    from srplatform.scenario_engine import orchestrator
    sess = _get_session(db, p, body.session_id)
    if sess.scenario_id != scenario_id:
        raise HTTPException(422, f"session runs scenario '{sess.scenario_id}'")
    try:
        _claim_owner = orchestrator.claim_operation(db, sess.session_id, "run")
    except orchestrator.OperationInProgress as e:
        raise HTTPException(409, {"error": "operation_in_progress", "operation": e.operation})
    _ok = False
    try:
        run = _start_red_run(db, p, body.session_id, scenario_id)
        lifecycle.start_clock(db, sess.session_id, actor=p.username)
        _ok = True
        return {"ok": True, "run_id": str(run.run_id), "status": run.status,
                "session_id": str(body.session_id)}
    finally:
        _release_claim_safely(db, sess.session_id, _ok, _claim_owner)


@app.post("/sessions/{session_id}/begin", status_code=202)
def begin_session(session_id: uuid.UUID, p: Principal = Depends(any_member),
                  db: DbSession = None):
    """BEGIN (pilot step 4): start the SERVER match clock and the attack
    schedule together, from the snapshot taken at session creation. The
    deadline ends the match; a duplicate Begin is idempotent and can never
    extend the ORIGINAL deadline."""
    from srplatform import lifecycle
    from srplatform.scenario_engine import orchestrator
    sess = _get_session(db, p, session_id)
    m = lifecycle.get_match(db, sess.session_id)
    if m is not None and m.state == "running":
        active = runs_svc.active_run_for_session(db, sess.session_id)
        return {"ok": True, "status": "running", "note": "already begun (idempotent)",
                "run_id": str(active.run_id) if active else None,
                "started_at": m.started_at.isoformat() if m.started_at else None,
                "deadline_at": m.deadline_at.isoformat() if m.deadline_at else None,
                "duration_minutes": m.duration_minutes, "pace_seconds": m.pace_seconds}
    try:
        _claim_owner = orchestrator.claim_operation(db, sess.session_id, "begin")
    except orchestrator.OperationInProgress as e:
        raise HTTPException(409, {"error": "operation_in_progress", "operation": e.operation})
    _ok = False
    try:
        # Validate the starting condition BEFORE spawning the worker: a
        # refused Begin must never leave an attacker running with the
        # match clock unstarted (the proof is idempotent; start_clock
        # re-establishes it for the event record).
        try:
            lifecycle.prove_assumed_breach(db, sess.session_id)
        except lifecycle.MatchBlocked as e:
            raise HTTPException(409, {"error": e.reason, "detail": e.detail,
                                      "note": "match NOT started; no worker "
                                              "was spawned, range stays "
                                              "reserved"})
        run = _start_red_run(db, p, sess.session_id, sess.scenario_id)
        try:
            m = lifecycle.start_clock(db, sess.session_id, actor=p.username)
        except lifecycle.MatchBlocked as e:
            # The pre-spawn proof passed but establishment failed here
            # (channel died in between): cease the just-spawned worker so
            # no attacker outlives the refused Begin, and say so loudly.
            ceased: dict = {}
            try:
                ceased = runs_svc.stop_run(db, run.run_id) or {}
            except Exception as ce:  # noqa: BLE001
                ceased = {"ok": False, "detail": str(ce)[:200]}
            raise HTTPException(409, {"error": e.reason, "detail": e.detail,
                                      "worker_ceased": bool(ceased.get("ok")),
                                      "note": "match NOT started; range stays "
                                              "reserved, fix the cause and "
                                              "begin again"})
        # UPTIME SCORING (pilot step 5): Begin starts the probe loop TOGETHER
        # with the clock + attack worker; samples are identity-bound to the
        # ready deployment generation.
        from srplatform import uptime
        dep = db.execute(select(Deployment).where(
            Deployment.session_id == sess.session_id,
            Deployment.status == "ready")
            .order_by(Deployment.created_at.desc())).scalars().first()
        uptime.start_for_session(db, sess, dep)
        # INJECTS (plan 13 phase 6): the trusted server derives the
        # release/deadline schedule from the FROZEN snapshot duration —
        # clients can never move it; a disabled inject set releases
        # nothing. Idempotent: a duplicate Begin re-reads, never re-times.
        from srplatform import injects as injects_svc
        from srplatform.scenario_engine.loader import load_scenario
        injects_svc.schedule(db, sess.session_id, m,
                             load_scenario(sess.scenario_id),
                             actor=p.username)
        _ok = True
        return {"ok": True, "run_id": str(run.run_id), "status": "running",
                "session_id": str(sess.session_id),
                "started_at": m.started_at.isoformat() if m and m.started_at else None,
                "deadline_at": m.deadline_at.isoformat() if m and m.deadline_at else None,
                "duration_minutes": m.duration_minutes if m else None,
                "pace_seconds": m.pace_seconds if m else None}
    finally:
        _release_claim_safely(db, sess.session_id, _ok, _claim_owner)


@app.get("/sessions/{session_id}/injects")
def list_injects(session_id: uuid.UUID, p: Principal = Depends(any_member),
                 db: DbSession = None):
    """Inject inbox: what is released, when it closes, and the outcome —
    per-session access enforced at the API (competition visibility is not
    a UI concern). Verification internals stay server-side."""
    from srplatform import injects as injects_svc
    from srplatform.db.models import InjectRelease
    sess = _get_session(db, p, session_id)
    injects_svc.expire_releases(db, sess.session_id)
    rows = db.execute(select(InjectRelease).where(
        InjectRelease.session_id == sess.session_id)
        .order_by(InjectRelease.scheduled_at)).scalars().all()
    return {"releases": [{
        "release_id": str(r.release_id), "inject_id": r.inject_id,
        "kind": r.kind, "status": r.status,
        "description": injects_svc.CATALOG[r.inject_id]["description"],
        "scheduled_at": r.scheduled_at.isoformat(),
        "deadline_at": r.deadline_at.isoformat(),
        "submitted_at": r.submitted_at.isoformat() if r.submitted_at else None,
        "submissions": r.submissions} for r in rows],
        "score": injects_svc.summary(db, sess.session_id)}


class InjectSubmission(BaseModel):
    content: dict | str | None = None


@app.post("/sessions/{session_id}/injects/{release_id}")
def submit_inject(session_id: uuid.UUID, release_id: uuid.UUID,
                  body: InjectSubmission, p: Principal = Depends(any_member),
                  db: DbSession = None):
    """One identity-bound submission. The FIRST answer decides; duplicates
    count but never re-decide; the first answer after the deadline is
    `late`; written work is advisory (never verified points); an
    unverifiable moment keeps the release open instead of scoring a
    failure. Releases that are not yet open are refused, not queued."""
    from srplatform import injects as injects_svc
    from srplatform.db.models import InjectRelease
    sess = _get_session(db, p, session_id)
    rel = db.get(InjectRelease, release_id)
    if rel is None or rel.session_id != sess.session_id:
        raise HTTPException(404, {"error": "no_such_release"})
    injects_svc.expire_releases(db, sess.session_id)
    result = injects_svc.submit(db, rel, actor=p.username,
                                content=body.content)
    if result["status"] == "not_released":
        raise HTTPException(409, result)
    return result


@app.get("/runs/{run_id}")
def get_run(run_id: uuid.UUID, p: Principal = Depends(any_member), db: DbSession = None):
    run = db.get(Run, run_id)
    if run is None:
        raise HTTPException(404, "run not found")
    _get_session(db, p, run.session_id)
    return {"run_id": str(run.run_id), "status": run.status, "outcome": run.outcome,
            "started_at": run.started_at.isoformat() if run.started_at else None,
            "ended_at": run.ended_at.isoformat() if run.ended_at else None,
            "result": run.result, "error": run.error}


@app.post("/runs/{run_id}/stop")
def stop_run(run_id: uuid.UUID, p: Principal = Depends(any_member), db: DbSession = None):
    run = db.get(Run, run_id)
    if run is None:
        raise HTTPException(404, "run not found")
    _get_session(db, p, run.session_id)
    return runs_svc.stop_run(db, run_id)


class ModelCompleteIn(BaseModel):
    name: str = "red-turn"
    system: str
    user: str


@app.post("/internal/model/complete")
def internal_model_complete(body: ModelCompleteIn, p: Principal = Depends(service("runner"))):
    """ONE SHARED MODEL SCHEDULER (audit Stage 5): the worker's red turns are
    scheduled through the SAME gateway that serves interactive hints and AARs
    in this process — an interactive hint jumps the queue ahead of queued red
    turns ACROSS PROCESSES. The run-scoped capability is the authorization;
    no direct model credential ever reaches the worker. A running request is
    never preempted (documented bound); queue overflow is a visible 503."""
    from srplatform.model_gateway import PRIORITY_RED, QueueFull, get_model_gateway
    from srplatform.red_agent.llm import LLM
    if len(body.system) + len(body.user) > 200_000:
        raise HTTPException(413, "model request too large")
    s = get_settings()
    llm = LLM()
    try:
        fut = get_model_gateway().submit(PRIORITY_RED, f"{p.session_id}:{body.name}",
                                         llm.complete, body.system, body.user)
        text = get_model_gateway().wait(fut, s.llm_timeout_s + s.model_hint_max_wait_s + 60)
    except QueueFull:
        raise HTTPException(503, "model gateway saturated — retry the turn shortly")
    except TimeoutError:
        raise HTTPException(504, "model turn exceeded its bound")
    return {"text": text}


@app.post("/internal/runs/{run_id}/complete")
def run_complete(run_id: uuid.UUID, result: dict,
                 x_worker_token: str | None = Header(default=None),
                 db: DbSession = None):
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


# --- durable command-operation inventory (audit T01) ----------------------------
class OperationIn(BaseModel):
    op_id: str = Field(min_length=8, max_length=64)
    kind: str = "remote"          # remote | local


class OperationDoneIn(BaseModel):
    state: str = "completed"      # completed | cancel-unknown
    detail: str | None = None     # truthful containment verdict (audit T-04)


def _require_worker(db, run_id: uuid.UUID, token: str | None):
    run = db.get(Run, run_id)
    if run is None:
        raise HTTPException(404, "run not found")
    if not runs_svc.verify_worker_token(run, token):
        raise HTTPException(403, "bad worker token")
    return run


def _require_worker_locked(db, run_id: uuid.UUID, token: str | None):
    """Worker-authenticated run lookup holding the ROW LOCK until the request
    transaction ends (audit T-04): serializes operation registration against
    the guarded terminal transitions in stop_run/complete_run."""
    run = db.execute(select(Run).where(Run.run_id == run_id)
                     .with_for_update()).scalar_one_or_none()
    if run is None:
        raise HTTPException(404, "run not found")
    if not runs_svc.verify_worker_token(run, token):
        raise HTTPException(403, "bad worker token")
    return run


@app.post("/internal/runs/{run_id}/operations", status_code=201)
def register_run_operation(run_id: uuid.UUID, body: OperationIn,
                           x_worker_token: str | None = Header(default=None),
                           db: DbSession = None):
    """Persist a command operation BEFORE dispatch, associated with the run
    and the CURRENT deployment generation (audit T01). This is what lets the
    API recover and cancel the operation after worker death — the identity is
    never only in the worker's memory.

    SERIALIZED WITH STOP/FINALIZATION (audit T-04): registration holds the
    run row lock and is REFUSED for any status beyond queued/running — a
    stopping or cancel-unknown run is owned by the termination path, and an
    operation registered after the stop's containment pass could otherwise
    survive a 'cancelled' run. The guarded terminal transitions refuse to
    finalize while any operation is unresolved, so both sides of the race
    resolve to 'no active operation on a terminal run'."""
    from srplatform import verification_service
    from srplatform.db.models import RunOperation
    run = _require_worker_locked(db, run_id, x_worker_token)
    if run.status not in runs_svc.SPAWNNABLE:
        raise HTTPException(409, f"run is {run.status} — new command registration "
                                 "is refused until the termination path resolves "
                                 "every operation")
    if body.kind not in ("remote", "local"):
        raise HTTPException(422, "kind must be remote or local")
    existing = db.execute(select(RunOperation).where(RunOperation.run_id == run_id,
                                                     RunOperation.op_id == body.op_id)
                          ).scalars().first()
    if existing:
        return {"ok": True, "id": existing.id, "idempotent": True}
    # DOCUMENTED TEST SEAM (inert unless set): run a command WHILE HOLDING the
    # run-row lock, after the status fence and before the INSERT, so barrier
    # tests can pin the registration-vs-finalization interleaving (audit F2).
    # Production never sets it.
    _hook = os.environ.get("SR_TEST_REGISTER_HOOK")
    if _hook:
        import subprocess as _sp
        _sp.run(["/bin/sh", "-c", _hook], timeout=120, check=False)
    dep = verification_service.active_deployment(db, run.session_id)
    op = RunOperation(run_id=run.run_id, session_id=run.session_id,
                      deployment_id=dep.deployment_id if dep else None,
                      op_id=body.op_id, kind=body.kind, state="active")
    db.add(op)
    db.commit()
    return {"ok": True, "id": op.id}


@app.post("/internal/runs/{run_id}/operations/{op_id}/done")
def complete_run_operation(run_id: uuid.UUID, op_id: str, body: OperationDoneIn,
                           x_worker_token: str | None = Header(default=None),
                           db: DbSession = None):
    """Worker reports the operation finished. 'completed' is only accepted
    from the worker; unconfirmed cancellations are set by the API's own
    recovery paths and are never downgraded here. The containment verdict
    (surviving-descendant containment, unconfirmed-stop reason) is PERSISTED
    with the row (audit T-04)."""
    from sqlalchemy import update as sa_update
    from srplatform.db.models import RunOperation
    _require_worker(db, run_id, x_worker_token)
    if body.state not in ("completed", "cancel-unknown"):
        raise HTTPException(422, "state must be completed or cancel-unknown")
    res = db.execute(sa_update(RunOperation)
                     .where(RunOperation.run_id == run_id,
                            RunOperation.op_id == op_id,
                            RunOperation.state == "active")
                     .values(state=body.state,
                             detail=str(body.detail)[:2000] if body.detail else None,
                             ended_at=_now() if body.state == "completed" else None))
    db.commit()
    return {"ok": True, "updated": res.rowcount}


# --- trusted verification (backend executes; request is not a result) ----------
class VerifierCheckIn(BaseModel):
    objective_id: str


@app.get("/sessions/{session_id}/scenario")
def session_scenario(session_id: uuid.UUID,
                     p: Principal = Depends(principal), db: DbSession = None):
    """The session's IMMUTABLE scenario snapshot (audit N10): the worker and
    every consumer resolve objectives/targets from the bytes captured at
    session creation — never from the mutable current YAML. The run-scoped
    runner token may read only its own session's snapshot."""
    from srplatform import verification_service
    if p.kind == "service":
        if p.scope != "runner" or str(p.session_id) != str(session_id):
            raise HTTPException(403, "runner token does not match this session")
    else:
        _get_session(db, p, session_id)
    try:
        spec = verification_service.scenario_spec(db, session_id)
    except ValueError:
        raise HTTPException(404, "session not found")
    return {"session_id": str(session_id), "scenario": spec}


@app.post("/sessions/{session_id}/verifier_checks")
def verifier_check(session_id: uuid.UUID, body: VerifierCheckIn,
                   p: Principal = Depends(principal), db: DbSession = None):
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
                 db: DbSession = None):
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
                 db: DbSession = None):
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
    out = [_event_json(r) for r in rows]
    if getattr(p, "kind", None) == "member" and not p.is_operator:
        # competition filtering is per-SESSION (a member may own sessions
        # in different modes): seal red internals session by session.
        cache: dict[str, object] = {}
        if session_id is not None and sess is not None:
            cache[str(sess.session_id)] = sess
        filtered = []
        for ev in out:
            sid = ev.get("session_id")
            if sid not in cache:
                try:
                    cache[sid] = db.get(SessionModel, uuid.UUID(sid)) \
                        if sid else None
                except Exception:  # noqa: BLE001 — unresolvable: unfiltered
                    cache[sid] = None
            s = cache[sid]
            filtered.append(_apply_competition_filter(db, s, p, ev)
                            if s is not None else ev)
        out = filtered
    return out


def _event_json(r: Event) -> dict:
    return {"event_id": r.event_id, "session_id": str(r.session_id) if r.session_id else None,
            "ts": r.ts.isoformat() if r.ts else None,
            "ingested_at": r.ingested_at.isoformat() if r.ingested_at else None,
            "actor": r.actor, "host": r.host, "action_type": r.action_type,
            "phase": r.phase, "mitre_technique": r.mitre_technique, "payload": r.payload,
            "raw_ref": r.raw_ref, "raw_output_hash": r.raw_output_hash}


from srplatform.api.visibility import (
    competition_sealed as _competition_sealed,
    filter_event as _filter_one_event,
    filter_scorecard as _filter_card,
)


def _apply_competition_filter(db, sess, p, ev: dict) -> dict:
    return _filter_one_event(db, sess, p, ev)


# --- safety (operator-only; no arbitrary PIDs) -----------------------------------
@app.post("/safety/killswitch")
def killswitch(p: Principal = Depends(operator)):
    from sqlalchemy import select as sa_select
    extra = []
    try:
        with db() as s:
            for r in s.execute(sa_select(Run).where(
                    Run.status.in_(runs_svc.ACTIVE))).scalars():
                if r.pgid:
                    extra.append((str(r.run_id), int(r.pgid), r.pgid_pstart))
    except Exception:
        pass  # the latch still engages; the DB problem is visible in the result below
    # recovered groups are PASSED TO THE KILL (audit R03) — reporting them as
    # "recovered_groups" without terminating them was the fail-open bug.
    result = get_supervisor().engage(reason=f"killswitch by {p.username}",
                                     extra_groups=extra)
    # REMOTE containment (audit T01): killing local workers proves nothing
    # about commands already dispatched to the isolated runner. Every active
    # remote operation is cancelled through the control channel and the
    # verdict is reported truthfully (unconfirmed stays visible).
    try:
        remote = runs_svc.cancel_all_active_remote_operations()
        result["remote_operations"] = remote
        if not remote["ok"]:
            result["killswitch"] = "engaged-partial"
            result.setdefault("warning", "")
            result["warning"] += (" Remote command cessation UNCONFIRMED — "
                                  "range reservation retained. ")
    except Exception as e:  # noqa: BLE001 — visible, never silent
        result["remote_operations"] = {"ok": False, "detail": f"remote cancellation raised: {e}"}
        result["killswitch"] = "engaged-partial"
    return result


@app.post("/safety/killswitch-release")
def killswitch_release(p: Principal = Depends(operator)):
    return get_supervisor().release()


@app.get("/safety/status")
def safety_status(p: Principal = Depends(operator)):
    return get_supervisor().verify()


@app.get("/safety/panel")
def safety_panel(p: Principal = Depends(operator), db: DbSession = None):
    """Operator safety panel (plan 13 phase 7): BOTH latch states side by
    side — the supervisor killswitch latch (local workers + datapath) and
    the broker's independent cessation authority (remote commands on the
    isolated runner) — plus the authorized recovery procedure. Read-only:
    broker-local release authority stays behind ITS OWN endpoint; no
    browser action moves it here."""
    from srplatform.api.deps import get_broker
    sup = get_supervisor().latch_status()
    try:
        broker_latch = get_broker().latch_status()
    except Exception as e:  # noqa: BLE001 — a panel never 500s
        broker_latch = {"ok": False, "detail": str(e)[:200]}
    executors = []
    try:
        from srplatform.scenario_engine import deploy_executor
        executors = deploy_executor.live_executors()
    except Exception:  # noqa: BLE001
        pass
    return {
        "supervisor_latch": sup,
        "broker_cessation": broker_latch,
        "live_deploy_executors": executors,
        "recovery_procedure": [
            "1. Confirm the range is quiet: no live_deploy_executors, no "
            "active runs (GET /runs/active).",
            "2. Confirm remote cessation: broker_cessation must report "
            "confirmed stop for every dispatched remote operation.",
            "3. Only then release: POST /safety/killswitch-release "
            "(supervisor latch) through the broker's OWN release endpoint "
            "for broker-local authority — never from this panel.",
            "4. Re-verify: GET /safety/panel must show both latches clear.",
        ],
    }


class BaselineCheckIn(BaseModel):
    ok: bool | None = None      # omitted => the controller's own live status


@app.post("/safety/baseline-check")
def safety_baseline_check(body: BaselineCheckIn, p: Principal = Depends(operator)):
    """Run the backend's baseline verification and record the outcome.

    Audit R04: an operator attestation may record a FAILED check honestly, but
    can never override a failed live backend check to `ok=True` — that turned
    the evidence trail into a rubber stamp. A live verdict of None (static
    datapath: no backend check exists) is NOT a failure — the operator's
    explicit attestation is the evidence there, and the datapath proof
    carries the live observations."""
    sup = get_supervisor()
    live = sup.datapath.baseline_status()
    if body.ok and live["ok"] is False:
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
                    p: Principal = Depends(principal), db: DbSession = None):
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
                    db: DbSession = None):
    st = db.get(AgentState, session_id)
    if not st:
        raise HTTPException(404, "no agent state")
    if p.kind == "service":
        if not (p.scope == "runner" and str(p.session_id) == str(session_id)):
            raise HTTPException(403, "runner token mismatch")
    else:
        sess = _get_session(db, p, session_id)
        # the red worker's working memory (plan/summary/phase) is pure
        # spoiler in competition mode — sealed until the match completes.
        from srplatform.api.visibility import competition_sealed
        if competition_sealed(db, sess, p):
            raise HTTPException(403, {"error": "competition_sealed",
                                      "detail": "agent memory is sealed until "
                                                "the match completes"})
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
                         db: DbSession = None):
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
              db: DbSession = None):
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
    # Authoritative generation-bound pin for the dial target (the broker
    # pinned it as deployment evidence; the bastion verifies the guest
    # against THIS in memory instead of a copied file that rots on
    # relaunch). None when no ready deployment carries it — the proxy must
    # refuse rather than TOFU or trust a stale copy.
    host_key = None
    if t.session_id is not None:
        dep = db.execute(select(Deployment).where(
            Deployment.session_id == t.session_id,
            Deployment.status == "ready").order_by(
            Deployment.created_at.desc())).scalars().first()
        if dep is not None:
            for r in (dep.resources or []):
                if isinstance(r, dict) and r.get("ip") == t.target_host \
                        and r.get("host_key_ref"):
                    host_key = r["host_key_ref"]
                    break
    return {"token": t.token, "session_id": str(t.session_id) if t.session_id else None,
            "target_host": t.target_host, "target_port": int(t.target_port),
            "user_id": str(t.user_id) if t.user_id else None,
            "username": owner.username if owner else None,
            "target_host_key": host_key}


# --- enrollment confirmation (host-originated, audit T-05) ----------------------
class EnrollConfirmIn(BaseModel):
    nonce: str = Field(min_length=8, max_length=64)
    machine_id: str | None = None
    boot_id: str | None = None


@app.post("/enroll/confirm", status_code=201)
def enroll_confirm(body: EnrollConfirmIn, p: Principal = Depends(service("telemetry")),
                   db: DbSession = None):
    """AUTHENTICATED ENROLLMENT CALLBACK FROM THE PROVISIONED HOST (audit
    T-05, hardened for audit F4): evidence updates the EXACT authenticated
    ServiceToken — never 'the newest row for this session/host'. A stale or
    foreign capability presenting another enrollment's nonce is rejected; an
    obsolete deployment generation (torn_down/failed) is rejected; revoked or
    expired capabilities never reach this route. Confirmation is idempotent
    under CONCURRENCY (guarded single-row update: exactly one timestamp,
    exactly one event)."""
    import secrets as _secrets
    from sqlalchemy import update as sa_update
    tok = db.get(ServiceToken, p.token) if p.token else None
    if (tok is None or tok.scope != "telemetry" or tok.revoked_at is not None
            or str(tok.session_id) != str(p.session_id) or tok.host != p.host):
        raise HTTPException(403, "no enrollment pending for this capability/nonce")
    if tok.enrollment_deployment_id is not None:
        dep = db.get(Deployment, tok.enrollment_deployment_id)
        if dep is not None and dep.status in ("torn_down", "failed"):
            raise HTTPException(403, "enrollment belongs to an obsolete deployment "
                                     "generation — re-enroll against the current one")
    if not _secrets.compare_digest(tok.enroll_nonce or "", body.nonce):
        raise HTTPException(403, "no enrollment pending for this capability/nonce")
    now = _now()
    res = db.execute(sa_update(ServiceToken)
                     .where(ServiceToken.token == p.token,
                            ServiceToken.enroll_confirmed_at.is_(None))
                     .values(enroll_confirmed_at=now))
    db.commit()
    if res.rowcount:
        _log_event(db, p.session_id, "system", p.host, "telemetry_enroll_confirmed",
                   {"deployment_id": (str(tok.enrollment_deployment_id)
                                      if tok.enrollment_deployment_id else None),
                    "machine_id": body.machine_id, "boot_id": body.boot_id,
                    "note": "authenticated callback from the provisioned host — "
                            "API address, token and delivery path PROVEN"})
    db.refresh(tok)
    return {"ok": True, "confirmed_at": tok.enroll_confirmed_at.isoformat()}


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
                  db: DbSession = None):
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
    # CAPTURE ACCEPTANCE (audit T-05, hardened for audit F4): if this batch
    # carries the enrollment's capture-probe marker, a harmless command has
    # been observed AS AN AUDIT EVENT THROUGH THE INSTALLED SERVICE under its
    # actual identity — the input path and command capture are proven, not
    # assumed. The evidence updates the EXACT authenticated capability, never
    # 'the newest row for this session/host', and is idempotent under
    # concurrency (guarded single-row update).
    if accepted and p.token:
        from sqlalchemy import update as sa_update
        tok = db.get(ServiceToken, p.token)
        if (tok is not None and tok.scope == "telemetry" and tok.revoked_at is None
                and tok.enroll_nonce and tok.enroll_capture_at is None):
            from srplatform.scenario_engine.orchestrator import capture_marker
            marker = capture_marker(tok.enroll_nonce)
            for rec in body.events:
                if rec.argv and marker in rec.argv:
                    now = _now()
                    res = db.execute(sa_update(ServiceToken)
                                     .where(ServiceToken.token == p.token,
                                            ServiceToken.enroll_capture_at.is_(None))
                                     .values(enroll_capture_at=now))
                    db.commit()
                    if res.rowcount:
                        _log_event(db, p.session_id, "system", p.host,
                                   "telemetry_capture_verified",
                                   {"marker": marker,
                                    "note": "harmless command observed through the "
                                            "installed service — capture PROVEN"})
                    break
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
# NOTE: the ingest-only listener (SR_API_INGEST_ONLY=1, plan 13 phase 4) is
# a SECOND copy of this application serving the guest range address. It
# must NEVER reconcile runs, clear operation claims, start heartbeats or
# run the match scheduler: those belong to the single internal instance,
# and a listener restart would otherwise interrupt live operations and
# remove their serialization. The listener serves ingest routes only.
@app.on_event("startup")
def _startup():
    from srplatform.settings import get_settings as _gs0
    ingest_only = _gs0().api_ingest_only
    if ingest_only:
        return
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
    # milestone 02: wire the independent broker cessation layer into the
    # supervisor, and run the control-lease heartbeat when a real broker is
    # configured (the broker's own watchdog stops the range if we die).
    try:
        from srplatform.api import deps
        from srplatform.safety import get_supervisor
        from srplatform.settings import get_settings
        sup = get_supervisor()
        if sup.broker is None:
            try:
                sup.broker = deps.get_broker()
            except Exception:
                pass  # unconfigured broker: readiness reports it; killswitch
                # still latches + reports the layer honestly
        s = get_settings()
        if s.broker_url and sup.broker is not None:
            from srplatform.safety.lease import ControlHeartbeat
            hb = ControlHeartbeat(sup.broker, interval_s=s.broker_heartbeat_s)
            hb.start()
            app.state.control_heartbeat = hb
    except Exception:
        pass
    # PILOT STEP 4: match lifecycle — an API restart INTERRUPTS running
    # matches (never resumes them) and retries interrupted cleanup; the
    # scheduler enforces idle expiry + deadlines. Opt-in
    # (SR_MATCH_SCHEDULER_ENABLED=1) so shared-database test processes never
    # run background cleanup; tests drive lifecycle.tick directly.
    try:
        from srplatform.settings import get_settings as _gs4
        s4 = _gs4()
        if s4.match_scheduler_enabled:
            from srplatform import lifecycle
            from srplatform.api import deps as _deps4
            from srplatform.db.session import db as _db4
            broker4 = _deps4.get_broker()
            with _db4() as s:
                lifecycle.reconcile_on_startup(s, broker=broker4)
            lifecycle.start_scheduler(interval_s=s4.match_scheduler_interval_s)
    except Exception:
        pass  # the scheduler retries every tick; startup must not crash
