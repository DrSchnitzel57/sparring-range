"""FastAPI app — THE single front door (Part 3). rangectl today and the web app
(M7) are both just clients of this service; nothing else touches Postgres.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import Depends, FastAPI, HTTPException
from pydantic import BaseModel
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from srplatform.db.models import AgentState, Event, LoginToken, Session as SessionModel, User
from srplatform.db.session import db
from srplatform.safety import get_supervisor

app = FastAPI(title="sparring-range API", version="0.1.0")

# M5 coach routes (AAR + Socratic hints on a priority queue)
from srplatform.api.coach_routes import router as coach_router  # noqa: E402

app.include_router(coach_router)


def get_db():
    with db() as s:
        yield s


# --- health -------------------------------------------------------------------
@app.get("/healthz")
def healthz():
    return {"ok": True}


# --- sessions -----------------------------------------------------------------
class SessionCreate(BaseModel):
    scenario_id: str
    username: str | None = None
    players: dict | None = None


@app.post("/sessions", status_code=201)
def create_session(body: SessionCreate, db: Session = Depends(get_db)):
    user = None
    if body.username:
        user = db.execute(select(User).where(User.username == body.username)).scalar_one_or_none()
    sess = SessionModel(scenario_id=body.scenario_id, user_id=user.user_id if user else None, players=body.players)
    db.add(sess)
    db.flush()
    _log_event(db, sess.session_id, "system", None, "session_start", {"scenario_id": body.scenario_id})
    return {"session_id": str(sess.session_id)}


@app.get("/sessions")
def list_sessions(db: Session = Depends(get_db)):
    rows = db.execute(select(SessionModel).order_by(SessionModel.started_at)).scalars().all()
    return [
        {
            "session_id": str(r.session_id),
            "scenario_id": r.scenario_id,
            "user_id": str(r.user_id) if r.user_id else None,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "ended_at": r.ended_at.isoformat() if r.ended_at else None,
            "status": r.status,
        }
        for r in rows
    ]


@app.post("/sessions/{session_id}/end")
def end_session(session_id: uuid.UUID, db: Session = Depends(get_db)):
    sess = db.get(SessionModel, session_id)
    if not sess:
        raise HTTPException(404, "session not found")
    sess.status = "complete"  # sessions are mutable; the *log* is append-only
    sess.ended_at = datetime.now(timezone.utc)
    _log_event(db, session_id, "system", None, "session_end", {})
    return {"ok": True}


# --- event ingest (append-only writes; the log is the product) ------------------
class EventIn(BaseModel):
    session_id: uuid.UUID | None = None
    ts: datetime | None = None
    actor: str  # 'red' | 'blue:<user>' | 'system' | 'telemetry'
    host: str | None = None
    action_type: str  # 'tool_call'|'command'|'detection'|'verifier'|'hint'|'aar'
    phase: str | None = None
    mitre_technique: str | None = None
    payload: dict
    raw_ref: str | None = None
    raw_output_hash: str | None = None


@app.post("/events", status_code=201)
def ingest_event(body: EventIn, db: Session = Depends(get_db)):
    _log_event(
        db,
        body.session_id,
        body.actor,
        body.host,
        body.action_type,
        body.payload,
        phase=body.phase,
        mitre_technique=body.mitre_technique,
        raw_ref=body.raw_ref,
        raw_output_hash=body.raw_output_hash,
        ts=body.ts,
    )
    return {"ok": True}


@app.get("/events")
def query_events(
    session_id: uuid.UUID | None = None,
    action_type: str | None = None,
    actor: str | None = None,
    limit: int = 500,
    db: Session = Depends(get_db),
):
    q = select(Event).order_by(Event.ts, Event.event_id).limit(min(limit, 5000))
    if session_id:
        q = select(Event).where(Event.session_id == session_id).order_by(Event.ts, Event.event_id).limit(min(limit, 5000))
    if action_type:
        q = q.where(Event.action_type == action_type)
    if actor:
        q = q.where(Event.actor == actor)
    rows = db.execute(q).scalars().all()
    return [
        {
            "event_id": r.event_id,
            "session_id": str(r.session_id) if r.session_id else None,
            "ts": r.ts.isoformat() if r.ts else None,
            "ingested_at": r.ingested_at.isoformat() if r.ingested_at else None,
            "actor": r.actor,
            "host": r.host,
            "action_type": r.action_type,
            "phase": r.phase,
            "mitre_technique": r.mitre_technique,
            "payload": r.payload,
            "raw_ref": r.raw_ref,
            "raw_output_hash": r.raw_output_hash,
        }
        for r in rows
    ]


# --- safety (hard constraints live behind this API too) -------------------------
@app.post("/safety/killswitch")
def killswitch():
    return get_supervisor().killswitch()


@app.post("/safety/killswitch-release")
def killswitch_release():
    return get_supervisor().release()


@app.get("/safety/verify")
def safety_verify():
    return get_supervisor().verify()


class PidIn(BaseModel):
    pid: int


@app.post("/safety/register-pid")
def register_red_agent_pid(body: PidIn):
    """A red-agent process (possibly in another process/service) registers itself
    so the killswitch can stop it — constraint #2 across process boundaries."""
    get_supervisor().register_red_agent(body.pid)
    return {"ok": True}


# --- agent_state (M3): rolling red-agent memory, via the front door --------------
class AgentStateIn(BaseModel):
    summary: str | None = None
    summary_upto: int | None = None
    current_phase: str | None = None


@app.put("/agent_state/{session_id}")
def put_agent_state(session_id: uuid.UUID, body: AgentStateIn, db: Session = Depends(get_db)):
    st = db.get(AgentState, session_id)
    if not st:
        st = AgentState(session_id=session_id)
        db.add(st)
        db.flush()
    # agent_state is mutable working memory — the ONLY non-append-only table,
    # and it holds no evidence, only derived context.
    if body.summary is not None:
        st.summary = body.summary
    if body.summary_upto is not None:
        st.summary_upto = body.summary_upto
    if body.current_phase is not None:
        st.current_phase = body.current_phase
    return {"ok": True}


@app.get("/agent_state/{session_id}")
def get_agent_state(session_id: uuid.UUID, db: Session = Depends(get_db)):
    st = db.get(AgentState, session_id)
    if not st:
        raise HTTPException(404, "no agent state")
    return {"session_id": str(st.session_id), "summary": st.summary,
            "summary_upto": st.summary_upto, "current_phase": st.current_phase}


# --- run (M3): start the red agent loop for a session -----------------------------
class RunIn(BaseModel):
    session_id: uuid.UUID


@app.post("/run/{scenario_id}")
def run_scenario(scenario_id: str, body: RunIn):
    """Start the red agent loop in a background thread (dev/prod single-host).
    The loop itself registers with the safety supervisor, so the killswitch
    can stop it (constraint #2)."""
    import threading

    from srplatform.red_agent.llm import LLM
    from srplatform.red_agent.loop import RedAgentLoop
    from srplatform.red_agent.sandbox import KaliSandbox
    from srplatform.red_agent.transport import HttpTransport
    from srplatform.settings import get_settings as gs

    def _go():
        loop = RedAgentLoop(str(body.session_id), scenario_id, HttpTransport(gs().api_base_url), LLM(), KaliSandbox())
        loop.run()

    threading.Thread(target=_go, daemon=True).start()
    return {"ok": True, "session_id": str(body.session_id)}


# --- deploy layer (M1) — the API front door for scenario spin-up ----------------
class DeployIn(BaseModel):
    session_id: uuid.UUID | None = None


def _proxmox_for_request():
    from srplatform.api.deps import get_proxmox

    return get_proxmox()


@app.get("/scenarios")
def scenarios_list():
    from srplatform.scenario_engine.loader import list_scenarios

    return list_scenarios()


@app.post("/deploy/{scenario_id}")
def deploy_scenario(scenario_id: str, body: DeployIn | None = None):
    from srplatform.scenario_engine import orchestrator

    return orchestrator.deploy(scenario_id, _proxmox_for_request(),
                               session_id=body.session_id if body else None)


@app.post("/deploy/{scenario_id}/reset")
def reset_scenario(scenario_id: str, body: DeployIn | None = None):
    from srplatform.scenario_engine import orchestrator

    return orchestrator.reset(scenario_id, _proxmox_for_request(),
                              session_id=body.session_id if body else None)


@app.post("/deploy/{scenario_id}/teardown")
def teardown_scenario(scenario_id: str, body: DeployIn | None = None):
    from srplatform.scenario_engine import orchestrator

    return orchestrator.teardown(scenario_id, _proxmox_for_request(),
                                 session_id=body.session_id if body else None)


# --- login tokens (bastion target selection, M2) --------------------------------
class TokenIn(BaseModel):
    token: str
    target_host: str
    target_port: int = 22
    session_id: uuid.UUID | None = None


@app.post("/tokens", status_code=201)
def create_token(body: TokenIn, db: Session = Depends(get_db)):
    if db.get(LoginToken, body.token):
        raise HTTPException(409, "token exists")
    db.add(LoginToken(token=body.token, target_host=body.target_host,
                      target_port=body.target_port, session_id=body.session_id))
    return {"ok": True}


@app.get("/tokens/{token}")
def get_token(token: str, db: Session = Depends(get_db)):
    t = db.get(LoginToken, token)
    if not t or t.revoked_at is not None:
        raise HTTPException(404, "token not found")
    return {"token": t.token, "session_id": str(t.session_id) if t.session_id else None,
            "target_host": t.target_host, "target_port": int(t.target_port)}


# --- auditd ingest (M2): execve truth from range hosts, tied to live session ----
class AuditdIn(BaseModel):
    host: str
    ts: str | datetime | None = None
    uid: str | int | None = None
    comm: str | None = None
    exe: str | None = None
    argv: str | None = None
    raw: dict | None = None


@app.post("/ingest/auditd", status_code=201)
def ingest_auditd(body: AuditdIn, db: Session = Depends(get_db)):
    """Records auditd execve events as action_type='command'. The live session is
    resolved via active login tokens for this host (M2 acceptance: correct
    session_id). auditd — not the bastion PTY — is the command source of truth."""
    tok = db.execute(
        select(LoginToken)
        .where(LoginToken.target_host == body.host, LoginToken.revoked_at.is_(None))
        .order_by(LoginToken.created_at.desc())
    ).scalars().first()
    session_id = tok.session_id if tok else None
    _log_event(
        db, session_id, "telemetry", body.host, "command",
        {"source": "auditd", "uid": body.uid, "comm": body.comm, "exe": body.exe, "argv": body.argv,
         "raw": body.raw},
    )
    return {"ok": True, "session_id": str(session_id) if session_id else None}


# --- shared helper ---------------------------------------------------------------
def _log_event(db: Session, session_id, actor, host, action_type, payload, phase=None,
               mitre_technique=None, raw_ref=None, raw_output_hash=None, ts=None):
    ev = Event(
        session_id=session_id,
        ts=ts or datetime.now(timezone.utc),
        actor=actor,
        host=host,
        action_type=action_type,
        phase=phase,
        mitre_technique=mitre_technique,
        payload=payload,
        raw_ref=raw_ref,
        raw_output_hash=raw_output_hash,
    )
    db.add(ev)
    db.flush()
    return ev


# Keep imports referenced for later routers
_ = (AgentState, LoginToken, text)
