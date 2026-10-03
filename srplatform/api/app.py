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
