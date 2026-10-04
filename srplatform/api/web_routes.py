"""M7 web endpoints: accounts/login (simple LAN tokens), replay data, progress.
Every response here is either a query over the event log or a read of a .cast
recording — the web app is just another view over the same front door."""
from __future__ import annotations

import json
import secrets
import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import text as sa_text
from sqlalchemy.orm import Session

from srplatform.db.models import Event, User, WebToken
from srplatform.db.session import db as _db_ctx
from srplatform.settings import get_settings

router = APIRouter()


def get_db():
    with _db_ctx() as s:
        yield s


# --- accounts & login -------------------------------------------------------------
class UserIn(BaseModel):
    username: str
    display_name: str | None = None


@router.post("/users", status_code=201)
def create_user(body: UserIn, db: Session = Depends(get_db)):
    """Member accounts (LAN gym members — created by Drew from the UI or CLI)."""
    if db.query(User).filter(User.username == body.username).first():
        raise HTTPException(409, "exists")
    u = User(username=body.username, display_name=body.display_name)
    db.add(u)
    db.flush()
    return {"user_id": str(u.user_id), "username": u.username}


class LoginIn(BaseModel):
    username: str


@router.post("/auth/login")
def login(body: LoginIn, db: Session = Depends(get_db)):
    """Simple session token for a known member (no password prompt on a home LAN —
    hard constraint #6 says this is the trust boundary; add keys per member if
    that changes)."""
    u = db.query(User).filter(User.username == body.username).first()
    if not u:
        raise HTTPException(404, "no such member — ask Drew to create your account")
    tok = secrets.token_hex(16)
    db.add(WebToken(token=tok, user_id=u.user_id))
    return {"token": tok, "user_id": str(u.user_id), "username": u.username}


def user_from_token(db: Session, token: str) -> User:
    wt = db.get(WebToken, token)
    if not wt:
        raise HTTPException(401, "bad token")
    u = db.get(User, wt.user_id)
    if not u:
        raise HTTPException(401, "bad token")
    return u


# --- replay data (asciinema cast files, streamed for the web player) ---------------
@router.get("/sessions/{session_id}/replay")
def replay(session_id: uuid.UUID, db: Session = Depends(get_db)):
    """Locate .cast recordings for a session (via bastion events' raw_ref) and
    return parsed frames for scrubbing, plus the event timeline to sync against."""
    events = db.execute(
        sa_text("SELECT event_id, ts, actor, action_type, phase, payload FROM events "
                "WHERE session_id = :sid ORDER BY ts, event_id"), {"sid": str(session_id)}
    ).fetchall()

    casts = []
    seen = set()
    for e in events:
        ref = (e.payload or {}).get("cast")
        if ref and ref not in seen:
            seen.add(ref)
            try:
                lines = open(ref, encoding="utf-8").read().splitlines()
                header = json.loads(lines[0])
                frames = [json.loads(l) for l in lines[1:]]
                casts.append({"name": ref.split("/")[-1], "header": header, "frames": frames})
            except OSError:
                casts.append({"name": ref.split("/")[-1], "header": None, "frames": []})

    timeline = [{"event_id": e.event_id, "ts": e.ts.isoformat(), "actor": e.actor,
                 "action_type": e.action_type, "phase": e.phase} for e in events]
    return {"session_id": str(session_id), "casts": casts, "timeline": timeline}


# --- progress dashboard (a VIEW over the log — no new tables) ----------------------
@router.get("/users/{username}/progress")
def progress(username: str, db: Session = Depends(get_db)):
    """Per-domain scores across sessions, trends, lagging skills. Domain labels come
    from scenario YAML metadata; the numeric facts come from v_session_scores."""
    rows = db.execute(sa_text(
        "SELECT DISTINCT ON (session_id) session_id, scenario_id, earned, total, scored_at "
        "FROM v_session_scores WHERE username = :u ORDER BY session_id, scored_at DESC"),
        {"u": username}).fetchall()

    from srplatform.scenario_engine.loader import scenarios_dir

    def focus_of(scenario_id: str) -> list[str]:
        p = scenarios_dir() / f"{scenario_id}.yaml"
        if not p.exists():
            return ["general"]
        import yaml
        return (yaml.safe_load(p.read_text()) or {}).get("focus") or ["general"]

    sessions_out, domains = [], {}
    for r in rows:
        pct = round(100 * r.earned / r.total) if r.total else None
        sessions_out.append({"session_id": str(r.session_id), "scenario_id": r.scenario_id,
                             "earned": r.earned, "total": r.total, "pct": pct,
                             "scored_at": r.scored_at.isoformat()})
        for d in focus_of(r.scenario_id):
            domains.setdefault(d, []).append(pct)

    per_domain = {d: {"avg_pct": round(sum(v) / len(v)) if v else None, "sessions": len(v)}
                  for d, v in domains.items()}
    lagging = sorted([d for d, m in per_domain.items() if m["avg_pct"] is not None],
                     key=lambda d: per_domain[d]["avg_pct"])[:2]
    return {"username": username, "sessions": sessions_out, "by_domain": per_domain,
            "lagging_domains": lagging}


# --- live dashboard helper: current red phase + recent detections -------------------
@router.get("/sessions/{session_id}/live")
def live(session_id: uuid.UUID, db: Session = Depends(get_db)):
    sess_row = db.execute(sa_text("SELECT started_at, status FROM sessions WHERE session_id=:sid"),
                          {"sid": str(session_id)}).first()
    if not sess_row:
        raise HTTPException(404, "session not found")
    state = db.execute(sa_text("SELECT current_phase, summary_upto FROM agent_state WHERE session_id=:sid"),
                       {"sid": str(session_id)}).first()
    recent = db.execute(sa_text(
        "SELECT event_id, ts, actor, action_type, phase, payload FROM events "
        "WHERE session_id=:sid ORDER BY event_id DESC LIMIT 12"), {"sid": str(session_id)}).fetchall()
    detections = [d for d in reversed(recent) if d.action_type in ("verifier", "detection")]
    return {
        "session_id": str(session_id), "status": sess_row.status,
        "started_at": sess_row.started_at.isoformat(),
        "red_phase": state.current_phase if state else None,
        "recent": [{"event_id": e.event_id, "ts": e.ts.isoformat(), "actor": e.actor,
                    "action_type": e.action_type, "phase": e.phase} for e in reversed(recent)],
        "detections": [{"event_id": d.event_id, "ts": d.ts.isoformat(),
                        "objective": (d.payload or {}).get("objective"),
                        "passed": (d.payload or {}).get("passed")} for d in detections],
    }
