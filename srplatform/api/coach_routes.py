"""Coach endpoints (M5), mounted into the API app."""
from __future__ import annotations

import uuid

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from srplatform.coach.aar import build_aar, build_hint
from srplatform.coach.queue import coach_queue
from srplatform.db.models import Event, Session as SessionModel
from srplatform.db.session import db as _db_ctx
from srplatform.scenario_engine.loader import load_scenario


def get_db():
    with _db_ctx() as s:
        yield s

router = APIRouter()

# coach model; injectable for tests (set_coach_llm). Falls back to None (pure
# deterministic report) if no model server answers — the payoff never dies
# with the GPU box.
_coach_llm = None


def set_coach_llm(llm) -> None:
    global _coach_llm
    _coach_llm = llm


def get_coach_llm():
    global _coach_llm
    if _coach_llm is None:
        try:
            from srplatform.red_agent.llm import LLM
            from srplatform.settings import get_settings

            llm = LLM(model=get_settings().llm_model_coach)
            llm.complete("ping", "ping")  # prove the endpoint answers or fall back
            _coach_llm = llm
        except Exception:
            _coach_llm = False  # don't keep probing a dead GPU box per request
    return _coach_llm or None


def _events_of(db: Session, sid: uuid.UUID) -> list[dict]:
    rows = db.execute(select(Event).where(Event.session_id == sid)
                      .order_by(Event.ts, Event.event_id)).scalars().all()
    return [{"event_id": r.event_id, "ts": r.ts.isoformat(), "actor": r.actor, "host": r.host,
             "action_type": r.action_type, "phase": r.phase, "mitre_technique": r.mitre_technique,
             "payload": r.payload} for r in rows]


def _scorecard_from_log(events: list[dict]) -> dict | None:
    for e in reversed(events):
        p = e.get("payload") or {}
        if e["action_type"] == "verifier" and "scorecard" in p:
            return p["scorecard"]
    return None


class HintIn(BaseModel):
    question: str = ""


@router.post("/sessions/{session_id}/hint")
def hint(session_id: uuid.UUID, body: HintIn, db: Session = Depends(get_db)):
    """Interactive (priority 0): never queues behind AAR/red batches (M5)."""
    sess = db.get(SessionModel, session_id)
    if not sess:
        raise HTTPException(404, "session not found")
    events = _events_of(db, session_id)
    llm = get_coach_llm()
    fut = coach_queue.submit(0, f"hint-{session_id}", build_hint, events, body.question, llm)
    result = fut.result(timeout=120)
    # hints are events too — the log is the product
    db.add(Event(session_id=session_id, ts=datetime.now(timezone.utc), actor="system", action_type="hint",
                 payload={"question": body.question, "hint": result["hint"]}))
    return result


class AarIn(BaseModel):
    narrative: bool = True


@router.post("/sessions/{session_id}/aar")
def aar(session_id: uuid.UUID, body: AarIn, db: Session = Depends(get_db)):
    sess = db.get(SessionModel, session_id)
    if not sess:
        raise HTTPException(404, "session not found")
    spec = load_scenario(sess.scenario_id)
    events = _events_of(db, session_id)
    scorecard = _scorecard_from_log(events)

    def _gen():
        llm = get_coach_llm()
        narrative = None
        if llm and body.narrative:
            from srplatform.coach.timeline import compress_timeline
            timeline, _ = compress_timeline(events, max_lines=40)
            narrative = llm.complete(
                "You are a CCDC coach writing the narrative section of a graded AAR. "
                "Cite only events you were given. Be blunt and specific.",
                f"Timeline:\n{timeline}")
        return build_aar(events, spec, scorecard, narrative=narrative)

    fut = coach_queue.submit(9, f"aar-{session_id}", _gen)
    report = fut.result(timeout=300)
    db.add(Event(session_id=session_id, ts=datetime.now(timezone.utc), actor="system", action_type="aar",
                 payload={"grade": report["grade"], "cited_events": report["cited_events"]}))
    return report
