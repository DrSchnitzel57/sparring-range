"""Coach endpoints (M5) — auth-wired, gateway-scheduled, snapshot-persisting.

F12/F18/F20 fixes:
  * hints/AARs require session access;
  * NO database transaction is held while the model is thinking (data is read,
    session closed, model awaited through the bounded gateway, then a new
    session appends evidence);
  * reports are PERSISTED (versioned events with evidence cutoff + rubric
    version); GET fetches, POST regenerates — no generation on page loads;
  * hints get PRIORITY_HINT on the SAME gateway the red loop uses in-process.
"""
from __future__ import annotations

import time
import uuid

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from srplatform.api.auth import Principal
from srplatform.coach.aar import build_aar, build_hint
from srplatform.db.models import Event, Session as SessionModel
from srplatform.db.session import db as _db_ctx  # explicit sessions around model waits
from srplatform.model_gateway import PRIORITY_AAR, PRIORITY_HINT, QueueFull, get_model_gateway

router = APIRouter()

from srplatform.api.auth import make_auth_dependencies
from srplatform.api.deps import DbSession  # the ONE function-scoped session

_principal, any_member, _operator, _service = make_auth_dependencies()

# coach model; injectable for tests (set_coach_llm). Outage handling: fall back
# to the deterministic report and RETRY PERIODICALLY (no permanent poisoning).
_coach_llm = None
_coach_retry_at = 0.0


def set_coach_llm(llm) -> None:
    global _coach_llm, _coach_retry_at
    _coach_llm = llm
    _coach_retry_at = 0.0


def get_coach_llm():
    global _coach_llm, _coach_retry_at
    if _coach_llm is None or (_coach_llm is False and time.monotonic() >= _coach_retry_at):
        try:
            from srplatform.red_agent.llm import LLM
            from srplatform.settings import get_settings

            llm = LLM(model=get_settings().llm_model_coach)
            # Endpoint liveness probe OUTSIDE the gateway (audit Stage 5):
            # probing THROUGH the scheduler would make the probe itself wait
            # behind queued red turns, inflating the interactive hint bound
            # it is supposed to protect.
            llm.complete("ping", "ping")  # prove the endpoint answers or fall back
            _coach_llm = llm
        except Exception:
            from srplatform.settings import get_settings
            _coach_llm = False
            _coach_retry_at = time.monotonic() + get_settings().model_recovery_interval_s
    return _coach_llm or None


def _events_of(db: Session, sid: uuid.UUID) -> list[dict]:
    rows = db.execute(select(Event).where(Event.session_id == sid)
                      .order_by(Event.event_id)).scalars().all()
    return [{"event_id": r.event_id, "ts": r.ts.isoformat(), "actor": r.actor, "host": r.host,
             "action_type": r.action_type, "phase": r.phase, "mitre_technique": r.mitre_technique,
             "payload": r.payload} for r in rows]


def _latest_scorecard(db: Session, sid: uuid.UUID) -> dict | None:
    from srplatform.verification_service import latest_scorecard
    return latest_scorecard(db, sid)


class HintIn(BaseModel):
    question: str = ""


@router.post("/sessions/{session_id}/hint")
def hint(session_id: uuid.UUID, body: HintIn, p: Principal = Depends(any_member)):
    """Interactive priority (0). Reads evidence, releases the DB session, then
    waits on the gateway within the declared bound."""
    from srplatform.settings import get_settings
    with _db_ctx() as db:
        sess = db.get(SessionModel, session_id)
        if sess is None:
            raise HTTPException(404, "session not found")
        if not p.is_operator and str(sess.user_id) != str(p.user_id):
            raise HTTPException(403, "not your session")
        events = _events_of(db, session_id)

    llm = get_coach_llm()
    try:
        fut = get_model_gateway().submit(PRIORITY_HINT, f"hint-{session_id}",
                                         build_hint, events, body.question, llm)
        result = get_model_gateway().wait(fut, get_settings().model_hint_max_wait_s)
    except QueueFull:
        raise HTTPException(503, "model gateway saturated — try again shortly")
    except TimeoutError:
        raise HTTPException(504, "hint exceeded its declared wait bound")

    with _db_ctx() as db:
        db.add(Event(session_id=session_id, ts=datetime.now(timezone.utc), actor="system",
                     action_type="hint",
                     payload={"question": body.question, "hint": result["hint"]}))
    return result


class AarIn(BaseModel):
    regenerate: bool = False
    narrative: bool = True


@router.get("/sessions/{session_id}/aar")
def aar_get(session_id: uuid.UUID, p: Principal = Depends(any_member),
            db: DbSession = None):
    """Fetching a report RETRIEVES the persisted version — it never regenerates
    (silently) on page load."""
    sess = _check_access(db, p, session_id)
    ev = db.execute(select(Event).where(Event.session_id == session_id,
                                         Event.action_type == "aar")
                    .order_by(Event.event_id.desc())).scalars().first()
    if not ev:
        return {"status": "no-report", "session_id": str(session_id)}
    return {"status": "ok", "persisted": True,
            "version": (ev.payload or {}).get("version"),
            **ev.payload["report"]}


@router.post("/sessions/{session_id}/aar")
def aar_post(session_id: uuid.UUID, body: AarIn, p: Principal = Depends(any_member),
             db: DbSession = None):
    sess = _check_access(db, p, session_id)
    if not body.regenerate:
        existing = db.execute(select(Event).where(Event.session_id == session_id,
                                                   Event.action_type == "aar")
                              .order_by(Event.event_id.desc())).scalars().first()
        if existing:
            return {"status": "ok", "persisted": True, **existing.payload["report"]}
    from srplatform.verification_service import scenario_spec

    spec = scenario_spec(db, session_id)
    events = _events_of(db, session_id)
    scorecard = _latest_scorecard(db, session_id)

    def _gen():
        llm = get_coach_llm()
        narrative = None
        if llm and body.narrative:
            from srplatform.coach.timeline import compress_timeline
            timeline, _ = compress_timeline(events, max_lines=40)
            narrative = llm.complete(
                "You are a CCDC coach writing the narrative section of a graded AAR. "
                "Cite only events you were given (as #<event_id>). Be blunt and specific.",
                f"Timeline:\n{timeline}")
        return build_aar(events, spec, scorecard, narrative=narrative)

    try:
        fut = get_model_gateway().submit(PRIORITY_AAR, f"aar-{session_id}", _gen)
        report = get_model_gateway().wait(fut, 300)
    except QueueFull:
        raise HTTPException(503, "model gateway saturated — try again shortly")
    except TimeoutError:
        raise HTTPException(504, "AAR generation exceeded its bound")

    version = 1 + db.execute(select(Event).where(Event.session_id == session_id,
                                                  Event.action_type == "aar")).scalars().all().__len__()
    db.add(Event(session_id=session_id, ts=datetime.now(timezone.utc), actor="system",
                 action_type="aar",
                 payload={"version": version, "report": report,
                          "evidence_cutoff_event_id": report["evidence_cutoff_event_id"],
                          "rubric_version": report["rubric_version"]}))
    return {"status": "ok", "persisted": True, "version": version, **report}


def _check_access(db, p, session_id) -> SessionModel:
    sess = db.get(SessionModel, session_id)
    if sess is None:
        raise HTTPException(404, "session not found")
    if not p.is_operator and str(sess.user_id) != str(p.user_id):
        raise HTTPException(403, "not your session")
    return sess
