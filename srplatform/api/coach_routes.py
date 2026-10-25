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
from srplatform.model_gateway import PRIORITY_AAR, PRIORITY_HINT

router = APIRouter()

from srplatform.api.auth import make_auth_dependencies
from srplatform.api.deps import DbSession  # the ONE function-scoped session

_principal, any_member, _operator, _service = make_auth_dependencies()

# coach model DOUBLE; injectable for tests (set_coach_llm). Production uses
# JobCoachModel below — durable jobs, ONE admission slot, no out-of-queue
# probe. Outage handling: the hint/AAR fallbacks stay honest; the failure is
# visible in the job list, never a silently poisoned endpoint.
_coach_llm = None
_coach_retry_at = 0.0


def set_coach_llm(llm) -> None:
    global _coach_llm, _coach_retry_at
    _coach_llm = llm
    _coach_retry_at = 0.0


def get_coach_llm():
    """Test/dev double injection point. Production NEVER probes the model
    endpoint out of queue (the old ping consumed an admission slot without
    being one): liveness is now a job outcome — a probe queued through the
    single slot, or the visible failure of the hint/AAR call itself."""
    return _coach_llm if _coach_llm else None


class JobCoachModel:
    """The production coach ``.complete()`` surface: every call becomes a
    DURABLE job admitted through the ONE slot at the caller's priority.
    Model-side failures surface as CompletionRejected so the existing hint
    and AAR fallbacks stay honest (a hint says it could not consult the
    model — it never invents one)."""

    def __init__(self, session_id, *, priority: int, wait_s: float | None = None):
        self.session_id = session_id
        self.priority = priority
        self.wait_s = wait_s

    def complete(self, system: str, user: str) -> str:
        from srplatform import model_admin as ma
        from srplatform import model_jobs
        from srplatform.db.session import db as _db
        from srplatform.red_agent.llm import CompletionRejected
        from srplatform.settings import get_settings as _gs
        caller_bound = self.wait_s or _gs().model_hint_max_wait_s
        try:
            with _db() as s:
                _pin, prof = ma.bind_for(s, self.session_id, "coach")
                job = model_jobs.enqueue(
                    s, kind="coach-text", priority=self.priority,
                    payload={"mode": "text", "system": system, "user": user},
                    session_id=self.session_id, profile=prof, actor="coach",
                    deadline_at=model_jobs.match_deadline(s, self.session_id))
                jid = job.job_id
        except ma.ProfileProblem as exc:
            raise CompletionRejected(f"coach model unavailable: {exc}") from exc
        except model_jobs.QueueFull as exc:
            raise CompletionRejected("coach model queue saturated") from exc
        # COHERENT bound (finding 11): the caller's bound caps QUEUE
        # waiting; the call itself may legitimately take the profile's
        # full timeout. A bound shorter than the call would cancel a
        # healthy call mid-flight and manufacture a cessation
        # obligation — which fail-closed semantics must reserve for
        # real uncertainty.
        bound = caller_bound + prof.timeout_s + 15
        try:
            with _db() as s:
                try:
                    job = model_jobs.wait(s, jid, bound)
                except TimeoutError:
                    # the caller's bound wins: request cessation, never let
                    # a late completion answer a request that gave up
                    try:
                        model_jobs.cancel(s, jid, actor="coach wait bound")
                    except Exception:  # noqa: BLE001
                        pass
                    raise CompletionRejected(
                        "coach model exceeded its declared wait bound") from None
        except TimeoutError:  # pragma: no cover — converted above
            raise
        if job.state != "succeeded":
            raise CompletionRejected(
                f"coach model call failed: {(job.error or job.state)[:300]}")
        return (job.result or {}).get("text") or ""


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
    wait: bool = True


@router.post("/sessions/{session_id}/hint")
def hint(session_id: uuid.UUID, body: HintIn, p: Principal = Depends(any_member)):
    """Interactive priority (0). Reads evidence, releases the DB session, then
    either waits on the gateway within the declared bound OR (``wait=false``,
    finding 11) returns a durable job id whose completion persists the hint
    event through the job's terminal transaction — reload-recoverable, and
    no DB transaction is held across the model call either way."""
    from srplatform.settings import get_settings
    with _db_ctx() as db:
        sess = db.get(SessionModel, session_id)
        if sess is None:
            raise HTTPException(404, "session not found")
        if not p.is_operator and str(sess.user_id) != str(p.user_id):
            raise HTTPException(403, "not your session")
        # The coach reasons ONLY over member-visible evidence in
        # competition: raw red payloads never reach the model, so a hint
        # cannot launder sealed attack commands back to the requester.
        from srplatform.api.visibility import filter_event
        events = [filter_event(db, sess, p, e)
                  for e in _events_of(db, session_id)]

    llm = get_coach_llm()
    if llm is None and not body.wait:
        from srplatform import model_admin as ma
        from srplatform import model_jobs
        from srplatform.coach.aar import hint_fallback, hint_prompt
        system, user, state_line = hint_prompt(events, body.question)
        try:
            with _db_ctx() as db:
                _pin, prof = ma.bind_for(db, session_id, "coach")
                job = model_jobs.enqueue(
                    db, kind="hint", priority=PRIORITY_HINT,
                    payload={"mode": "text", "system": system, "user": user,
                             "hint_meta": {
                                 "question": body.question,
                                 "fallback": hint_fallback(
                                     "Model call failed", state_line)}},
                    session_id=session_id, profile=prof,
                    actor="member",
                    deadline_at=model_jobs.match_deadline(db, session_id))
                jid = job.job_id
        except ma.ProfileProblem as exc:
            raise HTTPException(503, str(exc)) from exc
        except model_jobs.QueueFull as exc:
            raise HTTPException(503, str(exc)) from exc
        return {"status": "queued", "job_id": str(jid), "hint": None,
                "pending": True}

    llm = llm or JobCoachModel(session_id, priority=PRIORITY_HINT)
    # build_hint runs inline; its llm.complete call IS the queue admission
    # (durable job, interactive priority) — no separate scheduler hop.
    result = build_hint(events, body.question, llm)

    with _db_ctx() as db:
        db.add(Event(session_id=session_id, ts=datetime.now(timezone.utc), actor="system",
                     action_type="hint",
                     payload={"question": body.question, "hint": result["hint"]}))
    return result


class AarIn(BaseModel):
    regenerate: bool = False
    narrative: bool = True
    wait: bool = True


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
    from srplatform.api.visibility import competition_sealed
    if competition_sealed(db, sess, p):
        raise HTTPException(409, {"error": "competition_sealed",
                                  "detail": "the graded report is available "
                                            "after the match completes"})
    return {"status": "ok", "persisted": True,
            "version": (ev.payload or {}).get("version"),
            **ev.payload["report"]}


@router.post("/sessions/{session_id}/aar")
def aar_post(session_id: uuid.UUID, body: AarIn, p: Principal = Depends(any_member),
             db: DbSession = None):
    sess = _check_access(db, p, session_id)
    # the graded report narrates the full attack timeline — generating one
    # mid-match would hand members the spoiler summary. Competition reports
    # are available after the match completes (practice unaffected).
    from srplatform.api.visibility import competition_sealed
    if competition_sealed(db, sess, p):
        raise HTTPException(409, {"error": "competition_sealed",
                                  "detail": "the graded report is available "
                                            "after the match completes"})
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

    llm = get_coach_llm()
    if llm is None and body.narrative and not body.wait:
        # DURABLE async report (finding 11): the narrative rides a job
        # at AAR priority; on completion the registered handler rebuilds
        # and persists the report with the model's narrative (or,
        # honestly, without it and with the failure recorded) — the job
        # row alone answers "is my report still cooking?" after reload.
        from srplatform import model_admin as ma
        from srplatform import model_jobs
        from srplatform.coach.timeline import compress_timeline
        timeline, _ = compress_timeline(events, max_lines=40)
        try:
            _pin, prof = ma.bind_for(db, session_id, "coach")
            job = model_jobs.enqueue(
                db, kind="aar-narrative", priority=PRIORITY_AAR,
                payload={"mode": "text",
                         "system": AAR_NARRATIVE_SYSTEM,
                         "user": f"Timeline:\n{timeline}",
                         "aar_meta": {"requested_by":
                                      str(p.user_id or "member")}},
                session_id=session_id, profile=prof, actor="member",
                deadline_at=model_jobs.match_deadline(db, session_id))
            jid = job.job_id
        except ma.ProfileProblem as exc:
            raise HTTPException(503, str(exc)) from exc
        except model_jobs.QueueFull as exc:
            raise HTTPException(503, str(exc)) from exc
        return {"status": "queued", "job_id": str(jid), "pending": True}

    narrative = None
    if llm and body.narrative:
        from srplatform.coach.timeline import compress_timeline
        timeline, _ = compress_timeline(events, max_lines=40)
        from srplatform.red_agent.llm import CompletionRejected
        try:
            narrative = llm.complete(
                AAR_NARRATIVE_SYSTEM,
                f"Timeline:\n{timeline}")
        except CompletionRejected:
            # A missing/truncated optional narrative cannot erase the
            # deterministic evidence-linked report or invent model advice.
            narrative = None
    if llm is None and body.narrative:
        # production path: the narrative rides a durable job at AAR
        # priority (batches yield to hints and turns by design).
        # NO database transaction may be held across the model wait:
        # release the request-scoped snapshot now (finding 11).
        db.commit()
        from srplatform.coach.timeline import compress_timeline
        timeline, _ = compress_timeline(events, max_lines=40)
        from srplatform.red_agent.llm import CompletionRejected
        try:
            narrative = JobCoachModel(session_id, priority=PRIORITY_AAR,
                                      wait_s=300).complete(
                AAR_NARRATIVE_SYSTEM,
                f"Timeline:\n{timeline}")
        except CompletionRejected:
            narrative = None
    report = build_aar(events, spec, scorecard, narrative=narrative)

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


AAR_NARRATIVE_SYSTEM = (
    "You are a CCDC coach writing the narrative section of a graded AAR. "
    "Cite only events you were given (as #<event_id>). Be blunt and specific.")


@router.get("/sessions/{session_id}/model-jobs")
def model_jobs_list(session_id: uuid.UUID, limit: int = 25,
                    p: Principal = Depends(any_member), db: DbSession = None):
    """The member-visible ASYNC surface (finding 11): durable state and
    timing of the session's model jobs — for "is my hint/report still
    running?" after a reload. Deliberately NO result payloads: turn
    transcripts may contain sealed attack data; outcome texts are
    persisted through the normal evidence channels instead."""
    _check_access(db, p, session_id)
    from srplatform import model_jobs
    from srplatform.db.models import ModelJob
    limit = max(1, min(limit, 100))
    rows = db.execute(select(ModelJob).where(
        ModelJob.session_id == session_id)
        .order_by(ModelJob.requested_at.desc()).limit(limit)
    ).scalars().all()
    return {"jobs": [{
        "job_id": str(j.job_id), "kind": j.kind, "state": j.state,
        "cancel_requested": j.cancel_requested,
        "error": model_jobs.redact_error(j.error)[:300] if j.error else None,
        "requested_at": j.requested_at.isoformat() if j.requested_at else None,
        "started_at": j.started_at.isoformat() if j.started_at else None,
        "finished_at": j.finished_at.isoformat() if j.finished_at else None,
    } for j in rows]}


# --------------------------------------------------------------------------- #
# durable-async result handlers (registered with the job scheduler)            #
# --------------------------------------------------------------------------- #

def _hint_result_handler(db, job, success: bool) -> None:
    """Persist the hint EXACTLY ONCE, atomically with the job's final
    state. A failed model call still produces the honest deterministic
    fallback — async never means silently dropped."""
    meta = (job.payload or {}).get("hint_meta") or {}
    text = None
    if success:
        t = (job.result or {}).get("text")
        if isinstance(t, str) and t.strip():
            text = t
    if not text:
        text = meta.get("fallback") or (
            "Model call failed — deterministic guidance unavailable; "
            "no AI-generated hint is invented.")
    db.add(Event(session_id=job.session_id,
                 ts=datetime.now(timezone.utc), actor="system",
                 action_type="hint",
                 payload={"question": meta.get("question", ""),
                          "hint": text,
                          "model_job": str(job.job_id),
                          "model_ok": bool(success)}))


def _aar_result_handler(db, job, success: bool) -> None:
    """Persist the graded report once: with the narrative when the job
    succeeded, honestly WITHOUT it (and the redacted failure recorded)
    when it did not — a missing narrative never erases the
    deterministic report, and never silently retries either."""
    sid = job.session_id
    from srplatform.verification_service import scenario_spec
    narrative = None
    narrative_error = None
    if success:
        narrative = (job.result or {}).get("text") or None
    else:
        from srplatform import model_jobs
        narrative_error = model_jobs.redact_error(job.error or job.state)[:300]
    events = _events_of(db, sid)
    spec = scenario_spec(db, sid)
    scorecard = _latest_scorecard(db, sid)
    report = build_aar(events, spec, scorecard, narrative=narrative)
    version = 1 + db.execute(select(Event).where(
        Event.session_id == sid, Event.action_type == "aar")
    ).scalars().all().__len__()
    payload = {"version": version, "report": report,
               "evidence_cutoff_event_id":
                   report["evidence_cutoff_event_id"],
               "rubric_version": report["rubric_version"],
               "model_job": str(job.job_id)}
    if narrative_error is not None:
        payload["narrative_error"] = narrative_error
    db.add(Event(session_id=sid, ts=datetime.now(timezone.utc),
                 actor="system", action_type="aar", payload=payload))


def _register_result_handlers() -> None:
    from srplatform import model_jobs
    model_jobs.register_result_handler("hint", _hint_result_handler)
    model_jobs.register_result_handler("aar-narrative", _aar_result_handler)


_register_result_handlers()
