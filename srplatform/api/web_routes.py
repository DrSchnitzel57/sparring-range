"""M7 web endpoints — auth-wired, recording-ID-based, domain-aware progress.

  * Replay data comes from RECORDING IDS (F16) with strict root containment
    and size/frame validation — never from client-supplied filesystem paths.
  * Progress is computed per scoring DOMAIN from score-snapshot items (F20),
    with chronological history, event-ID tie-break, trend deltas, and honest
    handling of empty/zero/unknown scores.
  * The live dashboard reads real detections with source times.
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, text as sa_text
from sqlalchemy.orm import Session

from srplatform.api.auth import Principal, make_auth_dependencies
from srplatform.api.deps import DbSession  # the ONE function-scoped session
from srplatform.db.models import Event, Recording, Run, Session as SessionModel
from srplatform.settings import get_settings

router = APIRouter()

principal, any_member, operator, service = make_auth_dependencies()


def _session_or_403(db: Session, p: Principal, session_id: uuid.UUID) -> SessionModel:
    sess = db.get(SessionModel, session_id)
    if sess is None:
        raise HTTPException(404, "session not found")
    if not p.is_operator and str(sess.user_id) != str(p.user_id):
        raise HTTPException(403, "not your session")
    return sess


# --- recordings (opaque IDs; server-side paths — F16) ---------------------------
class RecordingIn(BaseModel):
    cast_path: str = Field(min_length=1)
    status: str = "recording"


@router.post("/sessions/{session_id}/recordings", status_code=201)
def register_recording(session_id: uuid.UUID, body: RecordingIn,
                       p: Principal = Depends(service("bastion")),
                       db: DbSession = None):
    """Called by the bastion with its capability; the path never becomes a
    client-facing identifier — clients only ever see recording_id."""
    if p.session_id is not None and str(p.session_id) != str(session_id):
        raise HTTPException(403, "bastion token bound to another session")
    if db.get(SessionModel, session_id) is None:
        raise HTTPException(404, "session not found")
    root = Path(get_settings().recordings_dir).resolve()
    path = Path(body.cast_path).resolve()
    if not path.is_relative_to(root):
        raise HTTPException(422, "cast path outside recordings root")
    rec = Recording(session_id=session_id, cast_path=str(path), status=body.status)
    db.add(rec)
    db.flush()
    return {"recording_id": str(rec.recording_id)}


@router.get("/sessions/{session_id}/recordings")
def list_recordings(session_id: uuid.UUID, p: Principal = Depends(any_member),
                    db: DbSession = None):
    _session_or_403(db, p, session_id)
    rows = db.execute(select(Recording).where(Recording.session_id == session_id)
                      .order_by(Recording.created_at)).scalars().all()
    return [{"recording_id": str(r.recording_id), "created_at": r.created_at.isoformat(),
             "status": r.status, "bytes": r.bytes} for r in rows]


def _safe_read_cast(path: str) -> dict:
    """Root containment + symlink policy + size cap + frame validation."""
    settings = get_settings()
    root = Path(settings.recordings_dir).resolve()
    p = Path(path)
    if p.is_symlink():
        raise HTTPException(422, "symlink recordings rejected")
    p = p.resolve()
    if not p.is_relative_to(root):
        raise HTTPException(422, "recording path escapes storage root")
    if not p.exists():
        raise HTTPException(404, "recording file missing on this host "
                                 "(shared storage/transfer contract — see docs/OPERATOR_RUNBOOK.md)")
    size = p.stat().st_size
    if size > settings.recording_max_bytes:
        raise HTTPException(413, f"recording exceeds size cap ({size} bytes)")
    lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    if not lines:
        raise HTTPException(422, "empty recording")
    header = json.loads(lines[0])
    frames = []
    for ln in lines[1:]:
        try:
            f = json.loads(ln)
            if (isinstance(f, list) and len(f) == 3 and isinstance(f[0], (int, float))
                    and f[1] in ("o", "i", "r") and isinstance(f[2], str)):
                frames.append(f)
        except json.JSONDecodeError:
            continue  # a torn tail line must not break the whole replay
    return {"header": header, "frames": frames, "bytes": size}


@router.get("/recordings/{recording_id}")
def get_recording(recording_id: uuid.UUID, p: Principal = Depends(any_member),
                  db: DbSession = None):
    rec = db.get(Recording, recording_id)
    if rec is None:
        raise HTTPException(404, "recording not found")
    _session_or_403(db, p, rec.session_id)
    data = _safe_read_cast(rec.cast_path)
    return {"recording_id": str(rec.recording_id), "session_id": str(rec.session_id), **data}


@router.get("/sessions/{session_id}/replay")
def replay(session_id: uuid.UUID,
           after_event_id: int | None = None,
           limit: int | None = None,
           actor: str | None = None,
           action_type: str | None = None,
           collapsed: bool = True,
           include_frames: bool = False,
           p: Principal = Depends(any_member), db: DbSession = None):
    """Session-clock replay, PAGINATED and FILTERED (plan 20).

    * the timeline is a cursor-paged projection (``after_event_id`` +
      ``limit``, default 400, max 2000) — a session view never downloads
      the whole audit; ``actor``/``action_type`` filter server-side;
    * ``collapsed`` (default) folds consecutive connection/bastion noise
      into one honest summary entry (counted, expandable via its id
      range) so the meaningful events are readable;
    * casts are returned as SUMMARIES (frame count, duration, epoch);
      full frames come from ``GET /recordings/{id}`` or explicitly via
      ``include_frames=1`` — rendering a list never fetches casts;
    * ``operations`` is the attacker command track (intent paired with
      result, plus per-operation capture facts and ``has_output``); a
      SEALED competition member gets NO commands — visibility is
      enforced here, not by hiding a button;
    * missing/corrupt casts are per-entry honest errors, never dropped.
    """
    sess = _session_or_403(db, p, session_id)
    from srplatform.api.visibility import competition_sealed
    sealed = competition_sealed(db, sess, p)
    limit = 400 if limit is None else max(1, min(limit, 2000))
    conds = ["session_id = :sid"]
    params = {"sid": str(session_id), "lim": limit + 1}
    if after_event_id is not None:
        conds.append("event_id > :after")
        params["after"] = after_event_id
    if actor:
        conds.append("actor = :actor")
        params["actor"] = actor
    if action_type:
        conds.append("action_type = :atype")
        params["atype"] = action_type
    where = " AND ".join(conds)
    rows = db.execute(sa_text(
        f"SELECT event_id, ts, actor, action_type, phase FROM events "
        f"WHERE {where} ORDER BY event_id LIMIT :lim"), params).fetchall()
    has_more = len(rows) > limit
    rows = rows[:limit]
    total = db.execute(sa_text(
        f"SELECT count(*) FROM events WHERE {where}"),
        {k: v for k, v in params.items() if k != "lim"}).scalar() or 0

    noise = {"bastion_session_start", "bastion_session_end"}
    timeline: list[dict] = []
    run_noise: list = []

    def _flush_noise():
        if not run_noise:
            return
        first, last = run_noise[0], run_noise[-1]
        kinds = sorted({e.action_type for e in run_noise})
        timeline.append({
            "event_id": first.event_id, "collapsed": len(run_noise),
            "first_event_id": first.event_id, "last_event_id": last.event_id,
            "ts": first.ts.isoformat(), "actor": first.actor,
            "action_type": "connection_noise", "kinds": kinds, "phase": None})
        run_noise.clear()

    for e in rows:
        # Red kill-chain phases are sealed content (a live `priv-esc`
        # timeline is the spoiler). Casts stay unfiltered: defender
        # first-party transcripts, no red internals.
        phase = None if (sealed and e.actor == "red") else e.phase
        if collapsed and e.action_type in noise:
            run_noise.append(e)
            continue
        _flush_noise()
        timeline.append({"event_id": e.event_id, "ts": e.ts.isoformat(),
                         "actor": e.actor, "action_type": e.action_type,
                         "phase": phase})
    _flush_noise()

    recs = db.execute(select(Recording).where(Recording.session_id == session_id)
                      .order_by(Recording.created_at)).scalars().all()
    casts = []
    for r in recs:
        try:
            data = _safe_read_cast(r.cast_path)
            frames = data["frames"]
            entry = {"recording_id": str(r.recording_id),
                     "name": os.path.basename(r.cast_path),
                     "header": data["header"],
                     "frame_count": len(frames),
                     "duration_s": frames[-1][0] if frames else 0,
                     "started_at": data["header"].get("timestamp"),
                     "bytes": data["bytes"]}
            if include_frames:
                entry["frames"] = frames
            casts.append(entry)
        except HTTPException as e:
            casts.append({"recording_id": str(r.recording_id), "error": e.detail,
                          "header": None, "frame_count": 0})

    # attacker command track — pair intent with result by op_uuid
    operations = _operation_track(db, session_id, sealed)
    return {"session_id": str(session_id), "scenario_id": sess.scenario_id,
            "sealed": sealed,
            "casts": casts, "timeline": timeline,
            "operations": operations,
            "total_events": total, "has_more": has_more,
            "next_after_event_id": rows[-1].event_id if has_more and rows else None}


def _operation_track(db: Session, session_id, sealed: bool) -> list[dict]:
    """attacker commands paired with their results (plan 20 replay). A
    SEALED member sees NO red command content — the track is empty, not
    redacted page by page. Legacy operations without capture rows keep
    ``has_output`` False: they render as command-only evidence, never
    as a reconstructed fake cast."""
    if sealed:
        return []
    rows = db.execute(sa_text(
        "SELECT event_id, ts, actor, action_type, payload FROM events "
        "WHERE session_id = :sid AND action_type IN "
        "('action_intent','action_result') ORDER BY event_id"),
        {"sid": str(session_id)}).fetchall()
    have_output = {r[0] for r in db.execute(sa_text(
        "SELECT DISTINCT op_id FROM operation_outputs WHERE session_id = :sid"),
        {"sid": str(session_id)}).fetchall()}
    by_uuid: dict[str, dict] = {}
    order: list[str] = []
    for e in rows:
        payload = e.payload or {}
        ouuid = payload.get("op_uuid")
        if not ouuid:
            continue          # pre-UUID legacy lines: not a forged track
        if e.action_type == "action_intent":
            by_uuid[ouuid] = {"op_uuid": ouuid,
                              "op_id": payload.get("op_id"),
                              "command": payload.get("command"),
                              "intent_event_id": e.event_id,
                              "ts": e.ts.isoformat(),
                              "result_event_id": None, "end_ts": None,
                              "exit_code": None, "timed_out": None,
                              "cancel_state": None, "capture": None,
                              "has_output": ouuid in have_output}
            order.append(ouuid)
        else:
            op = by_uuid.get(ouuid)
            if op is None:
                # result without intent (events predating the pairing or
                # trimmed history): still show it, honestly incomplete
                op = {"op_uuid": ouuid, "op_id": payload.get("op_id"),
                      "command": payload.get("command"),
                      "intent_event_id": None,
                      "ts": e.ts.isoformat(), "result_event_id": e.event_id,
                      "end_ts": e.ts.isoformat(),
                      "has_output": ouuid in have_output}
                order.append(ouuid)
            op.update({"result_event_id": e.event_id, "end_ts": e.ts.isoformat(),
                       "exit_code": payload.get("exit_code"),
                       "timed_out": payload.get("timed_out"),
                       "cancel_state": payload.get("cancel_state"),
                       "capture": payload.get("output_capture")})
            op["has_output"] = ouuid in have_output
    return [by_uuid[u] for u in order]


@router.get("/sessions/{session_id}/operations/{op_id}/output")
def operation_output(session_id: uuid.UUID, op_id: str,
                     after_seq: int | None = None,
                     limit: int = 200,
                     p: Principal = Depends(any_member), db: DbSession = None):
    """One operation's timed output chunks (plan 20). Sealed competition
    members get NOTHING for red operations — chunks are attacker output
    and never cross the visibility boundary through this door either.
    Operations that predate capture honestly report zero rows (the
    caller renders the command-only fallback)."""
    sess = _session_or_403(db, p, session_id)
    from srplatform.api.visibility import competition_sealed
    sealed = competition_sealed(db, sess, p)
    if sealed:
        return {"op_id": op_id, "chunks": [], "hidden": True}
    limit = max(1, min(limit, 1000))
    conds = ["session_id = :sid", "op_id = :op"]
    params: dict = {"sid": str(session_id), "op": op_id,
                    "lim": limit + 1}
    if after_seq is not None:
        conds.append("seq > :after")
        params["after"] = after_seq
    rows = db.execute(sa_text(
        f"SELECT seq, ts, kind, text, dropped_bytes FROM operation_outputs "
        f"WHERE {' AND '.join(conds)} ORDER BY seq LIMIT :lim"),
        params).fetchall()
    has_more = len(rows) > limit
    rows = rows[:limit]
    return {"op_id": op_id,
            "chunks": [{"seq": r.seq, "ts": r.ts.isoformat(),
                        "kind": r.kind, "text": r.text,
                        "dropped_bytes": r.dropped_bytes} for r in rows],
            "has_more": has_more,
            "next_after_seq": rows[-1].seq if has_more and rows else None}


# --- progress: per-domain scores from scoring ITEMS (F20) -------------------------
@router.get("/users/{username}/progress")
def progress(username: str, p: Principal = Depends(any_member), db: DbSession = None):
    if not p.is_operator and p.username != username:
        raise HTTPException(403, "own progress only")
    rows = db.execute(sa_text("""
        SELECT session_id, scenario_id, username, event_id, scored_at, domain,
               awarded, points, status, scorecard_status
        FROM v_score_items
        WHERE username = :u
        ORDER BY scored_at, event_id"""), {"u": username}).fetchall()

    # latest scorecard per session (event_id tie-break, chronological order)
    by_sid: dict[str, dict] = {}
    for r in rows:
        if r.scorecard_status not in ("scored", "partial"):
            continue
        sid = str(r.session_id)
        cur = by_sid.get(sid)
        if cur is None or r.event_id > cur["event_id"]:
            by_sid[sid] = {"event_id": r.event_id, "items": [r]}
        elif r.event_id == cur["event_id"]:
            cur["items"].append(r)

    sessions_out, domains = [], {}
    for sid, entry in by_sid.items():
        items = entry["items"]
        earned = sum(i.awarded for i in items if i.awarded is not None)
        total = sum(i.points for i in items if i.points is not None)
        pct = round(100 * earned / total) if total else None
        sessions_out.append({"session_id": sid, "scenario_id": items[0].scenario_id,
                             "earned": earned, "total": total, "pct": pct,
                             "scored_at": items[0].scored_at.isoformat(),
                             "status": items[0].scorecard_status})
        for i in items:
            d = domains.setdefault(i.domain or "general", [])
            d.append(i)
    sessions_out.sort(key=lambda s: s["scored_at"])

    per_domain = {}
    for d, items in domains.items():
        earned = sum(i.awarded for i in items if i.awarded is not None)
        total = sum(i.points for i in items if i.points is not None)
        avg = round(100 * earned / total) if total else None
        # trend: compare first half vs second half of per-session domain pcts
        by_sess: dict[str, list] = {}
        for i in items:
            by_sess.setdefault(str(i.session_id), []).append(i)
        pcts = []
        for ss in sorted(by_sess, key=lambda x: min(i.scored_at for i in by_sess[x])):
            e = sum(i.awarded for i in by_sess[ss] if i.awarded is not None)
            t = sum(i.points for i in by_sess[ss] if i.points is not None)
            if t:
                pcts.append(100 * e / t)
        trend = None
        if len(pcts) >= 2:
            half = len(pcts) // 2
            avg_of = lambda xs: sum(xs) / len(xs)
            trend = round(avg_of(pcts[half:]) - avg_of(pcts[:half]))
        per_domain[d] = {"avg_pct": avg, "sessions": len(by_sess), "trend": trend}

    lagging = sorted((d for d, m in per_domain.items() if m["avg_pct"] is not None),
                     key=lambda d: per_domain[d]["avg_pct"])[:2]
    return {"username": username, "sessions": sessions_out, "by_domain": per_domain,
            "lagging_domains": lagging,
            "unscored_note": "sessions without a trusted scorecard are listed only when scored"}


# --- live dashboard: current red phase + real detections with source times -------
def _attacker_projection(run, event, *, sealed: bool, now: datetime) -> dict | None:
    """Operational status is distinct from match state and service uptime.

    A heartbeat is liveness evidence, NOT proof that commands are progressing.
    Do not serialize credentials, PID identities, results, or sealed errors.
    """
    if run is None:
        return None
    def age(value):
        return max(0, int((now - value).total_seconds())) if value else None
    progress_at = event.ingested_at if event is not None else None
    heartbeat = run.worker_heartbeat_at
    return {
        "run_id": str(run.run_id), "status": run.status,
        "outcome": None if sealed else run.outcome,
        "error": ("Attacker failed; operator diagnostics required" if sealed and run.error
                  else run.error),
        "heartbeat_age_s": age(heartbeat),
        "last_event_at": progress_at.isoformat() if progress_at else None,
        "last_event_kind": None if sealed or event is None else event.action_type,
        "event_age_s": age(progress_at or run.started_at),
    }


@router.get("/sessions/{session_id}/live")
def live(session_id: uuid.UUID, p: Principal = Depends(any_member),
         db: DbSession = None):
    sess = _session_or_403(db, p, session_id)
    state = db.execute(sa_text(
        "SELECT current_phase, summary_upto FROM agent_state WHERE session_id=:sid"),
        {"sid": str(session_id)}).first()
    recent = db.execute(sa_text(
        "SELECT event_id, ts, actor, action_type, phase, payload FROM events "
        "WHERE session_id=:sid ORDER BY event_id DESC LIMIT 12"),
        {"sid": str(session_id)}).fetchall()
    detections = [d for d in reversed(recent) if d.action_type in ("verifier", "detection")]
    from srplatform import uptime as _uptime
    from srplatform.api.visibility import (
        competition_sealed, filter_detection)
    sealed = competition_sealed(db, sess, p)
    from sqlalchemy import func
    from srplatform.api.runs import ACTIVE
    latest_run = db.execute(select(Run).where(Run.session_id == session_id).order_by(
        Run.status.in_(ACTIVE).desc(),
        func.coalesce(Run.ended_at, Run.started_at).desc().nulls_last(),
        Run.run_id.desc()).limit(1)).scalar_one_or_none()
    last_agent_event = None
    if latest_run is not None and latest_run.started_at is not None:
        last_agent_event = db.execute(select(Event).where(
            Event.session_id == session_id, Event.actor == "red",
            Event.ingested_at >= latest_run.started_at,
            Event.action_type.in_(("action_intent", "action_result", "agent_note")))
            .order_by(Event.event_id.desc()).limit(1)).scalar_one_or_none()
    return {
        "session_id": str(session_id), "status": sess.status,
        "attacker": _attacker_projection(latest_run, last_agent_event,
                                         sealed=sealed, now=datetime.now(timezone.utc)),
        "uptime": _uptime.live_projection(db, session_id),
        "started_at": sess.started_at.isoformat() if sess.started_at else None,
        "red_phase": None if sealed else (state.current_phase if state else None),
        "recent": [{"event_id": e.event_id, "ts": e.ts.isoformat(), "actor": e.actor,
                    "action_type": e.action_type,
                    "phase": (None if sealed and e.actor == "red" else e.phase)}
                   for e in reversed(recent)],
        "detections": [filter_detection({"event_id": d.event_id,
                                         "ts": d.ts.isoformat()})
                       if sealed else
                       {"event_id": d.event_id, "ts": d.ts.isoformat(),
                        "objective": (d.payload or {}).get("objective"),
                        "passed": (d.payload or {}).get("passed")}
                       for d in detections],
    }
