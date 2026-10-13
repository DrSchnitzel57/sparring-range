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
from srplatform.db.models import Event, Recording, Session as SessionModel
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
def replay(session_id: uuid.UUID, p: Principal = Depends(any_member),
           db: DbSession = None):
    """Multiple recordings; each header's epoch is the sync anchor (F17)."""
    sess = _session_or_403(db, p, session_id)
    events = db.execute(sa_text(
        "SELECT event_id, ts, actor, action_type, phase FROM events "
        "WHERE session_id = :sid ORDER BY event_id"), {"sid": str(session_id)}).fetchall()
    timeline = [{"event_id": e.event_id, "ts": e.ts.isoformat(), "actor": e.actor,
                 "action_type": e.action_type, "phase": e.phase} for e in events]
    recs = db.execute(select(Recording).where(Recording.session_id == session_id)
                      .order_by(Recording.created_at)).scalars().all()
    casts = []
    for r in recs:
        try:
            data = _safe_read_cast(r.cast_path)
            casts.append({"recording_id": str(r.recording_id),
                          "name": os.path.basename(r.cast_path), **data})
        except HTTPException as e:
            casts.append({"recording_id": str(r.recording_id), "error": e.detail,
                          "header": None, "frames": []})
    return {"session_id": str(session_id), "scenario_id": sess.scenario_id,
            "casts": casts, "timeline": timeline}


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
    return {
        "session_id": str(session_id), "status": sess.status,
        "uptime": _uptime.summarize_for_session(db, session_id),
        "started_at": sess.started_at.isoformat() if sess.started_at else None,
        "red_phase": state.current_phase if state else None,
        "recent": [{"event_id": e.event_id, "ts": e.ts.isoformat(), "actor": e.actor,
                    "action_type": e.action_type, "phase": e.phase} for e in reversed(recent)],
        "detections": [{"event_id": d.event_id, "ts": d.ts.isoformat(),
                        "objective": (d.payload or {}).get("objective"),
                        "passed": (d.payload or {}).get("passed")} for d in detections],
    }
