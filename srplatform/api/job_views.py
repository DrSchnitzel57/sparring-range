"""Shared job status/stream views (plan 19 review round 2, findings 4/6/13).

ONE serializer for the durable job surface: internal worker status,
member status, admin detail and both SSE streams all render through
:func:`chain_status_body`, so "the logical request" means the same
chain-aware thing everywhere. Privilege is a single boolean axis:

* ``errors=True`` (privileged): the redacted, class/status-only
  diagnostic (finding 3) rides along.
* ``errors=False`` (member/competition-safe): only the neutral
  :func:`srplatform.model_jobs.error_kind` classification survives —
  raw diagnostics could echo sealed conversation content even after
  secret redaction (finding 4).

The event stream is bounded, reconnect-safe (terminal state is durable,
so the final event is ALWAYS replayable), and — critically — closing a
stream never touches job state: a disconnect is not a cancellation.
"""
from __future__ import annotations

import time
import uuid

from fastapi.responses import StreamingResponse

# Member coach work stays label-visible when sealed: hint, AAR
# narrative and (plan 20) the conversational coach are all the member's
# OWN session surface; attacker kinds never enter this tuple.
MEMBER_VISIBLE_WHEN_SEALED = ("hint", "aar-narrative", "coach-chat")


def chain_status_body(s, job_id: uuid.UUID, *, errors: bool,
                      result_kind: bool = True) -> dict:
    """ONE logical request, chain-aware: the chain's FINAL outcome plus
    the attempt history, from whichever attempt id the caller holds.

    ``result_kind`` keeps the privileged worker contract (a successful
    turn reports its RESULT kind — "text"/"tool_call"); member surfaces
    keep the JOB kind, which is also the competition-visible one."""
    from srplatform import model_jobs
    final, rows = model_jobs.chain_view(s, job_id)
    done = (final.state in model_jobs.TERMINAL_STATES
            or final.state == "cessation_unknown")
    body = {"job_id": str(final.job_id), "requested_job_id": str(job_id),
            "state": final.state, "kind": final.kind, "done": done,
            "attempt": final.attempt,
            "error_kind": model_jobs.error_kind(final),
            "attempts": [{
                "job_id": str(j.job_id), "attempt": j.attempt,
                "state": j.state, "error_kind": model_jobs.error_kind(j),
                "error": (model_jobs.redact_error(j.error)[:300]
                          if errors and j.error else None),
                "requested_at": (j.requested_at.isoformat()
                                 if j.requested_at else None),
                "started_at": (j.started_at.isoformat()
                               if j.started_at else None),
                "finished_at": (j.finished_at.isoformat()
                                if j.finished_at else None),
            } for j in sorted(rows, key=lambda j: j.attempt)]}
    if done and final.state == "succeeded":
        r = final.result or {}
        body.update({"kind": (r.get("kind") or final.kind) if result_kind
                     else final.kind,
                     "text": r.get("text"),
                     "tool_call": r.get("tool_call"),
                     "usage": r.get("usage"),
                     "finish_reason": r.get("finish_reason")})
    elif done:
        body["error"] = (model_jobs.redact_error(final.error or "")[:500]
                         if errors else body["error_kind"])
    return body


def strip_results(body: dict) -> dict:
    """Member async surface carries NO result payloads at all (the
    accepted contract: transcripts may contain attack data; outcome
    texts arrive through the central evidence filter instead)."""
    body.pop("text", None)
    body.pop("tool_call", None)
    body.pop("usage", None)
    body.pop("finish_reason", None)
    for a in body.get("attempts", []):
        a.pop("error", None)
    return body


def strip_sealed(body: dict) -> dict:
    """Competition filter for the member view (finding 4): during a
    sealed match only the member's OWN coach work (hint/AAR) shows —
    attacker turn/summary kinds and their metadata stay invisible."""
    strip_results(body)
    if body.get("kind") not in MEMBER_VISIBLE_WHEN_SEALED:
        body["kind"] = "model-work"
    return body


def _sse(obj: dict, *, event: str, event_id: str) -> str:
    import json
    return (f"id: {event_id}\n"
            f"event: {event}\n"
            f"data: {json.dumps(obj, default=str)}\n\n")


def job_event_stream(dbctx, job_id: uuid.UUID, *, errors: bool,
                     bound_s: float, tick_s: float = 0.5,
                     sealed_filter=None, results: bool = True,
                     result_kind: bool = True):
    """Bounded SSE pump over ONE logical job. Every state/attempt
    transition pushes a ``progress`` event; the terminal ``result`` or
    ``error`` event is ALWAYS emitted (a reconnecting client replays it
    from the durable row — no server-side window to exhaust); after the
    window closes the job simply keeps running (``window_closed`` then
    the stream ends — the job is untouched either way)."""
    def gen():
        end = time.monotonic() + bound_s
        last_sig = None
        while True:
            with dbctx() as s:
                body = chain_status_body(s, job_id, errors=errors,
                                         result_kind=result_kind)
                if sealed_filter is not None:
                    body = sealed_filter(s, body)
            sig = (body["state"], body["attempt"])
            if sig != last_sig:
                yield _sse({"state": body["state"],
                            "attempt": body["attempt"],
                            "kind": body["kind"],
                            "error_kind": body.get("error_kind")},
                           event="progress",
                           event_id=f"{body['attempt']}-{body['state']}")
                last_sig = sig
            if body["done"]:
                if body["state"] == "succeeded":
                    keys = ("kind", "job_id") if not results else (
                        "kind", "text", "tool_call", "usage",
                        "finish_reason", "job_id")
                    yield _sse({k: body.get(k) for k in keys},
                               event="result", event_id="final")
                else:
                    yield _sse({"state": body["state"],
                                "error_kind": body.get("error_kind"),
                                "error": body.get("error")},
                               event="error", event_id="final")
                return
            if time.monotonic() >= end:
                yield _sse(
                    {"state": body["state"], "done": False,
                     "note": "stream window closed; the job continues — "
                             "reconnect or poll the status URL"},
                    event="window_closed", event_id="window")
                return
            time.sleep(tick_s)

    return StreamingResponse(
        gen(), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache",
                 "X-Accel-Buffering": "no"})
