"""Durable model jobs (plan 19): ONE admission slot, enforced by the DATABASE.

Every model admission — red-loop turns, interactive hints, AAR narratives,
compaction summaries, operator probes, and every bounded retry attempt — is
a ``model_jobs`` ROW. The partial UNIQUE index on ``state='running'`` makes
"at most one provider request" a database invariant across processes, not a
process-local courtesy; queue order (priority ASC, FIFO within priority),
cancellation state, and the obligation of a call whose cessation cannot be
confirmed all survive reloads and restarts because they ARE the row.

Policy carried over unchanged from the in-process gateway (F18):
priorities are hints (0) over red turns (5) over AAR batches (9); priority
schedules the QUEUE — a request already running is never preempted (the
declared interactive bound accounts for one in-flight call); a running
request is never overlapped; retries are at most MODEL_ATTEMPTS total with
5/15 s delays, and every retry is a NEW visible row (attempt+1,
parent_job) — never a hidden re-send.

Cessation semantics (fail closed):
* cancel a QUEUED job  → cancelled before it ever runs;
* cancel a RUNNING job → ``cancel_requested``; the slot releases only when
  the live call actually returns, and its discarded result is recorded;
* an ``running`` row found at startup → ``cessation_unknown``: the provider
  call MAY still be live; we never delete the obligation and never replay.

No DB session is held during a provider call: claim, execute, and terminal
write are separate short transactions.
"""
from __future__ import annotations

import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from srplatform.db.models import ConversationRevision, ModelJob, ModelProfile
from srplatform.db.session import db as db_ctx

# single source of the priority ladder (re-exported for existing callers)
PRIORITY_HINT = 0
PRIORITY_RED = 5
PRIORITY_AAR = 9
MODEL_ATTEMPTS = 3          # initial attempt + two retries, like the gateway
RETRY_DELAYS = (5.0, 15.0)  # seconds before attempt 2 and attempt 3

TERMINAL_STATES = ("succeeded", "failed", "cancelled", "cessation_unknown")


class QueueFull(RuntimeError):
    """Visible overflow — bounded queue, never silent memory growth."""


class JobProblem(ValueError):
    """Operational refusal (bad id, terminal-state transition...)."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------------- #
# enqueue / wait / cancel (called from request handlers)                       #
# --------------------------------------------------------------------------- #

def enqueue(db, *, kind: str, priority: int, payload: dict,
            session_id: uuid.UUID | None = None,
            profile: ModelProfile | None = None,
            actor: str | None = None,
            parent_job: uuid.UUID | None = None,
            attempt: int = 1,
            run_at: datetime | None = None) -> ModelJob:
    """Queue a durable admission. ``run_at`` (retry backoff) sets
    requested_at to a future instant; the claimer honors it. Overflow of
    the bounded queue is QueueFull — the caller surfaces 503."""
    from srplatform.settings import get_settings
    n = db.execute(text(
        "SELECT count(*) FROM model_jobs "
        "WHERE state IN ('queued','running')")).scalar_one()
    if int(n) >= get_settings().model_queue_max:
        raise QueueFull(
            f"model queue saturated ({n} pending/running; "
            f"cap {get_settings().model_queue_max})")
    job = ModelJob(kind=kind, priority=priority, payload=payload,
                   session_id=session_id, actor=actor,
                   parent_job=parent_job, attempt=attempt,
                   profile_id=profile.profile_id if profile else None,
                   profile_name=profile.name if profile else None,
                   state="queued")
    if run_at is not None:
        job.requested_at = run_at
    db.add(job)
    db.flush()
    start_model_jobs()      # backstop: whoever queues work ensures a runner
    return job


def wait(db, job_id: uuid.UUID, timeout: float, poll_s: float = 0.05) -> ModelJob:
    """Watch the durable row until terminal or the caller's bound elapses.
    Exceeding the bound raises TimeoutError; the JOB remains visible in
    the queue with its state — nothing is silently dropped."""
    deadline = time.monotonic() + timeout
    while True:
        job = db.get(ModelJob, job_id)
        db.refresh(job)
        if job is None:
            raise JobProblem("job not found")
        if job.state in TERMINAL_STATES or job.state == "cessation_unknown":
            return job
        if time.monotonic() >= deadline:
            raise TimeoutError(f"model job exceeded its {timeout:.0f} s bound")
        db.expunge_all()
        time.sleep(poll_s)


def cancel(db, job_id: uuid.UUID, *, actor: str = "operator") -> ModelJob:
    """Visible cancellation. Queued: terminal now. Running: request
    cessation — the slot releases only when the live call returns, and
    its (discarded) return is what CONFIRMS cessation."""
    job = db.get(ModelJob, job_id)
    if job is None:
        raise JobProblem("job not found")
    if job.state in TERMINAL_STATES:
        return job
    if job.state == "queued":
        job.state = "cancelled"
        job.error = f"cancelled by {actor} before execution"
        job.finished_at = _now()
    elif job.state == "running":
        job.cancel_requested = True
        job.error = (f"cancellation requested by {actor}: slot held until "
                     "the live provider call returns (never preempted)")
    db.flush()
    return job


def reconcile_startup(db) -> int:
    """Rows left 'running' by a crash: the call may or may not have
    completed provider-side — cessation cannot be confirmed, and it is
    NEVER assumed or replayed. The rows stay as obligations."""
    rows = db.execute(select(ModelJob).where(ModelJob.state == "running")
                      ).scalars().all()
    for job in rows:
        job.state = "cessation_unknown"
        job.error = ("API restarted while this call was live: provider-side "
                     "cessation cannot be confirmed; never replayed")
        job.finished_at = _now()
    db.flush()
    return len(rows)


# --------------------------------------------------------------------------- #
# the scheduler thread (one per API/controller process)                         #
# --------------------------------------------------------------------------- #

_CLAIM_SQL = text("""
    UPDATE model_jobs
       SET state = 'running', started_at = now()
     WHERE job_id = (SELECT job_id FROM model_jobs
                      WHERE state = 'queued' AND requested_at <= now()
                      ORDER BY priority ASC, requested_at ASC
                      LIMIT 1)
       AND NOT EXISTS (SELECT 1 FROM model_jobs WHERE state = 'running')
    RETURNING job_id
""")


def _job_result_from_turn(res) -> dict:
    from srplatform.red_agent import conversation as conv
    return {
        "kind": res.kind, "text": res.text, "tool_call": res.tool_call,
        "usage": res.usage, "finish_reason": res.finish_reason,
        "response_messages": conv.dump_messages(res.response_messages),
    }


def _persist_turn(db, job: ModelJob, result: dict) -> None:
    """Append the response revision IN THE SAME transaction that marks the
    job succeeded: history and job state can never disagree."""
    payload = job.payload or {}
    persist = payload.get("persist")
    if not persist:
        return
    for msg in result.get("response_messages") or []:
        db.add(ConversationRevision(
            session_id=uuid.UUID(persist["session_id"]),
            kind="messages", payload=msg, profile_id=job.profile_id,
            usage=result.get("usage"),
            finish_reason=result.get("finish_reason")))


def _execute(job_id: uuid.UUID) -> None:
    """Run one claimed job: load (short tx) → provider call (NO session)
    → terminal write (short tx) → visible retry row when eligible."""
    from srplatform.model_admin import ProfileUnavailable
    from srplatform.red_agent import conversation as conv
    from srplatform.red_agent.conversation import (CompletionRejected,
                                                   ProviderProblem)

    payload: dict = {}
    with db_ctx() as s:
        job = s.get(ModelJob, job_id)
        if job is None or job.state != "running":
            return
        payload = dict(job.payload or {})
        job_profile_id = str(job.profile_id) if job.profile_id else None
        if job.cancel_requested:
            job.state = "cancelled"
            job.error = (job.error or "cancellation requested") + \
                        "; never dispatched"
            job.finished_at = _now()
            s.commit()
            return
        profile = s.get(ModelProfile, uuid.UUID(job_profile_id)) \
            if job_profile_id else None
        if profile is None or profile.status != "active":
            job.state = "failed"
            job.error = ("profile version is no longer active "
                         f"({profile.status if profile else 'missing'}) — "
                         "refusing to run on a substitute")
            job.finished_at = _now()
            s.commit()
            return
        profile_snapshot = profile

    mode = payload.get("mode", "text")
    error_text: str | None = None
    retryable = False
    try:
        if mode == "turn":
            messages = conv.load_messages(payload["messages"])
            res = conv.run_turn(profile_snapshot, messages,
                                timeout_s=profile_snapshot.timeout_s,
                                stream=bool(payload.get("stream")))
            result = _job_result_from_turn(res)
        else:
            res = conv.run_text(profile_snapshot, payload["system"],
                                payload["user"],
                                max_tokens=payload.get("max_tokens"),
                                timeout_s=profile_snapshot.timeout_s)
            result = _job_result_from_turn(res)
    except ProfileUnavailable as exc:
        error_text, retryable = str(exc)[:900], False
    except CompletionRejected as exc:
        error_text, retryable = str(exc)[:900], False
    except ProviderProblem as exc:
        error_text, retryable = str(exc)[:900], bool(exc.retryable)
    except Exception as exc:  # noqa: BLE001 — normalized, never swallowed
        error_text, retryable = f"{type(exc).__name__}: {exc}"[:900], True

    with db_ctx() as s:
        job = s.get(ModelJob, job_id)
        if job is None:
            return
        # did an operator/rotation request cessation while we were live?
        s.refresh(job)
        if error_text is None:
            if job.cancel_requested:
                job.state = "cancelled"
                job.error = ("cancelled: provider call returned; result "
                             "discarded per cancellation request")
                job.finished_at = _now()
            else:
                job.state = "succeeded"
                job.result = result
                job.finished_at = _now()
                _persist_turn(s, job, result)
        else:
            eligible = retryable and job.attempt < MODEL_ATTEMPTS
            if job.cancel_requested:
                job.state = "cancelled"
                job.error = error_text
                job.finished_at = _now()
            elif eligible:
                job.state = "failed"
                job.error = (error_text + f" — retry attempt "
                             f"{job.attempt + 1}/{MODEL_ATTEMPTS} queued")
                job.finished_at = _now()
            else:
                job.state = "failed"
                job.error = error_text
                job.finished_at = _now()
        s.commit()

    # visible retry: a NEW row (attempt+1, parent) entering the same queue
    if error_text is not None and retryable:
        with db_ctx() as s:
            job = s.get(ModelJob, job_id)
            if job and job.state == "failed" and job.attempt < MODEL_ATTEMPTS:
                try:
                    enqueue(s, kind=job.kind, priority=job.priority,
                            payload=job.payload, session_id=job.session_id,
                            profile=s.get(ModelProfile, job.profile_id)
                            if job.profile_id else None,
                            actor=job.actor, parent_job=job.job_id,
                            attempt=job.attempt + 1,
                            run_at=_now() + timedelta(
                                seconds=RETRY_DELAYS[
                                    min(job.attempt - 1,
                                        len(RETRY_DELAYS) - 1)]))
                    s.commit()
                except QueueFull:
                    s.commit()   # the failure is already durable: visible


class ModelJobScheduler(threading.Thread):
    """ONE worker slot: the thread claims at most one job and executes it
    inline, so process-level concurrency matches the database invariant
    (and a provider can prove it: max_concurrent == 1)."""

    def __init__(self, poll_s: float = 0.2):
        super().__init__(daemon=True, name="model-jobs")
        self._stop = threading.Event()
        self.poll_s = poll_s

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        backoff_s = self.poll_s
        while not self._stop.is_set():
            try:
                claimed = self._claim()
                if claimed is None:
                    self._stop.wait(self.poll_s)
                    backoff_s = self.poll_s
                    continue
                _execute(claimed)
                backoff_s = self.poll_s
            except Exception:  # noqa: BLE001 — never die silently, but
                # a broken DB must not spin: back off and stay visibly down
                backoff_s = min(30.0, max(self.poll_s, backoff_s * 2))
                self._stop.wait(backoff_s)

    def _claim(self) -> uuid.UUID | None:
        with db_ctx() as s:
            try:
                row = s.execute(_CLAIM_SQL).first()
                s.commit()
            except IntegrityError:
                # another process won the single-running slot for this
                # instant; nothing was lost, the row stays queued
                s.rollback()
                return None
            return row[0] if row else None


_scheduler: ModelJobScheduler | None = None
_lock = threading.Lock()


def start_model_jobs() -> ModelJobScheduler:
    """Idempotent: ensure this process has its scheduler thread."""
    global _scheduler
    with _lock:
        if _scheduler is not None and _scheduler.is_alive():
            return _scheduler
        _scheduler = ModelJobScheduler()
        _scheduler.start()
        return _scheduler


def stop_model_jobs(timeout: float = 5.0) -> None:
    global _scheduler
    with _lock:
        if _scheduler is not None:
            _scheduler.stop()
            sched, _scheduler = _scheduler, None
        else:
            sched = None
    if sched is not None:
        sched.join(timeout=timeout)
