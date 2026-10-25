"""Durable model jobs (plan 19): ONE admission slot, enforced by the
DATABASE — and the slot's obligation survives everything except
CONFIRMED cessation.

Every model admission — red-loop turns, interactive hints, AAR
narratives, compaction summaries, operator probes, and every bounded
retry attempt — is a ``model_jobs`` ROW. The partial UNIQUE index over
``('running','cessation_unknown')`` makes "at most one provider request
live" a database invariant across processes, not a process-local
courtesy. Review finding 2 was exactly this: only ``running`` was
protected, so a CLIENT timeout released the slot while the provider was
still generating. Now an uncertain cessation (timeout, mid-stream reset,
deadline, local cancel-close, crash) keeps the slot occupied as
``cessation_unknown`` until an operator records a bounded resolution —
a socket closing is never proof the provider stopped.

Policy carried over unchanged from the in-process gateway (F18):
priorities are hints (0) over red turns (5) over AAR batches (9);
priority schedules the QUEUE — a request already running is never
preempted; retries are at most MODEL_ATTEMPTS total with 5/15 s delays,
and every retry is a NEW visible row (attempt+1, parent_job) created
ATOMICALLY with its parent's failure — the caller's wait FOLLOWS the
chain and gets one final result (finding 5).

Failure axes (finding 2): a DEFINITE failure (complete HTTP error,
connection never opened, protocol rejection) releases the slot and may
retry. An UNCERTAIN failure (timeout, mid-stream close, local cancel,
crash reconciliation) never retries and never releases: it becomes a
cessation obligation. ``JobScheduler`` passes ``cancel_check`` and the
job deadline into the conversation layer, which CANCELS the live SDK
task — cancellation reaches generation, it is not just a flagged row.

No DB session is held during a provider call: claim, execute, and
terminal write are separate short transactions.
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

#: states a waiter treats as final (the job itself will not progress)
TERMINAL_STATES = ("succeeded", "failed", "cancelled", "cessation_resolved")
#: states that HOLD the one admission slot
OBLIGATION_STATES = ("running", "cessation_unknown")


class QueueFull(RuntimeError):
    """Visible overflow — bounded queue, never silent memory growth."""


class JobProblem(ValueError):
    """Operational refusal (bad id, terminal-state transition...)."""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def redact_error(text: str) -> str:
    """Defense in depth at persistence/display time: credentials are
    redacted at the SOURCE (conversation), and again here, so no layer
    can be the one that leaked (finding 3)."""
    from srplatform.red_agent.conversation import redact_secrets
    return redact_secrets(text)


def match_deadline(db, session_id):
    """Authoritative match end (server clock). While the session's match
    is RUNNING, model work must stop by this instant: queued jobs past
    it are cancelled before dispatch, live calls are closed by the
    watcher (finding 11: remaining match time caps queue, start AND
    generation, not just the loop check before a 900 s call)."""
    from srplatform.db.models import MatchModel
    row = db.execute(select(MatchModel).where(
        MatchModel.session_id == session_id)).scalars().first()
    if row is None or row.state != "running" or row.deadline_at is None:
        return None
    if row.deadline_at.tzinfo is None:
        from datetime import timezone
        return row.deadline_at.replace(tzinfo=timezone.utc)
    return row.deadline_at


_result_handlers: dict = {}


def register_result_handler(kind: str, fn) -> None:
    """Feature modules register ``fn(db, job, success)`` for a job kind.
    The scheduler calls it INSIDE the job's terminal transaction: a
    durable async request (member hint, AAR narrative) therefore has
    its outcome persisted exactly once, atomically with the job's final
    state — and the job row alone recovers it after a reload. Handlers
    must compute BEFORE writing rows (a raising handler leaves the job
    failed with the reason recorded)."""
    _result_handlers[kind] = fn


# --------------------------------------------------------------------------- #
# enqueue / wait / cancel (called from request handlers)                        #
# --------------------------------------------------------------------------- #

def enqueue(db, *, kind: str, priority: int, payload: dict,
            session_id: uuid.UUID | None = None,
            profile: ModelProfile | None = None,
            actor: str | None = None,
            parent_job: uuid.UUID | None = None,
            depends_on: uuid.UUID | None = None,
            deadline_at: datetime | None = None,
            attempt: int = 1,
            run_at: datetime | None = None) -> ModelJob:
    """Queue a durable admission. ``run_at`` (retry backoff) sets
    requested_at to a future instant; the claimer honors it.
    ``depends_on`` gates the job on ANOTHER job's success (compaction →
    gated turn, finding 4); ``deadline_at`` bounds the whole lifecycle:
    a job whose deadline elapsed before dispatch fails WITHOUT touching
    the provider. Overflow of the bounded queue is QueueFull."""
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
                   parent_job=parent_job, depends_on=depends_on,
                   deadline_at=deadline_at,
                   attempt=attempt,
                   profile_id=profile.profile_id if profile else None,
                   profile_name=profile.name if profile else None,
                   state="queued")
    if run_at is not None:
        job.requested_at = run_at
    db.add(job)
    db.flush()
    start_model_jobs()      # backstop: whoever queues work ensures a runner
    return job


def _retry_child(db, job: ModelJob):
    return db.execute(
        select(ModelJob)
        .where(ModelJob.parent_job == job.job_id)
        .order_by(ModelJob.attempt.desc())).scalars().first()


def wait(db, job_id: uuid.UUID, timeout: float,
         poll_s: float = 0.05) -> ModelJob:
    """Watch the durable row until its WHOLE retry chain is terminal or
    the caller's bound elapses. The caller gets ONE final result: a
    failed attempt with a queued retry child moves the watch to the
    child (finding 5 — no "502 now, silent success later"). Exceeding
    the bound raises TimeoutError; the JOB keeps its state."""
    deadline = time.monotonic() + timeout
    current = job_id
    while True:
        job = db.get(ModelJob, current)
        db.refresh(job)
        if job is None:
            raise JobProblem("job not found")
        if job.state in TERMINAL_STATES or job.state == "cessation_unknown":
            child = _retry_child(db, job) if job.state == "failed" else None
            if child is not None and child.job_id != current:
                current = child.job_id
                continue
            return job
        if time.monotonic() >= deadline:
            raise TimeoutError(f"model job exceeded its {timeout:.0f} s bound")
        # end the transaction between polls: a waiter must never occupy a
        # pool connection (or hold a snapshot) across its own wait bound —
        # the same rule that keeps provider calls transaction-free
        db.commit()
        db.expunge_all()
        time.sleep(poll_s)


def cancel(db, job_id: uuid.UUID, *, actor: str = "operator") -> ModelJob:
    """Visible cancellation, CASCADING over retry descendants (finding
    2/5: cancel must kill queued/backoff children, and a running call's
    close is reported as UNCERTAIN cessation, never as proof of stop).
    Queued: terminal now. Running: request cessation — the execution
    watcher closes the live SDK task; the slot releases only when the
    call returns definitively, or the obligation stands."""
    job = db.get(ModelJob, job_id)
    if job is None:
        raise JobProblem("job not found")
    if job.state in TERMINAL_STATES:
        return job
    if job.state == "queued":
        job.state = "cancelled"
        job.error = f"cancelled by {actor} before execution"
        job.finished_at = _now()
        _cascade_cancel_queued(db, job, actor=actor)
    elif job.state == "running":
        job.cancel_requested = True
        job.error = (f"cancellation requested by {actor}: the live request "
                     "is being closed; if its return cannot confirm "
                     "cessation the slot stays held")
    db.flush()
    return job


def _cascade_cancel_queued(db, parent: ModelJob, *, actor: str) -> None:
    """Retry/backoff children of a cancelled job must not survive it."""
    frontier = [parent.job_id]
    while frontier:
        children = db.execute(select(ModelJob).where(
            ModelJob.parent_job.in_(frontier),
            ModelJob.state == "queued")).scalars().all()
        frontier = []
        for child in children:
            child.state = "cancelled"
            child.error = f"cancelled with its parent job (by {actor})"
            child.finished_at = _now()
            frontier.append(child.job_id)
    db.flush()


def resolve_cessation(db, job_id: uuid.UUID, *, actor: str,
                      resolution: str,
                      action: str = "release") -> ModelJob:
    """The BOUNDED supported resolution for an unknown-cessation
    obligation (review finding 2): an operator — who can see the actual
    provider/appliance state — records what they did (e.g. confirmed
    the request finished or stopped it out-of-band). ``release`` frees
    the slot; the job stays terminal and non-replayable. There is no
    automatic expiry: unknown is never assumed stopped."""
    job = db.get(ModelJob, job_id)
    if job is None:
        raise JobProblem("job not found")
    if job.state != "cessation_unknown":
        raise JobProblem(
            f"job is {job.state}; only cessation_unknown can be resolved")
    if action != "release":
        raise JobProblem("the only supported resolution action is release")
    if not resolution or len(resolution) > 2000:
        raise JobProblem("resolution must be a short explanation")
    job.state = "cessation_resolved"
    job.resolved_by = actor
    job.resolution = resolution
    job.resolved_at = _now()
    db.flush()
    return job


def reconcile_startup(db) -> int:
    """Rows left 'running' by a crash: the call may or may not have
    completed provider-side — cessation cannot be confirmed, it is
    NEVER assumed, replayed, or released. These rows HOLD THE SLOT:
    no new admission is granted until an operator resolves each
    obligation (finding 2's restart case)."""
    rows = db.execute(select(ModelJob).where(ModelJob.state == "running")
                      ).scalars().all()
    for job in rows:
        job.state = "cessation_unknown"
        job.error = ("API restarted while this call was live: provider-side "
                     "cessation cannot be confirmed; never replayed; slot "
                     "held until an operator resolves this obligation")
        job.finished_at = _now()
    db.flush()
    return len(rows)


def cancel_session_jobs(db, session_id, *, actor: str = "run finalization") -> dict:
    """Run stop/completion/finalization reaches model work (finding 2:
    nothing used to call cancel from run finalization — generation kept
    burning a 900 s profile timeout after the match ended). Queued jobs
    for this session die; running ones get the cessation request, which
    closes the live SDK call within the watcher interval."""
    queued = db.execute(select(ModelJob).where(
        ModelJob.session_id == session_id,
        ModelJob.state == "queued")).scalars().all()
    running = db.execute(select(ModelJob).where(
        ModelJob.session_id == session_id,
        ModelJob.state == "running")).scalars().all()
    for job in queued:
        cancel(db, job.job_id, actor=actor)
    for job in running:
        cancel(db, job.job_id, actor=actor)
    db.flush()
    return {"queued_cancelled": len(queued), "running_cancellation_requested":
            len(running)}


# --------------------------------------------------------------------------- #
# the scheduler thread (one per API/controller process)                         #
# --------------------------------------------------------------------------- #

#: claim honors priority+FIFO, skips backoff-future rows, waits for a
#: free slot (running OR unresolved cessation obligation), and refuses
#: to admit a gated job before its prerequisite job reached a terminal
#: state (the executor then fails it visibly if the prerequisite did not
#: succeed).
_CLAIM_SQL = text("""
    UPDATE model_jobs
       SET state = 'running', started_at = now()
     WHERE job_id = (SELECT j.job_id FROM model_jobs j
                      WHERE j.state = 'queued' AND j.requested_at <= now()
                        AND (j.depends_on IS NULL OR EXISTS (
                              SELECT 1 FROM model_jobs d
                               WHERE d.job_id = j.depends_on
                                 AND d.state IN ('succeeded',
                                         'cessation_resolved',
                                         'cessation_unknown',
                                         'failed', 'cancelled')))
                      ORDER BY j.priority ASC, j.requested_at ASC
                      LIMIT 1)
       AND NOT EXISTS (SELECT 1 FROM model_jobs
                        WHERE state IN ('running', 'cessation_unknown'))
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
    """Append THIS turn's INPUTS and OUTPUTS in the SAME transaction
    that marks the job succeeded (review finding 1): history and job
    state can never disagree, every message the model saw is recorded
    exactly once, and the replay rule (system-bearing first revision,
    then every later revision) reconstructs a valid complete
    conversation on every later turn — tool calls, tool returns, the
    permanent system framing, all of it.

    Compaction checkpoints (kind=``summarize``) append their
    COVERAGE-BOUNDED checkpoint here, transactionally, using the range
    CAPTURED AT ENQUEUE — never "whatever max revision is now"."""
    payload = job.payload or {}
    persist = payload.get("persist")
    if not persist:
        return
    sid = uuid.UUID(persist["session_id"])
    if job.kind == "summarize":
        # The summarizer's answer is NOT part of the attacker
        # conversation — its compact artifact is the checkpoint below.
        # (Its wire input is likewise ephemeral: it was rendered from
        # rows that remain durably recorded until coverage.)
        summary = (result.get("text") or "").strip()
        if summary and payload.get("covers_through"):
            db.add(ConversationRevision(
                session_id=sid, kind="checkpoint",
                payload={"summary": summary,
                         "covers_through": int(payload["covers_through"])},
                profile_id=job.profile_id))
        return
    for msg in persist.get("input_new") or payload.get("input_new") or []:
        db.add(ConversationRevision(
            session_id=sid, kind="messages", payload=msg,
            profile_id=job.profile_id))
    for msg in result.get("response_messages") or []:
        db.add(ConversationRevision(
            session_id=sid, kind="messages", payload=msg,
            profile_id=job.profile_id,
            usage=result.get("usage"),
            finish_reason=result.get("finish_reason")))


def _cancel_requested(job_id: uuid.UUID) -> bool:
    """Cheap dedicated read used by the conversation-layer watcher from
    its own event loop (short-lived session, never nested)."""
    with db_ctx() as s:
        row = s.execute(text(
            "SELECT cancel_requested FROM model_jobs WHERE job_id = :j"),
            {"j": str(job_id)}).first()
        s.commit()
    return bool(row and row[0])


def _execute(job_id: uuid.UUID) -> None:
    """Run one claimed job: load (short tx) → provider call with cancel
    watcher (NO session) → terminal write (short tx), retry children
    created ATOMICALLY with the failure they continue."""
    from srplatform.model_admin import ProfileUnavailable
    from srplatform.red_agent import conversation as conv
    from srplatform.red_agent.conversation import (CompletionRejected,
                                                   LocalCancellation,
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
            _cascade_cancel_queued(s, job, actor="cancellation")
            s.commit()
            return
        if job.depends_on is not None:
            dep = s.get(ModelJob, job.depends_on)
            ok = dep is not None and dep.state in ("succeeded",
                                                    "cessation_resolved")
            if not ok:
                job.state = "failed"
                job.error = (
                    "prerequisite job did not succeed "
                    f"({dep.state if dep else 'missing'}) — refusing to "
                    "run the gated work")
                job.finished_at = _now()
                _cascade_cancel_queued(s, job, actor="prerequisite failure")
                s.commit()
                return
        if job.deadline_at is not None and job.deadline_at <= _now():
            job.state = "cancelled"
            job.error = ("deadline elapsed before dispatch — nothing was "
                         "sent to the provider")
            job.finished_at = _now()
            _cascade_cancel_queued(s, job, actor="deadline")
            s.commit()
            return
        profile = s.get(ModelProfile, uuid.UUID(job_profile_id)) \
            if job_profile_id else None
        if profile is None or profile.status not in ("active", "superseded"):
            # A superseded version still RUNS already-queued work (its
            # session was frozen on it); revoked/retired never does.
            job.state = "failed"
            job.error = ("profile version cannot serve this job "
                         f"({profile.status if profile else 'missing'}) — "
                         "refusing to run on a substitute")
            job.finished_at = _now()
            s.commit()
            return
        profile_snapshot = profile
        deadline_at = job.deadline_at

    mode = payload.get("mode", "text")
    error_text: str | None = None
    retryable = False
    uncertain = True
    # deadline → monotonic budget for the conversation-layer watcher;
    # the provider client timeout stays the profile's own
    deadline_monotonic: float | None = None
    if deadline_at is not None:
        left = (deadline_at - _now()).total_seconds()
        if left <= 0:
            left = 0.001
        deadline_monotonic = time.monotonic() + left
    try:
        if mode == "turn":
            # A turn's message list is RECONSTRUCTED at execution time
            # from the append-only store (plus this turn's captured
            # input), never from the enqueue-time snapshot: if this turn
            # was gated behind a summarize job, the checkpoint is now
            # committed and the request goes out COMPRESSED — sending
            # the pre-compaction blob after compaction would defeat the
            # entire purpose of gating (finding 4). For ungated turns
            # the reconstruction equals the snapshot by construction
            # (single slot, append-only history).
            persist = payload.get("persist") or {}
            if persist.get("session_id") and persist.get("input_new"):
                from srplatform import conversation_store as store
                with db_ctx() as rs:
                    prior, _cp, _cov = store.load_thread(
                        rs, uuid.UUID(persist["session_id"]))
                messages = (list(prior)
                            + conv.load_messages(persist["input_new"]))
            else:
                messages = conv.load_messages(payload["messages"])
            res = conv.run_turn(
                profile_snapshot, messages,
                timeout_s=profile_snapshot.timeout_s,
                stream=bool(payload.get("stream")),
                cancel_check=lambda: _cancel_requested(job_id),
                deadline_monotonic=deadline_monotonic)
            result = _job_result_from_turn(res)
        else:
            res = conv.run_text(
                profile_snapshot, payload["system"], payload["user"],
                max_tokens=payload.get("max_tokens"),
                timeout_s=profile_snapshot.timeout_s,
                cancel_check=lambda: _cancel_requested(job_id),
                deadline_monotonic=deadline_monotonic)
            result = _job_result_from_turn(res)
    except ProfileUnavailable as exc:
        error_text, retryable, uncertain = (
            redact_error(str(exc))[:900], False, False)
    except CompletionRejected as exc:
        error_text, retryable, uncertain = (
            redact_error(str(exc))[:900], False, bool(exc.uncertain))
    except LocalCancellation as exc:
        # the close proves nothing provider-side: obligation stands
        error_text, retryable, uncertain = (
            redact_error(str(exc))[:900], False, True)
    except ProviderProblem as exc:
        error_text, retryable, uncertain = (
            redact_error(str(exc))[:900], bool(exc.retryable),
            bool(getattr(exc, "uncertain", True)))
    except Exception as exc:  # noqa: BLE001 — normalized, never swallowed
        # unknown internal failure: assume nothing about the wire
        error_text, retryable, uncertain = (
            redact_error(f"{type(exc).__name__}: {exc}")[:900], False, True)

    with db_ctx() as s:
        job = s.get(ModelJob, job_id)
        if job is None:
            return
        s.refresh(job)
        child = None
        if error_text is None:
            if job.cancel_requested:
                # the call RETURNED: that is definitive cessation —
                # result discarded, slot releases
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
            if job.cancel_requested:
                job.state = ("cessation_unknown" if uncertain
                             else "cancelled")
                job.error = (error_text + " — provider-side cessation "
                             "cannot be confirmed; slot held until an "
                             "operator resolves this obligation"
                             if uncertain else
                             (error_text + " (cancellation confirmed by "
                              "the definitive failure of the call)"))
                job.finished_at = _now()
            elif uncertain:
                job.state = "cessation_unknown"
                job.error = (error_text + " — provider-side cessation "
                             "cannot be confirmed; slot held until an "
                             "operator resolves this obligation")
                job.finished_at = _now()
            elif retryable and job.attempt < MODEL_ATTEMPTS:
                # ATOMIC chain: the retry child exists exactly when the
                # parent is terminal-failed — no window where the caller
                # sees "final" while a retry starts (finding 5)
                run_at = _now() + timedelta(
                    seconds=RETRY_DELAYS[min(job.attempt - 1,
                                             len(RETRY_DELAYS) - 1)])
                child = ModelJob(
                    kind=job.kind, priority=job.priority,
                    payload=job.payload, session_id=job.session_id,
                    actor=job.actor, parent_job=job.job_id,
                    depends_on=job.depends_on, deadline_at=job.deadline_at,
                    attempt=job.attempt + 1,
                    profile_id=job.profile_id,
                    profile_name=job.profile_name,
                    state="queued", requested_at=run_at)
                s.add(child)
                job.state = "failed"
                job.error = (error_text + f" — retry attempt "
                             f"{job.attempt + 1}/{MODEL_ATTEMPTS} queued")
                job.finished_at = _now()
            else:
                job.state = "failed"
                job.error = error_text
                job.finished_at = _now()
        handler = _result_handlers.get(job.kind)
        if handler is not None:
            try:
                handler(s, job, job.state == "succeeded")
            except Exception as exc:  # noqa: BLE001 — visible, not lost
                job.state = "failed"
                job.error = (redact_error(
                    f"result handler failed: {type(exc).__name__}: {exc}")
                    [:800])
                job.finished_at = _now()
        s.commit()
        if child is not None:
            start_model_jobs()


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
                # another process won the single-slot claim for this
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
