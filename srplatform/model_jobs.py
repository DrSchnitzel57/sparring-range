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
    if deadline_at is not None and deadline_at <= _now():
        # An expired authority at ADMISSION is terminal before the queue:
        # the provider is never contacted for a match that is already
        # over, whatever path enqueued it (round-2 finding 8 — every
        # route inherits this, not just the ones that remember).
        job.state = "cancelled"
        job.error = ("deadline elapsed before admission — nothing was "
                     "sent to the provider")
        job.finished_at = _now()
        db.add(job)
        db.flush()
        job.chain_root = job.job_id
        db.flush()
        _persist_logical_outcome(db, [job])
        return job
    db.add(job)
    db.flush()
    # round-3: the logical request's identity is fixed at birth — a root
    # is its own chain, a child inherits its parent's root. SQL-side
    # admission/dependency gates need the whole chain in one lookup.
    if parent_job is not None:
        parent = db.get(ModelJob, parent_job)
        job.chain_root = (parent.chain_root if parent is not None
                          and parent.chain_root is not None
                          else parent_job)
    else:
        job.chain_root = job.job_id
    db.flush()
    start_model_jobs()      # backstop: whoever queues work ensures a runner
    return job


def _retry_child(db, job: ModelJob):
    return db.execute(
        select(ModelJob)
        .where(ModelJob.parent_job == job.job_id)
        .order_by(ModelJob.attempt.desc())).scalars().first()


def _chain_rows(db, job_id: uuid.UUID) -> list[ModelJob]:
    """ALL rows of the LOGICAL request (round-2 findings 5/6/7): walk up
    to the chain root, then down through every retry descendant. Root
    operations — cancellation, deadline cascades, status reporting,
    outcome persistence — always operate on this whole closure, never
    on one attempt row in isolation: "the request" is the chain."""
    row = db.get(ModelJob, job_id)
    if row is None:
        raise JobProblem("job not found")
    root = row
    depth = 0
    while root.parent_job is not None and depth < 16:
        parent = db.get(ModelJob, root.parent_job)
        if parent is None:
            break
        root = parent
        depth += 1
    rows = [root]
    frontier = [root.job_id]
    while frontier:
        children = db.execute(select(ModelJob).where(
            ModelJob.parent_job.in_(frontier))
            .order_by(ModelJob.attempt.asc())).scalars().all()
        rows.extend(children)
        frontier = [c.job_id for c in children]
    return rows


def chain_view(db, job_id: uuid.UUID) -> tuple[ModelJob, list[ModelJob]]:
    """(final row, chain rows attempt-ordered) for one logical request
    (round-2 finding 6): every status API resolves ANY chain id to the
    chain's final outcome plus the attempt history, so an async caller
    polling the id it submitted never reports "failed" while a retry
    actually succeeded."""
    rows = _chain_rows(db, job_id)
    rows.sort(key=lambda j: j.attempt)
    final = max(rows, key=lambda j: (j.attempt, j.requested_at))
    return final, rows


#: states after which the chain will not change by itself any more
#: (an open cessation obligation still counts: it only changes via an
#: operator, and the member-visible outcome must not hang until then)
_QUIESCENT_STATES = TERMINAL_STATES + ("cessation_unknown",)


def _lock_chain(db, job_id: uuid.UUID,
                _passes: int = 24) -> list[ModelJob]:
    """Round-3 findings 1/2: return the WHOLE logical chain with an
    open row lock on every row, in a deterministic order (walk-up to
    the root first, then children attempt-ascending).

    This is the serialization point shared by cancellation, retry-child
    creation and the terminal write: every one of them takes the lock on
    the row it is about to change FIRST, so a stale snapshot can never
    overwrite a fresher one — the loser of the race blocks, re-reads the
    committed truth, and acts on that. The re-enumeration loop closes
    the one remaining window (a child committed by the terminal write
    between our lock pass and the enumeration): chains are bounded and
    a fenced chain grows no more, so the loop terminates.
    """
    row = db.execute(select(ModelJob)
                     .where(ModelJob.job_id == job_id)
                     ).scalars().first()
    if row is None:
        raise JobProblem("job not found")
    # walk up WITHOUT locking, so every cancellation acquires its row
    # locks in the SAME order: root first, then descendants
    # attempt-ascending. Consistent order = no lock-order deadlock.
    root = row
    depth = 0
    while root.parent_job is not None and depth < 16:
        parent = db.execute(select(ModelJob)
                            .where(ModelJob.job_id == root.parent_job)
                            ).scalars().first()
        if parent is None:
            break
        root = parent
        depth += 1

    def _lock(jid):
        return db.execute(select(ModelJob)
                          .where(ModelJob.job_id == jid)
                          .with_for_update()
                          .execution_options(populate_existing=True)
                          ).scalars().one()

    locked: dict[uuid.UUID, ModelJob] = {root.job_id: _lock(root.job_id)}
    for _ in range(_passes):
        frontier = list(locked)
        found: dict[uuid.UUID, None] = {}
        while frontier:
            children = db.execute(select(ModelJob)
                                  .where(ModelJob.parent_job.in_(frontier))
                                  .order_by(ModelJob.attempt.asc())
                                  ).scalars().all()
            frontier = []
            for c in children:
                if c.job_id not in locked and c.job_id not in found:
                    found[c.job_id] = None
                    frontier.append(c.job_id)
        if not found:
            break
        for jid in sorted(found, key=str):
            locked[jid] = _lock(jid)
    return [locked[jid] for jid in sorted(locked,
                                          key=lambda j: (locked[j].attempt,
                                                         str(j)))]


def error_kind(job: ModelJob) -> str | None:
    """NEUTRAL, content-free error classification for non-privileged
    surfaces (round-2 finding 4): the fact that something failed is
    never a secret, but WHY is provider-supplied and may echo the
    conversation (sealed competition material). Members and streams
    get this classification; the redacted diagnostic itself is
    operator-only."""
    if job.state == "cancelled":
        return "cancelled"
    if job.state == "cessation_unknown":
        return "cessation_unresolved"
    if job.state == "failed" or job.error:
        return "model_call_failed"
    return None


def _persist_logical_outcome(db, rows: list[ModelJob]) -> bool:
    """Run the job kind's result handler EXACTLY ONCE per logical
    request (round-2 finding 7): not per attempt. The handler belongs
    to the chain's FINAL row and fires only when every row of the chain
    is quiescent (no retry may still dispatch), claimed atomically with
    a guarded UPDATE so a terminal write racing a cancellation can
    never persist two hint/AAR events. Attempt diagnostics stay visible
    as their own rows; the OUTCOME (member evidence) is one event."""
    if not rows:
        return False
    handler = _result_handlers.get(rows[0].kind)
    if handler is None:
        return False
    if any(j.state not in _QUIESCENT_STATES for j in rows):
        return False
    final = max(rows, key=lambda j: (j.attempt, j.requested_at))
    claim = db.execute(text(
        "UPDATE model_jobs SET outcome_persisted = true "
        "WHERE job_id = :j AND outcome_persisted = false"),
        {"j": str(final.job_id)})
    if claim.rowcount != 1:
        return False                      # another writer owns the outcome
    try:
        handler(db, final, final.state == "succeeded")
    except Exception as exc:  # noqa: BLE001 — visible, and re-claimable
        db.execute(text(
            "UPDATE model_jobs SET outcome_persisted = false "
            "WHERE job_id = :j"), {"j": str(final.job_id)})
        final.error = ((final.error or "") +
                       f"; outcome handler failed: {type(exc).__name__}: "
                       f"{str(exc)[:200]}")[:2000]
        db.flush()
        return False
    return True


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
    """Cancellation of the LOGICAL REQUEST (round-2 finding 5, round-3
    findings 1/2): the operation cascades across the whole retry chain
    regardless of which row the caller named and regardless of any
    row's previously READ state. The protocol is lock-then-act, never
    read-then-overwrite:

    * every chain row is loaded UNDER ``FOR UPDATE`` in a deterministic
      order, so a scheduler that claimed the row between our read and
      our write makes us wait — and we then act on the committed truth
      (a LIVE row never receives a stale ``cancelled`` stamp; it
      receives the cessation request, keeping the slot obligation);
    * the cancellation INTENT is stamped durably on every chain row:
      retry-child creation and admission must both consult it under
      the row lock, so a "cancelled" request can never respawn,
      whichever direction the race goes;
    * after the locks are held, the chain is RE-ENUMERATED (a child
      committed by the terminal write mid-flight is found and killed
      too — nothing born of a cancelled chain survives it).

    Queued rows die un-executed; running rows get the cessation request
    (the watcher closes the live SDK task; the slot releases only on a
    definitive return, otherwise the obligation stands)."""
    job = db.get(ModelJob, job_id)
    if job is None:
        raise JobProblem("job not found")
    rows = _lock_chain(db, job_id)
    for j in rows:
        # durable intent FIRST (under our lock): no child may be born
        # or dispatch past this point, whichever transaction grows the
        # chain next
        j.cancel_intent = True
        if j.state == "queued":
            j.state = "cancelled"
            j.error = (f"cancelled by {actor} before execution "
                       "(logical request cancellation)")
            j.finished_at = _now()
        elif j.state == "running":
            if not j.cancel_requested:
                j.cancel_requested = True
                j.error = (
                    f"cancellation requested by {actor}: the live request "
                    "is being closed; if its return cannot confirm "
                    "cessation the slot stays held")
        # every OTHER state is terminal — the row stays what it is; the
        # INTENT still applies (it forbids any further growth of the
        # chain, e.g. a retry child racing this very cancellation)
    db.flush()
    _persist_logical_outcome(db, rows)
    db.refresh(job)
    return job


def _cascade_cancel_queued(db, parent: ModelJob, *, actor: str) -> None:
    """Retry/backoff children of a cancelled job must not survive it.
    Round-3: single conditional UPDATE per level — a row is cancelled
    ONLY if it is still queued at write time, so this can never stomp a
    row the scheduler claimed in the same instant."""
    frontier = [parent.job_id]
    while frontier:
        res = db.execute(text(
            "UPDATE model_jobs SET state = 'cancelled', cancel_intent = "
            "true, error = :e, finished_at = now() "
            "WHERE parent_job = ANY(:f) AND state = 'queued' "
            "RETURNING job_id"),
            {"e": f"cancelled with its parent job (by {actor})",
             "f": frontier})
        frontier = [r[0] for r in res]


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
    # the operator's resolution made this chain quiescent-final — the
    # member-visible outcome persists through the same once-protocol
    # (round-3 finding 4: NO terminal path bypasses it)
    _persist_logical_outcome(db, _chain_rows(db, job_id))
    db.flush()
    return job


def reconcile_startup(db) -> int:
    """Rows left 'running' by a crash: the call may or may not have
    completed provider-side — cessation cannot be confirmed, it is
    NEVER assumed, replayed, or released. These rows HOLD THE SLOT:
    no new admission is granted until an operator resolves each
    obligation (finding 2's restart case). Chains that end quiescent at
    reconciliation still owe the member ONE durable outcome (round-3
    finding 4: restart/recovery is a terminal path like every other)."""
    rows = db.execute(select(ModelJob).where(ModelJob.state == "running")
                      ).scalars().all()
    for job in rows:
        job.state = "cessation_unknown"
        job.error = ("API restarted while this call was live: provider-side "
                     "cessation cannot be confirmed; never replayed; slot "
                     "held until an operator resolves this obligation")
        job.finished_at = _now()
    db.flush()
    for job in rows:
        _persist_logical_outcome(db, _chain_rows(db, job.job_id))
    return len(rows)


def cancel_session_jobs(db, session_id, *, actor: str = "run finalization") -> dict:
    """Run stop/completion/finalization reaches model work (finding 2:
    nothing used to call cancel from run finalization — generation kept
    burning a 900 s profile timeout after the match ended). Queued jobs
    for this session die; running ones get the cessation request, which
    closes the live SDK call within the watcher interval. Round-3: every
    logical chain is cancelled ONCE, root first, so finalization takes
    exactly the cancellation protocol (durable intent, locked rows,
    one outcome per chain) and cannot deadlock a concurrent cancel."""
    rows = db.execute(select(ModelJob).where(
        ModelJob.session_id == session_id,
        ModelJob.state.in_(("queued", "running")))).scalars().all()
    # distinct logical chains, locked in a global order (root id)
    roots: dict = {}
    for job in rows:
        root = job
        depth = 0
        while root.parent_job is not None and depth < 16:
            parent = db.get(ModelJob, root.parent_job)
            if parent is None:
                break
            root = parent
            depth += 1
        roots.setdefault(root.job_id, None)
    cancelled = requested = 0
    for root_id in sorted(roots, key=str):
        chain = _lock_chain(db, root_id)
        was = {j.job_id: j.state for j in chain}
        cancel(db, root_id, actor=actor)
        cancelled += sum(1 for j in chain
                         if was[j.job_id] == "queued")
        requested += sum(1 for j in chain if was[j.job_id] == "running")
    db.flush()
    return {"queued_cancelled": cancelled,
            "running_cancellation_requested": requested}


# --------------------------------------------------------------------------- #
# the scheduler thread (one per API/controller process)                         #
# --------------------------------------------------------------------------- #

#: claim honors priority+FIFO, skips backoff-future rows, waits for a
#: free slot (running OR unresolved cessation obligation), and admits a
#: gated job ONLY once its prerequisite's LOGICAL CHAIN is quiescent —
#: while any attempt of the chain may still dispatch or recover the
#: dependent WAITS at admission (round-3 finding 3: a failed attempt
#: with a queued retry child has NOT finished). Quiescence is what the
#: slot decision needs; whether the final attempt then SUCCEEDED is the
#: executor's decision under the row lock — admitting a truly-failed
#: dependency is what lets the dependent fail truthfully ONCE instead
#: of being stranded in the queue forever. Rows carrying a cancellation
#: INTENT are never admitted, and neither are rows of a chain that
#: CONTAINS a cancelled row (round-4 finding 2: the candidate's own
#: flags are not enough — an escaped child of the pre-0023 defect has
#: clean flags and a cancelled root). A cancelled logical request does
#: not dispatch, wherever its rows are in the queue. The outer
#: ``state``/intent re-check is the CAS against a cancellation
#: committing between this statement's read and its write.
_CLAIM_SQL = text("""
    UPDATE model_jobs
       SET state = 'running', started_at = now()
     WHERE job_id = (SELECT j.job_id FROM model_jobs j
                      WHERE j.state = 'queued' AND j.requested_at <= now()
                        AND NOT j.cancel_intent AND NOT j.cancel_requested
                        AND NOT EXISTS (
                              SELECT 1 FROM model_jobs fc
                               WHERE fc.chain_root =
                                     COALESCE(j.chain_root, j.job_id)
                                 AND fc.state = 'cancelled')
                        AND (j.depends_on IS NULL OR (
                              (SELECT dr.chain_root FROM model_jobs dr
                                  WHERE dr.job_id = j.depends_on)
                                  IS NOT NULL
                          AND NOT EXISTS (
                                SELECT 1 FROM model_jobs q
                                 WHERE q.chain_root =
                                       (SELECT dr2.chain_root
                                          FROM model_jobs dr2
                                         WHERE dr2.job_id = j.depends_on)
                                   AND q.state IN ('queued', 'running'))))
                      ORDER BY j.priority ASC, j.requested_at ASC
                      LIMIT 1)
       AND state = 'queued'
       AND NOT cancel_intent AND NOT cancel_requested
       AND NOT EXISTS (SELECT 1 FROM model_jobs
                        WHERE state IN ('running', 'cessation_unknown'))
    RETURNING job_id
""")


def claim_next(s) -> uuid.UUID | None:
    """Run one production claim on the given session (the scheduler
    commits immediately; a test may hold the transaction open to
    exercise the exact cancellation/claim interleaving — SAME
    statement, SAME locks, no test-only path)."""
    row = s.execute(_CLAIM_SQL).first()
    return row[0] if row else None


def _checkpoint_persisted(db, job: ModelJob) -> bool:
    """Did THIS summarize attempt durably persist its coverage-bounded
    checkpoint? ``_persist_turn`` writes the checkpoint transactionally
    with success — but only when the summary text and the captured
    coverage range exist, and round-4 finding 3 demands the DEPENDENT
    side verify the artifact rather than trust the state label: a
    "succeeded" summary without a checkpoint still describes an
    uncompacted context, and dispatching a gated turn on it would send
    the over-budget blob the gate exists to prevent."""
    payload = job.payload or {}
    persist = payload.get("persist") or {}
    sid = persist.get("session_id")
    covers = payload.get("covers_through")
    if not sid or covers is None:
        return False
    from srplatform.db.models import ConversationRevision
    row = db.execute(
        select(ConversationRevision.revision_id).where(
            ConversationRevision.session_id == uuid.UUID(str(sid)),
            ConversationRevision.kind == "checkpoint",
            ConversationRevision.payload["covers_through"].as_integer()
            == int(covers)).limit(1)).first()
    return row is not None


def _dep_chain_state(db, dep_id: uuid.UUID) -> tuple[str, ModelJob]:
    """(state, final row) of the prerequisite's LOGICAL chain — the
    single authority for admission, execution and gated failure
    (round-3 finding 3, reworked by round-4 finding 3).

    ``in-flight``: an attempt may still dispatch or is live (the
    dependent must WAIT, not fail).
    ``succeeded``: the final attempt genuinely SUCCEEDED — and for a
    compaction summary, genuinely produced its durable checkpoint with
    the exact covered range. An operator's ``cessation_resolved`` is a
    slot-release ATTESTATION, not a result: it created no summary and
    must never authorize a dependent call, so it is failure, honestly
    reported as ``failed-final`` (state ``cessation_resolved``).
    ``no-checkpoint``: the summary attempt ended "succeeded" but no
    checkpoint row exists — dependent fails, never dispatches.
    An unresolved cessation is NEVER success."""
    rows = _chain_rows(db, dep_id)
    rows.sort(key=lambda j: (j.attempt, j.requested_at))
    final = rows[-1]
    if any(j.state in ("queued", "running") for j in rows):
        return "in-flight", final
    if final.state == "succeeded":
        if final.kind == "summarize" and not _checkpoint_persisted(db, final):
            return "no-checkpoint", final
        return "succeeded", final
    return "failed-final", final


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
        if job.cancel_requested or job.cancel_intent:
            # round-3 finding 2: a durable cancellation INTENT is
            # absolute — the request never dispatches, whichever row
            # carries it, and nothing may be born from it
            job.state = "cancelled"
            job.error = (job.error or "cancellation requested") + \
                        "; never dispatched"
            job.finished_at = _now()
            _cascade_cancel_queued(s, job, actor="cancellation")
            _persist_logical_outcome(s, _chain_rows(s, job_id))
            s.commit()
            return
        # round-4 finding 2 (fail-closed reconciliation before
        # dispatch): a chain that CONTAINS a cancelled row IS a
        # cancelled logical request, whatever this row's own flags
        # say — an escaped child of the pre-0023 defect, or of any
        # writer that grew the chain around the fence. It never
        # dispatches; it cancels truthfully and settles the chain.
        fenced = s.execute(text(
            "SELECT 1 FROM model_jobs WHERE chain_root = "
            "COALESCE(CAST(:r AS uuid), CAST(:j AS uuid)) "
            "AND state = 'cancelled' AND job_id <> CAST(:j2 AS uuid) "
            "LIMIT 1"),
            {"r": str(job.chain_root) if job.chain_root else None,
             "j": str(job_id), "j2": str(job_id)}).first()
        if fenced is not None:
            job.cancel_intent = True
            job.state = "cancelled"
            job.error = ("cancelled with its logical request — a "
                         "cancellation fence covers this chain; the "
                         "attempt never dispatched")
            job.finished_at = _now()
            _cascade_cancel_queued(s, job, actor="cancellation fence")
            _persist_logical_outcome(s, _chain_rows(s, job_id))
            s.commit()
            return
        if job.depends_on is not None:
            dep_row = s.get(ModelJob, job.depends_on)
            if dep_row is None:
                dep_state, dep_final = "failed-final", None
            else:
                dep_state, dep_final = _dep_chain_state(s, job.depends_on)
            if dep_state == "in-flight":
                # round-3 finding 3: the prerequisite logical request
                # may STILL recover (a retry is queued or live). The
                # dependent goes back to the queue untouched — waiting
                # for owned recovery is not a failure, and admitting
                # now would fail the caller before its own summary's
                # retry can succeed. The claim gate blocks re-admission
                # until the chain is quiescent, so this cannot spin.
                s.execute(text(
                    "UPDATE model_jobs SET state = 'queued' "
                    "WHERE job_id = :j AND state = 'running'"),
                    {"j": str(job_id)})
                s.commit()
                return
            if dep_state in ("failed-final", "no-checkpoint"):
                job.state = "failed"
                if dep_state == "no-checkpoint":
                    job.error = (
                        "prerequisite compaction summary did not persist "
                        "its coverage-bounded checkpoint — refusing to run "
                        "the gated turn against an uncompacted context "
                        "(nothing was sent to the provider)")
                else:
                    job.error = (
                        "prerequisite logical request did not succeed "
                        + (f"(final attempt {dep_final.attempt}: "
                           f"{dep_final.state})" if dep_final is not None
                           else "(prerequisite row missing)")
                        + " — refusing to run the gated work")
                job.finished_at = _now()
                _cascade_cancel_queued(s, job, actor="prerequisite failure")
                _persist_logical_outcome(s, _chain_rows(s, job_id))
                s.commit()
                return
        if job.deadline_at is not None and job.deadline_at <= _now():
            job.state = "cancelled"
            job.error = ("deadline elapsed before dispatch — nothing was "
                         "sent to the provider")
            job.finished_at = _now()
            _cascade_cancel_queued(s, job, actor="deadline")
            _persist_logical_outcome(s, _chain_rows(s, job_id))
            s.commit()
            return
        profile = s.get(ModelProfile, uuid.UUID(job_profile_id)) \
            if job_profile_id else None
        if profile is None or profile.status not in ("active", "superseded"):
            # A superseded version still RUNS already-queued work (its
            # session was frozen on it); revoked/retired never does.
            # Terminal for the logical request — so it goes through the
            # same outcome protocol (round-3 finding 4), never a silent
            # row write.
            job.state = "failed"
            job.error = ("profile version cannot serve this job "
                         f"({profile.status if profile else 'missing'}) — "
                         "refusing to run on a substitute")
            job.finished_at = _now()
            _cascade_cancel_queued(s, job, actor="profile unavailable")
            _persist_logical_outcome(s, _chain_rows(s, job_id))
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
        # round-3 finding 1: take the row lock FIRST, then act. A
        # cancellation committing concurrently either lands before our
        # read (its intent/requested flag is committed and we honor it)
        # or waits behind this transaction (and then acts on the state
        # we leave). There is no window in which a stale read becomes a
        # stale WRITE — every writer here locks before writing.
        s.execute(select(ModelJob).where(ModelJob.job_id == job_id)
                  .with_for_update())
        s.refresh(job)
        cease = bool(job.cancel_requested or job.cancel_intent)
        child = None
        if error_text is None:
            if cease:
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
            if cease:
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
                if job.cancel_intent:
                    # round-3 finding 2: a cancelled logical request
                    # spawns NOTHING. The failure is recorded honestly,
                    # but the retry chain ENDS here — the cancellation
                    # intent was stamped under this chain's row lock,
                    # so it is committed truth, not a racing opinion.
                    job.state = "cancelled"
                    job.error = (error_text + " — no retry is admitted "
                                 "for a cancelled logical request")
                    job.finished_at = _now()
                else:
                    # ATOMIC chain: the retry child exists exactly when
                    # the parent is terminal-failed — no window where
                    # the caller sees "final" while a retry starts
                    # (finding 5)
                    run_at = _now() + timedelta(
                        seconds=RETRY_DELAYS[min(job.attempt - 1,
                                                 len(RETRY_DELAYS) - 1)])
                    child = ModelJob(
                        kind=job.kind, priority=job.priority,
                        payload=job.payload, session_id=job.session_id,
                        actor=job.actor, parent_job=job.job_id,
                        depends_on=job.depends_on,
                        deadline_at=job.deadline_at,
                        attempt=job.attempt + 1,
                        chain_root=job.chain_root or job.job_id,
                        profile_id=job.profile_id,
                        profile_name=job.profile_name,
                        state="queued", requested_at=run_at)
                    s.add(child)
                    job.state = "failed"
                    job.error = (error_text + f" — retry attempt "
                                 f"{job.attempt + 1}/{MODEL_ATTEMPTS} "
                                 "queued")
                    job.finished_at = _now()
            else:
                job.state = "failed"
                job.error = error_text
                job.finished_at = _now()
        # the member-visible OUTCOME persists exactly once for the
        # whole logical request (round-2 finding 7), never per attempt:
        # an attempt that failed WITH a queued retry child leaves the
        # chain non-quiescent, so nothing fires until the final row
        _persist_logical_outcome(s, _chain_rows(s, job_id))
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
                claimed = claim_next(s)
                s.commit()
            except IntegrityError:
                # another process won the single-slot claim for this
                # instant; nothing was lost, the row stays queued
                s.rollback()
                return None
            return claimed


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
