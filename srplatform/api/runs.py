"""Run manager (F02/F13): supervised red-worker subprocesses with durable state.

Replaces the daemon-thread + arbitrary-PID model:
  * /run validates everything BEFORE spawning (safety latch/evidence, runner
    availability, session exists/matches, no duplicate active run) — and the
    whole validate→spawn window participates in the SAME durable operation
    claim used by end/reset/teardown (audit T02): a run can never slip its
    worker between teardown's "no active worker" check and its release.
  * Each run is a subprocess in its OWN process group; the API registers the
    handle and a watchdog thread finalizes state if the worker dies uncleanly.
  * The worker authenticates back to the API with a one-shot run-scoped token
    (only its sha256 is stored) limited to its own session's evidence plane.
  * Termination kills the process GROUP (worker), and — for REMOTE commands —
    the durable `run_operations` inventory is cancelled through the runner
    control channel with CONFIRMED cessation (audit T01). A worker exiting
    proves nothing about remote work; unconfirmed cessation becomes
    'cancel-unknown': visible, blocks new commands, retains the reservation,
    and is retried by startup recovery. 'stopping' is never a success.
"""
from __future__ import annotations

import hashlib
import os
import secrets
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from srplatform.db.models import Run, RunOperation
from srplatform.db.session import db as db_ctx
from srplatform.safety import get_supervisor
from srplatform.safety.runregistry import (RunHandle, pgid_alive, pgid_matches_identity,
                                           pgid_start_time, run_registry)

# ONE consistent operation state machine (audit T02): every lifecycle check,
# uniqueness lookup, active-run lookup and restart recovery treats these
# states as ACTIVE (a run whose work is not confirmed finished). 'stopping'
# and 'cancel-unknown' are NOT finished and NOT success.
ACTIVE = ("queued", "running", "stopping", "cancel-unknown")
# states a stop attempt may legitimately act on (retryable) vs final states
STOPPABLE = ACTIVE
TERMINAL = ("completed", "failed", "cancelled")
# a run may only spawn/register commands while it is one of these (audit
# T-04): 'stopping'/'cancel-unknown' runs must NOT accept new work — the
# stop/recovery path owns them until every operation is resolved.
SPAWNNABLE = ("queued", "running")
# operation states that mean "remote work may still exist"
UNRESOLVED_OPS = ("active", "cancel-unknown")


def _now():
    return datetime.now(timezone.utc)


def _unresolved_ops_exists():
    """Correlated EXISTS over unresolved operations of the UPDATE's run row
    (audit T-04): a terminal transition is a SINGLE statement that also
    requires 'no operation may still be live' — a registration cannot slip
    between a check and the transition."""
    return select(RunOperation.id).where(
        RunOperation.run_id == Run.run_id,
        RunOperation.state.in_(UNRESOLVED_OPS)).exists()


def lock_run(db: Session, run_id) -> None:
    """Acquire the run-row serialization lock (held until the CURRENT
    transaction ends). Registration holds the same lock from its status
    fence through its INSERT commit — so an inventory check performed AFTER
    this call cannot miss a registration that committed before it (audit F2:
    the guarded UPDATE alone is not enough, its statement snapshot can
    predate a registration commit under READ COMMITTED)."""
    db.execute(select(Run.run_id).where(Run.run_id == run_id).with_for_update())


def has_unresolved_operations(db: Session, run_id) -> bool:
    """FRESH statement — after lock acquisition this sees every committed
    registration (audit F2)."""
    return db.execute(
        select(RunOperation.id).where(RunOperation.run_id == run_id,
                                      RunOperation.state.in_(UNRESOLVED_OPS))
        .limit(1)).first() is not None


def unresolved_operations(db: Session, session_id) -> list[RunOperation]:
    """DURABLE lifecycle obligations for a session — unresolved operations on
    ANY of its runs, independent of run status (audit F2: an active-run-only
    lookup lets a corrupt terminal row hide live work from release)."""
    return db.execute(select(RunOperation)
                      .join(Run, Run.run_id == RunOperation.run_id)
                      .where(Run.session_id == session_id,
                             RunOperation.state.in_(UNRESOLVED_OPS))).scalars().all()


def guarded_terminal_update(db: Session, run_id, values: dict,
                            extra_where=()) -> int:
    """ONE coherent terminal-writer protocol (audit F2): take the run-row
    lock, re-check the operation inventory with a FRESH query, and perform
    the transition GUARDED against unresolved operations. Returns rowcount —
    0 means the obligation stands and the caller must persist a visible
    cancel-unknown instead. EVERY terminal writer (stop, complete, spawn
    race, latch recheck, watchdog, startup reconciliation) goes through
    this; per-operation commits inside the resolution passes release the
    lock, so callers re-check AFTER them, never before."""
    lock_run(db, run_id)
    stmt = (update(Run)
            .where(Run.run_id == run_id, *extra_where, ~_unresolved_ops_exists())
            .values(**values))
    res = db.execute(stmt)
    db.commit()
    return res.rowcount


class RunConflict(RuntimeError):
    pass


class RunStateError(RuntimeError):
    """Terminal run state is final — a late/duplicate callback may not rewrite it."""


class GateRefused(RuntimeError):
    def __init__(self, reasons):
        self.reasons = reasons
        super().__init__("; ".join(reasons))


def active_run_for_session(db: Session, session_id) -> Run | None:
    return db.execute(select(Run).where(Run.session_id == session_id,
                                         Run.status.in_(ACTIVE))
                      .order_by(Run.started_at.desc().nullslast())).scalars().first()


# ------------------------------------------------------- remote cancellation --
def _control_runner():
    """Runner adapter used for AUTHORITATIVE remote cancellation over the
    control channel (independent of any worker). None when the transport has
    no remote channel (local-dev). Construction failure is NOT silence: the
    caller reports it as unconfirmed."""
    from srplatform.settings import get_settings
    s = get_settings()
    if s.runner_transport != "ssh":
        return None
    from srplatform.red_agent.runner import SshRunner
    return SshRunner(s)   # raises RunnerUnavailable when misconfigured


def _resolve_local_operations(db: Session, run: Run) -> dict:
    """AUDIT F7: the terminal guard counts LOCAL rows too, so the resolution
    pass must handle them with REAL local cessation evidence (recorded
    command-group identity), never by dropping the guard or marking rows done
    because the worker exited — LocalDevRunner creates INDEPENDENT command
    groups that outlive it. Unconfirmed rows become VISIBLE cancel-unknown
    (retained, retryable), never silently active."""
    ops = db.execute(select(RunOperation).where(
        RunOperation.run_id == run.run_id,
        RunOperation.state.in_(("active", "cancel-unknown")),
        RunOperation.kind == "local")).scalars().all()
    if not ops:
        return {"ok": True, "ops": [], "detail": "no local operations"}
    from srplatform.red_agent.runner import local_op_cessation
    results = []
    for o in ops:
        res = local_op_cessation(o.op_id)
        o.state = "completed" if res["confirmed"] else "cancel-unknown"
        if res["confirmed"]:
            o.ended_at = _now()
        o.detail = f"local cessation: {res['detail']}"[:2000]
        db.commit()   # each verdict is durable as it is made
        results.append({"op_id": o.op_id, "cancelled": res["confirmed"],
                        "detail": res["detail"]})
    ok = all(r["cancelled"] for r in results)
    return {"ok": ok, "ops": results,
            "detail": "all local operations confirmed gone" if ok else
                      f"{sum(1 for r in results if not r['cancelled'])} local "
                      "operation(s) UNCONFIRMED — reservation retained"}


def cancel_remote_operations(db: Session, run: Run, runner=None,
                             timeout_s: float = 15.0) -> dict:
    """Resolve every UNRESOLVED operation of a run: LOCAL rows through the
    recorded command-group identity (audit F7), REMOTE rows through the
    runner control channel with CONFIRMED cessation (audit T01). Rows are
    only marked completed on confirmation; otherwise they stay visible as
    'cancel-unknown' — never dropped from the inventory, and RETRIED by every
    later stop/recovery until confirmed. Returns a truthful per-op summary;
    ok=True only when nothing remains unconfirmed."""
    local = _resolve_local_operations(db, run)
    ops = db.execute(select(RunOperation).where(
        RunOperation.run_id == run.run_id,
        RunOperation.state.in_(("active", "cancel-unknown")),
        RunOperation.kind == "remote")).scalars().all()
    if not ops:
        return {"ok": local["ok"], "ops": local["ops"],
                "detail": (local["detail"] if local["ops"]
                           else "no unresolved remote operations")}
    if runner is None:
        try:
            runner = _control_runner()
        except Exception as e:  # noqa: BLE001 — misconfigured channel = unconfirmed
            for o in ops:
                o.state = "cancel-unknown"
            db.commit()
            return {"ok": False,
                    "ops": local["ops"] + [{"op_id": o.op_id, "cancelled": False,
                                            "detail": f"control channel unavailable: {e}"}
                                           for o in ops],
                    "detail": "remote cancellation UNAVAILABLE — cessation unconfirmed"}
    if runner is None:  # local-dev transport: remote ops cannot exist, but if
        for o in ops:   # a stale row does, it is unconfirmed, never silent
            o.state = "cancel-unknown"
        db.commit()
        return {"ok": False, "ops": local["ops"],
                "detail": "remote op rows exist but transport has no remote channel"}
    results = []
    for o in ops:
        try:
            confirmed = bool(runner.cancel_remote(o.op_id, timeout_s=timeout_s))
        except Exception as e:  # noqa: BLE001
            confirmed = False
            detail = f"control channel error: {e}"[:200]
        else:
            detail = ("runner confirmed cessation" if confirmed
                      else "runner did NOT confirm cessation")
        o.state = "completed" if confirmed else "cancel-unknown"
        if confirmed:
            o.ended_at = _now()
        results.append({"op_id": o.op_id, "cancelled": confirmed, "detail": detail})
        db.commit()   # each verdict is durable as it is made
    ok = local["ok"] and all(r["cancelled"] for r in results)
    return {"ok": ok, "ops": local["ops"] + results,
            "detail": "all operations confirmed gone" if ok else
                      f"{sum(1 for r in results if not r['cancelled'])} remote operation(s) "
                      "UNCONFIRMED — reservation retained"}


def cancel_all_active_remote_operations(runner=None) -> dict:
    """Killswitch/startup helper: cancel remote ops of every active run."""
    actions = []
    with db_ctx() as db:
        runs = db.execute(select(Run).where(Run.status.in_(ACTIVE))).scalars().all()
        for run in runs:
            res = cancel_remote_operations(db, run, runner=runner)
            actions.append({"run_id": str(run.run_id), **res})
    ok = all(a["ok"] for a in actions) if actions else True
    return {"ok": ok, "actions": actions}


# ------------------------------------------------------------------ start ----
def start_run(db: Session, session_id, scenario_id: str) -> Run:
    # ---- duplicate guard: repeated /run on an active run does NOT spawn ----
    existing = active_run_for_session(db, session_id)
    if existing:
        return existing

    sup = get_supervisor()
    ok, reasons = sup.start_gate()
    if not ok:
        raise GateRefused(reasons)

    run = Run(session_id=session_id, scenario_id=scenario_id, status="queued")
    token = secrets.token_urlsafe(32)
    run.worker_token = hashlib.sha256(token.encode()).hexdigest()
    db.add(run)
    try:
        # DURABLE BEFORE SPAWN (audit R01): the run row + credential commit
        # first so the worker never races its own credential. The partial
        # unique index (migrations 0007/0008) makes the duplicate check
        # ATOMIC — concurrent /run requests cannot both pass select-then-insert.
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = active_run_for_session(db, session_id)
        if existing:
            return existing
        raise RunConflict("an active run already exists for this session")

    from srplatform.settings import get_settings
    s = get_settings()
    from srplatform.db.models import MatchModel
    env = _worker_env(s, token, session_id, scenario_id, run,
                      match=db.get(MatchModel, session_id))
    try:
        proc = subprocess.Popen([sys.executable, "-m", "srplatform.red_agent.worker"],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, start_new_session=True, env=env)
    except OSError as e:
        run.status, run.outcome = "failed", "worker_failure"
        run.error = f"worker spawn failed: {e}"[:1000]
        run.ended_at = _now()
        db.flush()
        db.commit()
        raise RunConflict(f"worker spawn failed: {e}") from e

    pgid = os.getpgid(proc.pid)
    pstart = pgid_start_time(proc.pid)
    # ATOMIC queued->running transition (audit N02): a concurrent stop/end
    # flips the row out of 'queued'; this conditional update detects exactly
    # that and hands the freshly spawned process to the termination path.
    res = db.execute(
        update(Run)
        .where(Run.run_id == run.run_id, Run.status == "queued")
        .values(status="running", pid=proc.pid, pgid=pgid, pgid_pstart=pstart,
                started_at=_now()))
    db.commit()
    if res.rowcount == 0:
        # run terminated concurrently (stopping/cancelled/cancel-unknown).
        # PERSIST the outcome (audit T02): the termination obligation must
        # not depend on this request surviving. Success -> terminal cancelled
        # WITH the process identity retained; failure -> cancel-unknown so
        # recovery retries the kill, never a silent 'stopping' row. AUDIT F2:
        # the cancelled write is GUARDED — operations registered while the
        # row was 'queued' must not be hidden by this writer.
        term = run_registry.terminate_group(pgid, expected_pstart=pstart)
        if term["ok"]:
            wrote = guarded_terminal_update(
                db, run.run_id,
                {"status": "cancelled", "outcome": "canceled",
                 "pid": proc.pid, "pgid": pgid, "pgid_pstart": pstart,
                 "error": f"terminated concurrently during spawn: {term['detail']}"[:1000],
                 "ended_at": _now(), "worker_token": None})
            if wrote == 0:
                db.execute(update(Run).where(Run.run_id == run.run_id)
                           .values(status="cancel-unknown", outcome="worker_failure",
                                   pid=proc.pid, pgid=pgid, pgid_pstart=pstart,
                                   error=f"concurrently terminated but UNRESOLVED "
                                         f"operations exist — cessation UNCONFIRMED "
                                         f"({term['detail']})"[:1000]))
                db.commit()
        else:
            db.execute(update(Run).where(Run.run_id == run.run_id)
                       .values(status="cancel-unknown", outcome="worker_failure",
                               pid=proc.pid, pgid=pgid, pgid_pstart=pstart,
                               error=f"concurrently terminated but spawned worker "
                                     f"could not be killed: {term['detail']}"[:1000]))
            db.commit()
        raise RunConflict("run was terminated concurrently; spawned worker handed to "
                          f"termination ({term['detail']})")
    run.status, run.pid, run.pgid, run.pgid_pstart = "running", proc.pid, pgid, pstart
    run_registry.add(RunHandle(run_id=str(run.run_id), pid=proc.pid, pgid=pgid,
                               process=proc, meta={"session_id": str(session_id)},
                               pgid_pstart=pstart))

    # START/ENGAGE RACE (audit N02): the latch could have been engaged between
    # the gate check and process registration. Re-check AFTER registration and
    # kill our own group if so — a start racing an engaged latch never escapes
    # supervision. A FAILED kill is never reported as cancelled (audit T02).
    if get_supervisor().latch_status()["latched"]:
        term = run_registry.terminate_group(pgid, expected_pstart=pstart)
        if term["ok"]:
            # AUDIT F2: guarded — an operation registered in the spawn window
            # must not be hidden by a latch-path 'cancelled'.
            wrote = guarded_terminal_update(
                db, run.run_id,
                {"status": "cancelled", "outcome": "canceled",
                 "ended_at": _now(), "worker_token": None})
            if wrote == 0:
                run.status, run.outcome = "cancel-unknown", "worker_failure"
                run.error = ("latch engaged during spawn but UNRESOLVED operations "
                             "exist — cessation UNCONFIRMED")
            else:
                run.status, run.outcome, run.ended_at = "cancelled", "canceled", _now()
                run.worker_token = None
        else:
            run.status, run.outcome = "cancel-unknown", "worker_failure"
            run.error = (f"latch engaged during spawn and the kill FAILED: "
                         f"{term['detail']} — worker group may still be running")
        db.commit()
        raise GateRefused([f"safety latch engaged during worker start — spawned "
                           f"worker termination {'confirmed' if term['ok'] else 'UNCONFIRMED'} "
                           f"({term['detail']})"])
    _watch(proc, str(run.run_id))
    return run


# The worker environment is serialized from the controller's RESOLVED settings
# (audit N04): it must not depend on whether the operator supplied a value via
# os.environ or via dotenv, and it must not inherit anything else. The worker
# is the least-privileged component — API capability and runner channel ONLY;
# no DB/Proxmox/owner/bastion credentials AND no model endpoint credential
# (audit Stage 5: red turns are scheduled through the API's shared gateway).
_WORKER_SETTING_KEYS = {
    "SR_ENV": "sr_env",
    "API_BASE_URL": "api_base_url",
    "RUNNER_TRANSPORT": "runner_transport",
    "RUNNER_SSH_TARGET": "runner_ssh_target",
    "RUNNER_SSH_KEY_PATH": "runner_ssh_key_path",
    "RUNNER_SSH_KNOWN_HOSTS": "runner_ssh_known_hosts",
    "RUNNER_COMMAND_TIMEOUT_S": "runner_command_timeout_s",
    "RUNNER_MAX_OUTPUT_BYTES": "runner_max_output_bytes",
    "RUNNER_SUPERVISOR_BIN": "runner_supervisor_bin",
    "RUNNER_LOCAL_OP_DIR": "runner_local_op_dir",
}


def _worker_env(s, token: str, session_id, scenario_id: str, run: Run,
                match=None) -> dict:
    import os as _os
    env = {k: _os.environ.get(k, "") for k in ("PATH", "HOME", "LANG", "LC_ALL", "TZ")}
    env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
    env["SR_PROCESS_ROLE"] = "worker"
    for k, attr in _WORKER_SETTING_KEYS.items():
        env[k] = str(getattr(s, attr))
    env.update({
        "SR_API_BASE": s.api_base_url,
        "SR_SESSION_ID": str(session_id),
        "SR_SCENARIO_ID": scenario_id,
        "SR_RUN_ID": str(run.run_id),
        "SR_WORKER_TOKEN": token,
    })
    # SUSTAINED MATCH (pilot steps 3+4): the per-action throttle and the
    # SERVER match deadline come from the session's SNAPSHOT row (never
    # re-read live mid-match). Harmless operational values — no credential
    # ever rides the worker environment.
    env["SR_ATTACK_PACE_S"] = str(
        match.pace_seconds if match is not None else s.match_default_pace_seconds)
    if match is not None and match.deadline_at is not None:
        env["SR_MATCH_DEADLINE_UTC"] = match.deadline_at.isoformat()
    return env


def _watch(proc: subprocess.Popen, run_id: str) -> None:
    def _j():
        code = proc.wait()
        run_registry.remove(run_id)
        with db_ctx() as s:
            run = s.get(Run, run_id)
            if run is None:
                return
            if run.status in ("queued", "running"):
                # worker never reported and NO stop owns this row (a
                # 'stopping'/'cancel-unknown' row belongs to the stop/recovery
                # path — finalizing it here would race the authoritative
                # cessation check). LOCAL containment died with the worker;
                # REMOTE work must be confirmed through the control channel
                # before anything is called finished (audit T01). AUDIT F2:
                # the 'failed' write is GUARDED — an operation registered
                # during the resolution pass keeps the obligation visible.
                remote = cancel_remote_operations(s, run)
                if remote["ok"]:
                    wrote = guarded_terminal_update(
                        s, run.run_id,
                        {"status": "failed", "outcome": "worker_failure",
                         "error": f"worker exited {code} without reporting",
                         "ended_at": _now()})
                    if wrote == 0:
                        s.execute(update(Run).where(Run.run_id == run_id)
                                  .values(status="cancel-unknown",
                                          error="worker exited without reporting and "
                                                "UNRESOLVED operations remain — "
                                                "cessation UNCONFIRMED"))
                        s.commit()
                else:
                    run.status = "cancel-unknown"
                    run.error = (f"worker exited {code} without reporting and remote "
                                 f"cessation is UNCONFIRMED: {remote['detail']}")
    threading.Thread(target=_j, daemon=True, name=f"run-watch-{run_id[:8]}").start()


# ------------------------------------------------------------------- stop ----
def stop_run(db: Session, run_id, runner=None) -> dict:
    """Authoritative stop (audit T01/T02): the run becomes 'cancelled' ONLY
    when the worker group is confirmed dead AND every remote operation is
    confirmed gone. A failed kill never sets cancelled; 'stopping' is an
    intermediate state that is never reported as success (ok=False)."""
    run = db.get(Run, run_id)
    if run is None:
        raise KeyError("run not found")
    if run.status in TERMINAL:
        # AUDIT F2: 'already finished' is only truthful when NO obligation
        # survives the finished row. A pre-existing inconsistent terminal row
        # (terminal status + unresolved operation) is ATTEMPTED for genuine
        # resolution here — and blocks (ok=False) while unconfirmed, never a
        # fabricated cessation.
        lock_run(db, run_id)
        if not has_unresolved_operations(db, run_id):
            db.commit()
            return {"ok": True, "status": run.status, "note": "already finished"}
        res = cancel_remote_operations(db, run, runner=runner)
        lock_run(db, run_id)
        still = has_unresolved_operations(db, run_id)
        db.commit()
        if not still and res["ok"]:
            return {"ok": True, "status": run.status,
                    "note": "already finished; lingering operations resolved"}
        return {"ok": False, "status": run.status,
                "detail": f"terminal run has unresolved operations — {res['detail']}",
                "note": "unresolved_operations"}

    # CONDITIONAL transition into stopping (audit T02): concurrent stops
    # converge on one attempt; a terminal row can never be dragged back.
    was_queued = run.status == "queued"
    db.execute(update(Run).where(Run.run_id == run_id,
                                 Run.status.in_(("queued", "running")))
               .values(status="stopping"))
    db.commit()   # 'stopping' must be durable BEFORE the spawner race resolves
    db.refresh(run)

    if was_queued and not run.pgid:
        # SPAWN/STOP RACE (audit N02): the worker may be between Popen and
        # the spawner's pgid commit. The spawner's queued->running update
        # FAILS and it persists the terminal outcome itself. Poll briefly;
        # an unresolved race is NOT a success — the obligation is retained.
        for _ in range(50):
            db.refresh(run)
            if run.pgid or run.status not in ("stopping", "queued"):
                break
            time.sleep(0.1)
        if run.status in TERMINAL:
            return {"ok": True, "status": run.status,
                    "detail": "spawner completed the termination"}
        if not run.pgid:
            return {"ok": False, "status": run.status,
                    "detail": "worker not yet registered; the spawner or startup "
                              "recovery retains the termination obligation — NOT confirmed"}

    # 1. LOCAL containment: kill the worker's process group, confirmed.
    group_res = (run_registry.terminate_group(run.pgid, expected_pstart=run.pgid_pstart)
                 if run.pgid else {"ok": True, "detail": "no worker pgid recorded"})

    # 2. REMOTE containment: cancel + confirm every active remote operation.
    #    The terminal transition is GUARDED (audit T-04) and SERIALIZED
    #    (audit F2): before each attempt the run-row lock is re-acquired and
    #    the operation inventory re-checked with a FRESH query — the
    #    resolution passes commit per operation and therefore SURRENDER the
    #    lock, so a check made before them is not a terminal invariant.
    remote = {"ok": True, "detail": "no remote pass"}
    for _attempt in range(3):
        remote = cancel_remote_operations(db, run, runner=runner)
        if group_res["ok"] and remote["ok"]:
            lock_run(db, run_id)
            if has_unresolved_operations(db, run_id):
                db.commit()   # release the lock; retry the resolution pass
                continue
            res = db.execute(update(Run).where(Run.run_id == run_id,
                                               Run.status.in_(ACTIVE),
                                               ~_unresolved_ops_exists())
                             .values(status="cancelled", outcome="canceled",
                                     ended_at=_now(), worker_token=None))
            db.commit()
            if res.rowcount:
                return {"ok": True, "status": "cancelled", "detail": group_res["detail"]}
            db.refresh(run)
            if run.status in TERMINAL:
                return {"ok": True, "status": run.status,
                        "detail": "another request finalized the run"}
            continue    # an operation slipped in — cancel it, then retry
    # NEVER convert a failed/unconfirmed termination into 'cancelled'.
    detail = (f"worker group: {group_res['detail']}; remote: {remote['detail']}")
    db.execute(update(Run).where(Run.run_id == run_id, Run.status.in_(ACTIVE))
               .values(status="cancel-unknown",
                       error=f"stop UNCONFIRMED — {detail}"[:1000]))
    db.commit()
    return {"ok": False, "status": "cancel-unknown", "detail": detail}


# ---------------------------------------------------------------- complete ---
def complete_run(db: Session, run_id: str, worker_token: str, result: dict) -> Run:
    """Worker callback (authenticated by the run-scoped capability). The
    terminal transition is ATOMIC (audit T02): one conditional UPDATE binds
    token consumption + terminal state, so a concurrent stop can never have
    its cancellation overwritten by a late callback (or vice versa).

    FINALIZATION GATE (audit T-04): NO terminal state — success or failure —
    while remote operations remain unresolved. Any straggler is first taken
    through authoritative containment; an unconfirmed verdict leaves the run
    'cancel-unknown' (visible, blocking, retried by recovery). The worker's
    reported outcome never outranks the containment verdict."""
    run = db.get(Run, run_id)
    if run is None:
        raise KeyError("run not found")
    if run.worker_token is None:
        raise PermissionError("worker credential already consumed")
    token_hash = hashlib.sha256(worker_token.encode()).hexdigest()
    if token_hash != run.worker_token:
        raise PermissionError("bad worker token")
    outcome = str(result.get("outcome", "incomplete"))[:64]
    if outcome == "cancel_unconfirmed":
        # the worker itself could not confirm remote cessation (audit T01):
        # visible, blocks new commands, recovery retries — never 'completed'.
        status, ended = "cancel-unknown", None
    else:
        # AUDIT F2: resolution + SERIALIZED re-check. The passes commit per
        # operation (releasing locks); only a fresh inventory taken AFTER
        # re-acquiring the run-row lock can prove nothing registered in
        # between — the guarded UPDATE's own snapshot may predate a
        # registration commit under READ COMMITTED.
        status = "failed" if outcome == "worker_failure" else "completed"
        ended = _now()
        resolved = False
        remote = {"ok": True, "detail": "no unresolved operations"}
        for _attempt in range(3):
            remote = cancel_remote_operations(db, run)
            lock_run(db, run_id)
            if remote["ok"] and not has_unresolved_operations(db, run_id):
                resolved = True
                break
        if not resolved:
            status, ended = "cancel-unknown", None
            result = {**result, "containment": remote}
    values = dict(status=status, outcome=outcome, result=result,
                  ended_at=ended, worker_token=None)
    stmt = (update(Run)
            .where(Run.run_id == run_id, Run.worker_token == token_hash,
                   Run.status.in_(("queued", "running"))))
    if status in ("completed", "failed"):
        # guarded: refuse finalization while ANY operation is unresolved
        stmt = stmt.where(~_unresolved_ops_exists())
    res = db.execute(stmt.values(**values))
    db.commit()
    if res.rowcount == 0:
        db.refresh(run)
        if run.worker_token is None:
            raise PermissionError("worker credential already consumed")
        if run.status in ("queued", "running"):
            # LOST THE CONTAINMENT GUARD (audit T-04): a registration landed
            # between the containment pass and the transition. Consume the
            # credential, refuse the terminal state, leave the obligation
            # visible as 'cancel-unknown' for stop/recovery to retry.
            db.execute(update(Run).where(Run.run_id == run_id,
                                         Run.status.in_(("queued", "running")))
                       .values(status="cancel-unknown", worker_token=None,
                               error="run finalization REFUSED: unresolved remote "
                                     "operations exist — cessation UNCONFIRMED"))
            db.commit()
            db.refresh(run)
            return run
        raise RunStateError(f"run already {run.status}")
    db.refresh(run)
    return run


def verify_worker_token(run: Run, token: str | None) -> bool:
    return bool(token and run.worker_token
                and hashlib.sha256(token.encode()).hexdigest() == run.worker_token)


# ------------------------------------------------------------- reconciliation
def reconcile_on_startup() -> dict:
    """After an API restart: any run still marked active whose process group is
    gone is failed — AFTER remote operations are confirmed cancelled (audit
    T01: a worker exiting does not prove remote cessation; unconfirmed work
    stays visible as 'cancel-unknown' and keeps blocking). Groups still alive
    are RE-REGISTERED (so the killswitch can reach them) and terminated if the
    safety latch is engaged (the latch never forgets). 'stopping' and
    'cancel-unknown' rows are retried, never skipped (audit T02)."""
    from srplatform.db.models import Event
    actions = []
    with db_ctx() as db:
        rows = db.execute(select(Run).where(Run.status.in_(ACTIVE))).scalars().all()
        for run in rows:
            alive, identity_ok = False, False
            if run.pgid:
                alive = pgid_alive(run.pgid)
                identity_ok = pgid_matches_identity(run.pgid, run.pgid_pstart)
            if alive and identity_ok:
                # SURVIVING GROUP RE-ENTER SUPERVISION (audit R03): without
                # this the killswitch would only report the group, never kill
                # it.
                run_registry.add(RunHandle(run_id=str(run.run_id), pid=run.pid,
                                           pgid=run.pgid, process=None,
                                           pgid_pstart=run.pgid_pstart,
                                           meta={"session_id": str(run.session_id),
                                                 "recovered": True}))
                if get_supervisor().latch_status()["latched"]:
                    res = run_registry.terminate_group(run.pgid, expected_pstart=run.pgid_pstart)
                    remote = cancel_remote_operations(db, run)
                    run.worker_token = None
                    db.commit()
                    # AUDIT F2: guarded — a startup terminal write must not
                    # hide operations that are still unresolved.
                    if res["ok"] and remote["ok"] and guarded_terminal_update(
                            db, run.run_id,
                            {"status": "cancelled", "outcome": "canceled",
                             "ended_at": _now(), "worker_token": None}):
                        run.status, run.outcome, run.ended_at = "cancelled", "canceled", _now()
                        actions.append(f"run {str(run.run_id)[:8]}: latched kill on startup — {res['detail']}")
                    else:
                        # NEVER convert a failed termination into 'cancelled'
                        # (audit N05/T01): the work is still out there.
                        run.status = "cancel-unknown"
                        run.error = (f"latched kill on startup UNCONFIRMED: {res['detail']}; "
                                     f"remote: {remote['detail']}")
                        db.commit()
                        actions.append(f"run {str(run.run_id)[:8]}: LATCHED KILL UNCONFIRMED — {res['detail']}")
                    continue
            # worker gone (or identity mismatch — never signal a reused PGID)
            remote = cancel_remote_operations(db, run)
            if not remote["ok"]:
                run.status = "cancel-unknown"
                run.error = (f"reconciled after API restart: worker gone but remote "
                             f"cessation UNCONFIRMED: {remote['detail']}")
                db.add(Event(session_id=run.session_id, ts=_now(), actor="system",
                             action_type="run_reconciled",
                             payload={"run_id": str(run.run_id), "note": run.error}))
                actions.append(f"run {str(run.run_id)[:8]}: cancel-unknown (remote unconfirmed)")
            else:
                # AUDIT F2: guarded 'failed' — unresolved operations keep the
                # obligation visible as cancel-unknown instead.
                wrote = guarded_terminal_update(
                    db, run.run_id,
                    {"status": "failed", "outcome": "worker_failure",
                     "error": ("reconciled after API restart: worker gone" if not alive
                               else "reconciled after API restart: recorded process-group "
                                    "identity does not match (PGID reused?) — NOT signalling it"),
                     "ended_at": _now(), "worker_token": None})
                if wrote:
                    run.status, run.outcome = "failed", "worker_failure"
                    db.add(Event(session_id=run.session_id, ts=_now(), actor="system",
                                 action_type="run_reconciled",
                                 payload={"run_id": str(run.run_id), "note": run.error}))
                    actions.append(f"run {str(run.run_id)[:8]}: failed (worker gone)")
                else:
                    run.status = "cancel-unknown"
                    run.error = ("reconciled after API restart but UNRESOLVED operations "
                                 "remain — cessation UNCONFIRMED")
                    db.add(Event(session_id=run.session_id, ts=_now(), actor="system",
                                 action_type="run_reconciled",
                                 payload={"run_id": str(run.run_id), "note": run.error}))
                    actions.append(f"run {str(run.run_id)[:8]}: cancel-unknown (unresolved ops)")
        db.flush()
    return {"actions": actions}
