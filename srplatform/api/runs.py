"""Run manager (F02/F13): supervised red-worker subprocesses with durable state.

Replaces the daemon-thread + arbitrary-PID model:
  * /run validates everything BEFORE spawning (safety latch/evidence, runner
    availability, session exists/matches, no duplicate active run).
  * Each run is a subprocess in its OWN process group; the API registers the
    handle and a watchdog thread finalizes state if the worker dies uncleanly.
  * The worker authenticates back to the API with a one-shot run-scoped token
    (only its sha256 is stored) limited to its own session's evidence plane.
  * Termination kills the process GROUP (command descendants), never the API,
    and works after an API restart via recovered pid/pgid rows.
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

from srplatform.db.models import Run
from srplatform.db.session import db as db_ctx
from srplatform.safety import get_supervisor
from srplatform.safety.runregistry import (RunHandle, pgid_alive, pgid_matches_identity,
                                           pgid_start_time, run_registry)

ACTIVE = ("queued", "running")


def _now():
    return datetime.now(timezone.utc)


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
                      .order_by(Run.started_at.desc())).scalars().first()


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
        # unique index (migration 0007) makes the duplicate check ATOMIC —
        # concurrent /run requests cannot both pass a select-then-insert.
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = active_run_for_session(db, session_id)
        if existing:
            return existing
        raise RunConflict("an active run already exists for this session")

    from srplatform.settings import get_settings
    s = get_settings()
    env = _worker_env(s, token, session_id, scenario_id, run)
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
    # that and hands the freshly spawned process to the termination path
    # instead of resurrecting a terminal run. A worker that COMPLETED before
    # this point also leaves 'queued' — its process is already gone, and
    # killing its (dead) group is harmless.
    from sqlalchemy import update
    res = db.execute(
        update(Run)
        .where(Run.run_id == run.run_id, Run.status == "queued")
        .values(status="running", pid=proc.pid, pgid=pgid, pgid_pstart=pstart,
                started_at=_now()))
    db.commit()
    if res.rowcount == 0:
        # run terminated concurrently (cancelled/stopping/completed)
        term = run_registry.terminate_group(pgid, expected_pstart=pstart)
        if not term["ok"]:
            db.execute(update(Run).where(Run.run_id == run.run_id)
                       .values(status="failed", outcome="worker_failure",
                               error=f"concurrently terminated but spawned worker "
                                     f"could not be killed: {term['detail']}"[:1000],
                               ended_at=_now()))
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
    # supervision.
    if get_supervisor().latch_status()["latched"]:
        term = run_registry.terminate_group(pgid, expected_pstart=pstart)
        run.status, run.outcome, run.ended_at = "cancelled", "canceled", _now()
        run.worker_token = None
        db.commit()
        raise GateRefused([f"safety latch engaged during worker start — spawned "
                           f"worker terminated ({term['detail']})"])
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
}


def _worker_env(s, token: str, session_id, scenario_id: str, run: Run) -> dict:
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
    return env


def _watch(proc: subprocess.Popen, run_id: str) -> None:
    def _j():
        code = proc.wait()
        run_registry.remove(run_id)
        with db_ctx() as s:
            run = s.get(Run, run_id)
            if run is None:
                return
            if run.status in ACTIVE:  # worker never reported → unclean death
                run.status = "failed"
                run.outcome = "worker_failure"
                run.error = f"worker exited {code} without reporting"
                run.ended_at = _now()
    threading.Thread(target=_j, daemon=True, name=f"run-watch-{run_id[:8]}").start()


def stop_run(db: Session, run_id) -> dict:
    run = db.get(Run, run_id)
    if run is None:
        raise KeyError("run not found")
    if run.status not in ACTIVE:
        return {"ok": True, "status": run.status, "note": "already finished"}
    if run.status == "queued" and not run.pgid:
        # SPAWN/STOP RACE (audit N02): the worker may be between Popen and
        # the spawner's pgid commit. Mark 'stopping' (committed) — the
        # spawner's queued->running update then FAILS and it terminates the
        # group itself. Poll briefly so the common case is confirmed here.
        run.status = "stopping"
        db.commit()
        for _ in range(50):
            db.refresh(run)
            if run.pgid:
                break
            time.sleep(0.1)
        if run.pgid:
            res = run_registry.terminate_group(run.pgid, expected_pstart=run.pgid_pstart)
            if not res["ok"]:
                run.status = "running"   # stop FAILED — do not lie about state
                db.flush()
                return {"ok": False, "status": "running", "detail": res["detail"]}
            run.status, run.outcome, run.ended_at = "cancelled", "canceled", _now()
            run.worker_token = None
            db.flush()
            return {"ok": True, "status": run.status, "detail": res["detail"]}
        return {"ok": True, "status": "stopping",
                "detail": "worker not yet registered; the spawner holds the "
                          "termination obligation and will kill the group"}
    run.status = "stopping"
    db.flush()
    res = (run_registry.terminate_group(run.pgid, expected_pstart=run.pgid_pstart)
           if run.pgid else {"ok": True, "detail": "no pgid"})
    if not res["ok"]:
        run.status = "running"  # stop FAILED — do not lie about state
        db.flush()
        return {"ok": False, "status": "running", "detail": res["detail"]}
    run.status, run.outcome, run.ended_at = "cancelled", "canceled", _now()
    run.worker_token = None  # credential dies with the run (one-shot, R01)
    db.flush()
    return {"ok": True, "status": run.status}


def complete_run(db: Session, run_id: str, worker_token: str, result: dict) -> Run:
    """Worker callback (authenticated by the run-scoped capability)."""
    run = db.get(Run, run_id)
    if run is None:
        raise KeyError("run not found")
    if run.worker_token is None:
        # credential was already consumed (or the run predates it): ONE-SHOT.
        raise PermissionError("worker credential already consumed")
    if hashlib.sha256(worker_token.encode()).hexdigest() != run.worker_token:
        raise PermissionError("bad worker token")
    if run.status not in ACTIVE:
        # Terminal state is FINAL (audit R01): a late callback can never
        # resurrect or rewrite a cancelled/failed/completed run.
        raise RunStateError(f"run already {run.status}")
    run.status = "completed" if result.get("outcome") != "worker_failure" else "failed"
    run.outcome = str(result.get("outcome", "incomplete"))[:64]
    run.result = result
    run.ended_at = _now()
    run.worker_token = None  # ONE-SHOT: the callback consumes the credential
    db.flush()
    return run


def verify_worker_token(run: Run, token: str | None) -> bool:
    return bool(token and run.worker_token
                and hashlib.sha256(token.encode()).hexdigest() == run.worker_token)


def reconcile_on_startup() -> dict:
    """After an API restart: any run still marked active whose process group is
    gone is failed; groups still alive are RE-REGISTERED (so the killswitch can
    reach them) and terminated if the safety latch is engaged (the latch never
    forgets)."""
    from srplatform.db.models import Event
    actions = []
    with db_ctx() as db:
        rows = db.execute(select(Run).where(Run.status.in_(ACTIVE))).scalars().all()
        for run in rows:
            alive, identity_ok = False, False
            if run.pgid:
                alive = pgid_alive(run.pgid)
                identity_ok = pgid_matches_identity(run.pgid, run.pgid_pstart)
            if not alive or not identity_ok:
                run.status, run.outcome = "failed", "worker_failure"
                run.error = ("reconciled after API restart: worker gone" if not alive
                             else "reconciled after API restart: recorded process-group "
                                  "identity does not match (PGID reused?) — NOT signalling it")
                run.ended_at = _now()
                run.worker_token = None
                db.add(Event(session_id=run.session_id, ts=_now(), actor="system",
                             action_type="run_reconciled",
                             payload={"run_id": str(run.run_id), "note": run.error}))
                actions.append(f"run {str(run.run_id)[:8]}: failed (worker gone)")
            else:
                # SURVIVING GROUP RE-ENTER SUPERVISION (audit R03): without this
                # the killswitch would only report the group, never kill it.
                run_registry.add(RunHandle(run_id=str(run.run_id), pid=run.pid,
                                           pgid=run.pgid, process=None,
                                           pgid_pstart=run.pgid_pstart,
                                           meta={"session_id": str(run.session_id),
                                                 "recovered": True}))
                if get_supervisor().latch_status()["latched"]:
                    res = run_registry.terminate_group(run.pgid, expected_pstart=run.pgid_pstart)
                    run.worker_token = None
                    if res["ok"]:
                        run.status, run.outcome, run.ended_at = "cancelled", "canceled", _now()
                        actions.append(f"run {str(run.run_id)[:8]}: latched kill on startup — {res['detail']}")
                    else:
                        # NEVER convert a failed termination into 'cancelled'
                        # (audit N05): the group is still alive — keep it
                        # registered and report the failure loudly.
                        run.status, run.outcome = "failed", "worker_failure"
                        run.error = (f"latched kill on startup FAILED: {res['detail']} — "
                                     "process group may still be running")
                        run.ended_at = _now()
                        actions.append(f"run {str(run.run_id)[:8]}: LATCHED KILL FAILED — {res['detail']}")
        db.flush()
    return {"actions": actions}
