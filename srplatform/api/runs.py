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
from datetime import datetime, timezone

from sqlalchemy import select
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
    db.flush()
    # DURABLE BEFORE SPAWN (audit R01): the worker's first API request can beat
    # the caller's request-transaction commit — the run row and its credential
    # must already be visible, or the worker races its own credential into
    # nonexistence and every request 401s.
    db.commit()

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
    run.pid, run.pgid = proc.pid, os.getpgid(proc.pid)
    run.pgid_pstart = pgid_start_time(proc.pid)  # identity guard against PGID reuse
    run.status, run.started_at = "running", _now()
    db.flush()
    db.commit()
    run_registry.add(RunHandle(run_id=str(run.run_id), pid=proc.pid, pgid=run.pgid,
                               process=proc, meta={"session_id": str(session_id)},
                               pgid_pstart=run.pgid_pstart))
    _watch(proc, str(run.run_id))
    return run


# Environment allowlist handed to the worker process (audit R12: the worker is
# the least-privileged component — it must NOT inherit the API's DB/Proxmox/
# owner credentials by an os.environ copy).
_WORKER_ENV_KEYS = (
    "PATH", "HOME", "LANG", "LC_ALL", "TZ",
    "SR_ENV", "SR_API_BASE", "SR_SESSION_ID", "SR_SCENARIO_ID", "SR_RUN_ID",
    "SR_WORKER_TOKEN", "API_BASE_URL",
    "RUNNER_TRANSPORT", "RUNNER_SSH_TARGET", "RUNNER_SSH_KEY_PATH",
    "RUNNER_SSH_KNOWN_HOSTS", "RUNNER_COMMAND_TIMEOUT_S", "RUNNER_MAX_OUTPUT_BYTES",
    "LLM_BASE_URL", "LLM_MODEL_RED", "LLM_API_KEY", "MODEL_QUEUE_MAX",
)


def _worker_env(s, token: str, session_id, scenario_id: str, run: Run) -> dict:
    import os as _os
    env = {k: v for k, v in _os.environ.items() if k in _WORKER_ENV_KEYS}
    env.setdefault("PATH", _os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"))
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
                    run.status, run.outcome, run.ended_at = "cancelled", "canceled", _now()
                    run.worker_token = None
                    actions.append(f"run {str(run.run_id)[:8]}: latched kill on startup — {res['detail']}")
        db.flush()
    return {"actions": actions}
