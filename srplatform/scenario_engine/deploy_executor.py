"""Supervised background executor for lifecycle operations (plan 13 phase 5,
202 refinement).

The request path performs DURABLE ACCEPTANCE synchronously (claim +
operation row + lease/preconditions committed) and returns 202 with the
operation reference. The long, effectful work — clone/provision/readiness —
runs here, in a daemon thread with its OWN database session (never the
request's), fenced by the same owner token. Outcomes (including terminal
evidence) are committed to the operation row; the claim is released fenced
at the end either way.

Crash semantics: threads die with the process. Startup reconciliation
marks accepted/running rows `interrupted` and clears claims, so a dead
executor can neither revive nor block a replacement — the next launch
resumes through the durable deployment inventory.
"""
from __future__ import annotations

import threading
import traceback
import uuid as uuidlib
from datetime import datetime, timezone

_LOCK = threading.Lock()
_THREADS: dict[str, threading.Thread] = {}


def live_executors() -> list[str]:
    """Operation ids with a thread still running (diagnostics only)."""
    with _LOCK:
        return [op for op, t in _THREADS.items() if t.is_alive()]


def submit(*, operation_id, session_id, user_id: str | None,
           operation: str, scenario_id: str, broker,
           owner: str) -> None:
    """Hand an accepted operation to the supervisor. Returns immediately;
    the attempt's durable row already exists (accepted) before this call."""
    t = threading.Thread(
        target=_execute,
        kwargs={"operation_id": str(operation_id), "session_id": session_id,
                "user_id": user_id, "operation": operation,
                "scenario_id": scenario_id, "broker": broker, "owner": owner},
        name=f"sr-deploy-{operation}-{str(operation_id)[:8]}",
        daemon=True)
    with _LOCK:
        _THREADS[str(operation_id)] = t
    t.start()


def _execute(*, operation_id, session_id, user_id, operation, scenario_id,
             broker, owner) -> None:
    from srplatform.db.models import DeployOperation
    from srplatform.db.session import db as db_ctx
    from srplatform.scenario_engine import orchestrator

    def note(msg: str) -> None:
        try:
            with db_ctx() as s:
                row = s.get(DeployOperation, uuidlib.UUID(operation_id))
                if row is not None and row.state in ("accepted", "running"):
                    row.phase = msg[:120]
                    row.updated_at = datetime.now(timezone.utc)
                    s.commit()
        except Exception:  # noqa: BLE001 — progress notes are best-effort
            pass

    try:
        with db_ctx() as db:
            row = db.get(DeployOperation, uuidlib.UUID(operation_id))
            if row is None:
                return  # reconciled away; nothing to do
            if row.deadline_at and datetime.now(timezone.utc) > row.deadline_at:
                orchestrator.finish_deploy_operation(
                    db, row, "failed",
                    error="deadline exceeded before dispatch")
                orchestrator.release_operation(db, session_id, owner)
                return
            if operation == "launch":
                orchestrator.advance_deploy_operation(db, row, "deploying")
                try:
                    result = orchestrator.deploy(db, session_id, scenario_id,
                                                 broker)
                except orchestrator.ForeignResourceError as e:
                    raise _Failed(409, "foreign_resource",
                                  str(e)[:500]) from e
                _finish_launch(db, row, session_id, user_id, scenario_id,
                               result, owner, note)
            elif operation == "reset":
                orchestrator.advance_deploy_operation(db, row, "redeploy")
                try:
                    out = orchestrator.reset(db, session_id, scenario_id,
                                             broker)
                except orchestrator.LeaseConflict as e:
                    raise _Failed(409, "range_busy",
                                  f"holder_session={e.holder_session_id}") from e
                except RuntimeError as e:
                    raise _Failed(409, "reset_failed", str(e)[:500]) from e
                _finish_reset(db, row, session_id, user_id, out, owner, note)
            else:
                orchestrator.finish_deploy_operation(
                    db, row, "failed",
                    error=f"unknown lifecycle operation {operation!r}")
                orchestrator.release_operation(db, session_id, owner)
    except _Failed as e:
        _record_failure(session_id, owner, operation_id,
                        f"{e.code}: {e.error}")
    except Exception as e:  # noqa: BLE001 — executor never dies silent
        _record_failure(
            session_id, owner, operation_id,
            f"executor error: {str(e)[:300]}\n"
            f"{traceback.format_exc(limit=3)[-500:]}")
    finally:
        with _LOCK:
            t = _THREADS.pop(operation_id, None)


class _Failed(Exception):
    def __init__(self, status: int, code: str, detail: str):
        super().__init__(detail)
        self.status = status
        self.code = code
        self.error = detail


def _finish_launch(db, row, session_id, user_id, scenario_id, result, owner,
                   note) -> None:
    """Readiness gate + capabilities + ready transition (moved from the
    request path: identical checks, executor-owned session)."""
    from srplatform import verification_service
    from srplatform.db.models import Event, Session as SessionModel
    from srplatform.scenario_engine import orchestrator

    orchestrator.advance_deploy_operation(db, row, "readiness")
    try:
        instructions, readiness = orchestrator.finalize_ready(
            db, session_id, user_id, result)
    except orchestrator.ReadinessFailed as e:
        db.add(Event(session_id=session_id, ts=datetime.now(timezone.utc),
                     actor="system", action_type="readiness_failed",
                     payload=e.payload))
        db.commit()
        raise _Failed(409, "readiness_failed", str(e)[:500]) from e
    orchestrator.finish_deploy_operation(
        db, row, "succeeded",
        result=_redacted_result(result, instructions, readiness))
    orchestrator.release_operation(db, session_id, owner)
    note("ready")


def _finish_reset(db, row, session_id, user_id, out, owner, note) -> None:
    from srplatform.db.models import Event, Session as SessionModel
    from srplatform.scenario_engine import orchestrator

    try:
        orchestrator.advance_deploy_operation(db, row, "readiness")
        instructions, readiness = orchestrator.finalize_ready(
            db, session_id, user_id, out)
    except orchestrator.ReadinessFailed as e:
        sess = db.get(SessionModel, session_id)
        if sess is not None:
            sess.status = "preparing"
        db.add(Event(session_id=session_id, ts=datetime.now(timezone.utc),
                     actor="system", action_type="session_reset_incomplete",
                     payload={"detail": str(e)[:500]}))
        db.commit()
        raise _Failed(409, "readiness_failed", str(e)[:500]) from e
    orchestrator.finish_deploy_operation(
        db, row, "succeeded",
        result=_redacted_result(out, instructions, readiness))
    orchestrator.release_operation(db, session_id, owner)
    note("ready")


def _redacted_result(deploy_out: dict, instructions: list,
                     readiness: dict) -> dict:
    """The completed result pollers receive. REDACTED by construction:
    plaintext telemetry enrollments are NEVER persisted (the ServiceToken
    rows are the durable record; the lost-response recovery path re-issues
    references). Connection capabilities are the requester's own rows,
    identical to what the sync response used to carry."""
    enrollments = deploy_out.get("telemetry_enrollments") or {}
    hosts = deploy_out.get("hosts", [])
    result = {
        "status": "ready",
        "deployment_id": deploy_out.get("deployment_id"),
        "deployment": {"deployment_id": deploy_out.get("deployment_id"),
                       "hosts": hosts},
        "hosts": hosts,
        "enrolled_hosts": sorted(enrollments.keys()),
        "enrollments_issued": len(enrollments),
        "connections": instructions,
        "readiness": {
            "ok": readiness.get("ok"),
            "enforced": readiness.get("enforced"),
            "reason": readiness.get("reason"),
            "checks": readiness.get("checks", []),
        },
    }
    if deploy_out.get("removed") is not None:  # reset also reports teardown
        result["removed"] = deploy_out["removed"]
    return result


def _record_failure(session_id, owner, operation_id, error: str) -> None:
    from srplatform.db.session import db as db_ctx
    from srplatform.scenario_engine import orchestrator

    try:
        with db_ctx() as db:
            row = orchestrator.latest_deploy_operation(db, session_id)
            if row is not None and str(row.operation_id) == str(operation_id) \
                    and row.fence == owner \
                    and row.state in ("accepted", "running"):
                orchestrator.finish_deploy_operation(db, row, "failed",
                                                     error=error)
            orchestrator.release_operation(db, session_id, owner)
    except Exception:  # noqa: BLE001 — evidence best-effort; claim release
        pass           # also attempted; startup reconcile is the backstop
