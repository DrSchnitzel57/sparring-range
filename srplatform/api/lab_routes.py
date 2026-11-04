"""Lab API (Underpressure step 3): durable replica labs, membership, plans.

A LAB owns the replica (`labs`/`lab_guests`) and OUTLIVES exercise sessions;
the lab's HOME session deploys it once, and every destructive reset is a
versioned PLAN the captain approves. Fences apply BEFORE the first rebuild
(AI offence is stopped and CONFIRMED, capabilities are revoked), the
selective executor destroys only the plan's rebuild set, and any preserved
guest keeps running.

Refusals carry HTTP status + reason; the caller never has to interpret a
200 that hides a degraded lab.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from srplatform import lab_service
from srplatform.api.auth import Principal, make_auth_dependencies
from srplatform.api.deps import DbSession, get_broker
from srplatform.db.models import Session as SessionModel
from srplatform.scenario_engine import deploy_executor, orchestrator
from srplatform.settings import get_settings

router = APIRouter()

_principal, any_member, _operator, _service = make_auth_dependencies()


class LabCreate(BaseModel):
    environment_id: str
    name: str | None = None
    scenario_id: str | None = None


class MemberInvite(BaseModel):
    username: str | None = None
    user_id: uuid.UUID | None = None
    role: str = "member"


class PlanRequest(BaseModel):
    selected: list[str] = []
    full: bool = False


class ExerciseRequest(BaseModel):
    name: str = "practice"


# --------------------------------------------------------------- helpers ----
def _error(e: lab_service.LabError) -> HTTPException:
    return HTTPException(e.status, e.detail)


def _lab(db, p: Principal, lab_id):
    try:
        return lab_service.require_lab(db, lab_id, p.user_id, p.is_operator)
    except lab_service.LabError as e:
        raise _error(e) from e


def _home(db, lab):
    home = lab_service.home_session(db, lab)
    if home is None:
        raise HTTPException(409, {"error": "no_home_session",
                                  "detail": "lab has no deployment session"})
    return home


def _abandon(session_id, owner, error: str) -> None:
    """Record a failed operation and release the claim through a SEPARATE
    session: the request transaction may be discarded by the raise and must
    never clobber durable failure evidence."""
    from srplatform.db.session import db as db_ctx

    try:
        with db_ctx() as s2:
            row = orchestrator.latest_deploy_operation(s2, session_id)
            if row is not None and row.fence == owner and row.state in (
                    "accepted", "running"):
                orchestrator.finish_deploy_operation(
                    s2, row, "failed", error=error,
                    release_claim_owner=owner)
            else:
                orchestrator.release_operation(s2, session_id, owner)
    except Exception:  # noqa: BLE001 — best effort; startup reconcile is the
        pass           # backstop for a claim left behind


def _accept(db, sess: SessionModel, p: Principal, operation: str,
            progress: dict | None = None, *, stop_worker: bool = False,
            revoke_reason: str | None = None):
    """Durable acceptance for a lab-session operation (same discipline as
    the session launch/reset routes): claim -> op row -> lease -> broker ->
    executor, all committed BEFORE any side effect.

    Fences run BEFORE acceptance is finalised for a reset: the worker must
    confirm cessation and old capabilities must be revoked, or the caller
    gets a conflict and NOTHING is destroyed."""
    try:
        owner = orchestrator.claim_operation(db, sess.session_id, operation)
    except orchestrator.OperationInProgress as e:
        row = orchestrator.latest_deploy_operation(db, sess.session_id)
        raise HTTPException(409, {
            "error": "operation_in_progress", "operation": e.operation,
            "operation_id": str(row.operation_id) if row is not None else None})
    deadline_s = get_settings().deploy_operation_deadline_s
    row = orchestrator.begin_deploy_operation(
        db, sess.session_id, operation, fence=owner, deadline_s=deadline_s)
    if progress:
        row.progress = dict(progress)
        db.commit()
    try:
        if stop_worker:
            lab_service.stop_worker_or_conflict(db, sess.session_id)
            lab_service.revoke_session_capabilities(
                db, sess.session_id, revoke_reason or operation)
            db.commit()
    except lab_service.LabError as e:
        _abandon(sess.session_id, owner, f"{e.status}: {str(e.detail)[:300]}")
        raise _error(e) from e
    except HTTPException as e:
        _abandon(sess.session_id, owner, str(e.detail)[:300])
        raise
    try:
        orchestrator.acquire_lease(db, sess.session_id)
    except orchestrator.LeaseConflict as e:
        _abandon(sess.session_id, owner,
                 f"range_busy holder={e.holder_session_id}")
        raise HTTPException(409, {"error": "range_busy",
                                  "holder_session": e.holder_session_id,
                                  "acquired_at": e.acquired_at}) from e
    try:
        broker = get_broker()
    except Exception as e:  # noqa: BLE001 — broker unresolvable pre-dispatch
        _abandon(sess.session_id, owner, f"broker_unavailable: {str(e)[:200]}")
        raise HTTPException(502, {"error": "broker_unavailable",
                                  "detail": str(e)[:300]}) from e
    deploy_executor.submit(operation_id=row.operation_id,
                           session_id=sess.session_id,
                           user_id=str(p.user_id),
                           operation=operation,
                           scenario_id=sess.scenario_id,
                           broker=broker, owner=owner)
    return {
        "lab_session_id": str(sess.session_id),
        "operation_id": str(row.operation_id),
        "status": "accepted",
        "deadline_at": row.deadline_at.isoformat() if row.deadline_at else None,
        "operation": f"/labs/{sess.lab_id}/operation",
    }


# ------------------------------------------------------------------ labs ----
@router.post("/labs", status_code=201)
def create_lab(body: LabCreate, p: Principal = Depends(_principal),
               db: DbSession = None):
    """Create the durable lab + its home session. No guest is cloned until
    `POST /labs/{id}/provision`."""
    if p.kind not in ("member", "operator"):
        raise HTTPException(403, "member or operator required")
    try:
        lab = lab_service.create_lab(
            db, owner_id=p.user_id, environment_id=body.environment_id,
            name=body.name, scenario_id=body.scenario_id)
    except lab_service.LabError as e:
        raise _error(e) from e
    return lab_service.lab_view(db, lab)


@router.get("/labs")
def list_labs(p: Principal = Depends(_principal), db: DbSession = None):
    if p.kind not in ("member", "operator"):
        raise HTTPException(403, "member or operator required")
    labs = lab_service.list_labs(db, user_id=p.user_id,
                                 is_operator=p.is_operator)
    return {"labs": [lab_service.lab_view(db, lab) for lab in labs]}


@router.get("/labs/{lab_id}")
def get_lab(lab_id: uuid.UUID, p: Principal = Depends(_principal),
            db: DbSession = None):
    lab, _role = _lab(db, p, lab_id)
    return lab_service.lab_view(db, lab)


@router.get("/labs/{lab_id}/operation")
def get_lab_operation(lab_id: uuid.UUID, p: Principal = Depends(_principal),
                      db: DbSession = None):
    """Proxy the home session's latest deploy operation (the executor's
    durable phase/outcome)."""
    lab, _role = _lab(db, p, lab_id)
    home = _home(db, lab)
    row = orchestrator.latest_deploy_operation(db, home.session_id)
    if row is None:
        return {"operation": None}
    return {"operation": row.operation, "state": row.state,
            "phase": row.phase, "error": row.error,
            "operation_id": str(row.operation_id),
            "deadline_at": row.deadline_at.isoformat()
            if row.deadline_at else None,
            "result": (row.progress or {}).get("result")}


@router.post("/labs/{lab_id}/provision", status_code=202)
def provision_lab(lab_id: uuid.UUID, p: Principal = Depends(_principal),
                  db: DbSession = None):
    """Deploy the lab's blueprint through the supervised executor. Captain
    (or operator) only; the environment must still match the frozen pins."""
    lab, role = _lab(db, p, lab_id)
    try:
        lab_service._require_captain(db, lab, p.user_id, p.is_operator, role)
        lab_service._require_env_unchanged(lab)
    except lab_service.LabError as e:
        raise _error(e) from e
    if lab.state not in ("provisioning", "degraded", "stopped"):
        raise HTTPException(409, {"error": "lab_not_provisionable",
                                  "state": lab.state,
                                  "detail": "an active lab is reset, not "
                                            "re-provisioned"})
    home = _home(db, lab)
    return _accept(db, home, p, "launch")


@router.delete("/labs/{lab_id}")
def delete_lab(lab_id: uuid.UUID, p: Principal = Depends(_principal),
               db: DbSession = None):
    """Verified delete: tear the home session down, and mark the lab deleted
    ONLY on a COMPLETE teardown. An uncertain destroy is a conflict with
    everything retained."""
    lab, role = _lab(db, p, lab_id)
    try:
        lab_service._require_captain(db, lab, p.user_id, p.is_operator, role)
    except lab_service.LabError as e:
        raise _error(e) from e
    home = _home(db, lab)
    try:
        broker = get_broker()
    except Exception as e:  # noqa: BLE001
        raise HTTPException(502, {"error": "broker_unavailable",
                                  "detail": str(e)[:300]}) from e
    try:
        out = orchestrator.teardown(db, home.session_id, home.scenario_id,
                                    broker)
    except Exception as e:  # noqa: BLE001 — teardown failures stay loud
        raise HTTPException(409, {"error": "teardown_failed",
                                  "detail": str(e)[:300]}) from e
    if not out.get("complete", False):
        raise HTTPException(409, {
            "error": "teardown_incomplete",
            "failed": out.get("failed"),
            "note": "verified absence is required; the lab and its "
                    "reservation are retained"})
    # A deleted lab must not keep the single-range reservation: the VMs are
    # verified gone, so the lease is released for the NEXT lab (live find:
    # gate delete left the lease held and the next provision failed
    # range_busy with a session that no longer existed in use).
    home.status = "torn_down"
    db.flush()
    orchestrator.release_lease(db, home.session_id)
    lab_service.mark_deleted(db, lab, actor_id=p.user_id)
    lab_service.revoke_session_capabilities(db, home.session_id, "lab_deleted")
    db.commit()
    return {"lab_id": str(lab.lab_id), "state": "deleted",
            "removed": out.get("removed", [])}


# ------------------------------------------------------------- membership ----
@router.post("/labs/{lab_id}/members", status_code=201)
def add_member(lab_id: uuid.UUID, body: MemberInvite,
               p: Principal = Depends(_principal), db: DbSession = None):
    lab, role = _lab(db, p, lab_id)
    try:
        row = lab_service.add_member(
            db, lab, actor_id=p.user_id, is_operator=p.is_operator,
            actor_role=role, user_id=body.user_id, username=body.username,
            role=body.role)
    except lab_service.LabError as e:
        raise _error(e) from e
    return {"lab_id": str(lab.lab_id), "user_id": str(row.user_id),
            "role": row.role, "added_at": row.added_at.isoformat()}


@router.delete("/labs/{lab_id}/members/{user_id}")
def remove_member(lab_id: uuid.UUID, user_id: uuid.UUID,
                  p: Principal = Depends(_principal), db: DbSession = None):
    lab, role = _lab(db, p, lab_id)
    try:
        row = lab_service.remove_member(
            db, lab, user_id, actor_id=p.user_id, is_operator=p.is_operator,
            actor_role=role)
    except lab_service.LabError as e:
        raise _error(e) from e
    return {"lab_id": str(lab.lab_id), "user_id": str(row.user_id),
            "removed_at": row.removed_at.isoformat()}


# ------------------------------------------------------------ reset plans ----
@router.post("/labs/{lab_id}/reset-plans", status_code=201)
def plan_reset(lab_id: uuid.UUID, body: PlanRequest,
               p: Principal = Depends(_principal), db: DbSession = None):
    """Compute (and PERSIST) the versioned dependency plan — blockers and
    advisories included. Nothing is destroyed by planning."""
    lab, role = _lab(db, p, lab_id)
    try:
        lab_service._require_captain(db, lab, p.user_id, p.is_operator, role)
        row = lab_service.compute_plan(
            db, lab, requested_by=p.user_id,
            selected=list(body.selected or []), full=body.full)
    except lab_service.LabError as e:
        raise _error(e) from e
    return {"lab_id": str(lab.lab_id), "plan_id": str(row.plan_id),
            "status": row.status, "plan": row.plan,
            "request": row.request}


@router.post("/labs/{lab_id}/reset-plans/{plan_id}/approve", status_code=202)
def approve_reset(lab_id: uuid.UUID, plan_id: uuid.UUID,
                  p: Principal = Depends(_principal), db: DbSession = None):
    """Captain approval = the destructive authority. The OFFENCE/SCORING
    fences and capability revocation are applied before acceptance, then the
    selective executor rebuilds ONLY the planned guests."""
    lab, role = _lab(db, p, lab_id)
    try:
        lab_service._require_env_unchanged(lab)
        plan = lab_service.approve_plan(
            db, lab, plan_id, approved_by=p.user_id,
            is_operator=p.is_operator, actor_role=role)
    except lab_service.LabError as e:
        raise _error(e) from e
    home = _home(db, lab)
    try:
        return _accept(db, home, p, "reset",
                       progress={"lab_plan_id": str(plan.plan_id),
                                 "lab_id": str(lab.lab_id)},
                       stop_worker=True, revoke_reason="lab_reset")
    except HTTPException:
        # acceptance failed (range busy / worker not stopped / broker down):
        # NOTHING was destroyed and the plan is not executing, so return it
        # to `proposed` — a retry is an explicit re-approval, never a
        # half-approved plan that a later approve call would refuse.
        from srplatform.db.session import db as db_ctx
        try:
            with db_ctx() as s2:
                from srplatform.db.models import LabResetPlan
                row = s2.get(LabResetPlan, plan.plan_id)
                if row is not None and row.status == "approved":
                    row.status = "proposed"
                    row.approved_by = None
                    row.approved_at = None
                    s2.commit()
        except Exception:  # noqa: BLE001 — the conflict is the real answer
            pass
        raise


# ------------------------------------------------------- exercise sessions ---
@router.post("/labs/{lab_id}/sessions", status_code=201)
def attach_exercise(lab_id: uuid.UUID, body: ExerciseRequest,
                    p: Principal = Depends(_principal), db: DbSession = None):
    """Start an exercise session ON the lab's existing deployment.

    No clone: the lab deployed its guests once (its home session), and an
    exercise session is a durable handle on that SAME range, so members share
    what they were actually given. Refused while the lab is not live.
    """
    lab, _role = _lab(db, p, lab_id)
    try:
        sess = lab_service.attach_exercise(db, lab, p.user_id, name=body.name)
    except lab_service.LabError as e:
        raise _error(e) from e
    db.commit()
    return lab_service.session_view(db, sess)


@router.get("/labs/{lab_id}/sessions")
def list_exercise_sessions(lab_id: uuid.UUID,
                           p: Principal = Depends(_principal),
                           db: DbSession = None):
    lab, _role = _lab(db, p, lab_id)
    return {"sessions": [lab_service.session_view(db, s)
                         for s in lab_service.sessions_of(db, lab)]}
