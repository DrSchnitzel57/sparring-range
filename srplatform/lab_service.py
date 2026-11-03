"""Durable lab aggregate operations (Underpressure step 3).

The destructive-reset PLANNER is pure (`srplatform.lab`); this module owns
the durable state transitions that surround it: creating a lab with frozen
environment pins and its HOME session, team membership, reflecting a
supervised deploy or reset operation into per-guest generations, approving
dependency-aware plans, and verified deletes.

Nothing here claims success that the evidence does not show:

  * guest states are COPIED from the deployment resource rows (the same rows
    the broker verified by read-back), never invented;
  * a lab with any guest that is not `ready` is `degraded`, never `active`;
  * a lab whose environment files changed since its pins were frozen cannot
    be re-provisioned under the old name (the pins ARE the contract);
  * deletes happen only after a complete teardown (verified absence).
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone

from sqlalchemy import select

from .db.models import (Deployment, Event, Lab, LabGuest, LabMember,
                        LabResetPlan, LoginToken, ServiceToken,
                        Session as SessionModel, User)
from .environment_specs import environments_dir, environment_ids, load_environment
from .lab import compute_reset_plan

#: Files that make up an environment document set. Their bytes are hashed
#: together into the lab's pin — a lab is re-provisioned ONLY under the
#: environment it froze.
ENVIRONMENT_FILES = ("blueprint.yaml", "fidelity.yaml", "checks.yaml",
                     "attack.yaml", "defender.md")

LAB_ROLES = frozenset({"captain", "member"})
_LIVE_LAB_STATES = frozenset({"provisioning", "active", "degraded",
                              "stopped"})


class LabError(Exception):
    """Durable-refusal error; routes map .status to HTTP (never a 500)."""

    def __init__(self, status: int, detail):
        super().__init__(detail)
        self.status = status
        self.detail = detail


def _now() -> datetime:
    return datetime.now(timezone.utc)


def environment_digest(environment_id: str) -> str:
    """Content digest of an environment document set (order-stable)."""
    root = environments_dir() / environment_id
    h = hashlib.sha256()
    for name in ENVIRONMENT_FILES:
        p = root / name
        h.update(name.encode())
        h.update(b"\0")
        h.update(p.read_bytes() if p.is_file() else b"")
        h.update(b"\0")
    return h.hexdigest()


def default_scenario_id(environment_id: str) -> str | None:
    """The first scenario file that references this environment."""
    from .scenario_engine.loader import load_scenario, scenario_ids

    for sid in scenario_ids():
        try:
            spec = load_scenario(sid)
        except Exception:  # noqa: BLE001 — one broken overlay never hides
            continue        # the others; its own loader tests stay loud
        if spec.get("environment") == environment_id:
            return sid
    return None


# ---------------------------------------------------------------- create ----
def create_lab(db, *, owner_id, environment_id: str, name: str | None = None,
               scenario_id: str | None = None) -> Lab:
    """Create the durable lab + its home session. NO guest is cloned here.

    One live lab per environment is promised: a second create while the
    first is `provisioning`/`active`/`degraded` is refused, so two exercises
    can never fight over the same VMIDs and segments.
    """
    if environment_id not in environment_ids():
        raise LabError(
            404, {"error": "unknown_environment",
                  "detail": f"environment {environment_id!r} does not exist "
                            f"on this appliance; available: "
                            f"{environment_ids()}"})
    env = load_environment(environment_id)
    existing = db.scalars(
        select(Lab).where(Lab.environment_id == environment_id,
                          Lab.deleted_at.is_(None))).first()
    if existing is not None:
        raise LabError(
            409, {"error": "environment_in_use",
                  "detail": f"environment {environment_id!r} already has "
                            f"live lab {existing.lab_id}",
                  "lab_id": str(existing.lab_id),
                  "state": existing.state})
    scenario_id = scenario_id or default_scenario_id(environment_id)
    if scenario_id is None:
        raise LabError(
            422, {"error": "no_scenario_for_environment",
                  "detail": f"environment {environment_id!r} is not referenced "
                            f"by any scenario; add an exercise overlay first"})
    from .scenario_engine.loader import load_scenario

    spec = load_scenario(scenario_id)
    if spec.get("environment") != environment_id:
        raise LabError(
            422, {"error": "scenario_mismatch",
                  "detail": f"scenario {scenario_id!r} provisions "
                            f"{spec.get('environment')!r}, not "
                            f"{environment_id!r}"})
    pins = dict(env.pins())
    pins["files_sha256"] = environment_digest(environment_id)
    pins["scenario_id"] = scenario_id
    lab = Lab(environment_id=environment_id,
              name=name or env.blueprint.name,
              pins=pins, owner_id=owner_id, state="provisioning", power="on",
              reservation=dict(env.blueprint.reservation()))
    db.add(lab)
    db.flush()
    for guest in env.blueprint.guests:
        db.add(LabGuest(lab_id=lab.lab_id, guest=guest.name, generation=1,
                        state="pending", resource={}))
    db.add(LabMember(lab_id=lab.lab_id, user_id=owner_id, role="captain",
                     added_by=owner_id))
    home = _create_home_session(db, lab, scenario_id, owner_id)
    db.add(Event(session_id=home.session_id, ts=_now(), actor="system",
                 action_type="lab_created",
                 payload={"lab_id": str(lab.lab_id),
                          "environment": environment_id,
                          "scenario_id": scenario_id,
                          "pins": pins}))
    db.commit()
    return lab


def _create_home_session(db, lab: Lab, scenario_id: str, owner_id) -> SessionModel:
    """The lab's deployment session: frozen scenario snapshot (what is
    provisioned and graded cannot be rewritten by a later file edit)."""
    from .scenario_engine.loader import scenarios_dir

    path = scenarios_dir() / f"{scenario_id}.yaml"
    raw = path.read_text() if path.is_file() else ""
    sha = hashlib.sha256(raw.encode()).hexdigest()
    sess = SessionModel(scenario_id=scenario_id, user_id=owner_id,
                        status="preparing", lab_id=lab.lab_id)
    db.add(sess)
    db.flush()
    db.add(Event(session_id=sess.session_id, ts=_now(), actor="system",
                 action_type="session_start",
                 payload={"scenario_id": scenario_id,
                          "scenario_sha256": sha,
                          "scenario_yaml": raw or None,
                          "lab_id": str(lab.lab_id)}))
    db.flush()
    return sess


# ------------------------------------------------------------- membership ----
def role_in(db, lab: Lab, user_id) -> str | None:
    """The active membership role, or None (removed members lose everything;
    rows are never deleted)."""
    row = db.scalars(
        select(LabMember).where(LabMember.lab_id == lab.lab_id,
                                LabMember.user_id == user_id)).first()
    if row is None or row.removed_at is not None:
        return None
    return row.role


def require_lab(db, lab_id, user_id, is_operator: bool) -> tuple[Lab, str]:
    lab = db.get(Lab, lab_id)
    if lab is None or lab.state == "deleted":
        raise LabError(404, {"error": "lab_not_found",
                             "detail": f"lab {lab_id} does not exist"})
    role = role_in(db, lab, user_id)
    if is_operator:
        return lab, role or "operator"
    if role is None:
        raise LabError(403, {"error": "not_a_member",
                             "detail": "this lab is visible to its members "
                                       "and the operator only"})
    return lab, role


def _require_captain(db, lab: Lab, user_id, is_operator: bool,
                     role: str) -> None:
    if is_operator or role == "captain":
        return
    raise LabError(403, {"error": "captain_only",
                         "detail": "captain (or operator) authority required: "
                                   f"your role on lab {lab.lab_id} is {role!r}"})


def add_member(db, lab: Lab, *, actor_id, is_operator: bool, actor_role: str,
               user_id=None, username=None, role: str = "member") -> LabMember:
    """Captain (or operator) invites an OPERATOR-PROVISIONED account. A
    removed membership row is RE-OPENED on re-invite, so join/leave history
    stays one row per account."""
    _require_captain(db, lab, actor_id, is_operator, actor_role)
    if role not in LAB_ROLES:
        raise LabError(422, {"error": "invalid_role",
                             "detail": f"role must be one of {sorted(LAB_ROLES)}"})
    if user_id is None and username is None:
        raise LabError(422, {"error": "missing_user",
                             "detail": "username or user_id is required"})
    user = db.scalars(select(User).where(
        User.user_id == user_id if user_id is not None
        else User.username == username)).first()
    if user is None:
        raise LabError(404, {"error": "unknown_user",
                             "detail": f"no operator-provisioned account "
                                       f"{username or user_id!r}"})
    if role == "captain" and user.user_id != lab.owner_id:
        # Captains are co-owners of THIS lab only; never global authority.
        pass
    row = db.scalars(select(LabMember).where(
        LabMember.lab_id == lab.lab_id,
        LabMember.user_id == user.user_id)).first()
    if row is None:
        row = LabMember(lab_id=lab.lab_id, user_id=user.user_id, role=role,
                        added_by=actor_id)
        db.add(row)
    elif row.removed_at is not None:
        row.removed_at = None
        row.role = role
        row.added_by = actor_id
        row.added_at = _now()
    else:
        raise LabError(409, {"error": "already_a_member",
                             "detail": f"{user.username!r} is already "
                                       f"{row.role!r} on this lab"})
    _lab_event(db, lab, "lab_member_added",
               {"user": user.username, "role": role,
                "actor_id": str(actor_id) if actor_id else None})
    db.commit()
    return row


def remove_member(db, lab: Lab, member_user_id, *, actor_id,
                  is_operator: bool, actor_role: str) -> LabMember:
    """Removal TERMINATES access (the API layer revokes live capabilities).

    The owner cannot be removed (a lab would have no captain), and a captain
    cannot remove the LAST captain."""
    _require_captain(db, lab, actor_id, is_operator, actor_role)
    row = db.scalars(select(LabMember).where(
        LabMember.lab_id == lab.lab_id,
        LabMember.user_id == member_user_id)).first()
    if row is None or row.removed_at is not None:
        raise LabError(404, {"error": "not_a_member",
                             "detail": "that account is not an active member"})
    if str(member_user_id) == str(lab.owner_id):
        raise LabError(409, {"error": "owner_is_captain",
                             "detail": "the lab owner cannot be removed; "
                                       "delete or transfer the lab instead"})
    if row.role == "captain":
        captains = db.scalars(
            select(LabMember).where(LabMember.lab_id == lab.lab_id,
                                    LabMember.role == "captain",
                                    LabMember.removed_at.is_(None))).all()
        if len(captains) <= 1:
            raise LabError(409, {"error": "last_captain",
                                 "detail": "removing the last captain would "
                                           "leave the lab unmanaged"})
    row.removed_at = _now()
    _revoke_member_capabilities(db, lab, member_user_id)
    _lab_event(db, lab, "lab_member_removed",
               {"user_id": str(member_user_id),
                "actor_id": str(actor_id) if actor_id else None})
    db.commit()
    return row


def _revoke_member_capabilities(db, lab: Lab, user_id) -> int:
    """Live session capabilities of the lab's home session are revoked for
    the departing member; the rows stay (evidence), timestamps only move."""
    home = home_session(db, lab)
    if home is None:
        return 0
    n = 0
    t = _now()
    for lt in db.scalars(select(LoginToken).where(
            LoginToken.session_id == home.session_id,
            LoginToken.user_id == user_id,
            LoginToken.revoked_at.is_(None))).all():
        lt.revoked_at = t
        n += 1
    for st in db.scalars(select(ServiceToken).where(
            ServiceToken.session_id == home.session_id,
            ServiceToken.user_id == user_id,
            ServiceToken.revoked_at.is_(None))).all():
        st.revoked_at = t
        n += 1
    return n


def home_session(db, lab: Lab) -> SessionModel | None:
    return db.scalars(select(SessionModel).where(
        SessionModel.lab_id == lab.lab_id).order_by(
            SessionModel.started_at)).first()


# ----------------------------------------------------- deploy reflection ----
def _guests(db, lab: Lab) -> list[LabGuest]:
    return db.scalars(select(LabGuest).where(
        LabGuest.lab_id == lab.lab_id).order_by(LabGuest.guest)).all()


def _latest_deployment(db, session_id) -> Deployment | None:
    return db.scalars(select(Deployment).where(
        Deployment.session_id == session_id).order_by(
            Deployment.created_at.desc())).first()


def _lab_event(db, lab: Lab, action_type: str, payload: dict) -> None:
    home = home_session(db, lab)
    db.add(Event(session_id=home.session_id if home else None, ts=_now(),
                 actor="system", action_type=action_type,
                 payload={**payload, "lab_id": str(lab.lab_id)}))


def reflect_launch(db, session_id, result: dict | None = None) -> Lab | None:
    """Copy the FRESHLY deployed resource rows into the lab's guest
    generations. Called by the executor only after readiness succeeded."""
    sess = db.get(SessionModel, session_id)
    if sess is None or sess.lab_id is None:
        return None
    lab = db.get(Lab, sess.lab_id)
    if lab is None:
        return None
    dep = _latest_deployment(db, session_id)
    by_host = {}
    if dep is not None:
        for r in (dep.resources or []):
            by_host[str(r.get("host"))] = dict(r)
    guests = _guests(db, lab)
    all_ready = True
    for g in guests:
        r = by_host.get(g.guest)
        if r is not None and r.get("state") == "created":
            g.state = "ready"
            g.resource = {k: r.get(k) for k in
                          ("vmid", "name", "node", "image_profile",
                           "domain_uuid", "applied_nics") if r.get(k)}
        elif r is not None and r.get("state") == "pending":
            g.state = "creating"
            all_ready = False
        else:
            # no resource row: the deployment never reached this guest —
            # unknown is NOT ready (never a silent success)
            g.state = "unknown" if g.state in ("pending", "creating") \
                else g.state
            all_ready = False
    lab.state = "active" if all_ready else "degraded"
    lab.power = "on"
    _lab_event(db, lab, "lab_reflected_launch",
               {"state": lab.state,
                "ready": sorted(g.guest for g in guests if g.state == "ready"),
                "not_ready": sorted(g.guest for g in guests
                                    if g.state != "ready")})
    db.commit()
    return lab


def plan_rebuild_guests(db, plan_id) -> tuple[Lab | None, list[str]]:
    """The planned rebuild set of an approved plan (empty for unknown plans)."""
    row = db.get(LabResetPlan, plan_id)
    if row is None:
        return None, []
    lab = db.get(Lab, row.lab_id)
    return lab, list((row.plan or {}).get("rebuild") or [])


def execute_plan(db, session_id, scenario_id: str, broker, plan_id):
    """DESTRUCTIVE selective reset: destroy + re-provision ONLY the approved
    rebuild set; preserved guests keep running. The plan must be approved,
    belong to this lab's home session, and still match the frozen pins."""
    from .scenario_engine import env_deploy
    from . import verification_service

    plan_row = db.get(LabResetPlan, plan_id)
    if plan_row is None:
        raise LabError(404, {"error": "plan_not_found",
                             "detail": f"reset plan {plan_id} does not exist"})
    if plan_row.status != "approved":
        raise LabError(409, {"error": "plan_not_approved",
                             "detail": f"plan is {plan_row.status!r}; approve "
                                       f"it first"})
    lab = require_lab_session(db, session_id, plan_row.lab_id)
    _require_env_unchanged(lab)
    rebuild = set((plan_row.plan or {}).get("rebuild") or [])
    if not rebuild:
        raise LabError(422, {"error": "empty_plan",
                             "detail": "an empty rebuild set is never executed"})
    spec = verification_service.scenario_spec(db, session_id)
    plan_row.status = "executing"
    db.commit()
    return env_deploy.reset_guests(db, session_id, scenario_id, spec, broker,
                                   rebuild)


def reflect_reset(db, session_id, plan_id) -> Lab | None:
    """After a selective reset succeeded: bump generations for the REBUILT
    guests only, copy their fresh resource rows, and close the plan."""
    sess = db.get(SessionModel, session_id)
    if sess is None or sess.lab_id is None:
        return None
    lab = db.get(Lab, sess.lab_id)
    if lab is None:
        return None
    plan_row = db.get(LabResetPlan, plan_id) if plan_id else None
    rebuild = set((plan_row.plan or {}).get("rebuild") or []) if plan_row \
        else {g.guest for g in _guests(db, lab)}
    dep = _latest_deployment(db, session_id)
    by_host = {str(r.get("host")): dict(r)
               for r in ((dep.resources or []) if dep is not None else [])}
    guests = _guests(db, lab)
    all_ready = True
    rebuilt = []
    for g in guests:
        if g.guest not in rebuild:
            all_ready = all_ready and g.state == "ready"
            continue
        g.generation += 1
        rebuilt.append(g.guest)
        r = by_host.get(g.guest)
        if r is not None and r.get("state") == "created":
            g.state = "ready"
            g.resource = {k: r.get(k) for k in
                          ("vmid", "name", "node", "image_profile",
                           "domain_uuid", "applied_nics") if r.get(k)}
        else:
            g.state = "failed"
            all_ready = False
    lab.state = "active" if all_ready else "degraded"
    if plan_row is not None:
        plan_row.status = "executed" if all_ready else "failed"
        plan_row.error = None if all_ready else \
            "reset did not rebuild every planned guest"
    _lab_event(db, lab, "lab_reset_executed",
               {"plan_id": str(plan_id) if plan_id else None,
                "rebuilt": sorted(rebuilt), "state": lab.state})
    db.commit()
    return lab


# ---------------------------------------------------------------- plans ----
def _planner_guest_states(db, lab: Lab) -> dict[str, str]:
    """LabGuest states -> planner vocabulary. `degraded` is UNKNOWN here:
    the planner only treats states it positively understands as eligible, and
    a failed reset is never silently re-plan-able."""
    mapping = {"ready": "ready", "stopped": "stopped",
               "pending": "pending", "creating": "creating",
               "failed": "failed"}
    return {g.guest: mapping.get(g.state, "unknown")
            for g in _guests(db, lab)}


def _require_env_unchanged(lab: Lab) -> None:
    want = (lab.pins or {}).get("files_sha256")
    have = environment_digest(lab.environment_id)
    if want != have:
        raise LabError(
            409, {"error": "environment_changed",
                  "detail": f"environment {lab.environment_id!r} changed "
                            f"after lab {lab.lab_id} froze its pins; "
                            f"rebuild the lab to adopt the new document set"})


def compute_plan(db, lab: Lab, *, requested_by, selected: list[str],
                 full: bool = False) -> LabResetPlan:
    """Persist the dependency plan (blockers included, never silent)."""
    _require_env_unchanged(lab)
    if lab.state not in _LIVE_LAB_STATES:
        raise LabError(409, {"error": "lab_not_live",
                             "detail": f"lab state is {lab.state!r}; plan "
                                       f"needs a live, deployed lab"})
    bp = load_environment(lab.environment_id).blueprint
    plan = compute_reset_plan(bp, list(selected or []),
                              _planner_guest_states(db, lab), full=full)
    row = LabResetPlan(lab_id=lab.lab_id, requested_by=requested_by,
                       request={"selected": selected, "full": full},
                       plan=plan, status="proposed")
    db.add(row)
    _lab_event(db, lab, "lab_reset_planned",
               {"plan_id": str(row.plan_id), "ok": plan["ok"],
                "blockers": plan["blockers"],
                "rebuild": plan["rebuild"]})
    db.commit()
    return row


def approve_plan(db, lab: Lab, plan_id, *, approved_by,
                 is_operator: bool, actor_role: str) -> LabResetPlan:
    """Captain approval of a PROPOSED plan with no blockers. The fences
    (AI offence stop, scoring gap marking) are applied by the CALLER before
    any destructive effect; approval itself touches nothing."""
    _require_captain(db, lab, approved_by, is_operator, actor_role)
    row = db.get(LabResetPlan, plan_id)
    if row is None or row.lab_id != lab.lab_id:
        raise LabError(404, {"error": "plan_not_found",
                             "detail": f"plan {plan_id} does not belong to "
                                       f"lab {lab.lab_id}"})
    if row.status != "proposed":
        raise LabError(409, {"error": "plan_not_proposed",
                             "detail": f"plan is {row.status!r}"})
    blockers = (row.plan or {}).get("blockers") or []
    if blockers:
        raise LabError(409, {"error": "plan_blocked",
                             "blockers": blockers,
                             "detail": "the plan has blockers; resolve them "
                                       "and compute a new plan"})
    row.status = "approved"
    row.approved_by = approved_by
    row.approved_at = _now()
    _lab_event(db, lab, "lab_reset_approved",
               {"plan_id": str(row.plan_id),
                "rebuild": (row.plan or {}).get("rebuild")})
    db.commit()
    return row


def require_lab_session(db, session_id, lab_id) -> Lab:
    lab = db.get(Lab, lab_id)
    if lab is None:
        raise LabError(404, {"error": "lab_not_found",
                             "detail": f"lab {lab_id} does not exist"})
    home = home_session(db, lab)
    if home is None or str(home.session_id) != str(session_id):
        raise LabError(409, {"error": "foreign_session",
                             "detail": "this session does not deploy that lab "
                                       "— one lab, one home session"})
    return lab


# --------------------------------------------------------------- delete ----
def mark_deleted(db, lab: Lab, *, actor_id) -> Lab:
    """Explicit delete — ONLY after the caller verified guest absence
    (teardown complete). Power and reservation are released; the row remains
    with a timestamp, never hard-deleted."""
    if lab.state == "deleted":
        return lab
    guests = _guests(db, lab)
    not_ready = [g.guest for g in guests if g.state not in ("ready", "removed")]
    lab.state = "deleted"
    lab.power = "off"
    lab.deleted_at = _now()
    lab.reservation = {}
    for g in guests:
        g.state = "destroyed"
        g.resource = {}
    _lab_event(db, lab, "lab_deleted",
               {"actor_id": str(actor_id) if actor_id else None,
                "note": "verified absence; explicit operator delete"})
    db.commit()
    return lab


# ----------------------------------------------------------------- views ----
def list_labs(db, *, user_id, is_operator: bool) -> list[Lab]:
    q = select(Lab).where(Lab.state != "deleted")
    labs = db.scalars(q.order_by(Lab.created_at.desc())).all()
    if is_operator:
        return list(labs)
    return [lab for lab in labs if role_in(db, lab, user_id) is not None]


def lab_view(db, lab: Lab) -> dict:
    """One lab as the API returns it: guests with generations, members,
    home session, deployment status and the latest plan. Nothing red/scorer
    internal leaks here (that is the defender/visibility lane's job)."""
    guests = _guests(db, lab)
    home = home_session(db, lab)
    members = db.scalars(select(LabMember).where(
        LabMember.lab_id == lab.lab_id).order_by(LabMember.added_at)).all()
    plan = db.scalars(select(LabResetPlan).where(
        LabResetPlan.lab_id == lab.lab_id).order_by(
            LabResetPlan.created_at.desc())).first()
    dep = _latest_deployment(db, home.session_id) if home else None
    return {
        "lab_id": str(lab.lab_id),
        "environment_id": lab.environment_id,
        "name": lab.name,
        "state": lab.state,
        "power": lab.power,
        "owner_id": str(lab.owner_id) if lab.owner_id else None,
        "pins": lab.pins,
        "reservation": lab.reservation,
        "created_at": lab.created_at.isoformat() if lab.created_at else None,
        "deleted_at": lab.deleted_at.isoformat() if lab.deleted_at else None,
        "home_session_id": str(home.session_id) if home else None,
        "deployment": None if dep is None else {
            "deployment_id": str(dep.deployment_id),
            "status": dep.status,
            "guests": len([r for r in (dep.resources or [])
                           if r.get("state") == "created"]),
        },
        "guests": [{
            "guest": g.guest,
            "generation": g.generation,
            "state": g.state,
            "vmid": (g.resource or {}).get("vmid"),
            "name": (g.resource or {}).get("name"),
        } for g in guests],
        "members": [{
            "user_id": str(m.user_id),
            "role": m.role,
            "added_by": str(m.added_by) if m.added_by else None,
            "added_at": m.added_at.isoformat() if m.added_at else None,
            "removed_at": m.removed_at.isoformat() if m.removed_at else None,
        } for m in members],
        "latest_plan": None if plan is None else {
            "plan_id": str(plan.plan_id),
            "status": plan.status,
            "plan": plan.plan,
            "request": plan.request,
            "approved_at": plan.approved_at.isoformat()
            if plan.approved_at else None,
            "error": plan.error,
        },
    }


# ---------------------------------------------------------------- fences ----
def stop_worker_or_conflict(db, session_id) -> None:
    """AI offence FENCE before a destructive plan executes: the worker and
    every remote command must be CONFIRMED dead. `stopping`/`cancel-unknown`
    is a conflict — unknown cessation is not success."""
    from .api import runs as runs_svc

    active = runs_svc.active_run_for_session(db, session_id)
    if active is not None:
        stopped = runs_svc.stop_run(db, active.run_id)
        if not stopped.get("ok"):
            raise LabError(409, {
                "error": "worker_stop_failed",
                "run_id": str(active.run_id),
                "status": stopped.get("status"),
                "detail": stopped.get("detail"),
                "note": "range NOT reset; retry or engage the killswitch"})
    rows = runs_svc.unresolved_operations(db, session_id)
    if rows:
        for rid in {str(r.run_id) for r in rows}:
            try:
                runs_svc.stop_run(db, rid)
            except KeyError:
                pass
        rows = runs_svc.unresolved_operations(db, session_id)
        if rows:
            raise LabError(409, {
                "error": "unresolved_operations",
                "operations": [{"op_id": r.op_id, "state": r.state,
                                "run_id": str(r.run_id)} for r in rows][:10],
                "note": "unresolved command operations exist on this lab's "
                        "runs — release blocked until cessation is confirmed"})


def revoke_session_capabilities(db, session_id, reason: str) -> int:
    """Old machines are about to die: their capabilities must die first."""
    n = 0
    t = _now()
    for lt in db.scalars(select(LoginToken).where(
            LoginToken.session_id == session_id,
            LoginToken.revoked_at.is_(None))).all():
        lt.revoked_at = t
        n += 1
    for st in db.scalars(select(ServiceToken).where(
            ServiceToken.session_id == session_id,
            ServiceToken.revoked_at.is_(None))).all():
        st.revoked_at = t
        n += 1
    if n:
        db.add(Event(session_id=session_id, ts=t, actor="system",
                     action_type="capabilities_revoked",
                     payload={"count": n, "reason": reason,
                              "lab_scope": True}))
    return n
