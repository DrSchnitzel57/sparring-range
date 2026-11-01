"""Durable lab aggregate (migration 0029) + dependency-aware reset plans.

The reset planner is pure and always exercised; the persistence tests run
on the real disposable Postgres lane (they SKIP without an explicit admin,
never fake DB guarantees).
"""
from __future__ import annotations

import uuid

import pytest

from srplatform.lab import RESET_PLAN_VERSION, compute_reset_plan
from srplatform.environment_specs import load_environment


@pytest.fixture(scope="module")
def bp():
    return load_environment("underpressure-range").blueprint


def _states(bp, state="ready"):
    return {g.name: state for g in bp.guests}


# ------------------------------------------------------------------- planner --
def test_plan_version_and_fences_are_stable(bp):
    plan = compute_reset_plan(bp, ["ubuntu-wkst"], _states(bp))
    assert plan["plan_version"] == RESET_PLAN_VERSION
    assert plan["fences"]["ai_offence_fence"] is True
    assert plan["fences"]["scoring_fence"] is True
    assert plan["fences"]["console_capabilities"] == "revoked-for-rebuilt"


def test_isolated_workstation_reset_preserves_everything_else(bp):
    plan = compute_reset_plan(bp, ["ubuntu-wkst"], _states(bp))
    assert plan["ok"], plan["blockers"]
    assert plan["rebuild"] == ["ubuntu-wkst"]
    assert "webmail" in plan["preserved"] and len(plan["preserved"]) == 11


def test_sql_reset_cascades_to_both_app_tiers(bp):
    plan = compute_reset_plan(bp, ["mssql"], _states(bp))
    assert plan["ok"], plan["blockers"]
    assert {"ecomm", "webmail"} <= set(plan["rebuild"])
    assert any("store AND webmail" in a for a in plan["advisories"])
    assert "splunk" in plan["preserved"]  # not a SQL consumer


def test_domain_controller_reset_cascades_then_refuses_stray_members(bp):
    # every domain member declares depends_on: [ad-dns], so a DC reset
    # CASCADES and preserves no member
    plan = compute_reset_plan(bp, ["ad-dns"], _states(bp))
    assert plan["ok"], plan["blockers"]
    assert {"mssql", "ecomm", "webmail", "splunk", "win11-wkst",
            "ubuntu-wkst"} <= set(plan["rebuild"])
    member_roles = {"windows-sql", "windows-desktop", "linux-server",
                    "mail-server", "splunk-server", "linux-desktop"}
    preserved_roles = {g.role.value for g in bp.guests if g.name in plan["preserved"]}
    assert not (preserved_roles & member_roles)
    assert any("forest" in a for a in plan["advisories"])
    # a manual-join member WITHOUT a declared dependency must block
    import copy
    from srplatform.environment_specs.blueprint import GuestRole
    stray = copy.deepcopy(bp)
    for g in stray.guests:
        if g.name == "team-kali":
            g.role = GuestRole.WINDOWS_DESKTOP  # trusts the domain, declares nothing
    stray_plan = compute_reset_plan(stray, ["ad-dns"], _states(stray))
    assert not stray_plan["ok"]
    assert any("isolated DC rollback" in b for b in stray_plan["blockers"])
    # full range always plans clean
    full = compute_reset_plan(bp, [], _states(bp), full=True)
    assert full["ok"] and full["preserved"] == []


def test_unknown_inventory_blocks_never_guesses(bp):
    states = _states(bp)
    del states["mssql"]
    plan = compute_reset_plan(bp, ["mssql"], states)
    assert not plan["ok"]
    assert any("no durable inventory" in b for b in plan["blockers"])
    states["splunk"] = "creating"
    plan2 = compute_reset_plan(bp, ["splunk"], states)
    assert not plan2["ok"]
    assert any("mid-provision" in b for b in plan2["blockers"])


def test_reset_state_policy_fails_closed(bp):
    """Only ready/stopped reset on their own; transitional, foreign,
    destroyed, unrecognized and un-reconciled-failed states NEVER plan ok
    (unknown-ownership rule), with ready/stopped controls passing."""
    base = _states(bp)
    for bad in ("unknown", "foreign", "destroying", "failed", "provisioning",
                "pending", "creating", "destroyed", "not-a-real-state"):
        states = dict(base, ecomm=bad)
        plan = compute_reset_plan(bp, ["ecomm"], states)
        assert not plan["ok"], f"state {bad!r} must block, got {plan['blockers']}"
        assert any("ecomm" in b for b in plan["blockers"])
    for good in ("ready", "stopped"):
        states = dict(base, ecomm=good)
        assert compute_reset_plan(bp, ["ecomm"], states)["ok"], good
    # failed resets ONLY with positive reconciled ownership of the generation
    states = dict(base, ecomm="failed")
    assert not compute_reset_plan(bp, ["ecomm"], states)["ok"]
    rec = compute_reset_plan(bp, ["ecomm"], states,
                             reconciled_guests=frozenset({"ecomm"}))
    assert rec["ok"], rec["blockers"]
    # reconciling one guest never whitewashes another failing guest
    states2 = dict(states, webmail="failed")
    p2 = compute_reset_plan(bp, ["ecomm", "webmail"], states2,
                            reconciled_guests=frozenset({"ecomm"}))
    assert not p2["ok"] and any("webmail" in b for b in p2["blockers"])


def test_empty_and_unknown_selections_refused(bp):
    plan = compute_reset_plan(bp, [], _states(bp))
    assert not plan["ok"] and any("at least one guest" in b for b in plan["blockers"])
    plan2 = compute_reset_plan(bp, ["ghost"], _states(bp))
    assert not plan2["ok"] and any("refusing to" in b for b in plan2["blockers"])


def test_router_rebuild_advises_segment_interruption(bp):
    plan = compute_reset_plan(bp, ["opnsense-fw"], _states(bp))
    assert plan["ok"], plan["blockers"]
    assert any("ALL segments" in a for a in plan["advisories"])


# ---------------------------------------------------------------- persistence --
def test_lab_aggregate_roundtrip_and_constraints(migrated_db):
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import Session as SASession
    from sqlalchemy.exc import IntegrityError

    from srplatform.db.models import (Base, Lab, LabGuest, LabMember,
                                      LabResetPlan, Session as SessionRow,
                                      User)
    eng = create_engine(migrated_db)
    Base.metadata.create_all(eng)  # no-op against the migrated schema
    with SASession(eng) as db:
        owner = User(username=f"cap-{uuid.uuid4().hex[:8]}")
        mate = User(username=f"mate-{uuid.uuid4().hex[:8]}")
        db.add_all([owner, mate])
        db.flush()
        lab = Lab(environment_id="underpressure-range",
                  pins={"blueprint_version": 1}, name="springs-lab",
                  owner_id=owner.user_id, state="active",
                  reservation={"memory_mb_total": 50176, "guests": 12})
        db.add(lab)
        db.flush()
        for name in ("vyos-edge", "ad-dns", "ecomm"):
            db.add(LabGuest(lab_id=lab.lab_id, guest=name))
        db.add(LabMember(lab_id=lab.lab_id, user_id=mate.user_id, role="member",
                         added_by=owner.user_id))
        sess = SessionRow(scenario_id="underpressure-range-01",
                          user_id=owner.user_id, lab_id=lab.lab_id)
        db.add(sess)
        db.commit()
        lab_id = lab.lab_id
        sess_id = sess.session_id

    with SASession(eng) as db:
        lab = db.get(Lab, lab_id)
        assert lab.reservation["guests"] == 12
        assert lab.power == "on"
        guests = db.scalars(select(LabGuest).where(LabGuest.lab_id == lab_id)).all()
        assert len(guests) == 3
        # one row per guest per lab
        db.add(LabGuest(lab_id=lab_id, guest="ecomm"))
        with pytest.raises(IntegrityError):
            db.flush()
        db.rollback()

    with SASession(eng) as db:
        g = db.scalars(select(LabGuest).where(LabGuest.lab_id == lab_id,
                                              LabGuest.guest == "ecomm")).one()
        g.generation += 1  # reset bumps the generation
        member = db.scalars(select(LabMember).where(LabMember.lab_id == lab_id,
                                                    LabMember.role == "member")).one()
        from datetime import datetime, timezone
        member.removed_at = datetime.now(timezone.utc)  # removal timestamps, never deletes
        plan = LabResetPlan(lab_id=lab_id, request={"selected": ["ecomm"]},
                            plan={"plan_version": RESET_PLAN_VERSION,
                                  "rebuild": ["ecomm"]},
                            status="proposed")
        db.add(plan)
        db.commit()
        plan_id = plan.plan_id
    with SASession(eng) as db:
        assert db.get(LabGuest, db.scalars(
            select(LabGuest.id).where(LabGuest.lab_id == lab_id,
                                      LabGuest.guest == "ecomm")).one()).generation == 2
        p = db.get(LabResetPlan, plan_id)
        assert p.status == "proposed" and p.plan["plan_version"] == \
            RESET_PLAN_VERSION
        s = db.get(SessionRow, sess_id)
        assert s.lab_id == lab_id


def test_sessions_predate_labs_and_stay_uninterpreted(migrated_db):
    """A flat-scenario session keeps lab_id NULL forever; creating a lab
    never backfills or reinterprets existing sessions."""
    import uuid

    from sqlalchemy import create_engine, func, select
    from sqlalchemy.orm import Session as SASession
    from srplatform.db.models import Lab, Session as SessionRow

    # unique marker: the DB lane shares one migrated database per session,
    # so this test must not assume it is the only writer of sessions
    marker = uuid.uuid4().hex
    eng = create_engine(migrated_db)
    with SASession(eng) as db:
        for i in range(3):
            db.add(SessionRow(scenario_id=f"legacy-{marker}-{i}"))
        db.commit()
    with SASession(eng) as db:
        db.add(Lab(environment_id="underpressure-range", name=f"late-lab-{marker}"))
        db.commit()
    with SASession(eng) as db:
        bound = db.scalar(select(func.count()).select_from(SessionRow)
                          .where(SessionRow.scenario_id.like(f"legacy-{marker}-%"),
                                 SessionRow.lab_id.is_(None)))
        assert bound == 3
