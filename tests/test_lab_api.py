"""Lab aggregate (step 3): durable labs, membership, plans, selective reset.

Two layers against real Postgres:

  * the SERVICE + env lane — create a lab, deploy its blueprint through the
    stub broker, and execute an approved single-guest plan while every
    preserved guest keeps running (the actual production path minus the
    supervised executor);
  * the HTTP surface — create/list/access, captain-only planning, approval
    that fences and defers the destructive work to the executor, and a
    verified delete that a second create can follow.

No DB guarantee is faked: the whole module SKIPS without an explicit admin.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session as SASession

pytestmark = pytest.mark.db

ENV_ID = "underpressure-range"
SCENARIO = "underpressure-range-01"


# --------------------------------------------------------------- helpers ----
@pytest.fixture()
def eng(migrated_db):
    """Owner engine with the lab tables emptied between tests: the service
    tests share one schema (the HTTP tests get their own TRUNCATE through
    the `client` fixture)."""
    from sqlalchemy import create_engine, text
    from sqlalchemy.orm import Session as SASession

    e = create_engine(migrated_db)
    with SASession(e) as db:
        db.execute(text("TRUNCATE lab_reset_plans, lab_members, lab_guests, "
                        "labs CASCADE"))
        db.commit()
    return e


def _env(eng):
    from tests.test_env_deploy_flow import _bp_and_catalog, StubBroker

    bp, catalog = _bp_and_catalog()

    class ResettingBroker(StubBroker):
        """Stub + the two calls a selective reset makes."""

        def destroy_and_wait(self, node, vmid, session_id=None):
            self.calls.append(("destroy", int(vmid)))
            self.vms.pop(int(vmid), None)
            return {"ok": True}

        def disown(self, node, vmid, session_id=None, reason=""):
            self.vms.pop(int(vmid), None)

        def vm_status(self, node, vmid, session_id=None):
            v = self.vms.get(int(vmid))
            return {"running": bool(v and v.get("running"))}

    return bp, ResettingBroker(catalog)


def _session_states(eng, lab_id):
    from srplatform.db.models import Lab, LabGuest

    with SASession(eng) as db:
        lab = db.get(Lab, uuid.UUID(str(lab_id)))
        guests = {g.guest: g.state for g in db.scalars(
            select(LabGuest).where(LabGuest.lab_id == lab.lab_id)).all()}
        return lab.state, guests


def _owner(eng, name="lab-owner"):
    from srplatform.db.models import User

    with SASession(eng) as db:
        u = User(username=f"{name}-{uuid.uuid4().hex[:8]}")
        db.add(u)
        db.commit()
        return u.user_id


def _service_lab(eng):
    """A lab created by the SERVICE (its own home session included)."""
    from srplatform.db.session import db as db_ctx

    from srplatform import lab_service

    user_id = _owner(eng)
    with db_ctx() as db:
        lab = lab_service.create_lab(db, owner_id=user_id,
                                     environment_id=ENV_ID,
                                     scenario_id=SCENARIO)
        return lab.lab_id


# ------------------------------------------------------- service + reset ----
def test_create_lab_freezes_pins_and_creates_one_member_per_guest(eng):
    from srplatform.db.models import Lab, LabGuest, LabMember
    from srplatform.db.session import db as db_ctx
    from srplatform.lab_service import environment_digest

    lab_id = _service_lab(eng)
    with db_ctx() as db:
        lab = db.get(Lab, lab_id)
        assert lab.state == "provisioning" and lab.power == "on"
        assert lab.pins["environment"] == ENV_ID
        assert lab.pins["scenario_id"] == SCENARIO
        assert lab.pins["files_sha256"] == environment_digest(ENV_ID)
        guests = db.scalars(select(LabGuest).where(
            LabGuest.lab_id == lab_id)).all()
        assert len(guests) == 12
        assert {g.state for g in guests} == {"pending"}
        assert {g.generation for g in guests} == {1}
        members = db.scalars(select(LabMember).where(
            LabMember.lab_id == lab_id)).all()
        assert len(members) == 1
        assert members[0].role == "captain"
        assert str(members[0].user_id) == str(lab.owner_id)


def test_one_live_lab_per_environment(eng):
    from srplatform.db.session import db as db_ctx
    from srplatform.lab_service import LabError, create_lab

    lab_id = _service_lab(eng)
    user_id = _owner(eng, "second-owner")
    with db_ctx() as db:
        with pytest.raises(LabError) as err:
            create_lab(db, owner_id=user_id, environment_id=ENV_ID,
                       scenario_id=SCENARIO)
    assert err.value.status == 409
    assert err.value.detail["error"] == "environment_in_use"
    assert str(lab_id) in err.value.detail["detail"]


def test_unknown_environment_and_foreign_scenario_are_refused(eng):
    from srplatform.db.session import db as db_ctx
    from srplatform.lab_service import LabError, create_lab

    user_id = _owner(eng)
    with db_ctx() as db:
        with pytest.raises(LabError) as err:
            create_lab(db, owner_id=user_id,
                       environment_id="no-such-range",
                       scenario_id=SCENARIO)
    assert err.value.status == 404
    with db_ctx() as db:
        with pytest.raises(LabError) as err:
            create_lab(db, owner_id=user_id, environment_id=ENV_ID,
                       scenario_id="web-foothold-01")
    assert err.value.status == 422
    assert err.value.detail["error"] == "scenario_mismatch"


def test_plan_is_refused_until_the_lab_is_live(eng):
    from srplatform.db.models import Lab
    from srplatform.db.session import db as db_ctx
    from srplatform.lab_service import LabError, compute_plan

    lab_id = _service_lab(eng)
    with db_ctx() as db:
        lab = db.get(Lab, lab_id)
        with pytest.raises(LabError) as err:
            compute_plan(db, lab, requested_by=lab.owner_id,
                         selected=["ubuntu-wkst"])
    assert err.value.status == 409
    assert err.value.detail["error"] == "lab_not_live"


def test_selective_reset_rebuilds_only_the_planned_guest(eng):
    """The production path: deploy through the stub broker, reflect, plan,
    approve, execute — only the planned guest dies and its generation
    bumps; every preserved guest keeps its VMID and generation."""
    from srplatform.db.models import Lab, LabGuest, LabResetPlan
    from srplatform.db.session import db as db_ctx
    from srplatform.scenario_engine.env_deploy import deploy_environment
    from srplatform import lab_service

    bp, broker = _env(eng)
    lab_id = _service_lab(eng)
    with db_ctx() as db:
        lab = db.get(Lab, lab_id)
        home = lab_service.home_session(db, lab)
        sid = home.session_id
        out = deploy_environment(db, sid, SCENARIO,
                                 {"environment": ENV_ID}, broker)
        assert len(out["hosts"]) == 12
        lab_service.reflect_launch(db, sid)
        state, guests = (lambda db: (db.get(Lab, lab_id).state,
                                     {g.guest: (g.state, g.generation)
                                      for g in db.scalars(
                                          select(LabGuest).where(
                                              LabGuest.lab_id == lab_id)).all()}))(db)
        assert state == "active"
        assert all(s == "ready" for s, _ in guests.values())
        vmid_before = {g.guest: g.resource.get("vmid") for g in db.scalars(
            select(LabGuest).where(LabGuest.lab_id == lab_id)).all()}

        plan = lab_service.compute_plan(db, lab, requested_by=lab.owner_id,
                                        selected=["ubuntu-wkst"])
        assert plan.plan["ok"], plan.plan["blockers"]
        assert plan.plan["rebuild"] == ["ubuntu-wkst"]
        lab_service.approve_plan(db, lab, plan.plan_id,
                                 approved_by=lab.owner_id, is_operator=False,
                                 actor_role="captain")
        out = lab_service.execute_plan(db, sid, SCENARIO, broker,
                                       plan.plan_id)
        assert out["action"] == "selective_reset"
        assert out["destroyed"] == ["ubuntu-wkst"]
        lab_service.reflect_reset(db, sid, plan.plan_id)

        lab = db.get(Lab, lab_id)
        assert lab.state == "active"
        rows = {g.guest: g for g in db.scalars(
            select(LabGuest).where(LabGuest.lab_id == lab_id)).all()}
        assert rows["ubuntu-wkst"].generation == 2
        assert rows["ubuntu-wkst"].state == "ready"
        for name in ("ecomm", "webmail", "ad-dns"):
            assert rows[name].generation == 1
            assert rows[name].state == "ready"
            assert rows[name].resource.get("vmid") == vmid_before[name]
        plan_row = db.get(LabResetPlan, plan.plan_id)
        assert plan_row.status == "executed"


def test_plan_blockers_are_persisted_not_swallowed(eng):
    """A guest with no durable ready state blocks the plan and the blocker
    text is stored in the plan row for the approver to read."""
    from srplatform.db.models import Lab
    from srplatform.db.session import db as db_ctx
    from srplatform.lab_service import compute_plan

    lab_id = _service_lab(eng)
    with db_ctx() as db:
        lab = db.get(Lab, lab_id)
        lab.state = "active"
        db.commit()
        plan = compute_plan(db, lab, requested_by=lab.owner_id,
                            selected=["ecomm"])
        assert plan.plan["ok"] is False
        assert plan.plan["blockers"], "blockers must be recorded verbatim"
        assert any("ecomm" in b for b in plan.plan["blockers"])
        assert plan.status == "proposed"


# ---------------------------------------------------------------- HTTP ------
def _auth(users, who="op"):
    return users[who]


def _http_lab(client, headers):
    r = client.post("/labs", headers=headers,
                    json={"environment_id": ENV_ID,
                          "name": "Underpressure replica"})
    assert r.status_code == 201, r.text
    return r.json()


def _make_ready(db_url, lab_id):
    from sqlalchemy import create_engine

    from srplatform.db.models import Lab, LabGuest

    with SASession(create_engine(db_url)) as db:
        lab = db.get(Lab, uuid.UUID(str(lab_id)))
        lab.state = "active"
        for g in db.scalars(select(LabGuest).where(
                LabGuest.lab_id == lab.lab_id)).all():
            g.state = "ready"
            g.resource = {"vmid": 300, "name": g.guest}
        db.commit()


def test_http_create_list_and_visibility(client, users, migrated_db):
    lab = _http_lab(client, users["member"])
    assert lab["environment_id"] == ENV_ID
    assert lab["state"] == "provisioning"
    assert lab["home_session_id"]
    assert len(lab["guests"]) == 12
    assert lab["members"][0]["role"] == "captain"

    mine = client.get("/labs", headers=users["member"]).json()["labs"]
    assert [x["lab_id"] for x in mine] == [lab["lab_id"]]
    assert client.get(f"/labs/{lab['lab_id']}",
                      headers=users["member"]).status_code == 200
    # the operator sees every lab
    all_ = client.get("/labs", headers=users["op"]).json()["labs"]
    assert [x["lab_id"] for x in all_] == [lab["lab_id"]]

    # a member who is NOT on the lab sees nothing and is refused
    client.post("/users", headers=users["op"],
                json={"username": "green", "password": "green-testpw-9",
                      "role": "member"})
    tok = client.post("/auth/login",
                      json={"username": "green",
                            "password": "green-testpw-9"}).json()["token"]
    other = {"Authorization": f"Bearer {tok}"}
    assert client.get("/labs", headers=other).json()["labs"] == []
    assert client.get(f"/labs/{lab['lab_id']}",
                      headers=other).status_code == 403


def test_http_membership_invite_remove_reinvite(client, users, migrated_db):
    lab = _http_lab(client, users["member"])
    added = client.post(f"/labs/{lab['lab_id']}/members",
                        headers=users["member"],
                        json={"username": "drew", "role": "member"})
    assert added.status_code == 201, added.text
    assert added.json()["role"] == "member"

    # duplicates are refused, and the OWNER cannot be removed
    dup = client.post(f"/labs/{lab['lab_id']}/members",
                      headers=users["member"],
                      json={"username": "drew", "role": "member"})
    assert dup.status_code == 409
    me = client.get("/users/me", headers=users["member"]).json()
    owner_removal = client.delete(
        f"/labs/{lab['lab_id']}/members/{me['user_id']}",
        headers=users["member"])
    assert owner_removal.status_code == 409
    assert owner_removal.json()["detail"]["error"] == "owner_is_captain"

    removed = client.delete(
        f"/labs/{lab['lab_id']}/members/{added.json()['user_id']}",
        headers=users["member"])
    assert removed.status_code == 200, removed.text
    assert removed.json()["removed_at"]
    again = client.post(f"/labs/{lab['lab_id']}/members",
                        headers=users["member"],
                        json={"username": "drew", "role": "member"})
    assert again.status_code == 201, again.text


def test_http_plan_approve_fences_and_hands_off(client, users,
                                                migrated_db, monkeypatch):
    """Captain-only planning; approval returns 202 with the durable
    operation and a plan id in progress, and destroys nothing itself."""
    from srplatform.db.models import DeployOperation, LabResetPlan
    from srplatform.scenario_engine import deploy_executor

    lab = _http_lab(client, users["member"])
    _make_ready(migrated_db, lab["lab_id"])
    submitted = []
    monkeypatch.setattr(
        deploy_executor, "submit",
        lambda **kw: submitted.append(kw))

    planned = client.post(f"/labs/{lab['lab_id']}/reset-plans",
                          headers=users["member"],
                          json={"selected": ["ubuntu-wkst"]})
    assert planned.status_code == 201, planned.text
    body = planned.json()
    assert body["plan"]["ok"], body["plan"]["blockers"]
    assert body["plan"]["rebuild"] == ["ubuntu-wkst"]

    ok = client.post(
        f"/labs/{lab['lab_id']}/reset-plans/{body['plan_id']}/approve",
        headers=users["member"])
    assert ok.status_code == 202, ok.text
    assert ok.json()["status"] == "accepted"
    assert len(submitted) == 1
    assert submitted[0]["operation"] == "reset"
    from sqlalchemy import create_engine

    with SASession(create_engine(migrated_db)) as db:
        plan = db.get(LabResetPlan, uuid.UUID(body["plan_id"]))
        assert plan.status == "approved"
        op = db.execute(select(DeployOperation)).scalars().first()
        assert op.operation == "reset"
        assert op.progress["lab_plan_id"] == body["plan_id"]

    # a member who is not a captain cannot plan
    client.post("/users", headers=users["op"],
                json={"username": "green", "password": "green-testpw-9",
                      "role": "member"})
    tok = client.post("/auth/login",
                      json={"username": "green",
                            "password": "green-testpw-9"}).json()["token"]
    other = {"Authorization": f"Bearer {tok}"}
    assert client.post(f"/labs/{lab['lab_id']}/reset-plans",
                       headers=other,
                       json={"selected": ["ecomm"]}).status_code == 403


def test_http_delete_is_verified_then_a_new_lab_can_follow(client, users,
                                                           migrated_db):
    lab = _http_lab(client, users["member"])
    deleted = client.delete(f"/labs/{lab['lab_id']}",
                            headers=users["member"])
    assert deleted.status_code == 200, deleted.text
    assert deleted.json()["state"] == "deleted"
    assert client.get(f"/labs/{lab['lab_id']}",
                      headers=users["member"]).status_code == 404
    fresh = _http_lab(client, users["member"])
    assert fresh["lab_id"] != lab["lab_id"]


def test_http_delete_releases_the_range_lease(client, users, migrated_db):
    """A deleted lab must not keep the single-range reservation: the next
    lab has to be able to provision (live find 2026-11-03: the gate's
    delete tore the VMs down but left the lease held, so the rerun failed
    range_busy with a dead holder)."""
    from sqlalchemy import create_engine, select
    from sqlalchemy.orm import Session as SASession

    from srplatform.db.models import RangeLease

    lab = _http_lab(client, users["member"])
    with SASession(create_engine(migrated_db)) as db:
        home_id = __import__("uuid").UUID(lab["home_session_id"])
        row = db.execute(select(RangeLease).where(
            RangeLease.id == 1)).scalar_one_or_none()
        if row is None:
            from srplatform.db.models import RangeLease as RL
            db.add(RL(id=1, session_id=home_id))
        else:
            row.session_id, row.released_at = home_id, None
        db.commit()
    deleted = client.delete(f"/labs/{lab['lab_id']}",
                            headers=users["member"])
    assert deleted.status_code == 200, deleted.text
    with SASession(create_engine(migrated_db)) as db:
        row = db.execute(select(RangeLease).where(
            RangeLease.id == 1)).scalar_one()
        assert row.released_at is not None
