"""Environment-deploy flow: blueprint guests through a stub broker.

Covers the durable side of the env lane on the real disposable-Postgres
fixture (the infra-free lanes cover the policies): nothing clones before
EVERY profile resolves, the pending intent is committed BEFORE its side
effect, the full per-guest NIC vector is applied in ONE set_config with
`expected_nics`, a NIC read-back drift parks that guest pending (never
falsely created) and a resumed pass converges it, and a ready deployment
returns idempotently with zero side effects.

The STUB stands in for the broker (the real producer→consumer contract is
guarded in test_backend_nic_vector.py / test_segment_nic_lane.py); the
blueprint here is the REAL underpressure-range environment.
"""
from __future__ import annotations

import uuid

import pytest

pytestmark = pytest.mark.db

ENV_ID = "underpressure-range"


class StubBroker:
    def __init__(self, catalog):
        self.catalog = catalog
        self.calls: list[tuple] = []
        self.vms: dict[int, dict] = {}
        self.on_first_clone = None

    def template_catalog(self):
        return list(self.catalog)

    def next_vmid(self, node, base, session_id=None):  # noqa: ARG002
        return 250 + len(self.vms)

    def lookup_vm(self, node, vmid):
        return dict(self.vms[vmid]) if vmid in self.vms else None

    def clone_and_wait(self, node, template_vmid, vmid, name, full=True,
                       session_id=None, generation=None):
        self.calls.append(("clone", int(vmid), int(template_vmid), name))
        if self.on_first_clone and not self.vms:
            self.on_first_clone()
        self.vms[int(vmid)] = {"name": name, "tags": "", "nics": []}

    def try_lookup_config(self, node, vmid):
        v = self.vms.get(int(vmid))
        if v is None:
            return {"_unavailable": "no domain"}
        return {"name": v["name"], "tags": v["tags"], "nics": v["nics"]}

    def set_config(self, node, vmid, name=None, tags=None, session_id=None,
                   expected_nics=None):
        self.calls.append(("set_config", int(vmid),
                           tuple((n["segment"], n["address"])
                                 for n in (expected_nics or []))))
        v = self.vms[int(vmid)]
        v["name"] = name or v["name"]
        v["tags"] = tags or ""
        v["nics"] = [{"index": i, "bridge": f"sr-{n['segment']}",
                      "mac": f"52:54:00:2b:{i:02d}:{len(expected_nics or []):02d}"}
                     for i, n in enumerate(expected_nics or [])]

    def start_and_wait(self, node, vmid, session_id=None):
        self.calls.append(("start", int(vmid)))
        self.vms[int(vmid)]["running"] = True

    def lookup_config(self, node, vmid):
        cfg = dict(self.try_lookup_config(node, int(vmid)))
        cfg["domain_uuid"] = f"uuid-{vmid}"
        return cfg

    def artifact_for_template(self, template_vmid):
        return None


def _bp_and_catalog():
    from srplatform.environment_specs import load_environment
    bp = load_environment(ENV_ID).blueprint
    by_profile: dict[str, str] = {}
    catalog = []
    for g in bp.guests:
        if g.boot.image_profile not in by_profile:
            by_profile[g.boot.image_profile] = str(9100 + len(by_profile))
        catalog.append({"profile": g.boot.image_profile,
                        "template_id": by_profile[g.boot.image_profile],
                        "role": "guest"})
    return bp, catalog


def _session_row(eng, scenario_id=None):
    from sqlalchemy.orm import Session as SASession
    from srplatform.db.models import Session as SessionRow, User
    with SASession(eng) as db:
        owner = User(username=f"env-{uuid.uuid4().hex[:8]}")
        db.add(owner)
        db.flush()
        s = SessionRow(scenario_id=scenario_id or
                       f"{ENV_ID}-{uuid.uuid4().hex[:4]}",
                       user_id=owner.user_id)
        db.add(s)
        db.commit()
        return str(s.session_id)


@pytest.fixture()
def eng(migrated_db):
    from sqlalchemy import create_engine
    from srplatform.db.models import Base
    e = create_engine(migrated_db)
    Base.metadata.create_all(e)  # no-op against the migrated schema
    return e


def _deploy(eng, session_id, broker):
    from sqlalchemy.orm import Session as SASession
    from srplatform.scenario_engine.env_deploy import deploy_environment
    with SASession(eng) as db:
        return deploy_environment(db, session_id, f"{ENV_ID}-t1",
                                  {"environment": ENV_ID}, broker)


def _deployment(eng, session_id):
    from sqlalchemy import select
    from sqlalchemy.orm import Session as SASession
    from srplatform.db.models import Deployment
    with SASession(eng) as db:
        return db.scalars(select(Deployment)
                          .where(Deployment.session_id == session_id)).one()


def test_deploy_every_guest_in_dependency_order_with_full_vectors(eng):
    bp, catalog = _bp_and_catalog()
    broker = StubBroker(catalog)
    sid = _session_row(eng)
    out = _deploy(eng, sid, broker)
    assert len(out["hosts"]) == len(bp.guests)
    assert all(h["state"] == "created" for h in out["hosts"])
    # one whole-vector set_config per guest — never leg-by-leg
    vec = [c for c in broker.calls if c[0] == "set_config"]
    assert len(vec) == len(bp.guests)
    planned = {c[1]: c[2] for c in vec}
    dep = _deployment(eng, sid)
    assert dep.status == "ready"
    res = {r["host"]: r for r in dep.resources}
    vyos = res["vyos-edge"]
    # every blueprint interface carried its planned segment+address
    assert [(s, a) for s, a in planned[vyos["vmid"]]] == \
        [(i.segment, str(i.ipv4.address)) for i in bp.guest("vyos-edge").interfaces]
    assert vyos["applied_nics"] and vyos["environment_guest"]
    assert vyos["host_key"] == "unenforced-environment-guest"
    # dependency order: ad-dns cloned before mssql (its domain depends on it)
    vmid_of = {r["host"]: r["vmid"] for r in dep.resources}
    clone_order = [c[1] for c in broker.calls if c[0] == "clone"]
    assert clone_order.index(vmid_of["ad-dns"]) < \
        clone_order.index(vmid_of["mssql"])


def test_intent_committed_before_the_side_effect(eng):
    _bp, catalog = _bp_and_catalog()
    sid = _session_row(eng)
    seen = {}

    def probe():
        from sqlalchemy import select
        from sqlalchemy.orm import Session as SASession
        from srplatform.db.models import Deployment
        with SASession(eng) as db:
            d = db.scalars(select(Deployment)
                           .where(Deployment.session_id == sid)).one_or_none()
            seen["resources"] = list(d.resources) if d else None

    broker = StubBroker(catalog)
    broker.on_first_clone = probe
    _deploy(eng, sid, broker)
    # at the first clone the durable row already owned a PENDING guest
    assert seen["resources"] and seen["resources"][0]["state"] == "pending"


def test_missing_profile_refuses_before_any_side_effect(eng):
    _bp, catalog = _bp_and_catalog()
    missing = [c for c in catalog if c["profile"] != "router-vyos-140"]
    assert len(missing) == len(catalog) - 1
    broker = StubBroker(missing)
    sid = _session_row(eng)
    from srplatform.scenario_engine.loader import ScenarioError
    with pytest.raises(ScenarioError, match="cannot provide"):
        _deploy(eng, sid, broker)
    assert broker.calls == []  # nothing cloned


def test_empty_catalog_refuses(eng):
    broker = StubBroker([])
    sid = _session_row(eng)
    from srplatform.scenario_engine.loader import ScenarioError
    with pytest.raises(ScenarioError, match="no template catalog"):
        _deploy(eng, sid, broker)
    assert broker.calls == []


def test_nic_drift_parks_pending_then_resume_converges(eng):
    bp, catalog = _bp_and_catalog()
    sid = _session_row(eng)
    broker = StubBroker(catalog)
    # the first running read-back drifts once; everything after is clean
    real_lookup = broker.lookup_config
    state = {"drift_once": True}

    def drift_once(node, vmid):
        cfg = real_lookup(node, vmid)
        if state["drift_once"]:
            state["drift_once"] = False
            cfg["_nic_drift"] = "intent != xml (injected)"
        return cfg

    broker.lookup_config = drift_once
    with pytest.raises(RuntimeError, match="domain XML disagrees"):
        _deploy(eng, sid, broker)
    dep = _deployment(eng, sid)
    assert dep.status == "failed"
    parked = [r for r in dep.resources if r["state"] != "created"]
    assert len(parked) == 1  # the drifted guest, never the whole lab
    vmid = parked[0]["vmid"]
    assert parked[0]["state"] == "pending"
    # resume: the pending guest is re-applied (never re-cloned) and converges
    out = _deploy(eng, sid, broker)
    assert len(out["hosts"]) == len(bp.guests)
    assert sum(1 for c in broker.calls
               if c[0] == "clone" and c[1] == vmid) == 1  # not re-cloned
    assert any(c == ("start", vmid) for c in broker.calls)
    assert _deployment(eng, sid).status == "ready"


def test_ready_deployment_is_idempotent(eng):
    _bp, catalog = _bp_and_catalog()
    sid = _session_row(eng)
    broker = StubBroker(catalog)
    first = _deploy(eng, sid, broker)
    calls = len(broker.calls)
    again = _deploy(eng, sid, broker)
    assert again["idempotent"] is True
    assert again["deployment_id"] == first["deployment_id"]
    assert len(broker.calls) == calls  # zero side effects on the second pass


def test_orchestrator_deploy_end_to_end(eng):
    """The shipped scenario `underpressure-range-01` through the REAL
    orchestrator entry point: snapshot-spec resolution, environment routing,
    full blueprint deploy, and the idempotent ready return — no component
    between them is stubbed except the broker."""
    from sqlalchemy.orm import Session as SASession
    from srplatform.scenario_engine.orchestrator import deploy as orch_deploy
    _bp, catalog = _bp_and_catalog()
    sid = _session_row(eng, scenario_id="underpressure-range-01")
    broker = StubBroker(catalog)
    with SASession(eng) as db:
        out = orch_deploy(db, sid, "underpressure-range-01", broker)
    assert len(out["hosts"]) == 12
    dep = _deployment(eng, sid)
    assert dep.status == "ready"
    assert all(r["environment_guest"] and r["applied_nics"]
               for r in dep.resources)
    with SASession(eng) as db:
        again = orch_deploy(db, sid, "underpressure-range-01", broker)
    assert again["idempotent"] is True and not [
        c for c in broker.calls if c[0] == "clone"][12:]
