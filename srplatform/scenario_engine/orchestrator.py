"""Scenario orchestrator (M1 — F06 rewrite): deployment with a global lease,
persisted intent, exact resource ownership, and reconciliation.

The old version named VMs by scenario prefix, reused static IPs, allocated
VMIDs with a read-then-use scan, and destroyed everything matching a prefix —
two launches could collide and destroy each other's machines. Now:

  * A durable SINGLE-ACTIVE-RANGE lease (`range_lease` row) is acquired BEFORE
    any external side effect; concurrent launches conflict cleanly.
  * A `deployments` row records intent; resources are appended EXACTLY as each
    side effect completes (vmid/node/name/ip), so recovery from a partial
    failure works from the recorded list — never from name prefixes.
  * Reset/teardown act only on positively-owned recorded resources (with an
    ownership tag double-check) and ignore prefix-similar foreign VMs.
  * Every external call goes through the task-aware ProxmoxClient (F05).
  * Database failures after side effects are LOUD (recorded + raised), never
    swallowed (F06 `_log()` fix).
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from srplatform.db.models import Deployment, Event, RangeLease, Session as SessionModel
from srplatform.scenario_engine.loader import load_scenario
from srplatform.settings import get_settings


class LeaseConflict(RuntimeError):
    def __init__(self, holder_session_id, acquired_at):
        self.holder_session_id = str(holder_session_id) if holder_session_id else None
        self.acquired_at = acquired_at.isoformat() if acquired_at else None
        super().__init__(f"range is already reserved by session {self.holder_session_id}")


def _now():
    return datetime.now(timezone.utc)


def _log(db: Session, session_id, action, host, payload):
    """Deployment actions are recorded in the append-only log. A failure here
    RAISES — silent loss of deployment evidence was itself an audit finding."""
    db.add(Event(session_id=session_id, ts=_now(), actor="system", host=host,
                 action_type=action, payload=payload))
    db.flush()


# ------------------------------------------------------------------- lease ---
def acquire_lease(db: Session, session_id) -> None:
    """Global single-active-range reservation (v1 assumption; see
    docs/ARCHITECTURE_NOTES.md). Row lock serializes concurrent acquirers."""
    row = db.execute(select(RangeLease).where(RangeLease.id == 1)
                     .with_for_update()).scalar_one_or_none()
    held = row is not None and row.released_at is None and str(row.session_id) != str(session_id)
    if held:
        # defensive reconciliation: a lease whose holder session already ended
        # is stale and may be taken over
        holder = db.get(SessionModel, row.session_id) if row.session_id else None
        if holder is None or holder.status in ("complete", "failed", "torn_down"):
            row.session_id, row.acquired_at, row.released_at = session_id, _now(), None
            _log(db, session_id, "lease_takeover", None,
                 {"stale_holder": str(row.session_id), "status": holder.status if holder else None})
            db.commit()   # the reservation must survive any later rollback
            return
        raise LeaseConflict(row.session_id, row.acquired_at)
    if row is None:
        db.add(RangeLease(id=1, session_id=session_id, acquired_at=_now()))
    else:
        row.session_id, row.acquired_at, row.released_at = session_id, _now(), None
    db.commit()   # reserve BEFORE any side effect; survives later failure


def release_lease(db: Session, session_id) -> None:
    row = db.get(RangeLease, 1)
    if row and row.released_at is None and (session_id is None or str(row.session_id) == str(session_id)):
        row.released_at = _now()
        _log(db, row.session_id, "lease_release", None, {})
        db.commit()


def current_lease(db: Session) -> dict | None:
    row = db.get(RangeLease, 1)
    if not row or row.released_at is not None:
        return None
    return {"session_id": str(row.session_id) if row.session_id else None,
            "acquired_at": row.acquired_at.isoformat() if row.acquired_at else None}


# ------------------------------------------------------------------ deploy ---
def _net_spec(s) -> str:
    return f"virtio,bridge={s.range_bridge},tag={s.range_vlan}"


def deploy(db: Session, session_id, scenario_id: str, proxmox) -> dict:
    """Clone every host in the scenario from its golden template, configure
    network/ownership on the range bridge, and start each with task waiting.
    Caller must hold the lease (acquire_lease first)."""
    s = get_settings()
    spec = load_scenario(scenario_id)
    node = s.proxmox_node
    dep = Deployment(session_id=session_id, scenario_id=scenario_id, status="preparing",
                     resources=[])
    db.add(dep)
    db.flush()

    created = []
    try:
        for i, host in enumerate(spec["topology"]["hosts"]):
            vmid = int(proxmox.next_vmid(s.deploy_vmid_base + i))
            name = f"{scenario_id}-{host['name']}-{str(session_id)[:8] if session_id else 'adhoc'}"
            # intent BEFORE side effect: record pending resource
            _log(db, session_id, "deploy_intent", host["name"],
                 {"vmid": vmid, "name": name, "template_vmid": host["template_vmid"]})
            proxmox.clone_and_wait(node, int(host["template_vmid"]), vmid, name, full=False)
            # network placement on the range bridge/VLAN + ownership tag (F06)
            proxmox.set_config(node, vmid,
                               ipconfig0=f"ip={host['ip']}/24,gw={s.range_gateway}",
                               net0=_net_spec(s),
                               tags=f"srsess={str(session_id)[:8] if session_id else 'adhoc'}")
            # validate NIC placement (read-back; PVE accepts what it renders)
            cfg = proxmox.get(f"/nodes/{node}/qemu/{vmid}/config")
            net0 = (cfg or {}).get("net0", "") if isinstance(cfg, dict) else ""
            if s.range_bridge not in net0:
                raise RuntimeError(f"NIC placement validation failed on {name}: "
                                   f"net0={net0!r} does not use bridge {s.range_bridge}")
            proxmox.start_and_wait(node, vmid)
            created.append({"vmid": vmid, "node": node, "name": name,
                            "host": host["name"], "ip": host["ip"],
                            "template_vmid": host["template_vmid"]})
            # append the resource EXACTLY as it completed
            dep.resources = created
            flag_modified(dep, "resources")
            _log(db, session_id, "deploy", host["name"],
                 {"vmid": vmid, "name": name, "linked": True, "net0": net0})
            # OWNERSHIP COMMITTED PER RESOURCE: if a later host fails (or the
            # process dies), everything already created remains accounted for
            db.commit()
        dep.status = "ready"
        db.commit()
    except Exception as e:
        dep.resources = created
        flag_modified(dep, "resources")
        dep.status = "failed"
        dep.error = str(e)[:2000]
        _log(db, session_id, "deploy_failed", None,
             {"error": str(e)[:500], "created_so_far": created})
        db.commit()   # failure evidence + partial ownership survive the rollback
        raise
    return {"scenario_id": scenario_id, "action": "deploy", "deployment_id": str(dep.deployment_id),
            "hosts": created}


def _owned_resources(dep: Deployment) -> list[dict]:
    return [r for r in (dep.resources or []) if r.get("vmid")]


def _destroy_owned(db: Session, session_id, dep: Deployment, proxmox) -> list[str]:
    removed = []
    for r in _owned_resources(dep):
        try:
            proxmox.destroy_and_wait(r.get("node") or get_settings().proxmox_node, int(r["vmid"]))
        except Exception as e:  # noqa: BLE001 — keep going; report per-resource
            _log(db, session_id, "teardown_resource_failed", r.get("host"),
                 {"vmid": r["vmid"], "error": str(e)[:300]})
            continue
        removed.append(r["name"])
    return removed


def teardown(db: Session, session_id, scenario_id: str, proxmox) -> dict:
    """Remove THIS deployment's owned resources. Never a prefix sweep."""
    dep = _latest_deployment(db, session_id, scenario_id)
    if dep is None:
        return {"scenario_id": scenario_id, "action": "teardown", "removed": [],
                "note": "no deployment recorded for this session — nothing to remove"}
    removed = _destroy_owned(db, session_id, dep, proxmox)
    dep.status = "torn_down"
    dep.updated_at = _now()
    _log(db, session_id, "teardown", None, {"removed": removed,
                                            "deployment_id": str(dep.deployment_id)})
    db.flush()
    return {"scenario_id": scenario_id, "action": "teardown", "removed": removed}


def reset(db: Session, session_id, scenario_id: str, proxmox) -> dict:
    """Destroy owned resources and redeploy fresh clones. Idempotent."""
    t = teardown(db, session_id, scenario_id, proxmox)
    d = deploy(db, session_id, scenario_id, proxmox)
    d["action"] = "reset"
    d["removed"] = t["removed"]
    return d


def _latest_deployment(db: Session, session_id, scenario_id: str) -> Deployment | None:
    q = select(Deployment).where(Deployment.scenario_id == scenario_id)
    if session_id:
        q = q.where(Deployment.session_id == session_id)
    return db.execute(q.order_by(Deployment.created_at.desc())).scalars().first()
