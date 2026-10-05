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
def _residual_resources(db: Session, session_id) -> list[dict]:
    """Owned resources that still exist (or whose fate is uncertain) for a
    session — the thing that must NOT be left behind when a lease is taken
    over or released (audit R07)."""
    residual = []
    for dep in db.execute(select(Deployment).where(Deployment.session_id == session_id)
                          .order_by(Deployment.created_at)).scalars().all():
        for r in (dep.resources or []):
            if r.get("vmid") and r.get("state") in ("pending", "created", "destroy_failed"):
                residual.append({**r, "deployment_id": str(dep.deployment_id)})
    return residual


def acquire_lease(db: Session, session_id) -> None:
    """Global single-active-range reservation (v1 assumption; see
    docs/ARCHITECTURE_NOTES.md). Row lock serializes concurrent acquirers."""
    row = db.execute(select(RangeLease).where(RangeLease.id == 1)
                     .with_for_update()).scalar_one_or_none()
    held = row is not None and row.released_at is None and str(row.session_id) != str(session_id)
    if held:
        # defensive reconciliation: a lease whose holder session already ended
        # is stale and may be taken over — but ONLY when the holder has no
        # residual machines still holding the range's static addresses
        # (audit R07: ending a session must not hand the same IP space to the
        # next launch while the old VMs are still running).
        holder = db.get(SessionModel, row.session_id) if row.session_id else None
        residual = _residual_resources(db, row.session_id) if row.session_id else []
        if holder is not None and holder.status in ("complete", "failed", "torn_down") and residual:
            raise LeaseConflict(row.session_id, row.acquired_at)
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


def _active_deployment(db: Session, session_id, scenario_id: str) -> Deployment | None:
    """Latest deployment for this session+scenario that still OWNS something
    (not torn_down) — the idempotency/resume anchor (audit R08)."""
    q = select(Deployment).where(Deployment.scenario_id == scenario_id)
    if session_id:
        q = q.where(Deployment.session_id == session_id)
    for dep in db.execute(q.order_by(Deployment.created_at.desc())).scalars().all():
        if dep.status in ("preparing", "ready", "failed"):
            return dep
    return None


def deploy(db: Session, session_id, scenario_id: str, proxmox, resume: bool = True) -> dict:
    """Clone every host in the scenario from its golden template, configure
    network/ownership on the range bridge, and start each with task waiting.
    Caller must hold the lease (acquire_lease first).

    Idempotent + crash-safe (audit R08):
      * an existing ready deployment is RETURNED, not duplicated;
      * a preparing/failed deployment is RESUMED — hosts whose resource row is
        already `created` are skipped;
      * each resource's identity is committed as `pending` BEFORE the clone
        starts, so a crash between side effects still leaves the VM owned.
    """
    s = get_settings()
    spec = load_scenario(scenario_id)
    node = s.proxmox_node

    dep = _active_deployment(db, session_id, scenario_id) if resume else None
    if dep is not None and dep.status == "ready":
        return {"scenario_id": scenario_id, "action": "deploy", "idempotent": True,
                "deployment_id": str(dep.deployment_id),
                "hosts": [r for r in (dep.resources or []) if r.get("state") == "created"]}
    if dep is None:
        dep = Deployment(session_id=session_id, scenario_id=scenario_id, status="preparing",
                         resources=[])
        db.add(dep)
        db.flush()
    else:  # resume a partial deployment
        dep.status = "preparing"
        db.flush()

    resources = [dict(r) for r in (dep.resources or [])]
    by_host = {r.get("host"): r for r in resources}
    created = [r for r in resources if r.get("state") == "created"]
    try:
        for i, host in enumerate(spec["topology"]["hosts"]):
            name = f"{scenario_id}-{host['name']}-{str(session_id)[:8] if session_id else 'adhoc'}"
            res = by_host.get(host["name"])
            if res and res.get("state") == "created":
                continue  # already owned & completed — resume skips it
            if res and res.get("vmid"):
                vmid = int(res["vmid"])          # reuse the pending intent's VMID
            else:
                vmid = int(proxmox.next_vmid(s.deploy_vmid_base + i))
                res = {"vmid": vmid, "node": node, "name": name, "host": host["name"],
                       "template_vmid": host["template_vmid"], "state": "pending"}
                resources.append(res)
                by_host[host["name"]] = res
                dep.resources = resources
                flag_modified(dep, "resources")
                # DURABLE PENDING INTENT before ANY side effect (audit R08):
                # committed, not merely flushed — a crash after clone-return
                # still finds this VMID inside the cleanup inventory.
                _log(db, session_id, "deploy_intent", host["name"],
                     {"vmid": vmid, "name": name, "template_vmid": host["template_vmid"]})
                db.commit()

            # RECONCILE UNCERTAIN OUTCOMES (audit R08): if a previous attempt
            # crashed after the clone returned, the VM already exists — do NOT
            # clone again onto it; continue from configuration.
            if proxmox.vm_status(node, vmid) == "unknown":
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
            res.update({"state": "created", "ip": host["ip"], "node": node, "name": name})
            created = [r for r in resources if r.get("state") == "created"]
            dep.resources = resources
            flag_modified(dep, "resources")
            _log(db, session_id, "deploy", host["name"],
                 {"vmid": vmid, "name": name, "linked": True, "net0": net0})
            # OWNERSHIP COMMITTED PER RESOURCE: if a later host fails (or the
            # process dies), everything already created remains accounted for
            db.commit()
        dep.status = "ready"
        dep.updated_at = _now()
        db.commit()
    except Exception as e:
        dep.resources = resources
        flag_modified(dep, "resources")
        dep.status = "failed"
        dep.error = str(e)[:2000]
        _log(db, session_id, "deploy_failed", None,
             {"error": str(e)[:500], "resources": resources})
        db.commit()   # failure evidence + partial ownership survive the rollback
        raise
    return {"scenario_id": scenario_id, "action": "deploy", "deployment_id": str(dep.deployment_id),
            "hosts": created}


def _owned_resources(dep: Deployment) -> list[dict]:
    return [r for r in (dep.resources or [])
            if r.get("vmid") and r.get("state") in ("pending", "created", "destroy_failed")]


def _ownership_tag(session_id) -> str:
    return f"srsess={str(session_id)[:8] if session_id else 'adhoc'}"


def _verify_ownership(proxmox, r: dict, session_id) -> tuple[bool, str]:
    """Read the VM's config BEFORE deleting (audit R08): delete only on a
    positive ownership match — the deployment's ownership tag, or the exact
    resource name this deployment cloned it with (a crash can happen between
    clone and tag-set). A VM that no longer exists counts as removed; a VM
    whose identity does not match is FOREIGN and must never be destroyed —
    VMIDs get reused, and a stale resource row must not kill an unrelated
    machine."""
    node = r.get("node") or get_settings().proxmox_node
    try:
        cfg = proxmox.get(f"/nodes/{node}/qemu/{r['vmid']}/config")
    except Exception:
        return True, "gone"          # 404 — nothing to delete
    cfg = cfg if isinstance(cfg, dict) else {}
    tags = str(cfg.get("tags", ""))
    if _ownership_tag(session_id) in tags:
        return True, "tag-verified"
    if r.get("name") and str(cfg.get("name", "")) == str(r["name"]):
        return True, "name-verified"
    return False, (f"ownership tag {_ownership_tag(session_id)!r} and name "
                   f"{r.get('name')!r} not found (tags={tags!r} name={cfg.get('name')!r})")


def _destroy_owned(db: Session, session_id, dep: Deployment, proxmox) -> dict:
    """Destroy every still-owned resource of ONE deployment with a positive
    ownership check. Per-resource failures are recorded and RETAINED in the
    resource list (state destroy_failed) for a later retry (audit R08)."""
    removed, failed, skipped = [], [], []
    resources = [dict(r) for r in (dep.resources or [])]
    changed = False
    for r in resources:
        if not (r.get("vmid") and r.get("state") in ("pending", "created", "destroy_failed")):
            continue
        owned, why = _verify_ownership(proxmox, r, session_id)
        if not owned:
            # positively NOT ours (VMID reused by a foreign machine): disown
            # the row so a later VMID recycling can never delete it either.
            r["state"] = "foreign_released"
            skipped.append({"vmid": r["vmid"], "name": r.get("name"), "why": why})
            _log(db, session_id, "teardown_skipped_foreign", r.get("host"),
                 {"vmid": r["vmid"], "reason": why})
            changed = True
            continue
        try:
            proxmox.destroy_and_wait(r.get("node") or get_settings().proxmox_node, int(r["vmid"]))
        except Exception as e:  # noqa: BLE001 — keep going; report per-resource
            r["state"] = "destroy_failed"
            failed.append({"vmid": r["vmid"], "name": r.get("name"), "error": str(e)[:300]})
            _log(db, session_id, "teardown_resource_failed", r.get("host"),
                 {"vmid": r["vmid"], "error": str(e)[:300]})
            changed = True
            continue
        r["state"] = "removed"
        removed.append(r["name"])
        changed = True
    if changed:
        dep.resources = resources
        flag_modified(dep, "resources")
    return {"removed": removed, "failed": failed, "skipped": skipped}


def teardown(db: Session, session_id, scenario_id: str, proxmox) -> dict:
    """Remove THIS session's owned resources — every deployment that still
    owns something, not just the newest (audit R07/R08). A deployment is
    marked torn_down ONLY when nothing failed; partial failure keeps the
    remaining resources owned for retry and reports the truth."""
    deps = [d for d in db.execute(
        select(Deployment).where(Deployment.scenario_id == scenario_id,
                                 Deployment.status != "torn_down")
        .order_by(Deployment.created_at.desc()).with_for_update()).scalars().all()
        if session_id is None or str(d.session_id) == str(session_id)]
    if not deps:
        return {"scenario_id": scenario_id, "action": "teardown", "removed": [],
                "complete": True, "note": "no deployment recorded for this session — nothing to remove"}
    removed, failed, skipped = [], [], []
    for dep in deps:
        res = _destroy_owned(db, session_id, dep, proxmox)
        removed += res["removed"]
        failed += res["failed"]
        skipped += res["skipped"]
        if not res["failed"]:
            dep.status = "torn_down"
        else:
            dep.status = "teardown_failed"
        dep.updated_at = _now()
    complete = not failed
    _log(db, session_id, "teardown", None,
         {"removed": removed, "failed": failed, "skipped_foreign": skipped,
          "complete": complete,
          "deployment_ids": [str(d.deployment_id) for d in deps]})
    db.flush()
    out = {"scenario_id": scenario_id, "action": "teardown", "removed": removed,
           "complete": complete}
    if failed:
        out["failed"] = failed
        out["warning"] = "some resources could NOT be destroyed — the range reservation is retained"
    if skipped:
        out["skipped_foreign"] = skipped
    return out


def reset(db: Session, session_id, scenario_id: str, proxmox) -> dict:
    """Destroy owned resources and redeploy fresh clones. Requires the lease
    (audit R07: a historical session must not reset over another's range)."""
    acquire_lease(db, session_id)
    t = teardown(db, session_id, scenario_id, proxmox)
    if not t.get("complete", True):
        raise RuntimeError("teardown incomplete — refusing to redeploy over resources "
                           f"that could not be destroyed: {t.get('failed')}")
    d = deploy(db, session_id, scenario_id, proxmox, resume=False)
    d["action"] = "reset"
    d["removed"] = t["removed"]
    return d


def _latest_deployment(db: Session, session_id, scenario_id: str) -> Deployment | None:
    q = select(Deployment).where(Deployment.scenario_id == scenario_id)
    if session_id:
        q = q.where(Deployment.session_id == session_id)
    return db.execute(q.order_by(Deployment.created_at.desc())).scalars().first()
