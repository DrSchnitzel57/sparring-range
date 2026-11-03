"""Environment-scenario provisioning: blueprint guests through the broker.

Where the v1 lane clones flat single-NIC guests onto the range bridge, an
ENVIRONMENT scenario provisions a whole blueprint: every guest is cloned
from the artifact its `boot.image_profile` resolves to in the BROKER's
catalog (the operator manifest — never a path or vmid from scenario data),
and its COMPLETE effective NIC vector — every interface, in blueprint
index order — is applied through the broker's segment lane with
`expected_nics` authority:

  * nothing is cloned before EVERY profile resolves in the catalog
    (a missing profile must not leave a half-deployed lab);
  * each NIC's address is validated by broker policy against the segment
    at the SAME index (bridge A + segment-B address is refused), and after
    the effect every interface is read back from the ACTUAL domain XML;
  * the clone order follows the blueprint's dependency order, and each
    resource row is committed `pending` BEFORE its side effect, so a crash
    leaves durable ownership, never an unclaimed machine.

Host-key pinning and telemetry enrollment are v1 golden-image lanes; full-OS
blueprint guests (routers, firewalls, Windows) are recorded honestly with
`environment_guest: true` and stay outside those lanes until their own
attestation work lands.
"""
from __future__ import annotations

from sqlalchemy.orm import Session  # type: ignore
from sqlalchemy.orm.attributes import flag_modified

from srplatform.db.models import Deployment  # type: ignore
from srplatform.environment_specs import load_environment
from srplatform.scenario_engine.loader import ScenarioError
from srplatform.settings import get_settings


def plan_guest_nics(bp, guest) -> list[dict]:
    """The blueprint's effective NIC vector: [{segment, address}, ...] in
    domain NIC order. Every interface must carry a static planned address —
    DHCP/blueprint-lane addresses have no broker-side authority yet, and a
    plan that cannot say WHICH segment owns WHICH address cannot bind one."""
    plan: list[dict] = []
    for iface in guest.interfaces:
        addr = iface.ipv4.address if iface.ipv4 else None
        if not addr:
            raise ScenarioError(
                [f"environment guest {guest.name!r} interface on segment "
                 f"{iface.segment!r} has no static planned address — "
                 f"environment provisioning refuses to guess addressing"])
        plan.append({"segment": iface.segment, "address": str(addr)})
    return plan


def resolve_catalog(bp, broker, env_id: str) -> dict[str, dict]:
    """Map every blueprint image profile to the broker-catalogued template.
    Fails with EVERY missing profile named, before any side effect."""
    catalog_raw = broker.template_catalog()
    if not isinstance(catalog_raw, list) or not catalog_raw:
        raise ScenarioError(
            [f"broker supplied no template catalog — cannot resolve "
             f"environment {env_id!r} image profiles to approved artifacts; "
             f"no side effects were attempted"])
    catalog: dict[str, dict] = {}
    for entry in catalog_raw:
        if isinstance(entry, dict) and entry.get("profile"):
            catalog[str(entry["profile"])] = entry
    missing = sorted({g.boot.image_profile for g in bp.guests
                      if g.boot.image_profile not in catalog})
    if missing:
        raise ScenarioError(
            [f"environment {env_id!r} needs image profiles this appliance "
             f"cannot provide: {', '.join(missing)} — add them to the "
             f"operator image manifest or edit the blueprint; no clone was "
             f"attempted"])
    return catalog


def _clear_resource(res: dict) -> None:
    """Forget a destroyed guest's identity, but KEEP a generation attempt.

    Two broker facts found live (2026-11-03):
      * destroy releases the vmid, so it must be re-allocated (removed here);
      * clone_and_wait is idempotent per (vmid, template, name, generation),
        and the deployment id alone does NOT change on reset — the same
        clone intent was replayed as "already done" and set_config then hit
        a domain that did not exist ("VMID 210 has no appliance domain").
    Bumping the attempt makes the reset clone a genuinely NEW intent."""
    res["state"] = "pending"
    res["generation_attempt"] = int(res.get("generation_attempt") or 0) + 1
    for key in ("vmid", "ip", "domain_uuid", "applied_nics", "host_key",
                "deployed_artifact"):
        res.pop(key, None)


def reset_guests(db: Session, session_id, scenario_id: str, spec: dict,
                 broker, rebuild: set[str]) -> dict:
    """SELECTIVE reset: destroy and re-provision ONLY the planned guests;
    every preserved guest keeps its VM, disks and running services.

    Fail closed BEFORE any redeploy: a guest of the rebuild set whose
    ownership cannot be positively verified aborts with its resources
    retained — destroying a possibly-foreign machine would be worse than an
    incomplete reset. Guests in the set that were never created are simply
    (re)provisioned by the normal resume path.
    """
    from srplatform.scenario_engine import orchestrator as orch

    if not rebuild:
        raise RuntimeError("refusing an empty selective reset")
    env_id = str(spec["environment"])
    env = load_environment(env_id)
    bp = env.blueprint
    known = {g.name for g in bp.guests}
    unknown = sorted(set(rebuild) - known)
    if unknown:
        raise RuntimeError(
            f"planned guests are not in blueprint {env_id!r}: {unknown} — "
            f"refusing to reset against a plan the environment does not own")
    resolve_catalog(bp, broker, env_id)  # same preflight as a deploy
    dep = orch._active_deployment(db, session_id, scenario_id)
    if dep is None:
        raise RuntimeError(
            "no deployment on record for this lab session — nothing to reset "
            "against (unknown ownership is not reset success)")
    resources = [dict(r) for r in (dep.resources or [])]
    node = get_settings().deploy_node
    destroyed: list[str] = []
    for r in resources:
        if r.get("host") not in rebuild:
            continue
        if r.get("state") not in ("created", "destroy_failed"):
            continue  # never created: resume provisions it fresh
        if not r.get("vmid"):
            raise RuntimeError(f"resource for {r.get('host')!r} has no vmid")
        try:
            verdict, why = orch._verify_ownership(broker, r, session_id)
        except Exception as e:  # noqa: BLE001 — uncertain identity ABORTS
            raise RuntimeError(
                f"ownership of {r.get('host')!r} (vmid {r['vmid']}) could not "
                f"be verified: {str(e)[:300]} — resources retained") from e
        if verdict != "owned":
            raise RuntimeError(
                f"{r.get('host')!r} (vmid {r['vmid']}) is not this "
                f"deployment's resource ({verdict}: {why}) — refusing to "
                f"destroy what we do not provably own")
        rnode = r.get("node") or node
        try:
            broker.destroy_and_wait(rnode, int(r["vmid"]),
                                    session_id=session_id)
        except Exception as e:  # noqa: BLE001 — destroy failure is RETAINED
            r["state"] = "destroy_failed"
            dep.resources = resources
            flag_modified(dep, "resources")
            db.commit()
            raise RuntimeError(
                f"destroy of {r.get('host')!r} (vmid {r['vmid']}) failed: "
                f"{str(e)[:300]} — resource retained, redeploy NOT attempted "
                f"over unremoved machines") from e
        destroyed.append(str(r.get("host")))
        orch._log(db, session_id, "lab_reset_destroyed", r.get("host"),
                  {"vmid": r["vmid"]})
        # The rebuilt guest keeps its inventory ROW but loses its identity
        # (fresh vmid on resume; a bumped clone attempt so the broker does
        # not replay the old clone intent).
        _clear_resource(r)
        dep.resources = resources
        flag_modified(dep, "resources")
        db.commit()  # evidence per guest survives a later failure
    dep.status = "preparing"
    dep.resources = resources
    flag_modified(dep, "resources")
    db.commit()
    out = deploy_environment(db, session_id, scenario_id, spec, broker,
                             resume=True)
    out["action"] = "selective_reset"
    out["destroyed"] = sorted(destroyed)
    out["preserved_planned"] = sorted(known - set(rebuild))
    return out


def deploy_environment(db: Session, session_id, scenario_id: str, spec: dict,
                       broker, resume: bool = True) -> dict:
    """Provision (or resume) every blueprint guest. Same idempotence
    discipline as the v1 lane: ready deployment returns as-is; per-guest
    pending intents are durable before side effects; created rows skip."""
    s = get_settings()
    env_id = str(spec["environment"])
    env = load_environment(env_id)
    bp = env.blueprint
    node = s.deploy_node
    catalog = resolve_catalog(bp, broker, env_id)

    from srplatform.scenario_engine import orchestrator as orch

    # Domain names truncate the readable scenario+guest middle to fit the
    # 63-char backend limit, so two guests whose names collide WITHIN the
    # surviving prefix produce the SAME domain (libvirt "already exists")
    # and the deploy strands. Refuse BEFORE any side effect, exactly like
    # the catalog gate above (live commissioning find, 2026-11-02).
    names = [orch._vm_name(scenario_id, g.name, session_id) for g in bp.guests]
    if len(set(names)) != len(names):
        dupes = sorted({n for n in names if names.count(n) > 1})
        colliding = sorted(g.name for g, n in zip(bp.guests, names)
                           if n in dupes)
        raise ScenarioError(
            [f"environment {env_id!r} guests {colliding} collapse to the "
             f"same domain name(s) {dupes} under scenario "
             f"{scenario_id!r} — guest names must stay distinct within "
             f"the truncated prefix; no clone was attempted"])

    dep = orch._active_deployment(db, session_id, scenario_id) if resume else None
    if dep is not None and dep.status == "ready":
        resources = [dict(r) for r in (dep.resources or [])]
        return {"scenario_id": scenario_id, "action": "deploy",
                "idempotent": True,
                "deployment_id": str(dep.deployment_id),
                "hosts": [r for r in resources
                          if r.get("state") == "created"],
                "telemetry_enrollments": {}}
    if dep is None:
        dep = Deployment(session_id=session_id, scenario_id=scenario_id,
                         status="preparing", resources=[])
        db.add(dep)
        db.flush()
    else:
        dep.status = "preparing"
        db.flush()

    resources = [dict(r) for r in (dep.resources or [])]
    by_host = {r.get("host"): r for r in resources}
    try:
        for i, guest_name in enumerate(bp.provision_order()):
            guest = bp.guest(guest_name)
            plan = plan_guest_nics(bp, guest)
            profile = guest.boot.image_profile
            template_vmid = int(catalog[profile]["template_id"])
            name = orch._vm_name(scenario_id, guest.name, session_id)
            res = by_host.get(guest.name)
            if res and res.get("state") == "created":
                continue  # owned & NIC-verified earlier — resume skips
            if res and res.get("vmid"):
                vmid = int(res["vmid"])
            else:
                vmid = int(broker.next_vmid(node, s.deploy_vmid_base + i,
                                            session_id=session_id))
                res = {"vmid": vmid, "node": node, "name": name,
                       "host": guest.name, "template_vmid": template_vmid,
                       "image_profile": profile, "state": "pending",
                       "environment_guest": True,
                       "planned_nics": plan}
                resources.append(res)
                by_host[guest.name] = res
                dep.resources = resources
                flag_modified(dep, "resources")
                orch._log(db, session_id, "deploy_intent", guest.name,
                          {"vmid": vmid, "name": name, "profile": profile,
                           "template_vmid": template_vmid, "nics": plan})
                db.commit()

            # POSITIVE IDENTITY before mutation (same audit N01 rule as v1):
            # a pending VMID is an intention; a foreign machine there gets
            # no set-config/start call.
            exists = broker.lookup_vm(node, vmid)
            attempt = int(res.get("generation_attempt") or 0) if res else 0
            generation = str(dep.deployment_id) + (f":a{attempt}"
                                                   if attempt else "")
            if exists is None:
                broker.clone_and_wait(node, template_vmid, vmid, name,
                                      full=True, session_id=session_id,
                                      generation=generation)
            else:
                cfg = broker.try_lookup_config(node, vmid)
                if cfg is None or "_unavailable" in (cfg or {}):
                    raise RuntimeError(
                        f"cannot verify identity of VMID {vmid} (intended "
                        f"for {name}): { (cfg or {}).get('_unavailable', 'vanished between reads') }"
                        " — deployment aborted, intent retained")
                verdict, why = orch._classify_identity(cfg, res, session_id)
                if verdict != "owned":
                    from srplatform.scenario_engine.orchestrator import (  # noqa: E501
                        ForeignResourceError)
                    raise ForeignResourceError(
                        f"VMID {vmid} (intended for {name}) is not this "
                        f"deployment's resource — refusing to mutate: {why}")

            # THE NIC VECTOR: one call, whole plan; the broker derives each
            # bridge from its own segment lane, refuses the vector before
            # touching anything, and after the effect reads EVERY interface
            # back from the domain XML. A read-back disagreement retains an
            # obligation and raises — it is never retried into silence.
            broker.set_config(node, vmid,
                              name=name,
                              tags=orch._ownership_tag(session_id),
                              session_id=session_id,
                              expected_nics=plan)
            broker.start_and_wait(node, vmid, session_id=session_id)
            cfg2 = broker.lookup_config(node, vmid)
            domain_uuid = (cfg2 or {}).get("domain_uuid")
            seen_nics = (cfg2 or {}).get("nics") or []
            res.update({"state": "created", "ip": plan[0]["address"],
                        "node": node, "name": name,
                        "applied_nics": [
                            {"index": n.get("index"),
                             "segment": plan[int(n["index"])]["segment"],
                             "address": plan[int(n["index"])]["address"],
                             "mac": n.get("mac")}
                            for n in sorted(seen_nics,
                                            key=lambda n: int(n["index"]))]
                            if len(seen_nics) == len(plan) else None,
                        "host_key": "unenforced-environment-guest"})
            if domain_uuid:
                res["domain_uuid"] = domain_uuid
            art = broker.artifact_for_template(template_vmid)
            if isinstance(art, dict) and art.get("artifact_sha256"):
                res["deployed_artifact"] = art
            if (cfg2 or {}).get("_nic_drift"):
                res["state"] = "pending"
                dep.resources = resources
                flag_modified(dep, "resources")
                orch._log(db, session_id, "deploy_nic_drift", guest.name,
                          {"vmid": vmid, "drift": cfg2["_nic_drift"]})
                db.commit()
                raise RuntimeError(
                    f"VMID {vmid} ({name}) domain XML disagrees with the "
                    f"recorded NIC intent: {cfg2['_nic_drift']}")
            dep.resources = resources
            flag_modified(dep, "resources")
            orch._log(db, session_id, "deploy", guest.name,
                      {"vmid": vmid, "name": name, "profile": profile,
                       "template_vmid": template_vmid,
                       "nics": res.get("applied_nics")})
            db.commit()
    except Exception as exc:
        dep.resources = resources
        flag_modified(dep, "resources")
        dep.status = "failed"
        orch._log(db, session_id, "deploy_failed", scenario_id,
                  {"error": str(exc)[:400]})
        db.commit()
        raise

    dep.status = "ready"
    dep.resources = resources
    flag_modified(dep, "resources")
    db.commit()
    return {"scenario_id": scenario_id, "action": "deploy",
            "deployment_id": str(dep.deployment_id),
            "hosts": [r for r in resources if r.get("state") == "created"],
            "telemetry_enrollments": {}}
