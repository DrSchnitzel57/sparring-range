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

import uuid as uuidlib
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from infra.proxmox_client import PveUnavailable, ProxmoxError
from srplatform.db.models import (Deployment, Event, OperationClaim, RangeLease,
                                  ServiceToken,
                                  Session as SessionModel)
from srplatform.scenario_engine.loader import load_scenario
from srplatform.settings import get_settings


class LeaseConflict(RuntimeError):
    def __init__(self, holder_session_id, acquired_at):
        self.holder_session_id = str(holder_session_id) if holder_session_id else None
        self.acquired_at = acquired_at.isoformat() if acquired_at else None
        super().__init__(f"range is already reserved by session {self.holder_session_id}")


class OperationInProgress(RuntimeError):
    """A durable operation claim for this session is held by another request."""

    def __init__(self, session_id, operation, claimed_at):
        self.session_id, self.operation = str(session_id), operation
        self.claimed_at = claimed_at.isoformat() if claimed_at else None
        super().__init__(f"operation '{operation}' already in progress for session "
                         f"{self.session_id}")


class ForeignResourceError(RuntimeError):
    """A VMID we intended to use is positively occupied by a foreign machine."""


# ------------------------------------------------------------------ claims ---
# DURABLE OPERATION CLAIMS (audit N02): a normal row lock does NOT survive the
# intent commits that deployment correctness REQUIRES (acquire_lease/deploy
# commit per side effect). The claim is a committed row: it serializes
# launch/deploy/reset/teardown/end for one session ACROSS those commits.
# Crash recovery: claims older than the stale window may be taken over (with
# loud evidence), and API startup clears claims (single-API architecture —
# see docs/ARCHITECTURE_NOTES.md).
CLAIM_STALE_AFTER = timedelta(minutes=30)


def claim_operation(db: Session, session_id, operation: str,
                    stale_after: timedelta = CLAIM_STALE_AFTER) -> str:
    """Acquire the durable operation claim and return the OWNER TOKEN
    (audit T02). Release is fenced on this token: a request whose claim was
    taken over (stale window) can never delete the replacement's row."""
    owner = uuidlib.uuid4().hex
    now = _now()
    row = db.get(OperationClaim, session_id)
    if row is not None:
        age = (now - row.claimed_at) if row.claimed_at else None
        if age is not None and age < stale_after:
            raise OperationInProgress(session_id, row.operation, row.claimed_at)
        _log(db, session_id, "operation_claim_takeover", None,
             {"stale_operation": row.operation, "stale_claimed_at":
              row.claimed_at.isoformat() if row.claimed_at else None,
              "new_operation": operation})
        row.operation, row.claimed_at, row.owner = operation, now, owner
        db.commit()   # the claim must survive any later rollback
        return owner
    db.add(OperationClaim(session_id=session_id, operation=operation,
                          claimed_at=now, owner=owner))
    try:
        db.commit()   # durable BEFORE any side effect
    except IntegrityError:
        # concurrent claimer won the race — they hold the operation
        db.rollback()
        row = db.get(OperationClaim, session_id)
        raise OperationInProgress(session_id, row.operation if row else "?",
                                  row.claimed_at if row else None)
    return owner


def release_operation(db: Session, session_id, owner: str | None = None) -> bool:
    """Release the claim. WITH an owner token the delete is FENCED (audit T02):
    it only removes the row this request still owns — a stale request whose
    claim was taken over returns False and erases nothing. Without a token
    (startup reconciliation only) the row is removed unconditionally."""
    row = db.get(OperationClaim, session_id)
    if row is None:
        return False
    if owner is not None and row.owner != owner:
        return False   # someone else holds it now — never erase their ownership
    db.delete(row)
    db.commit()
    return True


def clear_operation_claims(db: Session) -> int:
    """API startup reconciliation: claims only have meaning while the single
    API process is alive; anything left over belongs to a dead request."""
    n = 0
    for row in db.execute(select(OperationClaim)).scalars().all():
        db.delete(row)
        n += 1
    db.commit()
    return n


def _now():
    return datetime.now(timezone.utc)


def _log(db: Session, session_id, action, host, payload):
    """Deployment actions are recorded in the append-only log. A failure here
    RAISES — silent loss of deployment evidence was itself an audit finding."""
    db.add(Event(session_id=session_id, ts=_now(), actor="system", host=host,
                 action_type=action, payload=payload))
    db.flush()


def _enroll_telemetry(db: Session, session_id, host: str) -> str:
    """Per-deployment telemetry enrollment (audit N09): each clone gets a
    session-AND-host-bound telemetry capability, issued at deploy time. The
    plaintext is returned ONCE (deploy response / provisioning); the inventory
    keeps only a reference. Revocation follows the session lifecycle — end,
    reset and teardown revoke every session capability including these (the
    same code path), so an old clone can never contribute events to a new
    session. Trust limit: events from a COMPROMISED host are evidence of what
    that host CLAIMED under a valid capability, not ground truth."""
    import uuid as _u
    token = f"svc-telemetry-{_u.uuid4().hex}"
    db.add(ServiceToken(token=token, scope="telemetry", session_id=session_id,
                        host=host))
    return token


def _token_ref(token: str) -> str:
    return f"...{token[-6:]}"


# ------------------------------------------------- telemetry enrollment (T05) --
# Token ISSUANCE is not enrollment. Each clone must be PROVISIONED with its
# session-bound capability through the management channel and the running
# service CONFIRMED, with the phase persisted per resource so an interrupted
# or lost-response provisioning resumes safely instead of re-issuing blindly.
#
# Phases: (none) -> pending_token -> provisioned -> confirmed
#         failure states: provision_failed / confirm_failed / unconfigured
_enrollment_exec = None  # fn(addr, command) -> (code, out); test/operator hook


def set_enrollment_exec(fn):
    """Test/operator hook: replace the enrollment provisioning channel."""
    global _enrollment_exec
    _enrollment_exec = fn


def enrollment_channel_available() -> bool:
    """Enrollment is ENFORCED when a provisioning channel exists: the
    explicit hook, or the real pinned-key SSH management channel (key +
    EXISTING known-hosts file). A verifier-READ override does not count —
    reading host state is not the same capability as writing it."""
    if _enrollment_exec is not None:
        return True
    import os
    s = get_settings()
    return bool(s.verifier_ssh_key_path and s.verifier_ssh_known_hosts
                and os.path.exists(s.verifier_ssh_known_hosts))


def _enrollment_channel():
    if _enrollment_exec is not None:
        return _enrollment_exec
    if enrollment_channel_available():
        from srplatform import verification_service
        return verification_service.management_exec
    return None


def _recover_telemetry_token(db: Session, session_id, host: str) -> str | None:
    """Recover the issued plaintext after a lost deployment response: the
    ServiceToken row IS the durable record (plaintext primary key), so a
    retry resumes enrollment for the SAME capability instead of issuing a
    second one."""
    return db.execute(select(ServiceToken.token)
                      .where(ServiceToken.session_id == session_id,
                             ServiceToken.host == host,
                             ServiceToken.scope == "telemetry",
                             ServiceToken.revoked_at.is_(None))
                      .order_by(ServiceToken.created_at.desc())).scalars().first()


def _provision_command(host: str, token: str, s) -> str:
    """The per-clone provisioning command the golden image's installer
    contract expects: write the REAL env file (no placeholders), restrict it
    to the service identity, and enable+restart the enrolled service."""
    import shlex
    env = (f"SR_API_URL={s.api_base_url}\n"
           f"SR_TELEMETRY_TOKEN={token}\n"
           f"SR_HOST={host}\n"
           f"SR_SPOOL_DIR=/var/lib/sparring-range/shipper\n")
    return ("install -d -m 0750 /etc/sparring-range && "
            f"printf '%s' {shlex.quote(env)} > /etc/sparring-range/shipper.env && "
            "chown root:srshipper /etc/sparring-range/shipper.env && "
            "chmod 0640 /etc/sparring-range/shipper.env && "
            "systemctl enable --now sparring-shipper && "
            "systemctl restart sparring-shipper")


def _enroll_host_telemetry(db: Session, dep: Deployment, res: dict, resources: list,
                           session_id, host_name: str, ip: str | None, s,
                           out: dict) -> str:
    """Drive ONE host's enrollment as far as the channel allows, committing
    the phase after every step (crash/lost-response resumes, never repeats
    token issuance). Returns the resulting phase."""
    enroll = dict(res.get("telemetry_enroll") or {})
    if enroll.get("phase") == "confirmed":
        return "confirmed"
    tok = _recover_telemetry_token(db, session_id, host_name)
    if tok is None:
        tok = _enroll_telemetry(db, session_id, host_name)
        res["telemetry_token_ref"] = _token_ref(tok)
        dep.resources = resources
        flag_modified(dep, "resources")
        db.commit()
    enroll = {"phase": "pending_token", "token_ref": _token_ref(tok)}
    out[host_name] = tok  # plaintext returned to the deployment response
    chan = _enrollment_channel()
    if chan is None or not ip:
        enroll["phase"] = "unconfigured"
        enroll["note"] = ("provisioning channel not configured — dev-mode "
                          "relaxation, visible in readiness")
        res["telemetry_enroll"] = enroll
        dep.resources = resources
        flag_modified(dep, "resources")
        db.commit()
        return "unconfigured"
    code, tail = chan(ip, _provision_command(host_name, tok, s))
    if code != 0:
        enroll.update(phase="provision_failed", error=str(tail)[:200])
        res["telemetry_enroll"] = enroll
        dep.resources = resources
        flag_modified(dep, "resources")
        db.commit()
        return "provision_failed"
    enroll.update(phase="provisioned", provisioned_at=_now().isoformat())
    res["telemetry_enroll"] = enroll
    dep.resources = resources
    flag_modified(dep, "resources")
    db.commit()
    code, tail = chan(ip, "systemctl is-active --quiet sparring-shipper")
    if code == 0:
        enroll.update(phase="confirmed", confirmed_at=_now().isoformat())
    else:
        enroll.update(phase="confirm_failed", error=str(tail)[:200])
    res["telemetry_enroll"] = enroll
    dep.resources = resources
    flag_modified(dep, "resources")
    db.commit()
    return enroll["phase"]


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
    # IMMUTABLE SNAPSHOT (audit T04): deployment provisions what the SESSION
    # captured at creation — the same specification the worker executes and
    # the verifier grades. Editing the source YAML after session creation
    # must not change deployed topology independently of the graded spec.
    if session_id is not None:
        from srplatform import verification_service
        spec = verification_service.scenario_spec(db, session_id)
    else:
        spec = load_scenario(scenario_id)
    node = s.proxmox_node

    dep = _active_deployment(db, session_id, scenario_id) if resume else None
    if dep is not None and dep.status == "ready":
        # Idempotent return — but enrollment may have been interrupted
        # (lost response / crashed provisioning): RESUME it, never silently
        # return a "ready" deployment whose clones are unenrolled.
        resources = [dict(r) for r in (dep.resources or [])]
        enrollments = {}
        for r in resources:
            if r.get("state") == "created" and \
                    (r.get("telemetry_enroll") or {}).get("phase") != "confirmed":
                _enroll_host_telemetry(db, dep, r, resources, session_id,
                                       r.get("host"), r.get("ip"), s, enrollments)
        return {"scenario_id": scenario_id, "action": "deploy", "idempotent": True,
                "deployment_id": str(dep.deployment_id),
                "hosts": [r for r in resources if r.get("state") == "created"],
                "telemetry_enrollments": enrollments}
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
    enrollments: dict[str, str] = {}  # host -> plaintext token (returned ONCE)
    try:
        for i, host in enumerate(spec["topology"]["hosts"]):
            name = _vm_name(scenario_id, host["name"], session_id)
            res = by_host.get(host["name"])
            if res and res.get("state") == "created":
                if (res.get("telemetry_enroll") or {}).get("phase") != "confirmed":
                    # resume path: finish interrupted enrollment (T05)
                    _enroll_host_telemetry(db, dep, res, resources, session_id,
                                           host["name"], res.get("ip"), s, enrollments)
                continue  # already owned & completed — resume skips the clone
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

            # RECONCILE + POSITIVELY IDENTIFY before ANY mutation (audit N01):
            # a pending VMID is an INTENTION, not proof that the VM currently
            # occupying that number belongs to this deployment. Uncertain
            # reads abort the deployment (intent retained); a foreign machine
            # at the intended VMID receives NO set-config/start/delete call.
            exists = proxmox.lookup_vm(node, vmid)   # raises when uncertain
            if exists is None:
                proxmox.clone_and_wait(node, int(host["template_vmid"]), vmid, name,
                                       full=False)
            else:
                # The VM exists at our intended VMID. Identity read failures
                # are UNCERTAIN — abort with the intent retained rather than
                # mutate a VM we cannot positively identify (audit N01). The
                # documented creation identity (exact clone name + full-session
                # ownership tag) governs once the read answers again.
                cfg = proxmox.try_lookup_config(node, vmid)
                if cfg is None:
                    pass  # vanished between reads — set_config will fail loudly
                elif "_unavailable" in (cfg or {}):
                    _log(db, session_id, "deploy_resume_identity_uncertain", host["name"],
                         {"vmid": vmid, "error": cfg["_unavailable"],
                          "note": "refusing to mutate a VM whose identity cannot "
                                  "be read; pending intent retained for retry"})
                    raise RuntimeError(
                        f"cannot verify identity of VMID {vmid} (intended for {name}): "
                        f"{cfg['_unavailable']} — deployment aborted, intent retained")
                else:
                    verdict, why = _classify_identity(cfg, res, session_id)
                    if verdict != "owned":
                        raise ForeignResourceError(
                            f"VMID {vmid} (intended for {name}) is not this deployment's "
                            f"resource — refusing to mutate it: {why}")
                    # CONFIG ROUND-TRIP PROBE before mutating (audit N01): the
                    # resume must not half-configure a VM whose config endpoint
                    # is failing — probe with the SAME request shape the
                    # mutation will use, then skip the mutation when it works.
                    try:
                        proxmox.post(f"/nodes/{node}/qemu/{vmid}/config",
                                     tags=_ownership_tag(session_id))
                    except Exception as e:  # noqa: BLE001
                        raise RuntimeError(
                            f"config endpoint failing for VMID {vmid} ({name}) — "
                            f"resume mutation aborted, intent retained: {e}") from e
                    # probe succeeded: finish placement (idempotent re-POST)
                    proxmox.set_config(node, vmid,
                                       ipconfig0=f"ip={host['ip']}/24,gw={s.range_gateway}",
                                       net0=_net_spec(s))
                    cfg2 = proxmox.lookup_config(node, vmid)
                    net0 = (cfg2 or {}).get("net0", "") if isinstance(cfg2, dict) else ""
                    if s.range_bridge not in net0:
                        raise RuntimeError(f"NIC placement validation failed on {name}: "
                                           f"net0={net0!r} does not use bridge {s.range_bridge}")
                    proxmox.start_and_wait(node, vmid)
                    res.update({"state": "created", "ip": host["ip"], "node": node,
                                "name": name})
                    _enroll_host_telemetry(db, dep, res, resources, session_id,
                                           host["name"], host["ip"], s, enrollments)
                    created = [r for r in resources if r.get("state") == "created"]
                    dep.resources = resources
                    flag_modified(dep, "resources")
                    _log(db, session_id, "deploy", host["name"],
                         {"vmid": vmid, "name": name, "linked": True, "net0": net0,
                          "resumed": True})
                    db.commit()
                    continue
            # network placement on the range bridge/VLAN + ownership tag (F06)
            proxmox.set_config(node, vmid,
                               ipconfig0=f"ip={host['ip']}/24,gw={s.range_gateway}",
                               net0=_net_spec(s),
                               tags=_ownership_tag(session_id))
            # validate NIC placement (read-back; ANY read failure — injected,
            # transport, 403 — aborts loudly, it is never treated as success)
            try:
                cfg = proxmox.get(f"/nodes/{node}/qemu/{vmid}/config")
            except Exception as e:  # noqa: BLE001
                raise RuntimeError(f"NIC placement validation could not read the config "
                                   f"of {name} (vmid {vmid}): {e}") from e
            net0 = (cfg or {}).get("net0", "") if isinstance(cfg, dict) else ""
            if s.range_bridge not in net0:
                raise RuntimeError(f"NIC placement validation failed on {name}: "
                                   f"net0={net0!r} does not use bridge {s.range_bridge}")
            proxmox.start_and_wait(node, vmid)
            res.update({"state": "created", "ip": host["ip"], "node": node, "name": name})
            _enroll_host_telemetry(db, dep, res, resources, session_id,
                                   host["name"], host["ip"], s, enrollments)
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
            "hosts": created, "telemetry_enrollments": enrollments}


def _owned_resources(dep: Deployment) -> list[dict]:
    return [r for r in (dep.resources or [])
            if r.get("vmid") and r.get("state") in ("pending", "created", "destroy_failed")]


def _sid(session_id) -> str:
    """FULL session identity (32 hex) — collision-resistant, unlike an 8-char
    prefix (audit N01)."""
    if session_id is None:
        return "adhoc"
    if isinstance(session_id, uuidlib.UUID):
        return session_id.hex
    return uuidlib.UUID(str(session_id)).hex


def _ownership_tag(session_id) -> str:
    """PVE-valid tag (pve-tag-list charset; '=' is rejected by real PVE) that
    carries the FULL session identity."""
    return f"srsess-{_sid(session_id)}"


def _vm_name(scenario_id: str, host_name: str, session_id) -> str:
    """Exact creation identity name: always ends with the full session id so
    two sessions can never produce the same name; PVE names are <= 63 chars,
    so the readable prefix is truncated, NEVER the identity suffix."""
    sid = _sid(session_id)
    prefix = f"{scenario_id}-{host_name}"
    max_prefix = 63 - 1 - len(sid)
    return f"{prefix[:max_prefix].strip('-')}-{sid}"


def _parse_tags(cfg: dict) -> set[str]:
    """EXACT parsed tag set (PVE ';'-separated list) — substring matching can
    be forged by a longer tag (audit N01)."""
    return {t.strip() for t in str((cfg or {}).get("tags", "")).split(";") if t.strip()}


def _classify_identity(cfg: dict, r: dict, session_id) -> tuple[str, str]:
    """Pure identity classification of a READ config dict (see
    _verify_ownership for the policy)."""
    if _ownership_tag(session_id) in _parse_tags(cfg):
        return "owned", "tag-verified"
    if r.get("name") and str(cfg.get("name", "")) == str(r["name"]):
        return "owned", "name-verified (clone-before-tag window)"
    return "foreign", (f"ownership tag {_ownership_tag(session_id)!r} and name "
                       f"{r.get('name')!r} not found (tags={cfg.get('tags')!r} "
                       f"name={cfg.get('name')!r})")


def _verify_ownership(proxmox, r: dict, session_id) -> tuple[str, str]:
    """Positively identify a resource BEFORE any mutation (audit N01).

    Returns (verdict, why) with verdict in:
      'owned'   — exact ownership tag OR exact creation-identity name match
                  (the name covers the documented clone-before-tag crash
                  window: the clone itself sets this exact name);
      'absent'  — PVE CONFIRMED 404 (idempotent removal, no delete needed);
      'foreign' — the VMID now belongs to someone else: never mutate it.

    Uncertain reads (timeout/403/500/transport) RAISE PveUnavailable — they
    are NOT absence and NEVER authorize a mutation.
    """
    node = r.get("node") or get_settings().proxmox_node
    cfg = proxmox.lookup_config(node, int(r["vmid"]))   # raises when uncertain
    if cfg is None:
        return "absent", "PVE confirms the resource does not exist"
    return _classify_identity(cfg, r, session_id)


def _destroy_owned(db: Session, session_id, dep: Deployment, proxmox) -> dict:
    """Destroy every still-owned resource of ONE deployment with a positive
    ownership check BEFORE any mutation (audit N01/N02):

      * uncertain identity read  -> resource RETAINED (state untouched),
        reported as failed -> teardown incomplete -> lease retained;
      * confirmed absent         -> idempotent bookkeeping, NO delete call;
      * foreign                  -> disowned, never mutated;
      * owned                    -> destroy; per-resource failures are
        recorded and RETAINED (destroy_failed) for a later retry.

    Every state change is COMMITTED per resource: a later failure or request
    rollback must not lose the evidence of what was already removed or what
    remains uncertain (audit N02 item 7)."""
    removed, failed, skipped = [], [], []
    resources = [dict(r) for r in (dep.resources or [])]
    for r in resources:
        if not (r.get("vmid") and r.get("state") in ("pending", "created", "destroy_failed")):
            continue
        node = r.get("node") or get_settings().proxmox_node
        try:
            verdict, why = _verify_ownership(proxmox, r, session_id)
        except PveUnavailable as e:
            # UNCERTAIN: keep the resource owned, keep the lease, tell the truth
            failed.append({"vmid": r["vmid"], "name": r.get("name"),
                           "error": f"identity read unavailable: {e}"[:300]})
            _log(db, session_id, "teardown_identity_unavailable", r.get("host"),
                 {"vmid": r["vmid"], "error": str(e)[:300]})
            dep.resources = resources
            flag_modified(dep, "resources")
            db.commit()   # evidence survives the request rollback
            continue
        if verdict == "absent":
            r["state"] = "removed"
            removed.append(r.get("name"))
            _log(db, session_id, "teardown_already_absent", r.get("host"),
                 {"vmid": r["vmid"], "note": "confirmed absent — no delete issued"})
        elif verdict == "foreign":
            # positively NOT ours (VMID reused): disown so a later recycling
            # can never delete it either.
            r["state"] = "foreign_released"
            skipped.append({"vmid": r["vmid"], "name": r.get("name"), "why": why})
            _log(db, session_id, "teardown_skipped_foreign", r.get("host"),
                 {"vmid": r["vmid"], "reason": why})
        else:
            try:
                outcome = proxmox.destroy_and_wait(node, int(r["vmid"]))
            except (PveUnavailable, ProxmoxError) as e:
                r["state"] = "destroy_failed"
                failed.append({"vmid": r["vmid"], "name": r.get("name"),
                               "error": str(e)[:300]})
                _log(db, session_id, "teardown_resource_failed", r.get("host"),
                     {"vmid": r["vmid"], "error": str(e)[:300]})
            else:
                r["state"] = "removed"
                removed.append(r.get("name"))
                _log(db, session_id, "teardown_resource", r.get("host"),
                     {"vmid": r["vmid"], "outcome": outcome})
        dep.resources = resources
        flag_modified(dep, "resources")
        db.commit()   # per-resource durable bookkeeping
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
    # DURABLE BOOKKEEPING (audit N02 item 7): the evidence of what was removed
    # and what remains uncertain must survive a later request rollback — an
    # incomplete teardown that "rolled back" would silently re-own nothing
    # while the machines still exist.
    db.commit()
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
