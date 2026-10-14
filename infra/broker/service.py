"""Broker service — typed operations, durable intent, fail-closed cessation.

Every externally visible operation follows the same discipline:

  1. LATCH CHECK   — while cessation is latched, only stop/status/lease/
                     inventory operations proceed.
  2. POLICY CHECK  — node, template, bounded VMID, clone mode, exact NIC,
                     closed config keys, range-network provisioning, tag and
                     name shapes, aggregate capacity.
  3. LEDGER FIRST  — intent/claim recorded BEFORE the external side effect;
                     restart reconciles the ledger, never blindly replays.
  4. READ-BACK     — mutations are confirmed by reading reality afterwards
                     (task exit status, stopped/absent state), never by the
                     absence of an exception.

Cessation (hard_stop_all) persists the latch FIRST, then hard-stops every
owned VM including pending creations, continuing across failures and
retaining an obligation for anything it cannot confirm. The control lease
(5s heartbeat / 30s expiry) means a dead control plane stops the lab by
itself; a broker restart with active claims and an unverified lease latches
and stops before serving any request.
"""
from __future__ import annotations

import threading
import time
import uuid

from .errors import (BrokerConflict, BrokerLatched, BrokerRefused,
                     BrokerUnavailable, PolicyViolation)
from .ledger import Ledger, args_hash
from .policy import BrokerPolicy

MUTATING_OPS = frozenset({"next_vmid", "clone_and_wait", "set_config",
                          "start_and_wait", "destroy_and_wait", "enroll",
                          "renew_lease", "release_latch"})


class BrokerService:
    def __init__(self, policy: BrokerPolicy, pve, ledger: Ledger,
                 now=time.time, agent_ready_timeout_s: float = 120.0,
                 agent_ready_poll_s: float = 2.0):
        self.policy = policy
        self.pve = pve          # broker-private ProxmoxClient adapter
        self.ledger = ledger
        self.agent_ready_timeout_s = agent_ready_timeout_s
        self.agent_ready_poll_s = agent_ready_poll_s
        self._now = now
        self._op_lock = threading.RLock()
        self._watchdog: threading.Thread | None = None
        self._watch_stop = threading.Event()

    # ------------------------------------------------------------------ util ---
    def _require_unlatched(self, op: str) -> None:
        st = self.ledger.get_latch()
        if st["latched"]:
            raise BrokerLatched(f"cessation latched ({st['reason']}) — "
                                f"{op} refused; operator release required")

    def _check_session(self, claim: dict, session_id: str | None) -> None:
        if session_id is not None and claim.get("session_id") \
                and str(claim["session_id"]) != str(session_id):
            raise BrokerConflict(f"VMID {claim['vmid']} is owned by a different "
                                 "session generation — refusing cross-session mutation")

    def _active_claim(self, vmid: int, session_id: str | None = None) -> dict:
        claim = self.ledger.get_claim(vmid)
        if claim is None or claim["state"] == "destroyed":
            raise BrokerConflict(f"VMID {vmid} is not broker-owned — refusing to "
                                 "mutate a VM the ledger never claimed")
        self._check_session(claim, session_id)
        return claim

    def _node(self, node: str) -> str:
        self.policy.check_node(node)
        return node

    # ------------------------------------------------------------------ reads ---
    def lookup_vm(self, node: str, vmid: int):
        self._node(node)
        return self.pve.lookup_vm(node, int(vmid))

    def lookup_config(self, node: str, vmid: int):
        self._node(node)
        return self.pve.lookup_config(node, int(vmid))

    def try_lookup_config(self, node: str, vmid: int):
        self._node(node)
        return self.pve.try_lookup_config(node, int(vmid))

    def read_config(self, node: str, vmid: int) -> dict:
        """Typed replacement for a raw GET of the VM config endpoint."""
        self._node(node)
        cfg = self.pve.lookup_config(node, int(vmid))
        if cfg is None:
            raise BrokerRefused(f"VMID {vmid} has no readable config (absent)")
        if "_unavailable" in cfg:
            raise BrokerUnavailable(f"config read uncertain for VMID {vmid}: "
                                    f"{cfg['_unavailable']}")
        return cfg

    # ------------------------------------------------- guest host-key pin ---
    # Paired 03+04, step 3: initial typed guest-agent FileRead ONLY for the
    # fresh clone's PUBLIC SSH host key. The path is fixed by construction
    # (no caller-supplied path — arbitrary paths are unrepresentable), the
    # response is bounded/validated by the adapter, and ownership (claimed
    # VM/session/generation) is verified BEFORE and AFTER the read. Fresh
    # clone/reset generations pin fresh keys; a same-generation key change
    # (post-compromise re-pin attempt) is refused with an obligation retained.
    # Production requires the scoped `VM.GuestAgent.FileRead` privilege;
    # `VM.Monitor` / `VM.GuestAgent.Unrestricted` fallback is forbidden.
    def read_host_key(self, node: str, vmid: int, session_id: str | None = None,
                      generation: str | int = 1) -> str:
        from infra.proxmox_client import ProxmoxClient as _PC
        self._node(node)
        self.policy.check_vmid(int(vmid))
        with self._op_lock:
            claim = self._active_claim(int(vmid), session_id)
            if str(claim.get("generation", 1)) != str(generation):
                raise BrokerConflict(
                    f"VMID {vmid} is generation {claim.get('generation')!r}, "
                    f"not {generation!r} — refusing host-key read for a stale "
                    "generation")
            # Ownership verified BEFORE the read (claim) — now read the key.
            try:
                # First-boot reality (live find 2026-10-14): the agent needs
                # time after start; waiting here keeps the read a single
                # honest attempt instead of a certain-fail + obligation.
                self.pve.wait_agent_ready(node, int(vmid),
                                          timeout_s=self.agent_ready_timeout_s,
                                          poll_s=self.agent_ready_poll_s)
                key = self.pve.read_guest_file(node, int(vmid),
                                               _PC.GUEST_HOST_KEY_PATH)
            except Exception as e:  # noqa: BLE001 — uncertain, retain
                self.ledger.add_obligation("host-key-read-uncertain", int(vmid),
                                           str(e)[:300])
                self.ledger.audit("host-key-read-uncertain",
                                  {"vmid": int(vmid), "error": str(e)[:200]})
                from .errors import BrokerUnavailable as _BU
                raise _BU(f"host-key read uncertain for VMID {vmid}: {e}") from e
            # Verify ownership AFTER the read too (VMID recycled mid-read
            # must not pin a foreign machine's key).
            cfg = self.pve.try_lookup_config(node, int(vmid)) or {}
            if cfg.get("name") not in (None, claim.get("name")):
                self.ledger.add_obligation(
                    "host-key-foreign-identity", int(vmid),
                    f"claimed {claim.get('name')!r}, found {cfg.get('name')!r}")
                raise BrokerConflict(
                    f"VMID {vmid} identity changed during host-key read "
                    f"(claimed {claim.get('name')!r}, found {cfg.get('name')!r}) "
                    "— refusing to pin a possibly foreign key")
            detail = dict(claim.get("detail") or {})
            pinned = detail.get("host_key")
            pinned_gen = detail.get("host_key_generation")
            if pinned is not None and str(pinned_gen) == str(generation) \
                    and pinned != key:
                # Same generation, different key: possible compromise —
                # NEVER re-pin silently. Operator resolves.
                self.ledger.add_obligation(
                    "host-key-changed-same-generation", int(vmid),
                    "key changed without a new generation — refusing re-pin")
                raise BrokerConflict(
                    f"VMID {vmid} host key changed within generation "
                    f"{generation!r} — refusing post-compromise re-pin "
                    "(reset to a new generation for a fresh pin)")
            detail["host_key"] = key
            detail["host_key_generation"] = str(generation)
            self.ledger.upsert_claim(int(vmid), node=node, state=claim.get("state"),
                                     name=claim.get("name"),
                                     session_id=claim.get("session_id"),
                                     generation=claim.get("generation", generation),
                                     kind=claim.get("kind", "clone"),
                                     detail=detail)
            self.ledger.audit("host-key-pinned",
                              {"vmid": int(vmid), "generation": str(generation)})
            return key

    def vm_status(self, node: str, vmid: int) -> str:
        self._node(node)
        return self.pve.vm_status(node, int(vmid))

    def inventory(self) -> dict:
        return {"claims": self.ledger.all_claims(),
                "obligations": self.ledger.open_obligations(),
                "latch": self.ledger.get_latch(),
                "lease": self.ledger.get_lease(),
                "pending_intents": self.ledger.pending_intents()}

    def latch_status(self) -> dict:
        return self.ledger.get_latch()

    # -------------------------------------------------------------- allocate ---
    def next_vmid(self, node: str, start: int, session_id: str | None = None) -> int:
        self._require_unlatched("next_vmid")
        self._node(node)
        self.policy.check_vmid(int(start))
        with self._op_lock:
            self.policy.check_capacity(len(self.ledger.active_claims()))
            for candidate in range(max(int(start), self.policy.vmid_min),
                                   self.policy.vmid_max + 1):
                claim = self.ledger.get_claim(candidate)
                if claim is not None and claim["state"] != "destroyed":
                    continue
                if self.pve.lookup_vm(node, candidate) is not None:
                    continue
                self.ledger.upsert_claim(candidate, node=node, state="reserved",
                                         session_id=session_id,
                                         detail={"source": "next_vmid"})
                self.ledger.audit("reserve", {"vmid": candidate})
                return candidate
        raise BrokerRefused(f"no free VMID in [{max(int(start), self.policy.vmid_min)}, "
                            f"{self.policy.vmid_max}]")

    # ------------------------------------------------------------------ clone ---
    def clone_and_wait(self, node: str, template_vmid: int, new_vmid: int, name: str,
                       full: bool = False, session_id: str | None = None,
                       generation: str | int = 1) -> None:
        self._require_unlatched("clone_and_wait")
        self._node(node)
        self.policy.check_template(int(template_vmid))
        self.policy.check_vmid(int(new_vmid))
        self.policy.check_clone_mode(bool(full))
        self.policy.check_name(name)
        # The idempotency key is per DEPLOYMENT GENERATION: a reset creates a
        # new generation whose clone is a NEW intent even at the same VMID.
        key = (f"clone:{new_vmid}:{template_vmid}:{name}:{int(bool(full))}"
               f":{generation}")
        args = {"template": int(template_vmid), "name": name, "full": bool(full)}
        with self._op_lock:
            existing = self.ledger.get_claim(int(new_vmid))
            if existing and existing["state"] != "destroyed":
                self._check_session(existing, session_id)
                if existing["state"] in ("created", "enrolled") \
                        and existing.get("name") == name:
                    return  # ledger already confirms OUR clone — idempotent
                if existing["state"] not in ("reserved", "creating"):
                    raise BrokerConflict(f"VMID {new_vmid} is already claimed "
                                         f"({existing['state']}) — reconcile first")
            self.policy.check_capacity(len(self.ledger.active_claims()))
            state, _ = self.ledger.begin_intent(key, "clone", args)
            if state == "replay":
                return
            # 'execute' or 'pending' (a previous attempt died mid-effect):
            # RECONCILE against reality — never assume, never blind-replay.
            present = self.pve.lookup_vm(node, int(new_vmid))
            if present is not None:
                cfg = self.pve.try_lookup_config(node, int(new_vmid)) or {}
                if cfg.get("name") == name:
                    self._confirm_clone(node, int(new_vmid), name, session_id,
                                        generation, key, reconciled=True)
                    return
                raise BrokerConflict(
                    f"VMID {new_vmid} exists with foreign identity "
                    f"{cfg.get('name')!r} — refusing to clone over it")
            self.ledger.upsert_claim(int(new_vmid), node=node, name=name,
                                     session_id=session_id, generation=generation,
                                     state="creating")
            try:
                self.pve.clone_and_wait(node, int(template_vmid), int(new_vmid),
                                        name, full=bool(full))
            except Exception as e:  # noqa: BLE001 — outcome uncertain
                self.ledger.finish_intent(key, "failed")
                self.ledger.add_obligation("clone-outcome-unknown", int(new_vmid),
                                           f"clone raised: {e}")
                self.ledger.audit("clone-uncertain", {"vmid": int(new_vmid),
                                                      "error": str(e)})
                raise BrokerUnavailable(
                    f"clone of {name} onto {new_vmid} has an uncertain outcome: {e}") from e
            self._confirm_clone(node, int(new_vmid), name, session_id,
                                generation, key)

    def _confirm_clone(self, node: str, vmid: int, name: str, session_id,
                       generation: int, key: str, reconciled: bool = False) -> None:
        cfg = self.pve.try_lookup_config(node, vmid) or {}
        if cfg.get("name") != name:
            self.ledger.audit("clone-readback-mismatch",
                              {"vmid": vmid, "expected": name, "got": cfg.get("name")})
            self.ledger.add_obligation("clone-readback-mismatch", vmid,
                                       f"expected name {name!r}")
            raise BrokerUnavailable(
                f"clone read-back for VMID {vmid} does not show {name!r} — "
                "obligation retained")
        self.ledger.upsert_claim(vmid, node=node, name=name, session_id=session_id,
                                 generation=generation, state="created")
        self.ledger.finish_intent(key, "done", {"vmid": vmid, "name": name,
                                                "reconciled": reconciled})
        self.ledger.audit("clone-confirmed", {"vmid": vmid, "name": name})

    # ------------------------------------------------------------------ config ---
    def set_config(self, node: str, vmid: int, session_id: str | None = None,
                   **cfg) -> None:
        self._require_unlatched("set_config")
        self._node(node)
        self.policy.check_config_keys(cfg)
        if "net0" in cfg:
            self.policy.check_net0(cfg["net0"])
        if "ipconfig0" in cfg:
            self.policy.check_ipconfig(cfg["ipconfig0"])
        if "tags" in cfg:
            self.policy.check_tags(cfg["tags"])
        if "name" in cfg:
            self.policy.check_name(cfg["name"])
        with self._op_lock:
            self._active_claim(int(vmid), session_id)
            self.pve.set_config(node, int(vmid), **cfg)
            self.ledger.audit("set-config", {"vmid": int(vmid),
                                             "keys": sorted(cfg)})

    # ------------------------------------------------------------- start/stop ---
    def start_and_wait(self, node: str, vmid: int, timeout: int = 90,
                       session_id: str | None = None) -> None:
        self._require_unlatched("start_and_wait")
        self._node(node)
        with self._op_lock:
            self._active_claim(int(vmid), session_id)
            self.pve.start_and_wait(node, int(vmid), timeout=timeout)
        st = self.pve.vm_status(node, int(vmid))
        if st != "running":
            raise BrokerUnavailable(f"start read-back for VMID {vmid}: {st!r}, "
                                    "not 'running'")

    def stop(self, node: str, vmid: int, force: bool = False,
             session_id: str | None = None) -> str:
        """Cessation primitive — allowed while latched."""
        self._node(node)
        with self._op_lock:
            self._active_claim(int(vmid), session_id)
            return self.pve.stop(node, int(vmid), force=force)

    def stop_and_confirm(self, node: str, vmid: int, timeout: int = 60,
                         session_id: str | None = None) -> str:
        """Stop (kill), WAIT for the task, and READ BACK the state. Returns
        'stopped' | 'absent'; raises when unconfirmed (obligation retained).
        Only broker-owned VMIDs — cessation primitives still respect the
        ownership boundary so a stale caller cannot stop a foreign machine."""
        self._node(node)
        vmid = int(vmid)
        with self._op_lock:
            self._active_claim(vmid, session_id)
        status = self.pve.vm_status(node, vmid)
        if status in (None, "absent"):
            return "absent"
        if status != "stopped":
            upid = self.pve.stop(node, vmid, force=True)
            self.pve.wait_for_task(node, upid, timeout=timeout)
            status = self.pve.vm_status(node, vmid)
        if status == "stopped":
            return "stopped"
        if status in (None, "absent"):
            return "absent"
        raise BrokerUnavailable(f"VMID {vmid} read-back is {status!r}, not stopped")

    def destroy_and_wait(self, node: str, vmid: int, force_stop_timeout: int = 60,
                         session_id: str | None = None) -> str:
        self._require_unlatched("destroy_and_wait")
        self._node(node)
        vmid = int(vmid)
        with self._op_lock:
            self._active_claim(vmid, session_id)
            outcome = self.pve.destroy_and_wait(node, vmid,
                                                force_stop_timeout=force_stop_timeout)
            if outcome in ("destroyed", "already-absent"):
                self.ledger.upsert_claim(vmid, node=node, state="destroyed")
                self.ledger.audit("destroy-confirmed", {"vmid": vmid,
                                                        "outcome": outcome})
            return outcome

    def disown(self, node: str, vmid: int, session_id: str | None = None,
               reason: str = "") -> dict:
        """Release the broker's claim when the orchestrator has POSITIVELY
        established the resource is gone or foreign (confirmed-absent or
        foreign identity read-back). The broker never forgets silently: the
        claim transitions to 'destroyed' with the reason recorded."""
        self._node(node)
        with self._op_lock:
            claim = self.ledger.get_claim(int(vmid))
            if claim is None or claim["state"] == "destroyed":
                return {"disowned": int(vmid), "was": None}
            self._check_session(claim, session_id)
            self.ledger.upsert_claim(int(vmid), node=node, state="destroyed",
                                     name=claim.get("name"),
                                     session_id=claim.get("session_id"),
                                     generation=claim.get("generation", 1),
                                     kind=claim.get("kind", "clone"),
                                     detail={"disowned_reason": reason})
            self.ledger.audit("disown", {"vmid": int(vmid), "reason": reason})
            return {"disowned": int(vmid), "was": claim["state"]}

    # ------------------------------------------------------------- cessation ---
    def hard_stop_all(self, reason: str) -> dict:
        """Independent cessation: latch FIRST (durable), then hard-stop every
        owned VM — including pending creations — with task + stopped read-
        back, continuing across failures. Anything unconfirmed keeps an open
        obligation and an 'unknown' claim; this function never reports a
        blanket success it cannot substantiate.

        Identity guard: a claim whose VM reads back with a DIFFERENT name
        (VMID recycled out from under us) is NOT stopped — stopping a foreign
        machine is not cessation — it becomes an obligation for the operator.
        Unreadable identity inside our claimed VMID range stops anyway: the
        fail-closed direction is to stop."""
        self.ledger.set_latch(True, reason)
        self.ledger.audit("hard-stop-all", {"reason": reason})
        results = {"stopped": [], "already-stopped": [], "absent": [],
                   "foreign-retained": [], "failed": []}
        for claim in self.ledger.active_claims():
            vmid, node = int(claim["vmid"]), claim["node"]
            try:
                if claim.get("name"):
                    cfg = self.pve.try_lookup_config(node, vmid)
                    if (cfg and "_unavailable" not in cfg
                            and cfg.get("name") not in (None, claim["name"])):
                        results["foreign-retained"].append(
                            {"vmid": vmid, "claimed": claim["name"],
                             "found": cfg.get("name")})
                        self.ledger.upsert_claim(vmid, node=node, state="unknown",
                                                 name=claim.get("name"),
                                                 session_id=claim.get("session_id"),
                                                 generation=claim.get("generation", 1),
                                                 kind=claim.get("kind", "clone"),
                                                 detail={"foreign": cfg.get("name")})
                        self.ledger.add_obligation(
                            "vmid-recycled-no-stop", vmid,
                            f"claimed {claim['name']!r}, found {cfg.get('name')!r}")
                        continue
                status = self.pve.vm_status(node, vmid)
                if status in (None, "absent"):
                    results["absent"].append(vmid)
                    continue
                if status == "stopped":
                    results["already-stopped"].append(vmid)
                    continue
                upid = self.pve.stop(node, vmid, force=True)
                self.pve.wait_for_task(node, upid, timeout=60)
                status = self.pve.vm_status(node, vmid)
                if status in ("stopped", None, "absent"):
                    results["stopped"].append(vmid)
                else:
                    raise BrokerUnavailable(f"read-back {status!r}")
            except Exception as e:  # noqa: BLE001 — continue across failures
                results["failed"].append({"vmid": vmid, "error": str(e)})
                self.ledger.upsert_claim(vmid, node=node, state="unknown",
                                         name=claim.get("name"),
                                         session_id=claim.get("session_id"),
                                         generation=claim.get("generation", 1),
                                         kind=claim.get("kind", "clone"),
                                         detail={"stop_error": str(e)})
                self.ledger.add_obligation("vm-stop-unconfirmed", vmid, str(e))
        self.ledger.audit("hard-stop-all-result", results)
        return {"latched": True, "reason": reason, **results,
                "open_obligations": len(self.ledger.open_obligations())}

    # ------------------------------------------------------------------ lease ---
    def renew_lease(self, holder: str) -> dict:
        st = self.ledger.get_latch()
        if st["latched"]:
            raise BrokerLatched(f"cessation latched ({st['reason']}) — lease "
                                "renewal cannot resume a stopped range")
        return self.ledger.renew_lease(holder)

    def disarm_lease(self) -> None:
        self.ledger.disarm_lease()

    def check_lease(self) -> dict | None:
        """Watchdog tick: armed lease older than the TTL stops the range.
        Returns the hard_stop_all report when it fired, else None."""
        lease = self.ledger.get_lease()
        if not lease["armed"] or self.ledger.get_latch()["latched"]:
            return None
        age = self._now() - (lease["renewed_at"] or 0)
        if lease["renewed_at"] is None or age > self.policy.lease_ttl_s:
            return self.hard_stop_all(f"control-lease-expired (age {age:.0f}s)")
        return None

    def start_watchdog(self) -> None:
        if self._watchdog is not None:
            return
        self._watch_stop.clear()

        def loop() -> None:
            while not self._watch_stop.wait(self.policy.heartbeat_interval_s):
                try:
                    self.check_lease()
                except Exception:  # noqa: BLE001 — watchdog must not die
                    pass
        self._watchdog = threading.Thread(target=loop, name="broker-lease-watchdog",
                                          daemon=True)
        self._watchdog.start()

    def stop_watchdog(self) -> None:
        self._watch_stop.set()

    # --------------------------------------------------------------- startup ---
    def startup_reconcile(self) -> dict:
        """Fail-closed boot: pending intents are surfaced for reconciliation
        (never replayed); active claims with an unverified control lease
        latch and stop BEFORE the broker serves any request."""
        report = {"pending_intents": self.ledger.pending_intents(),
                  "latched": self.ledger.get_latch(), "stopped": None}
        for intent in report["pending_intents"]:
            self.ledger.audit("pending-intent-needs-reconciliation", intent)
        claims = self.ledger.active_claims()
        if claims and not self.ledger.get_latch()["latched"]:
            lease = self.ledger.get_lease()
            fresh = (lease["armed"] and lease["renewed_at"] is not None
                     and self._now() - lease["renewed_at"] <= self.policy.lease_ttl_s)
            if not fresh:
                report["stopped"] = self.hard_stop_all(
                    "broker-restart-unverified-control")
        report["latched"] = self.ledger.get_latch()
        return report

    # ------------------------------------------------------------- operator ---
    def release_latch(self, operator: str, note: str = "") -> dict:
        open_ob = self.ledger.open_obligations()
        if open_ob:
            raise BrokerConflict(
                f"{len(open_ob)} unresolved obligation(s) — resolve them "
                "(status/stop/reconcile) before releasing")
        self.ledger.set_latch(False)
        self.ledger.audit("release", {"operator": operator, "note": note})
        return {"released": True, "operator": operator}

    def enroll(self, vmid: int, name: str, tag: str, operator: str) -> dict:
        """Offline VERIFIED enrollment of an existing attacker VM: the PVE
        identity must match EXACTLY (name + ownership tag). No name/tag
        pattern auto-adoption, no guessing."""
        self._node(self.policy.node)
        self.policy.check_vmid(int(vmid))
        self.policy.check_name(name)
        self.policy.check_tags(tag)
        with self._op_lock:
            existing = self.ledger.get_claim(int(vmid))
            if existing and existing["state"] != "destroyed":
                raise BrokerConflict(f"VMID {vmid} already claimed "
                                     f"({existing['state']})")
            cfg = self.pve.try_lookup_config(self.policy.node, int(vmid))
            if cfg is None or "_unavailable" in (cfg or {}):
                raise BrokerUnavailable(
                    f"cannot read identity of VMID {vmid} — enrollment refused")
            tags = str(cfg.get("tags", ""))
            if cfg.get("name") != name or tag not in [t for t in
                                                      tags.replace(";", ";").split(";")]:
                raise BrokerConflict(
                    f"VMID {vmid} identity mismatch (name={cfg.get('name')!r}, "
                    f"tags={tags!r}) — refusing to adopt")
            self.policy.check_capacity(len(self.ledger.active_claims()))
            self.ledger.upsert_claim(int(vmid), node=self.policy.node, name=name,
                                     kind="enrolled", state="created",
                                     detail={"enrolled_by": operator})
            self.ledger.audit("enroll", {"vmid": int(vmid), "name": name,
                                         "operator": operator})
            return {"enrolled": int(vmid), "name": name}
