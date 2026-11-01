"""Isolated synthetic broker fixtures — acceptance/test/dev-fixture ONLY.

These build a REAL BrokerService (policy + ledger + typed operations) over
FakeBackend, an in-memory double implementing the broker's adapter contract
exactly as the production appliance backend does (lookup/clone/config/start/
stop/destroy, deterministic per-VMID NIC identity, and the two fixed
guest-agent reads).  Production configuration can never select this path:
the API requires broker_socket (or the legacy mutual-TLS broker_url) with
proper material in production (settings validation), and LocalTransport is
only constructed here or by tests.

The fake keeps the honesty invariants the broker's discipline depends on:
absence is ONLY ever a confirmed None, every failure is an UNCERTAIN raise,
config/identity read-back comes from the fake's own state (never from what
the caller claimed), and mutations become visible only when their "task"
completes.
"""
from __future__ import annotations

import hashlib
import re
import tempfile
import time
from pathlib import Path

from infra.appliance.errors import BackendUnavailable

from .client import BrokerClient, LocalTransport
from .ledger import Ledger
from .policy import BrokerPolicy
from .service import BrokerService

GUEST_HOST_KEY_PATH = "/etc/ssh/ssh_host_ed25519_key.pub"
_BOOT_MARKER = "/var/lib/sparring-range/first-boot-complete"

DEFAULT_TEST_POLICY = {
    "node": "r740",
    "templates": [9001, 9002, 9003, 9004, 9005, 9011, 9012],
    "vmid_range": [200, 999],
    "storage": ["local-zfs"],
    "clone_mode": "linked",
    "nic": {"bridge": "vmbr1", "vlan": 66},
    "provision": {"cidr": "10.66.0.0/24", "gateway": "10.66.0.1"},
    "name_prefix": "sr-",
    "limits": {"max_vms": 12, "cores_per_vm": 4, "memory_mb_per_vm": 8192,
               "disk_gb_per_vm": 48, "max_total_cores": 48,
               "max_total_memory_mb": 98304, "max_total_disk_gb": 512},
    "lease_ttl_s": 30,
    "heartbeat_interval_s": 5,
}

DEFAULT_TEMPLATES = (9001, 9002, 9003, 9004, 9005, 9011, 9012)


def _mac(seed: str) -> str:
    raw = hashlib.sha256(seed.encode()).digest()[:4]
    return "52:54:00:%02x:%02x:%02x" % (raw[0], raw[1], raw[2])


def _nic_mac(node: str, vmid: int, index: int) -> str:
    return _mac(f"{node}:{vmid}" if int(index) == 0 else f"{node}:{vmid}:{index}")


def _parse_bridge(net_spec: str) -> str:
    m = re.search(r"(?:^|,)bridge=([A-Za-z0-9._-]+)", net_spec or "")
    return m.group(1) if m else ""


class FakeBackend:
    """In-memory adapter double for the broker's typed backend contract.

    State is ``vms`` (vmid -> entry dict with name/status/template/config/
    guest_host_key/boot_completed).  Every public call is recorded in
    ``requests`` as (op, args).  Failure hooks:

      ``fail_reads``   dict {(op, vmid|None): Exception | int} — the call
                       raises (UNCERTAIN) before any effect, like an outage
                       or a permission denial at the hypervisor boundary.
      ``fail_tasks``   iterable of op names or (op, vmid|None) — the call's
                       effect/task phase fails: nothing changes state, the
                       outcome stays uncertain.
      ``task_polls_needed``  every task waits this many poll units before it
                       completes (widens race windows deterministically).
      ``agent_not_ready_polls`` / ``empty_key_polls``  first-boot guest-agent
                       windows: that many guest reads answer "no content
                       yet" before the marker/key materializes.

    ``agent_file_read`` is the single guest-agent hook (None = no content
    yet / agent silent, str = file content, raise = hard failure) — tests
    may replace it to script exact sequences.
    """

    GUEST_HOST_KEY_PATH = GUEST_HOST_KEY_PATH
    BOOT_MARKER_PATH = _BOOT_MARKER

    def __init__(self):
        self.vms: dict[int, dict] = {}
        self.requests: list[tuple[str, dict]] = []
        # failure hooks (kept deliberately blunt: they model "the boundary
        # said no", not protocol details)
        self.fail_reads: dict = {}
        self.fail_tasks = ()
        self.task_polls_needed = 0
        self.agent_not_ready_polls = 0
        self.empty_key_polls = 0
        # `.api` keeps the historical test handle onto the boundary object
        self.api = self

    # ------------------------------------------------------------------ util ---
    def _record(self, op: str, **args) -> None:
        self.requests.append((op, args))

    def _maybe_fail(self, op: str, vmid=None):
        """Immediate UNCERTAIN failure before any effect. The injected value
        may be an exception instance (raised as-is) or an int status."""
        for key, failure in list(self.fail_reads.items()):
            if not isinstance(key, tuple):
                key = (key, None)
            kop, kvmid = key
            if kop == op and (kvmid is None or (vmid is not None
                                                and int(kvmid) == int(vmid))):
                if isinstance(failure, BaseException):
                    raise failure
                raise BackendUnavailable(f"backend status {int(failure)}: "
                                         f"{op} refused for VMID {vmid}")

    def _maybe_fail_task(self, op: str, vmid=None) -> None:
        for key in tuple(self.fail_tasks):
            if not isinstance(key, tuple):
                key = (key, None)
            kop, kvmid = key
            if kop == op and (kvmid is None or (vmid is not None
                                                and int(kvmid) == int(vmid))):
                raise BackendUnavailable(
                    f"backend task for {op} VMID {vmid} failed (injected)")

    def _task_pause(self) -> None:
        if self.task_polls_needed:
            time.sleep(0.05 * int(self.task_polls_needed))

    def _entry(self, vmid: int) -> dict | None:
        return self.vms.get(int(vmid))

    # ---------------------------------------------------------------- reads ---
    def lookup_vm(self, node: str, vmid: int):
        self._record("lookup_vm", node=node, vmid=int(vmid))
        self._maybe_fail("lookup_vm", int(vmid))
        v = self._entry(vmid)
        if v is None:
            return None
        return {"vmid": int(vmid), "name": v.get("name") or "", "node": node,
                "state": v.get("status", "stopped"),
                "domain_uuid": f"fake-{vmid}"}

    def lookup_config(self, node: str, vmid: int) -> dict | None:
        self._record("lookup_config", node=node, vmid=int(vmid))
        self._maybe_fail("lookup_config", int(vmid))
        v = self._entry(vmid)
        if v is None:
            return None
        cfg = dict(v.get("config") or {})
        cfg.setdefault("name", v.get("name") or "")
        cfg.setdefault("ipconfig0", "")
        cfg.setdefault("tags", "")
        cfg["vmid"] = int(vmid)
        cfg["domain_uuid"] = f"fake-{vmid}"
        nics = v.get("nics")
        if nics:
            cfg["nics"] = [dict(n) for n in nics]
            for n in nics:
                cfg[f"net{n['index']}"] = f"virtio,bridge={n['bridge']}"
        return cfg

    def try_lookup_config(self, node: str, vmid: int) -> dict | None:
        try:
            return self.lookup_config(node, vmid)
        except Exception as exc:  # noqa: BLE001 — uncertain, never absence
            return {"_unavailable": str(exc)}

    def vm_status(self, node: str, vmid: int) -> str:
        self._record("vm_status", node=node, vmid=int(vmid))
        self._maybe_fail("vm_status", int(vmid))
        v = self._entry(vmid)
        if v is None:
            return "absent"
        return str(v.get("status", "stopped"))

    # ------------------------------------------------------------- lifecycle ---
    def clone_and_wait(self, node: str, template_vmid: int, new_vmid: int,
                       name: str, full: bool = True, **kwargs) -> None:
        self._record("clone_and_wait", node=node, template_vmid=int(template_vmid),
                     new_vmid=int(new_vmid), name=name, full=bool(full),
                     session_id=kwargs.get("session_id"),
                     generation=str(kwargs.get("generation", "1")))
        self._maybe_fail("clone_and_wait", int(new_vmid))
        if int(new_vmid) in self.vms:
            raise BackendUnavailable(f"VMID {new_vmid} already has a domain")
        self._maybe_fail_task("clone_and_wait", int(new_vmid))
        self._task_pause()
        # A fresh clone starts stopped with a FRESH synthetic host key: the
        # template's keys are scrubbed, so every clone regenerates its own
        # (never the template's, never reused across VMIDs).
        raw = hashlib.sha256(
            f"hostkey:{new_vmid}:{name}:{time.time_ns()}".encode()).digest()
        import base64
        key = "ssh-ed25519 " + base64.b64encode(raw + raw).decode()[:68]
        self.vms[int(new_vmid)] = {
            "name": name, "template": int(template_vmid), "status": "stopped",
            "config": {}, "guest_host_key": key, "boot_completed": True,
        }

    def set_config(self, node: str, vmid: int, **cfg) -> None:
        self._record("set_config", node=node, vmid=int(vmid), **cfg)
        self._maybe_fail("set_config", int(vmid))
        v = self._entry(vmid)
        if v is None:
            raise BackendUnavailable(f"VMID {vmid} has no domain")
        stored = v.setdefault("config", {})
        stored.update({k: str(val) for k, val in cfg.items()})
        nic_keys = sorted({
            int(m.group(1)) for key in cfg
            if (m := re.fullmatch(r"net(\d+)", key))})
        if nic_keys:
            nics = []
            for idx in range(max(nic_keys) + 1):
                key = f"net{idx}"
                bridge = ""
                if key in cfg:
                    bridge = _parse_bridge(str(cfg[key]))
                elif key in stored:
                    bridge = _parse_bridge(stored[key])
                if not bridge:
                    raise BackendUnavailable(
                        f"nic[{idx}] is not a closed 'virtio,bridge=X' spec")
                nics.append({"index": idx, "bridge": bridge,
                             "mac": _nic_mac(node, int(vmid), idx)})
            v["nics"] = nics

    def start_and_wait(self, node: str, vmid: int, timeout: int = 90) -> None:
        self._record("start_and_wait", node=node, vmid=int(vmid),
                     timeout=int(timeout))
        self._maybe_fail("start_and_wait", int(vmid))
        v = self._entry(vmid)
        if v is None:
            raise BackendUnavailable(f"VMID {vmid} has no domain")
        if v.get("status") == "running":
            return
        self._maybe_fail_task("start_and_wait", int(vmid))
        self._task_pause()
        v["status"] = "running"

    def stop(self, node: str, vmid: int, force: bool = False) -> str:
        self._record("stop", node=node, vmid=int(vmid), force=bool(force))
        self._maybe_fail("stop", int(vmid))
        v = self._entry(vmid)
        if v is None:
            return "already-absent"
        if v.get("status") != "running":
            return "already-stopped"
        self._maybe_fail_task("stop", int(vmid))
        self._task_pause()
        v["status"] = "stopped"
        return "stopped"

    def wait_for_task(self, node: str, token, timeout: int = 60) -> None:
        self._record("wait_for_task", node=node, token=str(token),
                     timeout=int(timeout))
        self._task_pause()

    def destroy_and_wait(self, node: str, vmid: int,
                         force_stop_timeout: int = 60) -> str:
        self._record("destroy_and_wait", node=node, vmid=int(vmid),
                     force_stop_timeout=int(force_stop_timeout))
        self._maybe_fail("destroy_and_wait", int(vmid))
        if self._entry(vmid) is None:
            return "already-absent"
        self._maybe_fail_task("destroy_and_wait", int(vmid))
        self._task_pause()
        self.vms.pop(int(vmid), None)
        return "destroyed"

    # ------------------------------------------------------------ guest agent ---
    def agent_file_read(self, node: str, vmid: int, path: str):
        """One guest-agent read: None = no content yet (agent silent or the
        fixed file not materialized), str = content, raise = hard failure.
        This is the scripted hook — tests may replace the bound method."""
        v = self._entry(vmid)
        if v is None:
            raise BackendUnavailable(f"VMID {vmid} has no domain")
        if self.agent_not_ready_polls > 0:
            self.agent_not_ready_polls -= 1
            return None
        if path == GUEST_HOST_KEY_PATH:
            if self.empty_key_polls > 0:
                self.empty_key_polls -= 1
                return None
            return str(v.get("guest_host_key") or "") or None
        if path == _BOOT_MARKER:
            return "" if v.get("boot_completed", True) else None
        raise BackendUnavailable(f"unlisted guest-agent path {path!r}")

    def read_boot_marker(self, node: str, vmid: int, timeout_s: float = 120.0,
                         poll_s: float = 2.0) -> bool:
        self._record("read_boot_marker", node=node, vmid=int(vmid))
        self._maybe_fail("read_boot_marker", int(vmid))
        deadline = time.monotonic() + max(0.0, float(timeout_s))
        while True:
            if self.agent_file_read(node, int(vmid), _BOOT_MARKER) is not None:
                return True
            if time.monotonic() >= deadline:
                return False
            time.sleep(max(0.05, min(float(poll_s),
                                     deadline - time.monotonic())))

    def read_guest_file_when_ready(self, node: str, vmid: int, path: str,
                                   timeout_s: float = 120.0,
                                   poll_s: float = 2.0) -> str | None:
        if path != GUEST_HOST_KEY_PATH:
            raise BackendUnavailable("only the fixed host-key path is readable")
        self._record("read_guest_file_when_ready", node=node, vmid=int(vmid))
        self._maybe_fail("read_guest_file_when_ready", int(vmid))
        deadline = time.monotonic() + max(0.0, float(timeout_s))
        while True:
            content = self.agent_file_read(node, int(vmid), path)
            if content:
                line = content.strip().splitlines()[0].strip()
                if line:
                    return line
            if time.monotonic() >= deadline:
                return None
            time.sleep(max(0.05, min(float(poll_s),
                                     deadline - time.monotonic())))


def policy_from_settings(s) -> BrokerPolicy:
    """Derive a synthetic fixture policy from (dev) settings so the fixture
    boundary matches the topology the scenarios provision."""
    raw = dict(DEFAULT_TEST_POLICY)
    raw["node"] = s.deploy_node
    raw["templates"] = sorted({s.template_vmid_web, s.template_vmid_win_dc,
                               s.template_vmid_win10, s.template_vmid_linux,
                               s.template_vmid_attacker, s.template_vmid_mojang_web,
                               s.template_vmid_mojang_db})
    raw["vmid_range"] = [s.deploy_vmid_base, s.deploy_vmid_base + 89]
    raw["nic"] = {"bridge": s.range_bridge, "vlan": s.range_vlan}
    raw["provision"] = {"cidr": s.range_cidr, "gateway": s.range_gateway}
    raw["clone_mode"] = getattr(s, "deploy_clone_mode", "linked")
    return BrokerPolicy.from_dict(raw)


def make_test_policy(**overrides) -> BrokerPolicy:
    raw = {**DEFAULT_TEST_POLICY, **overrides}
    return BrokerPolicy.from_dict(raw)


def make_broker_over(backend: FakeBackend, *, policy: BrokerPolicy,
                     ledger_path: str | Path | None = None,
                     now=None) -> tuple[BrokerClient, BrokerService]:
    """BrokerClient over an EXISTING FakeBackend (tests that build their own
    backend with seeded VMs / injected faults)."""
    if ledger_path is None:
        tmp = tempfile.mkdtemp(prefix="sr-broker-ledger-")
        ledger_path = Path(tmp) / "ledger.sqlite3"
    ledger = Ledger(ledger_path, **({"now": now} if now is not None else {}))
    kwargs = {"now": now} if now is not None else {}
    service = BrokerService(policy, backend, ledger, **kwargs)
    return BrokerClient(LocalTransport(service)), service


def reopen_broker(backend: FakeBackend, *, policy: BrokerPolicy,
                  ledger_path: str | Path,
                  now=None) -> tuple[BrokerClient, BrokerService]:
    """A broker RESTART: fresh service objects over the SAME ledger file and
    the SAME backend (what survives a real restart)."""
    return make_broker_over(backend, policy=policy, ledger_path=ledger_path,
                            now=now)


def make_fake_broker(*, policy: BrokerPolicy | None = None,
                     templates=None, vms: dict | None = None,
                     ledger_path: str | Path | None = None,
                     now=None) -> tuple[BrokerClient, BrokerService, FakeBackend]:
    """Returns (client, service, backend). The backend is the in-memory
    double BELOW the production service code, so every broker call runs the
    real ledger/policy/read-back discipline."""
    backend = FakeBackend()
    policy = policy or make_test_policy()
    for vmid in (templates if templates is not None else policy.templates):
        backend.vms[vmid] = {"name": f"tpl{vmid}", "template": vmid,
                             "status": "stopped"}
    if vms:
        for vmid, cfg in vms.items():
            backend.vms[int(vmid)] = dict(cfg)
    client, service = make_broker_over(backend, policy=policy,
                                       ledger_path=ledger_path, now=now)
    return client, service, backend
