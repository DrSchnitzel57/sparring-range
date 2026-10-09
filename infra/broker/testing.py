"""Isolated synthetic broker fixtures — acceptance/test/dev-fixture ONLY.

These build a REAL BrokerService (policy + ledger + typed operations) over
the FakePVEHttp boundary at the proxmoxer level, so production call ordering,
task states, policy enforcement, and ledger behavior are exercised for real.
Production configuration can never select this path: the API requires
broker_url + mutual-TLS material in production (settings validation), and
LocalTransport is only constructed here or by tests.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from infra.proxmox_client import FakePVEHttp, ProxmoxClient

from .client import BrokerClient, LocalTransport
from .ledger import Ledger
from .policy import BrokerPolicy
from .service import BrokerService

DEFAULT_TEST_POLICY = {
    "node": "r740",
    "templates": [9001, 9002, 9003, 9004],
    "vmid_range": [200, 999],
    "storage": ["local-zfs"],
    "clone_mode": "linked",
    "nic": {"bridge": "vmbr1", "vlan": 66},
    "provision": {"cidr": "10.66.0.0/24", "gateway": "10.66.0.1"},
    "name_prefix": "",
    "limits": {"max_vms": 12, "cores_per_vm": 4, "memory_mb_per_vm": 8192,
               "disk_gb_per_vm": 48, "max_total_cores": 48,
               "max_total_memory_mb": 98304, "max_total_disk_gb": 512},
    "lease_ttl_s": 30,
    "heartbeat_interval_s": 5,
}

DEFAULT_TEMPLATES = (9001, 9002, 9003, 9004)


def policy_from_settings(s) -> BrokerPolicy:
    """Derive a synthetic fixture policy from (dev) settings so the fixture
    boundary matches the topology the scenarios provision."""
    raw = dict(DEFAULT_TEST_POLICY)
    raw["node"] = s.proxmox_node
    raw["templates"] = sorted({s.template_vmid_web, s.template_vmid_win_dc,
                               s.template_vmid_win10, s.template_vmid_linux})
    raw["vmid_range"] = [s.deploy_vmid_base, s.deploy_vmid_base + 89]
    raw["nic"] = {"bridge": s.range_bridge, "vlan": s.range_vlan}
    raw["provision"] = {"cidr": s.range_cidr, "gateway": s.range_gateway}
    return BrokerPolicy.from_dict(raw)


def make_test_policy(**overrides) -> BrokerPolicy:
    raw = {**DEFAULT_TEST_POLICY, **overrides}
    return BrokerPolicy.from_dict(raw)


def make_broker_over(http: FakePVEHttp, *, policy: BrokerPolicy,
                     ledger_path: str | Path | None = None,
                     now=None) -> tuple[BrokerClient, BrokerService]:
    """BrokerClient over an EXISTING FakePVEHttp (tests that build their own
    fake with seeded VMs / injected faults)."""
    pve = ProxmoxClient(api=http)
    if ledger_path is None:
        tmp = tempfile.mkdtemp(prefix="sr-broker-ledger-")
        ledger_path = Path(tmp) / "ledger.sqlite3"
    ledger = Ledger(ledger_path, **({"now": now} if now is not None else {}))
    kwargs = {"now": now} if now is not None else {}
    service = BrokerService(policy, pve, ledger, **kwargs)
    return BrokerClient(LocalTransport(service)), service


def reopen_broker(http: FakePVEHttp, *, policy: BrokerPolicy,
                  ledger_path: str | Path,
                  now=None) -> tuple[BrokerClient, BrokerService]:
    """A broker RESTART: fresh service objects over the SAME ledger file and
    the SAME PVE boundary (what survives a real restart)."""
    return make_broker_over(http, policy=policy, ledger_path=ledger_path, now=now)


def make_fake_broker(*, policy: BrokerPolicy | None = None,
                     templates=None, vms: dict | None = None,
                     ledger_path: str | Path | None = None,
                     now=None) -> tuple[BrokerClient, BrokerService, FakePVEHttp]:
    """Returns (client, service, fake_http). The fake sits at the proxmoxer
    boundary BELOW the production adapter, so every broker call runs the
    real ProxmoxClient task-waiting code."""
    http = FakePVEHttp()
    policy = policy or make_test_policy()
    for vmid in (templates if templates is not None else policy.templates):
        http.vms[vmid] = {"name": f"tpl{vmid}", "template": vmid, "status": "stopped"}
    if vms:
        for vmid, cfg in vms.items():
            http.vms[int(vmid)] = dict(cfg)
    pve = ProxmoxClient(api=http)
    if ledger_path is None:
        tmp = tempfile.mkdtemp(prefix="sr-broker-ledger-")
        ledger_path = Path(tmp) / "ledger.sqlite3"
    ledger = Ledger(ledger_path, **({"now": now} if now is not None else {}))
    kwargs = {"now": now} if now is not None else {}
    service = BrokerService(policy, pve, ledger, **kwargs)
    return BrokerClient(LocalTransport(service)), service, http
