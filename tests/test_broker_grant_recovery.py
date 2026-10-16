"""Live find 2026-10-15: PVE deletes per-VMID ACL entries when it destroys
the VM, so each teardown silently eats the window grants its clones used
and the next scan dies on a 403 that used to surface as a raw 500 chain.
The scan must fail with the re-apply named, not a mystery."""
from __future__ import annotations

import pytest

from infra.broker.errors import BrokerUnavailable
from infra.broker.testing import make_fake_broker, make_test_policy
from infra.proxmox_client import PveUnavailable

NODE = "r740"


def test_next_vmid_denial_names_the_acl_reapply(tmp_path):
    policy = make_test_policy()
    client, service, http = make_fake_broker(
        policy=policy, ledger_path=tmp_path / "l.sqlite3")

    def denied(node, vmid):
        raise PveUnavailable(
            "PVE status 403: 403 Forbidden: Permission check failed "
            f"(/vms/{vmid}, VM.Audit)")

    service.pve.lookup_vm = denied
    with pytest.raises(BrokerUnavailable, match=r"pve_broker_acl\.sh --apply"):
        client.next_vmid(NODE, 210, session_id="s")


def _reserved_client(tmp_path, reads):
    from infra.broker.testing import make_fake_broker, make_test_policy
    policy = make_test_policy()
    client, service, http = make_fake_broker(
        policy=policy, ledger_path=tmp_path / "l4.sqlite3")
    service.agent_ready_poll_s = 0
    it = iter(reads)

    def scripted(node, vmid, path, timeout_s=None, poll_s=None):
        try:
            return next(it)
        except StopIteration:
            return reads[-1]

    service.pve.read_guest_file_when_ready = scripted
    vmid = client.next_vmid("r740", 210, session_id="s")
    http.vms.setdefault(vmid, {"status": "stopped", "name": None})
    return client, service, vmid


def test_pin_waits_out_first_boot_regen(tmp_path):
    client, service, vmid = _reserved_client(
        tmp_path, ["ssh-ed25519 AAAA", "ssh-ed25519 BBBB", "ssh-ed25519 BBBB"])
    key = service.read_host_key("r740", vmid, session_id="s")
    assert key == "ssh-ed25519 BBBB"


def test_pin_skips_empty_reads(tmp_path):
    client, service, vmid = _reserved_client(
        tmp_path, ["", "ssh-ed25519 CCCC", "ssh-ed25519 CCCC"])
    assert service.read_host_key("r740", vmid, session_id="s") == "ssh-ed25519 CCCC"


def test_ever_rotating_key_is_refused_loudly(tmp_path):
    from infra.broker.errors import BrokerUnavailable
    client, service, vmid = _reserved_client(
        tmp_path, ["ssh-ed25519 A", "ssh-ed25519 B", "ssh-ed25519 C",
                   "ssh-ed25519 D", "ssh-ed25519 E"])
    import pytest
    with pytest.raises(BrokerUnavailable, match="never stabilized"):
        service.read_host_key("r740", vmid, session_id="s")


def test_pin_waits_for_boot_completion(tmp_path):
    """Keys readable before first boot completes must not pin: the marker
    gate precedes even the stability reads."""
    from infra.broker.errors import BrokerUnavailable
    from infra.broker.testing import make_fake_broker, make_test_policy
    import pytest
    policy = make_test_policy()
    client, service, http = make_fake_broker(
        policy=policy, ledger_path=tmp_path / "l5.sqlite3")
    service.agent_ready_poll_s = 0
    service.agent_ready_timeout_s = 0
    vmid = client.next_vmid("r740", 210, session_id="s")
    http.vms.setdefault(vmid, {"status": "stopped", "name": None})
    http.vms[vmid]["boot_completed"] = False
    with pytest.raises(BrokerUnavailable, match="never finished"):
        service.read_host_key("r740", vmid, session_id="s")
    http.vms[vmid]["boot_completed"] = True
    key = service.read_host_key("r740", vmid, session_id="s")
    assert key.startswith("ssh-ed25519 ")
