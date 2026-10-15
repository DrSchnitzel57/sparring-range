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
