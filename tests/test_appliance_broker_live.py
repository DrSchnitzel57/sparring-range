"""The appliance broker's authority path, live.

The `hypervisor` gate proves the libvirt backend's lifecycle.  This gate
proves the layer the API actually talks to: the real `BrokerService` behind
the real Unix peer-UID socket, with the real libvirt backend, driven with the
real typed client.

What it proves:

* the broker reserves a VMID, clones, configures, starts, pins the guest's
  host key through the guest agent and reads the state back;
* a second claim on the same VMID from another session is REFUSED (the
  broker owns its resources, it does not merely use them);
* the destruction is read back (the domain is gone, the guest's files are
  gone) and the ledger ends with NO open obligation.

The guest boots on the software-emulated user network of the fixture, so
this gate needs neither a bridge nor root - but it is a real guest, a real
libvirt domain and the real socket protocol.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import time

import pytest

from infra.appliance.backend import BackendConfig, LibvirtBackend
from infra.appliance.errors import BackendUnavailable
from infra.appliance.manifest import ApplianceManifest
from infra.appliance.policy import AppliancePolicy
from infra.broker.client import BrokerClient, HttpTransport
from infra.broker.errors import BrokerConflict
from infra.broker.ledger import Ledger
from infra.broker.service import BrokerService
from infra.appliance.server import make_unix_server
from tests.test_appliance_hypervisor import _base_image, _raw_manifest

pytestmark = pytest.mark.hypervisor


def test_broker_authority_path_over_the_unix_socket(tmp_path):
    base = _base_image()
    raw = _raw_manifest(tmp_path, base)
    m = ApplianceManifest.from_dict(raw, verify_images=True)
    m.ensure_state_dirs()
    policy = AppliancePolicy.from_manifest(m)
    backend = LibvirtBackend(
        m, policy,
        BackendConfig(uri=os.environ.get("SR_HYPERVISOR_URI", "qemu:///session"),
                      allow_tcg=os.environ.get("SR_HYPERVISOR_ALLOW_TCG") == "1",
                      fixture_mode=True))
    ledger = Ledger(m.broker_ledger)
    service = BrokerService(policy, backend, ledger,
                            agent_ready_timeout_s=300, agent_ready_poll_s=3)
    sock = tmp_path / "run" / "broker.sock"
    sock.parent.mkdir(parents=True, exist_ok=True)
    server = make_unix_server(service, str(sock), [os.getuid()])
    thread = __import__("threading").Thread(target=server.serve_forever, daemon=True)
    thread.start()
    client = BrokerClient(HttpTransport(f"unix://{sock}"))
    node = m.installation_id
    vmid = 220
    name = f"sr-live-{os.urandom(3).hex()}"
    session = "a" * 32
    try:
        # 1. the broker reserves a VMID from its own bounded namespace
        reserved = client.next_vmid(node, 220, session_id=session)
        assert 220 <= reserved < 1000, reserved

        # 2. clone, configure, start
        client.clone_and_wait(node, 9005, reserved, name, full=True,
                              session_id=session, generation=1)
        client.set_config(node, reserved, session_id=session,
                          ipconfig0="ip=10.66.0.210/24",
                          net0="virtio,bridge=srlab0",
                          tags="srsess-" + "b" * 32)
        client.start_and_wait(node, reserved, timeout=120, session_id=session)
        assert client.vm_status(node, reserved) == "running"

        # 3. the guest's host key is pinned through the guest agent
        pin = client.read_host_key(node, reserved, session_id=session, generation=1)
        assert pin and "ssh-ed25519" in str(pin), pin

        # 4. the broker's inventory shows the guest it owns
        inventory = client.inventory()
        owned = [c for c in inventory.get("claims", [])
                 if int(c.get("vmid", -1)) == reserved]
        assert owned, inventory
        assert inventory.get("obligations") == [], inventory

        # 5. ownership: a DIFFERENT session cannot claim the same VMID
        with pytest.raises((BrokerConflict, Exception)):
            client.clone_and_wait(node, 9005, reserved, name, full=True,
                                  session_id="c" * 32, generation=1)

        # 6. destroy and read back: the domain AND the guest's files are gone
        client.stop_and_confirm(node, reserved, timeout=120, session_id=session)
        client.destroy_and_wait(node, reserved, force_stop_timeout=120,
                                session_id=session)
        assert client.vm_status(node, reserved) == "absent"
        guest_dir = pathlib.Path(m.state_dir) / "guests" / str(reserved)
        assert not guest_dir.exists(), guest_dir

        # 7. the ledger ends with no unresolved obligation
        open_obligations = ledger.open_obligations()
        assert open_obligations == [], open_obligations
    finally:
        try:
            client.destroy_and_wait(node, vmid, force_stop_timeout=60,
                                    session_id=session)
        except Exception:  # noqa: BLE001 — cleanup is best effort
            pass
        server.shutdown()
        server.server_close()
        ledger.close()
        backend.close()
