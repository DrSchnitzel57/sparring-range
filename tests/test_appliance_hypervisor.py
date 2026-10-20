"""Real libvirt/KVM hypervisor acceptance (appliance milestone 14/15).

This layer is intentionally REQUIRED-mode honest: it boots an actual Ubuntu
guest through the production :class:`LibvirtBackend` and proves clone, start,
QGA readiness/host-key read-back, ownership identity, stop and destroy.  KVM is
used when available; software TCG is accepted only when the operator explicitly
sets ``SR_HYPERVISOR_ALLOW_TCG=1``, and the test reports which accelerator it
actually used.  A missing libvirt/QEMU/base image FAILS in required mode rather
than silently skipping.
"""
from __future__ import annotations

import hashlib
import os
import pathlib
import time

import pytest

from infra.appliance.backend import BackendConfig, LibvirtBackend
from infra.appliance.errors import BackendUnavailable
from infra.appliance.manifest import ApplianceManifest
from infra.appliance.policy import AppliancePolicy
from tests.test_appliance_install import _manifest as install_manifest

pytestmark = pytest.mark.hypervisor


def _require(condition: bool, message: str) -> None:
    if condition:
        return
    if os.environ.get("SR_REQUIRE_HYPERVISOR") == "1":
        pytest.fail(message)
    pytest.skip(message)


def _base_image() -> pathlib.Path:
    raw = os.environ.get("SR_APPLIANCE_BASE_IMAGE", "").strip()
    _require(bool(raw), "SR_APPLIANCE_BASE_IMAGE is required for the hypervisor "
             "gate (a bootable Ubuntu qcow2 with cloud-init and qemu-guest-agent)")
    p = pathlib.Path(raw)
    _require(p.is_file(), f"SR_APPLIANCE_BASE_IMAGE is not a file: {p}")
    return p


def _libvirt():
    try:
        import libvirt
        import libvirt_qemu  # noqa: F401
    except ImportError as exc:  # pragma: no cover - host prerequisite
        _require(False, f"libvirt Python bindings missing: {exc}")
        raise AssertionError("unreachable")
    return libvirt


def _raw_manifest(tmp_path: pathlib.Path, base: pathlib.Path) -> dict:
    raw = install_manifest(tmp_path)
    st = base.stat()
    h = hashlib.sha256()
    with base.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    raw["images"]["attacker"] = {
        "template_id": 9005,
        "path": str(base),
        "sha256": h.hexdigest(),
        "size_bytes": st.st_size,
        "disk_gb": 8,
        "memory_mb": 1536,
        "vcpus": 2,
    }
    # The unattended fixture image is larger than the synthetic images used by
    # the installer contract test; keep the manifest budget internally valid.
    raw["budgets"].update({"max_memory_mb": 8192, "max_vcpus": 6,
                           "max_disk_gb": 44})
    return raw


def test_real_libvirt_lifecycle_qga_ownership_and_destroy(tmp_path):
    _libvirt()
    base = _base_image()
    qemu_img = os.environ.get("SR_QEMU_IMG", "qemu-img")
    _require(bool(__import__("shutil").which(qemu_img)),
             f"{qemu_img} is required for the libvirt hypervisor gate")
    allow_tcg = os.environ.get("SR_HYPERVISOR_ALLOW_TCG") == "1"
    uri = os.environ.get("SR_HYPERVISOR_URI", "qemu:///session")
    raw = _raw_manifest(tmp_path, base)
    m = ApplianceManifest.from_dict(raw, verify_images=True)
    m.ensure_state_dirs()
    policy = AppliancePolicy.from_manifest(m)
    backend = LibvirtBackend(
        m, policy,
        BackendConfig(uri=uri, allow_tcg=allow_tcg, fixture_mode=True,
                      qemu_img=qemu_img))
    init = m.installation_id
    vmid = 210
    name = f"sr-hyp-{os.urandom(4).hex()}"
    started = time.monotonic()
    try:
        backend.clone_and_wait(init, 9005, vmid, name, full=True,
                               session_id="hypervisor-gate", generation=1)
        backend.set_config(init, vmid, ipconfig0="ip=10.66.0.210/24",
                           net0="virtio,bridge=srlab0",
                           tags="srsess-" + "a" * 32)
        backend.start_and_wait(init, vmid, timeout=60)
        assert backend.vm_status(init, vmid) == "running"

        got = backend.lookup_vm(init, vmid)
        assert got is not None and got["name"] == name
        cfg = backend.lookup_config(init, vmid)
        assert cfg["role"] == "attacker"
        assert cfg["session_id"] == "hypervisor-gate"
        assert cfg["generation"] == "1"
        owned = {d["vmid"] for d in backend.list_owned()}
        assert vmid in owned

        # Ownership is read back from the domain's appliance-owned record, not
        # inferred from a name.  A different installation must be refused.
        with pytest.raises(BackendUnavailable):
            backend.lookup_vm("different-installation", vmid)

        # A missing VMID is absent, never an exception or a fabricated success.
        assert backend.lookup_vm(init, 999) is None
        assert backend.vm_status(init, 999) == "absent"

        assert backend.read_boot_marker(init, vmid, timeout_s=600,
                                        poll_s=5) is True, (
            "the real guest never wrote the first-boot completion marker; "
            "serial=" + str(pathlib.Path(m.state_dir) / "guests" / str(vmid)
                            / "serial.log"))
        key = backend.read_guest_file_when_ready(
            init, vmid, backend.GUEST_HOST_KEY_PATH, timeout_s=120, poll_s=5)
        assert key and key.startswith(("ssh-ed25519 ", "ssh-rsa ")), key
        assert "PRIVATE KEY" not in key

        assert backend.stop(init, vmid, force=True) == "destroyed"
        assert backend.vm_status(init, vmid) == "stopped"
        assert backend.destroy_and_wait(init, vmid) == "destroyed"
        assert backend.lookup_vm(init, vmid) is None
        assert not (pathlib.Path(m.state_dir) / "guests" / str(vmid)).exists()
        # A repeated destroy of an already-absent VMID is an idempotent outcome,
        # not an invented success.
        assert backend.destroy_and_wait(init, vmid) == "already-absent"
        print("hypervisor accelerator:", backend.accelerator,
              "elapsed_s:", round(time.monotonic() - started, 1), flush=True)
    finally:
        try:
            backend.destroy_and_wait(init, vmid)
        except Exception:  # noqa: BLE001 - cleanup best-effort, assertion above
            pass
        backend.close()
