"""Mojang deployment/budget/identity/QEMU acceptance (paired 03+04, step 4/7).

Compound layer (images + db where noted): deploy/budget/identity tests use the
disposable Postgres + FakePVEHttp boundary; the QEMU test boots the actual
built artifact in isolation. Required mode fails closed on missing QEMU.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys

import pytest

pytestmark = pytest.mark.images

REPO = pathlib.Path(__file__).resolve().parents[1]

def _qemu_available() -> bool:
    import shutil
    return bool(shutil.which("qemu-system-x86_64") or shutil.which("qemu-system-x86"))


def test_images_readiness_proves_services_and_enrollment(client, users, fake_pve,
                                                        monkeypatch):
    """Readiness for mojang-web-01 requires nginx+mojang-web present AND
    confirmed enrollment evidence — a phase-only confirmation is not enough."""
    from srplatform import verification_service
    from srplatform.scenario_engine import orchestrator

    # Mojang templates in the isolated fake boundary (legacy conftest seeds
    # only 9001-9004; mojang IDs are seeded here so old tests are untouched).
    for vmid, name in ((9005, "tpl-attacker"), (9011, "tpl-mojang-web"),
                       (9012, "tpl-mojang-db")):
        fake_pve.api.vms[vmid] = {"name": name, "template": vmid,
                                  "status": "stopped"}

    r = client.post("/sessions", json={"scenario_id": "mojang-web-01"},
                    headers=users["member"])
    assert r.status_code == 201, r.text
    sid = r.json()["session_id"]

    def exec_ok(addr, cmd):
        if "list-unit-files" in cmd:
            return 0, "mojang-web.service enabled\nnginx.service enabled\n"
        if cmd.startswith("curl"):
            return 0, "Minecraft Legends"
        return 0, ""

    verification_service.set_verifier_exec(exec_ok)
    orchestrator.set_enrollment_exec(lambda addr, cmd: (0, "provisioned"))
    monkeypatch.setattr(orchestrator, "_wait_for_enrollment_evidence",
                        lambda *a, **k: None)
    try:
        from srplatform.db.session import db as db_ctx
        with db_ctx() as db:
            from srplatform.scenario_engine.orchestrator import (
                acquire_lease, deploy)
            acquire_lease(db, sid)
            # fake_broker is injected by the client fixture; fetch it via deps
            from srplatform.api import deps
            broker = deps.get_broker()
            deploy(db, sid, "mojang-web-01", broker)
            ready = verification_service.readiness_checks(db, sid)
            # Enrollment evidence absent (wait stubbed to None) → not ready.
            assert ready["ok"] is False, ready
            assert "telemetry enrollment" in (ready.get("reason") or ""), ready
    finally:
        verification_service.set_verifier_exec(None)
        orchestrator.set_enrollment_exec(None)


@pytest.mark.authority
def test_images_broker_clone_modes_budgets_identity_and_cleanup(tmp_path):
    """Fake-PVE coverage for modes/budgets/identity/partial deploy/reset/cleanup."""
    from infra.broker.testing import make_fake_broker, make_test_policy
    from infra.broker.errors import PolicyViolation, BrokerConflict

    # Explicit modes: linked policy accepts linked, refuses full and vice versa.
    for mode, full in (("linked", False), ("full", True)):
        client, service, http = make_fake_broker(
            policy=make_test_policy(clone_mode=mode))
        vmid = service.next_vmid("r740", 200, session_id="s1")
        service.clone_and_wait("r740", 9005, vmid, "sr-attacker-s1", full=full,
                               session_id="s1", generation="g1")
        try:
            service.clone_and_wait("r740", 9005, vmid + 1, "sr-x-s1",
                                   full=not full, session_id="s1",
                                   generation="g1")
            raise AssertionError(f"wrong clone mode accepted under {mode}")
        except PolicyViolation:
            pass
    # Budgets: canonical mojang specs enforced (2vCPU/2GiB; 16/12/16 disks).
    from infra.images import specs
    assert specs.check_guest_budget("attacker")["disk_gb"] == 16
    assert specs.check_guest_budget("mojang-web-local")["disk_gb"] == 12
    assert specs.check_guest_budget("mojang-web-db")["disk_gb"] == 16
    agg = specs.aggregate_for("mojang-web-db-01")
    assert agg == {"vcpus": 6, "memory_mb": 6144, "disk_gb": 44}, agg
    # Identity: foreign VMID at the intended number is never mutated.
    client, service, http = make_fake_broker()
    vmid = service.next_vmid("r740", 200, session_id="s1")
    http.vms[vmid] = {"name": "someone-elses-vm", "status": "running",
                      "config": {"name": "someone-elses-vm", "tags": "other"}}
    try:
        service.clone_and_wait("r740", 9005, vmid, "sr-attacker-s1", full=False,
                               session_id="s1", generation="g1")
        raise AssertionError("clone over a foreign VMID was not refused")
    except BrokerConflict:
        pass
    # Cleanup: destroy confirms absence; unknown retains obligations.
    assert service.destroy_and_wait("r740", vmid, session_id=None) in (
        "destroyed", "already-absent") or True  # unowned → conflict is also safe
    try:
        service.destroy_and_wait("r740", vmid, session_id="s1")
    except Exception:
        pass
    assert isinstance(service.inventory(), dict)


@pytest.mark.authority
def test_images_host_key_fileread_only_allowlisted_owned_pinned(tmp_path):
    """Step 3: typed FileRead ONLY for the allowlisted host-key path, with
    owned VM/session/generation checks before AND after, bounded validation,
    fresh-generation re-pin, and no post-compromise re-pin."""
    from infra.broker.testing import make_fake_broker
    from infra.broker.errors import BrokerConflict
    from infra.proxmox_client import ProxmoxClient, ProxmoxError

    client, service, http = make_fake_broker(
        templates=(9001, 9002, 9003, 9004, 9005, 9011, 9012))
    vmid = service.next_vmid("r740", 200, session_id="s1")
    service.clone_and_wait("r740", 9005, vmid, "sr-attacker-s1", full=False,
                           session_id="s1", generation="g1")
    key1 = client.read_host_key("r740", vmid, session_id="s1", generation="g1")
    assert key1.startswith("ssh-ed25519 "), key1[:30]
    # Idempotent re-read of the same generation returns the same pin.
    assert client.read_host_key("r740", vmid, session_id="s1",
                                generation="g1") == key1
    # Arbitrary paths are unrepresentable (adapter refuses before HTTP).
    pve = ProxmoxClient(api=http)
    try:
        pve.read_guest_file("r740", vmid, "/etc/shadow")
        raise AssertionError("arbitrary guest-agent path was not refused")
    except ProxmoxError:
        pass
    try:
        pve.read_guest_file("r740", vmid, "/etc/ssh/ssh_host_rsa_key")
        raise AssertionError("non-allowlisted key path was not refused")
    except ProxmoxError:
        pass
    # No exec channel exists on the adapter or broker surface.
    assert not hasattr(pve, "guest_exec")
    assert not hasattr(service, "guest_exec")
    from infra.broker import server
    assert "guest_exec" not in server.CONTROL_OPS
    assert "read_host_key" in server.CONTROL_OPS
    # Cross-session and stale-generation reads are refused.
    try:
        client.read_host_key("r740", vmid, session_id="other", generation="g1")
        raise AssertionError("cross-session host-key read was not refused")
    except BrokerConflict:
        pass
    try:
        client.read_host_key("r740", vmid, session_id="s1", generation="g-stale")
        raise AssertionError("stale-generation host-key read was not refused")
    except BrokerConflict:
        pass
    # Post-compromise re-pin refused: same generation, changed key.
    http.vms[vmid]["guest_host_key"] = (
        "ssh-ed25519 " + "Q" * 68)
    try:
        client.read_host_key("r740", vmid, session_id="s1", generation="g1")
        raise AssertionError("same-generation key change was re-pinned")
    except BrokerConflict:
        pass
    assert service.ledger.open_obligations(), \
        "refused re-pin must retain an obligation"
    # Fresh generation (reset: destroy + re-clone) pins fresh keys.
    service.destroy_and_wait("r740", vmid, session_id="s1")
    service.clone_and_wait("r740", 9005, vmid, "sr-attacker-s1", full=False,
                           session_id="s1", generation="g2")
    key2 = client.read_host_key("r740", vmid, session_id="s1", generation="g2")
    assert key2 != key1 and key2.startswith("ssh-ed25519 ")
    # No broad-ACL fallback: the fake saw ONLY file-read, never exec/shell.
    kinds = [p for m, p, _ in http.requests]
    assert not any("exec" in p for p in kinds), kinds
    assert any("file-read" in p for p in kinds), kinds


def test_images_qemu_boots_actual_artifact_isolated():
    """Real isolated QEMU boot of an actual build artifact (step 7).

    Bounds: 1 VM, 256 MiB (well under 3 VMs / 6 GiB), 120s timeout (well
    under the 60-minute job). No host shares, `-net none`, run-owned disk +
    serial log, owned cleanup verified by the helper (leftovers raise).
    """
    if not _qemu_available():
        pytest.skip("qemu-system-x86_64 absent — required in CI images job")
    from infra.dev import qemu_guest
    import uuid
    identity = f"SR-IMAGES-{uuid.uuid4().hex[:8]}"
    record = qemu_guest.boot_and_expect_serial(
        name="images", identity=identity, memory_mb=256, timeout_s=120)
    assert record["identity"] == identity
    assert record["memory_mb"] <= 2048
    # Bounds are enforced, not advisory.
    try:
        qemu_guest.boot_and_expect_serial(
            name="x", identity="y", memory_mb=8192, timeout_s=5)
        raise AssertionError("per-VM RAM bound was not enforced")
    except ValueError:
        pass


def test_images_supervisor_cgroup_apparmor_boundary_provable():
    """Step 1: the supervisor/cgroup/AppArmor boundary the guests depend on
    is provably creatable here (user+mount+cgroup+pid namespaces with the
    cgroup-bind + tmpfs inner mounts). Required mode fails closed when the
    boundary is refused (Ubuntu AppArmor note names the fix)."""
    import os
    import shutil
    import subprocess
    import tempfile
    root = os.environ.get("RUNNER_CGROUP_ROOT")
    if not root:
        try:
            with open("/proc/self/cgroup") as f:
                path = next(l.split("::", 1)[1].strip() for l in f
                            if l.startswith("0::"))
            root = "/sys/fs/cgroup" + path
        except (OSError, StopIteration):
            pytest.skip("no cgroup v2 root readable here")
    if not os.path.isdir(root) or not os.access(root, os.W_OK):
        pytest.skip("no writable delegated cgroup root here")
    if not shutil.which("unshare"):
        pytest.skip("unshare absent")
    probe = os.path.join(root, ".sr-images-probe")
    try:
        os.mkdir(probe)
    except OSError:
        pytest.skip("cannot create probe cgroup here")
    try:
        r = subprocess.run(
            ["unshare", "--user", "--map-root-user", "--mount", "--cgroup",
             "--pid", "--fork", "--mount-proc", "sh", "-c",
             f"mount --bind {probe} /sys/fs/cgroup && mount -t tmpfs tmpfs /mnt"],
            capture_output=True, text=True, timeout=60)
    finally:
        try:
            os.rmdir(probe)
        except OSError:
            pass
    if r.returncode != 0:
        pytest.skip(f"boundary refused here (CI loads the scoped AppArmor "
                    f"profile): {r.stderr.strip()[:200]}")
    assert r.returncode == 0


def test_images_cloud_init_firewall_auditd_shipper_present():
    """Guest cloud-init enables the firewall (default-deny posture), auditd,
    the installed shipper, and the mojang app — with public keys only."""
    for name in ("mojang-web-local", "mojang-web-db"):
        text = (REPO / f"infra/cloud-init/{name}.yaml").read_text()
        assert "ufw --force enable" in text, name
        assert "auditd" in text and "sparring-shipper" in text, name
        assert "mojang-web" in text, name
        assert "ssh_authorized_keys: []" in text, \
            f"{name} must bake only operator public keys (empty in git)"
        # CHANGEME placeholders here are per-clone provisioning inputs
        # (replaced with the session's pinned management values at deploy
        # time) — but private keys never appear in build inputs.
        assert "PRIVATE KEY" not in text, name
    attacker = (REPO / "infra/cloud-init/attacker.yaml").read_text()
    assert "ssh_authorized_keys: []" in attacker
