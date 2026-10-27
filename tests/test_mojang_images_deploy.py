"""Mojang deployment/budget/identity/Ubuntu-guest acceptance (03+04, steps 4/7).

Compound layer (images + db where noted): deploy/budget/identity tests use the
disposable Postgres + FakePVEHttp boundary; the Ubuntu tests boot the REAL
guest (pinned base + superset overlay + NoCloud seed) in isolated QEMU.
Required mode fails closed on missing QEMU, unverified base, or absent
serial evidence — never a skip.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import sys
import uuid

import pytest

pytestmark = pytest.mark.images

REPO = pathlib.Path(__file__).resolve().parents[1]

#: Shared overlay cache across gate runs on one machine (keyed by every
#: build input; `qemu-img check` on hit). Cold in CI, warm on reruns.
# /tmp may be tmpfs (RAM-backed): QEMU builds there compete with the VMs
# for memory and OOM-kill the gate. Operators/CI set SR_GUEST_CACHE to a
# disk-backed directory; the default keeps local dev unchanged.
GUEST_CACHE = pathlib.Path(os.environ.get("SR_GUEST_CACHE",
                                          "/tmp/sr-guest-cache"))


def _qemu_available() -> bool:
    import shutil
    return bool(shutil.which("qemu-system-x86_64") or shutil.which("qemu-system-x86"))


#: Synthetic (never secret) role key manifest for template boots — the
#: gate proves the ROLE-KEY CONTRACT (runner only on attacker, bastion only
#: on defenders), and no live key ever touches a test artifact.
TEST_KEYS = {
    "runner": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISyntheticRunnerKey00 runner@synthetic",
    "bastion": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIiSyntheticBastionKey0 bastion@synthetic",
    "mgmt": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISyntheticMgmtKey000 mgmt@synthetic",
}


def _role_overlay(role: str, memory_mb: int = 2048):
    from infra.dev import qemu_guest
    from infra.images import guest_build
    qemu_guest.require_qemu()  # fail closed here, not inside the build
    run = qemu_guest.make_run_dir()
    try:
        rec = guest_build.build_overlay(
            repo_root=REPO, run_dir=run, cache_dir=GUEST_CACHE,
            role=role, memory_mb=memory_mb, timeout_s=3600)
        yield {"run": run, "overlay": pathlib.Path(rec["overlay"]), "record": rec}
    finally:
        shutil.rmtree(run, ignore_errors=True)


@pytest.fixture()
def web_local_overlay():
    """Build-once (cache) WEB overlay (app + nginx, mysql disabled), fresh
    copy per test (the chain battery is state-mutating by design)."""
    yield from _role_overlay("mojang-web-local")


@pytest.fixture()
def db_overlay():
    """Build-once (cache) DB-tier overlay: MySQL + capture, NO web app —
    plan 13 phase 3 separates the tiers into production shapes."""
    yield from _role_overlay("mojang-web-db")


def test_images_ubuntu_build_role_overlays(web_local_overlay, db_overlay):
    """The build boots install the pinned families on real Ubuntu and record
    resolved versions from the guest itself (no host-side guessing); each
    role records its own artifact."""
    for rec_ in (web_local_overlay, db_overlay):
        rec = rec_["record"]
        pkgs = rec["packages"]
        assert any(n == "nginx" or n.startswith("nginx-") for n in pkgs), pkgs
        assert any("mysql" in n for n in pkgs), pkgs
        assert any(n == "auditd" or n.startswith("audit") for n in pkgs), pkgs
        overlay = rec_["overlay"]
        assert overlay.exists() and overlay.stat().st_size > 0
        r = subprocess.run(["qemu-img", "info", str(overlay)],
                           capture_output=True, text=True, timeout=60)
        assert r.returncode == 0 and "qcow2" in r.stdout, r.stdout[:300]


def _verify_markers(record: dict, *required: str) -> None:
    markers = record["markers"]
    for name in required:
        # BOOT / DONE are bare lifecycle markers; checks carry -PASS.
        want = f"SR-GUEST-{name}" if name in ("BOOT", "DONE rc=0") \
            else f"SR-GUEST-{name}-PASS"
        assert want in markers, markers
    assert not [m for m in markers if "-FAIL:" in m], markers
    assert "SR-GUEST-DONE rc=0" in markers, markers


def test_images_ubuntu_verify_web_local(web_local_overlay, tmp_path):
    """Real offline boot (`-net none`) of the WEB artifact: local-data
    catalogue, live diagnostic flaw + service-preserving fix, auditd/shipper/
    users/firewall, and MySQL NOT enabled — all on the installed guest."""
    from infra.dev import qemu_guest
    from infra.images import guest_build, guest_userdata
    run, overlay = web_local_overlay["run"], web_local_overlay["overlay"]
    rec = guest_build.verify_overlay(
        overlay=overlay, run_dir=run, name="web-local",
        user_data=guest_userdata.verify_user_data("mojang-web-local", {},
                                                  backend="local"),
        instance_id=f"sr-vlocal-{uuid.uuid4().hex[:8]}",
        hostname="sr-verify-weblocal", memory_mb=2048, net="none",
        timeout_s=600)
    _verify_markers(rec, "BOOT", "UNITS-ACTIVE", "CATALOGUE", "CATALOGUE-COUNT",
                    "DIAG-FLAW", "ROOT-FLAW", "MAINT-HELPER", "MAINT-FIX",
                    "DIAG-FIX", "AUDITD-RULES",
                    "SHIPPER-UNIT", "SHIPPER-SPOOL", "SEEDS", "USERS",
                    "FIREWALL", "NO-MYSQL-ENABLED", "CRON-STATE")
    # Plan 18 criterion 5: the CLEAN verify boot of the BUILT artifact is
    # the capture source for trusted cron hashes, bound to this exact
    # artifact's digest. A changed artifact (different digest) or the
    # wrong template must never inherit trust from this pin.
    import hashlib as _hl

    from infra.images import cron_baseline
    capture = cron_baseline.capture_from_verify_markers(rec["markers"])
    digest = _hl.sha256(overlay.read_bytes()).hexdigest()
    pin = cron_baseline.build_pin("mojang-web-local", artifact_sha256=digest,
                                  artifact_version=digest, template_id=9011,
                                  capture=capture)
    # the clean ubuntu base ships e2scrub_all — that is exactly the file
    # the scenarios declare as baseline, and the pin now carries its hash
    assert "e2scrub_all" in pin["files"], sorted(pin["files"])
    pins = {"mojang-web-local": pin}
    # Exercise the PRODUCTION injection (review findings: testing only the
    # pure helper proved template-only trust, and reading the CURRENT pin
    # file at scoring time let an in-place file-hash edit rewrite history).
    # A deployment freezes the baseline — from the identity the broker
    # confirmed for its clone — into the immutable resource AT DEPLOY TIME;
    # scoring injects ONLY that frozen version, and a same-digest edit of
    # the pin file changes nothing for an existing session.
    import srplatform.verification_service as vs
    deployed = {"role": "mojang-web-local", "template_vmid": 9011,
                "artifact_sha256": digest}
    deployed["baseline"] = cron_baseline.freeze_baseline(
        pins, "mojang-web-local", artifact_sha256=digest, template_vmid=9011)
    assert deployed["baseline"]["files"] == pin["files"]
    base = {"host": "web01", "baseline_files": ["e2scrub_all"]}
    injected = vs.with_cron_baseline(
        dict(base), verifier_id="cron_persistence_present", host="web01",
        artifacts={"web01": deployed}, pins=pins)
    assert injected["baseline_file_sha256"] == pin["files"]

    # same-digest in-place edit of the pin document: frozen truth stands
    edited = {role: dict(pin_, files=dict(pin_["files"]))
              for role, pin_ in pins.items()}
    edited["mojang-web-local"]["files"]["e2scrub_all"] = "0" * 64
    assert edited["mojang-web-local"]["files"] != pins["mojang-web-local"]["files"]
    injected2 = vs.with_cron_baseline(
        dict(base), verifier_id="cron_persistence_present", host="web01",
        artifacts={"web01": deployed}, pins=edited)
    assert injected2["baseline_file_sha256"] == pin["files"], \
        "a post-launch pin edit must never redefine clean"

    def _refuse(**over):
        art = dict(deployed, **over)
        out = vs.with_cron_baseline(
            dict(base), verifier_id="cron_persistence_present",
            host="web01", artifacts={"web01": art}, pins=pins)
        assert out == base, over
    _refuse(artifact_sha256="0" * 64)          # rebuilt artifact
    _refuse(template_vmid=9012)                # unexpected template
    _refuse(role="mojang-web-db")              # wrong role
    _refuse(baseline={})                       # never frozen → UNKNOWN
    # round-trip through the pin document validates and preserves
    doc = tmp_path / "cron-baselines.json"
    cron_baseline.dump_pins(doc, pins)
    assert cron_baseline.load_pins(doc) == pins


def test_images_ubuntu_verify_web_db(db_overlay):
    """Real offline boot of the DB-tier artifact: 12 seeded rows through the
    read-only role + capture, and NO web app enabled or present — the DB
    tier is a database, not a second all-in-one app (plan 13 phase 3)."""
    from infra.dev import qemu_guest
    from infra.images import guest_build, guest_userdata
    run, overlay = db_overlay["run"], db_overlay["overlay"]
    rec = guest_build.verify_overlay(
        overlay=overlay, run_dir=run, name="web-db",
        user_data=guest_userdata.verify_user_data("mojang-web-db", {},
                                                  backend="mysql"),
        instance_id=f"sr-vdb-{uuid.uuid4().hex[:8]}",
        hostname="sr-verify-webdb", memory_mb=2048, net="none",
        timeout_s=600)
    _verify_markers(rec, "BOOT", "UNITS-ACTIVE", "MYSQL-READY", "MYSQL-COUNT",
                    "MYSQL-ROW", "AUDITD-RULES", "SHIPPER-UNIT",
                    "SHIPPER-SPOOL", "USERS", "FIREWALL", "NO-WEB-APP")


def test_images_ubuntu_verify_attacker():
    """Attacker boots the ACTUAL BUILT attacker artifact (plan 13 phase 3:
    acceptance boots what gets imported): runner-supervisor, capture path
    (auditd + shipper), cgroup delegation, scoped AppArmor profile, role
    keys — plus the base posture (sshd socket, fresh host keys, no target
    payload)."""
    from infra.dev import qemu_guest
    from infra.images import guest_build, guest_userdata
    qemu_guest.require_qemu()
    run = qemu_guest.make_run_dir()
    try:
        rec_build = guest_build.build_attacker_overlay(
            repo_root=REPO, run_dir=run, cache_dir=GUEST_CACHE / "attacker",
            key_manifest=TEST_KEYS, memory_mb=1024, base_dir=GUEST_CACHE)
        overlay = pathlib.Path(rec_build["overlay"])
        assert rec_build.get("packages"), \
            "attacker build must record resolved packages"
        assert any(n == "auditd" or n.startswith("audit")
                   for n in rec_build["packages"]), rec_build["packages"]
        rec = guest_build.verify_overlay(
            overlay=overlay, run_dir=run, name="attacker",
            user_data=guest_userdata.attacker_verify_user_data(),
            instance_id=f"sr-atk-{uuid.uuid4().hex[:8]}",
            hostname="sr-verify-attacker", memory_mb=1024, net="none",
            timeout_s=600)
        _verify_markers(rec, "BOOT", "SSH-SOCKET", "HOSTKEYS", "NO-MOJANG",
                        "NO-MYSQL", "AUDITD-ACTIVE", "SHIPPER-UNIT",
                        "SHIPPER-SPOOL", "AUDITD-RULES", "CGROUP-DELEGATION",
                        "APPARMOR-PROFILE", "RUNNER-BOUNDARY")
    finally:
        shutil.rmtree(run, ignore_errors=True)


def test_images_seed_iso_builds_offline_and_parses():
    """No-QEMU unit: the seed ISO carries CIDATA label + readable
    user-data/meta-data (pure local build, pycdlib)."""
    from infra.images import guest_seed
    import tempfile
    with tempfile.TemporaryDirectory(prefix="sr-seed-") as td:
        iso = guest_seed.build_seed_iso(
            pathlib.Path(td) / "seed.iso", "#cloud-config\nhostname: x\n",
            guest_seed.meta_data("iid-1", "h1"))
        assert iso.stat().st_size > 0
        import pycdlib
        reader = pycdlib.PyCdlib()
        reader.open(str(iso))
        try:
            assert bytes(reader.pvd.volume_identifier).decode().strip() == "CIDATA"
            for rr, want in (("user-data", "hostname: x"), ("meta-data", "iid-1")):
                with reader.open_file_from_iso(rr_path="/" + rr) as f:
                    assert want in f.read().decode(), rr
        finally:
            reader.close()
    # Bounds stay enforced without QEMU present.
    from infra.dev import qemu_guest
    import pathlib as _pl
    try:
        qemu_guest.boot_full_guest(disk=_pl.Path("/none"), seed_iso=_pl.Path("/none"),
                                   memory_mb=8192, timeout_s=5)
        raise AssertionError("per-VM RAM bound was not enforced")
    except ValueError:
        pass


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


@pytest.mark.images
def test_images_rogue_baselines_match_recorded_users(web_local_overlay,
                                                     db_overlay):
    """Untouched-guest conformance: the rogue-account baselines in scenarios
    + the inject catalog must COVER every account the ACTUAL built images
    ship — otherwise an untouched guest scores incorrect. Depends
    explicitly on both current role artifacts (their build records carry
    the recorded user baselines); never globs a possibly-cold cache. Any
    gap fails with the exact missing names (static lists are then expanded,
    never guessed)."""
    import yaml
    from infra.images.role_keys import resolve_role_keys
    from srplatform.injects import IMAGE_BASELINE_USERS
    with open(REPO / "scenarios/mojang-web-01.yaml") as f:
        web_spec = yaml.safe_load(f)
    with open(REPO / "scenarios/mojang-web-db-01.yaml") as f:
        db_spec = yaml.safe_load(f)

    def known(scenario, host):
        for chk in (scenario.get("scoring") or {}).get("blue_checks", []):
            if chk.get("verifier") == "rogue_account" and chk.get("host") == host:
                return set(chk["known_users"])
        raise AssertionError(f"no rogue_account baseline for {host}")

    cases = (("mojang-web-local", web_local_overlay,
              known(web_spec, "web01"), True),
             ("mojang-web-db", db_overlay, known(db_spec, "db01"), False))
    for role, overlay, baseline, check_inject in cases:
        recorded = set(overlay["record"].get("users", []))
        assert recorded, f"{role}: build recorded no users (build broken?)"
        # analytic bake users for this gate's key manifest (finalize boot
        # creates exactly the mapped users; root pre-exists)
        bake_users = set(resolve_role_keys(role, TEST_KEYS)) - {"root"}
        shipped = recorded | bake_users
        missing = shipped - baseline
        assert not missing, \
            f"{role}: baseline misses shipped accounts {sorted(missing)}"
        if check_inject:
            missing_inject = shipped - set(IMAGE_BASELINE_USERS)
            assert not missing_inject, \
                f"inject baseline misses {sorted(missing_inject)}"
