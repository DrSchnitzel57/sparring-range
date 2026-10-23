"""Appliance contract tests — strict manifest, policy and fixed artifacts.

These are infrastructure-free: they prove the fail-closed input boundary
before a single root-owned service or libvirt connection exists.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess

import pytest

from infra.appliance.manifest import ApplianceManifest
from infra.appliance.netrules import render_networkd, render_nftables
from infra.appliance.policy import AppliancePolicy
from infra.appliance.seed import SeedInputs, build_seed, render_user_data
from infra.broker.errors import PolicyViolation


def _key(tmp_path: pathlib.Path, name: str) -> pathlib.Path:
    path = tmp_path / f"{name}.pub"
    if not path.exists():
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                        "-C", f"sr-test-{name}", "-f", str(tmp_path / name)],
                       check=True, capture_output=True)
    return path


def _manifest(tmp_path: pathlib.Path, *, verify_files: bool = True) -> dict:
    images = {}
    for role, tid, size in (("attacker", 9005, 11),
                            ("mojang-web-local", 9011, 12),
                            ("mojang-web-db", 9012, 10)):
        p = tmp_path / f"{role}.qcow2"
        p.write_bytes((role + "-image").encode())
        images[role] = {
            "template_id": tid, "path": str(p),
            "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
            "size_bytes": p.stat().st_size, "disk_gb": size,
            "memory_mb": 2048, "vcpus": 2,
        }
    keys = {name: str(_key(tmp_path, name))
            for name in ("runner", "bastion", "mgmt")}
    (tmp_path / "model.key").write_text("test-model-key\n")
    return {
        "schema_version": 1,
        "installation_id": "4f0e7a1c-8a59-4a4e-9b5d-74f0e7a1c111",
        "appliance": {"hostname": "sr-appliance", "timezone": "UTC"},
        "network": {
            "lan_cidr": "10.10.10.0/24", "lan_address": "10.10.10.50",
            "range_cidr": "10.66.0.0/24", "range_bridge": "srlab0",
            "range_gateway": "10.66.0.1", "controller_range_ip": "10.66.0.1",
            "bastion_address": "10.66.0.2", "ingest_address": "10.66.0.1",
            "ingest_port": 8443, "management_cidr": "10.0.0.0/24",
        },
        "urls": {"public": "https://sr.example.edu", "internal":
                 "http://127.0.0.1:8000", "ingest":
                 "https://10.66.0.2:8443"},
        "broker": {
            "socket": str(tmp_path / "run/broker.sock"),
            "ledger": str(tmp_path / "state/ledger.sqlite3"),
            "state_dir": str(tmp_path / "state"),
        },
        "paths": {"images": str(tmp_path), "recordings": str(tmp_path / "rec"),
                  "secrets": str(tmp_path / "secrets")},
        "images": images,
        "access_keys": keys,
        "model": {"base_url": "http://127.0.0.1:8001/v1",
                  "alias": "sr-test-model",
                  "api_key_file": str(tmp_path / "model.key")},
        "budgets": {"max_guests": 6, "max_vcpus": 12, "max_memory_mb": 12288,
                    "max_disk_gb": 44, "min_free_gb": 20},
        "backup": {"enabled": False, "destination": ""},
    }


def test_manifest_loads_and_redacts(tmp_path):
    m = ApplianceManifest.from_dict(_manifest(tmp_path), verify_images=True)
    assert m.installation_id.endswith("c111")
    assert m.image_for_role("attacker").template_id == 9005
    assert m.public_key_for("runner").startswith("ssh-ed25519 ")
    view = m.redacted()
    assert "access_keys" not in json.dumps(view)
    assert view["range_bridge"] == "srlab0"
    assert view["images"]["attacker"]["sha256"]


def test_broker_manifest_never_accesses_model_secret(tmp_path, monkeypatch):
    raw = _manifest(tmp_path)
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(raw))
    model_key = pathlib.Path(raw["model"]["api_key_file"])
    original_stat = pathlib.Path.stat

    def deny_secret_stat(self, *args, **kwargs):
        if self == model_key:
            raise PermissionError("model secret belongs to another service")
        return original_stat(self, *args, **kwargs)

    monkeypatch.setattr(pathlib.Path, "stat", deny_secret_stat)
    with pytest.raises(PermissionError, match="another service"):
        ApplianceManifest.load(path, verify_images=True)
    m = ApplianceManifest.load(path, verify_images=True, verify_model_key=False)
    assert m.model_api_key_file == str(model_key)

    # The actual daemon must use this role-specific boundary too. Stop after
    # manifest loading so this regression needs no libvirt or service secrets.
    from infra.appliance import brokerd

    def reached_policy(*args, **kwargs):
        raise RuntimeError("reached policy validation")

    monkeypatch.setattr(brokerd.AppliancePolicy, "load", reached_policy)
    with pytest.raises(RuntimeError, match="reached policy validation"):
        brokerd.build(str(path), "unused", uri="qemu:///system",
                      allow_tcg=False, fixture=False)

    raw["images"]["attacker"]["sha256"] = "0" * 64
    path.write_text(json.dumps(raw))
    with pytest.raises(Exception, match="sha256 mismatch"):
        brokerd.build(str(path), "unused", uri="qemu:///system",
                      allow_tcg=False, fixture=False)


def test_broker_manifest_still_rejects_private_public_key(tmp_path):
    raw = _manifest(tmp_path)
    raw["access_keys"]["runner"] = str(tmp_path / "runner")
    with pytest.raises(Exception, match="PUBLIC key"):
        ApplianceManifest.from_dict(raw, verify_model_key=False)


def test_operator_manifest_still_requires_model_credential(tmp_path):
    raw = _manifest(tmp_path)
    pathlib.Path(raw["model"]["api_key_file"]).write_text("")
    with pytest.raises(Exception, match="model.api_key_file is empty"):
        ApplianceManifest.from_dict(raw)


def test_system_qemu_storage_acl_is_scoped_and_precedes_start(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from infra.appliance import backend as module

    m = ApplianceManifest.from_dict(_manifest(tmp_path))
    backend = module.LibvirtBackend(
        m, AppliancePolicy.from_manifest(m), module.BackendConfig(uri="qemu:///system"))
    guest = pathlib.Path(m.state_dir) / "guests" / "200"
    guest.mkdir(parents=True, mode=0o700)
    for name in ("disk.qcow2", "seed.iso"):
        (guest / name).touch(mode=0o600)
    calls = []
    monkeypatch.setattr(module.pwd, "getpwnam", lambda name: SimpleNamespace(pw_uid=64055))

    def run(cmd, **kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, 0, "", "")

    monkeypatch.setattr(module.subprocess, "run", run)

    class Domain:
        active = False

        def isActive(self):
            return self.active

        def create(self):
            assert len(calls) == 3
            self.active = True

    dom = Domain()
    monkeypatch.setattr(backend, "_find", lambda *args: (dom, {}))
    backend.start_and_wait(m.installation_id, 200)
    assert calls == [
        ["setfacl", "-m", "u:64055:--x", m.state_dir,
         str(guest.parent), str(guest)],
        ["setfacl", "-m", "u:64055:rw-", str(guest / "disk.qcow2"),
         str(guest / "serial.log")],
        ["setfacl", "-m", "u:64055:r--", str(guest / "seed.iso")],
    ]

    # Fail closed rather than trying to start after ACL setup fails.
    dom.active = False
    monkeypatch.setattr(module.subprocess, "run", lambda *args, **kwargs:
                        subprocess.CompletedProcess(args[0], 1, "", "ACL denied"))
    with pytest.raises(module.BackendUnavailable, match="ACL denied"):
        backend.start_and_wait(m.installation_id, 200)
    assert not dom.active

    (guest / "seed.iso").unlink()
    (guest / "seed.iso").symlink_to(tmp_path / "model.key")
    with pytest.raises(module.BackendUnavailable, match="symlink refused"):
        backend.start_and_wait(m.installation_id, 200)
    assert not dom.active


def test_session_qemu_does_not_change_storage_acl(tmp_path, monkeypatch):
    from infra.appliance import backend as module

    m = ApplianceManifest.from_dict(_manifest(tmp_path))
    backend = module.LibvirtBackend(m, AppliancePolicy.from_manifest(m))

    def forbidden(*args, **kwargs):
        pytest.fail("session QEMU must not change cross-UID permissions")

    monkeypatch.setattr(module.subprocess, "run", forbidden)
    backend._prepare_qemu_storage(200)


def test_manifest_unknown_key_placeholder_and_inline_secret_refused(tmp_path):
    raw = _manifest(tmp_path)
    raw["surprise"] = True
    with pytest.raises(Exception, match="unknown keys"):
        ApplianceManifest.from_dict(raw)

    raw = _manifest(tmp_path)
    raw["urls"]["public"] = "https://CHANGEME.example"
    with pytest.raises(Exception, match="placeholder"):
        ApplianceManifest.from_dict(raw)

    raw = _manifest(tmp_path)
    raw["model"]["api_key"] = "supersecret"
    with pytest.raises(Exception, match="inline credential"):
        ApplianceManifest.from_dict(raw)


def test_manifest_refuses_private_key_and_bad_image_hash(tmp_path):
    raw = _manifest(tmp_path)
    private = tmp_path / "private"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                    "-f", str(private)], check=True, capture_output=True)
    raw["access_keys"]["runner"] = str(private)
    with pytest.raises(Exception, match="PUBLIC key"):
        ApplianceManifest.from_dict(raw)

    raw = _manifest(tmp_path)
    raw["images"]["attacker"]["sha256"] = "0" * 64
    with pytest.raises(Exception, match="sha256 mismatch"):
        ApplianceManifest.from_dict(raw, verify_images=True)


def test_manifest_refuses_overlapping_or_unreachable_networks(tmp_path):
    raw = _manifest(tmp_path)
    raw["network"]["management_cidr"] = "10.66.0.0/24"
    with pytest.raises(Exception, match="must not overlap"):
        ApplianceManifest.from_dict(raw)

    raw = _manifest(tmp_path)
    raw["network"]["bastion_address"] = "10.99.0.2"
    with pytest.raises(Exception, match="inside range_cidr"):
        ApplianceManifest.from_dict(raw)


def test_policy_is_typed_and_refuses_gateway_and_linked_clone():
    raw = {
        "node": "4f0e7a1c-8a59-4a4e-9b5d-74f0e7a1c111",
        "templates": [9005, 9011, 9012], "vmid_range": [210, 219],
        "storage": ["images"], "clone_mode": "full",
        "nic": {"bridge": "srlab0"},
        "provision": {"cidr": "10.66.0.0/24", "gateway": "10.66.0.1"},
        "limits": {"max_vms": 3, "cores_per_vm": 2,
                   "memory_mb_per_vm": 2048, "disk_gb_per_vm": 16},
    }
    p = AppliancePolicy.from_dict(raw)
    assert p.net0_expected == "virtio,bridge=srlab0"
    p.check_net0("virtio,bridge=srlab0")
    p.check_ipconfig("ip=10.66.0.11/24")
    with pytest.raises(PolicyViolation):
        p.check_ipconfig("ip=10.66.0.11/24,gw=10.66.0.1")
    with pytest.raises(PolicyViolation):
        p.check_ipconfig("ip=10.66.0.1/24")
    with pytest.raises(PolicyViolation):
        p.check_clone_mode(False)
    with pytest.raises(PolicyViolation):
        p.check_name("web01")

    bad = json.loads(json.dumps(raw))
    bad["clone_mode"] = "linked"
    with pytest.raises(PolicyViolation, match="clone_mode"):
        AppliancePolicy.from_dict(bad)
    bad = json.loads(json.dumps(raw))
    bad["nic"] = {"bridge": "srlab0", "vlan": 66}
    with pytest.raises(PolicyViolation, match="exactly"):
        AppliancePolicy.from_dict(bad)


def test_range_ingress_cannot_use_management_source_or_ipv6_rules(tmp_path):
    rules = render_nftables(ApplianceManifest.from_dict(_manifest(tmp_path)))
    assert "$management_v4" not in rules and "$range_v4" not in rules
    assert rules.index("add table inet sr_appliance") < rules.index("delete table inet sr_appliance")
    for name in ("input", "forward"):
        chain = rules.split(f"chain {name} {{", 1)[1].split("\n    }", 1)[0]
        state = chain.index("ct state established,related accept")
        assert chain.index('iifname "srlab0" meta nfproto ipv6 counter drop') < state
        assert chain.index('iifname "srlab0" ip saddr != @range_v4 counter drop') < state
    for line in rules.splitlines():
        if "@management_v4" in line and "accept" in line:
            assert 'iifname != "srlab0"' in line


def test_seed_carries_only_role_keys_and_no_gateway_in_production(tmp_path):
    m = ApplianceManifest.from_dict(_manifest(tmp_path), verify_images=True)
    image = m.image_for_role("mojang-web-local")
    user = render_user_data(SeedInputs(
        manifest=m, image=image, vmid=211, session_id="a" * 32,
        hostname="web01", address="10.66.0.11", prefix=24))
    assert "ssh-ed25519" in user
    assert "PRIVATE KEY" not in user
    assert "gateway" not in user.split("#cloud-config", 1)[1]
    assert m.public_key_for("bastion") in user
    assert m.public_key_for("runner") not in user
    assert "first-boot-complete" in user

    seed = build_seed(tmp_path / "seed.iso", SeedInputs(
        manifest=m, image=image, vmid=211, session_id="a" * 32,
        hostname="web01", address="10.66.0.11", prefix=24))
    assert seed.is_file() and seed.stat().st_size > 0


def test_attacker_seed_separates_management_and_runner_public_keys(tmp_path):
    import yaml
    from deploy.appliance import render_control_env

    m = ApplianceManifest.from_dict(_manifest(tmp_path))
    inp = SeedInputs(manifest=m, image=m.image_for_role("attacker"), vmid=210,
                     session_id="a" * 32, hostname="attacker",
                     address="10.66.0.9", prefix=24)
    rendered = render_user_data(inp)
    doc = yaml.safe_load(rendered)
    users = {user["name"]: user for user in doc["users"]}
    assert users["attacker"]["ssh_authorized_keys"] == [m.public_key_for("runner")]
    assert users["root"]["ssh_authorized_keys"] == [m.public_key_for("mgmt")]
    assert "PRIVATE KEY" not in rendered
    assert m.public_key_for("bastion") not in rendered
    assert "defender" not in users
    files = {entry["path"]: entry["content"] for entry in doc["write_files"]}
    profile = files["/etc/apparmor.d/usr.bin.unshare"]
    assert "flags=(attach_disconnected,mediate_deleted)" in profile
    assert "allow userns," in profile and "allow mount," in profile
    assert "allow capability," in profile and "/** rix," in profile
    assert "change_profile unshare," not in profile
    first_boot = files["/usr/local/sbin/sr-first-boot-complete"]
    assert "apparmor_parser -r /etc/apparmor.d/usr.bin.unshare" in first_boot
    assert "unshare --user --map-root-user" in first_boot
    assert first_boot.index("unshare --user --map-root-user") < \
        first_boot.index("/var/lib/sparring-range/first-boot-complete")
    assert doc["runcmd"].index("apparmor_parser -r /etc/apparmor.d/usr.bin.unshare") < \
        doc["runcmd"].index("/usr/local/sbin/sr-first-boot-complete")
    assert any("unshare --user --map-root-user" in cmd for cmd in doc["runcmd"])
    assert "SR_RUNNER_SSH_TARGET=attacker@10.66.0.9" in render_control_env(m)

    defended = yaml.safe_load(render_user_data(SeedInputs(
        manifest=m, image=m.image_for_role("mojang-web-local"), vmid=211,
        session_id="a" * 32, hostname="web01", address="10.66.0.10", prefix=24)))
    users = {user["name"]: user for user in defended["users"]}
    assert users["root"]["ssh_authorized_keys"] == [m.public_key_for("mgmt")]
    assert users["defender"]["ssh_authorized_keys"] == [m.public_key_for("bastion")]
    assert "attacker" not in users
    assert "/etc/apparmor.d/usr.bin.unshare" not in {
        entry["path"] for entry in defended["write_files"]}


def test_seed_addressing_is_static_in_every_mode(tmp_path):
    """A golden image has no machine-id, so a DHCP client cannot even be
    configured (systemd-networkd: "Failed to configure DHCPv4 client").  The
    seed therefore always writes a STATIC address: the fixture gets the
    isolated network's own gateway, the production range gets no route at
    all."""
    m = ApplianceManifest.from_dict(_manifest(tmp_path), verify_images=True)
    image = m.image_for_role("attacker")
    fixture = render_user_data(SeedInputs(
        manifest=m, image=image, vmid=210,
        session_id="b" * 32, hostname="attacker", address="10.0.2.15",
        prefix=24, gateway="10.0.2.2"))
    assert "dhcp4: true" not in fixture
    assert "dhcp4: false" in fixture
    assert "10.0.2.15" in fixture
    assert "10.0.2.2" in fixture
    assert m.public_key_for("runner") in fixture

    production = render_user_data(SeedInputs(
        manifest=m, image=image, vmid=210,
        session_id="b" * 32, hostname="attacker", address="10.66.0.210",
        prefix=24, gateway=None))
    assert "dhcp4: true" not in production
    assert "10.66.0.210" in production
    assert "to: default" not in production
    assert m.public_key_for("runner") in production


def test_seed_never_blocks_the_boot_on_a_missing_agent_device(tmp_path):
    """`systemctl --now` waits for the guest-agent device: a guest whose
    channel is not visible would hang its whole cloud-init stage."""
    m = ApplianceManifest.from_dict(_manifest(tmp_path), verify_images=True)
    user = render_user_data(SeedInputs(
        manifest=m, image=m.image_for_role("attacker"), vmid=210,
        session_id="b" * 32, hostname="attacker", address="10.0.2.15",
        prefix=24, gateway="10.0.2.2"))
    assert "systemctl enable --now" not in user
    assert "start --no-block qemu-guest-agent.service" in user


def test_network_artifacts_are_isolated_and_fixed(tmp_path):
    m = ApplianceManifest.from_dict(_manifest(tmp_path), verify_images=True)
    rules = render_nftables(m)
    assert "policy drop" in rules
    assert "iifname \"srlab0\" oifname \"srlab0\" accept" in rules
    assert "masquerade" not in rules.lower()
    assert "srl0" not in rules
    assert str(m.network.controller_range_ip) in rules
    netdev = render_networkd(m)
    assert "Name=srlab0" in netdev
    assert "IPMasquerade=no" in netdev
    assert f"Address={m.network.controller_range_ip}/{m.network.range_cidr.prefixlen}" in netdev


def test_overlay_is_never_smaller_than_its_base(tmp_path, monkeypatch):
    """A qcow2 overlay smaller than its backing file truncates the partition
    table: the guest then cannot find root=LABEL=... and drops to an
    initramfs shell.  The overlay therefore inherits at least the base's
    virtual size, and the manifest's disk budget is a floor."""
    from infra.appliance.backend import BackendConfig, LibvirtBackend
    from infra.appliance.policy import AppliancePolicy

    m = ApplianceManifest.from_dict(_manifest(tmp_path), verify_images=True)
    policy = AppliancePolicy.from_manifest(m)
    base = pathlib.Path(m.image_for_role("attacker").path)
    base.write_bytes(b"fake-image")

    calls = []

    def fake_qemu_img(args, **kwargs):
        calls.append(args)
        if args[1] == "info":
            return subprocess.CompletedProcess(
                args, 0, json.dumps({"virtual-size": 12 * 1024 ** 3}), "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(subprocess, "run", fake_qemu_img)
    backend = LibvirtBackend(m, policy, BackendConfig(fixture_mode=True))
    backend._overlay(m.image_for_role("attacker"), tmp_path / "disk.qcow2")
    create = [c for c in calls if c[1] == "create"]
    assert create, calls
    assert create[0][-1] == "12G", create[0]
