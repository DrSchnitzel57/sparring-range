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


def test_seed_fixture_mode_uses_dhcp_and_fixture_marker(tmp_path):
    m = ApplianceManifest.from_dict(_manifest(tmp_path), verify_images=True)
    user = render_user_data(SeedInputs(
        manifest=m, image=m.image_for_role("attacker"), vmid=210,
        session_id="b" * 32, hostname="attacker", address="10.0.2.15",
        prefix=24, fixture_dhcp=True))
    assert "dhcp4: true" in user
    assert "10.0.2.15" not in user
    assert m.public_key_for("runner") in user


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
