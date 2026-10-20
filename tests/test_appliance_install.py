"""Appliance installer contract (milestone 14/15 foundation).

Fast, infrastructure-free tests for the deterministic renderer, the
manifest→policy cross-check, idempotent dry-run, and evidence-bound obligation
resolution. Real apply/reboot/upgrade sequences belong to the operator and the
`hypervisor`/`install` gates, not to this file.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import sys

import pytest

from deploy.appliance import (DEFAULT_ETC, DEFAULT_PREFIX, render_files,
                              render_policy, recovery_resolve)
from infra.appliance.manifest import ApplianceManifest
from infra.appliance.policy import AppliancePolicy
from infra.broker.ledger import Ledger

REPO = pathlib.Path(__file__).resolve().parents[1]


def _key(tmp_path: pathlib.Path, name: str) -> pathlib.Path:
    path = tmp_path / f"{name}.pub"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                    "-C", f"sr-install-{name}", "-f", str(tmp_path / name)],
                   check=True, capture_output=True)
    return path


def _manifest(tmp_path: pathlib.Path) -> dict:
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
        "installation_id": "4f0e7a1c-8a59-4a4e-9b5d-74f0e7a1c222",
        "appliance": {"hostname": "sr-appliance", "timezone": "UTC"},
        "network": {
            "lan_cidr": "10.10.10.0/24", "lan_address": "10.10.10.50",
            "range_cidr": "10.66.0.0/24", "range_bridge": "srlab0",
            "range_gateway": "10.66.0.1", "controller_range_ip": "10.66.0.1",
            "bastion_address": "10.66.0.2", "ingest_address": "10.66.0.1",
            "ingest_port": 8443, "management_cidr": "10.0.0.0/24",
        },
        "urls": {"public": "https://sr.example.edu",
                 "internal": "http://127.0.0.1:8000",
                 "ingest": "https://10.66.0.1:8443"},
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


def test_policy_derived_from_manifest_round_trips(tmp_path):
    m = ApplianceManifest.from_dict(_manifest(tmp_path), verify_images=True)
    rendered = json.loads(render_policy(m))
    p = AppliancePolicy.from_dict(rendered, source="test")
    p.validate_manifest(m)
    assert p.node == m.installation_id
    assert p.templates == (9005, 9011, 9012)
    assert p.vmid_min == 200 and p.vmid_max == 999
    assert p.bridge == "srlab0"
    assert p.limits["max_vms"] == 6
    assert p.limits["disk_gb_per_vm"] == 12


def test_rendered_files_are_deterministic_and_secret_free(tmp_path):
    m = ApplianceManifest.from_dict(_manifest(tmp_path), verify_images=True)
    a = render_files(m, prefix=DEFAULT_PREFIX, etc=DEFAULT_ETC)
    b = render_files(m, prefix=DEFAULT_PREFIX, etc=DEFAULT_ETC)
    assert [f.path for f in a.files] == [f.path for f in b.files]
    assert [f.content for f in a.files] == [f.content for f in b.files]
    everything = "\n".join(f.content for f in a.files)
    assert "PRIVATE KEY" not in everything
    assert "CHANGE" not in everything
    by_name = {f.path.name: f for f in a.files}
    assert "SR_BROKER_SOCKET=" + m.broker_socket in \
        by_name["control-plane.derived.env"].content
    assert "SR_WORKER_DISPATCH=supervisor" in \
        by_name["control-plane.derived.env"].content
    assert "User=srbroker" in by_name["sr-appliance-broker.service"].content
    assert "--allowed-uid srrange" in \
        by_name["sr-appliance-broker.service"].content
    assert "ReadWritePaths=" in by_name["sr-appliance-broker.service"].content
    allowed = by_name["sr-appliance-broker.service"].content.split(
        "ReadWritePaths=", 1)[1].splitlines()[0].split()
    assert str(m.images_dir) not in allowed
    assert str(m.state_dir) in allowed
    assert "User=sringest" in by_name["sr-appliance-ingest.service"].content
    assert "User=srworker" in by_name["sr-worker-supervisor.service"].content
    # The broker unit must not carry DB, API or model secret paths.
    broker = by_name["sr-appliance-broker.service"].content
    assert "POSTGRES" not in broker and "LLM" not in broker
    assert "SR_WORKER" not in broker


def test_cli_plan_is_idempotent_and_apply_dry_run_has_no_effect(tmp_path):
    man = tmp_path / "manifest.json"
    man.write_text(json.dumps(_manifest(tmp_path)))
    env = {**os.environ, "PYTHONPATH": str(REPO)}
    cmd = [sys.executable, str(REPO / "deploy/appliance.py"), "plan",
           "--manifest", str(man)]
    r1 = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO, env=env)
    r2 = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO, env=env)
    assert r1.returncode == 0, (r1.stdout + r1.stderr)[-1200:]
    assert r2.returncode == 0, (r2.stdout + r2.stderr)[-1200:]
    assert r1.stdout == r2.stdout

    prefix = tmp_path / "prefix"
    dry = subprocess.run(
        [sys.executable, str(REPO / "deploy/appliance.py"), "apply",
         "--manifest", str(man), "--prefix", str(prefix),
         "--etc", str(tmp_path / "etc"), "--dry-run"],
        capture_output=True, text=True, cwd=REPO, env=env)
    assert dry.returncode == 0, (dry.stdout + dry.stderr)[-1200:]
    assert "DRY:" in dry.stdout
    assert not prefix.exists() and not (tmp_path / "etc").exists()


def test_recovery_resolve_requires_rechecked_backend_absence(tmp_path,
                                                            monkeypatch):
    m = ApplianceManifest.from_dict(_manifest(tmp_path), verify_images=True)
    p = AppliancePolicy.from_manifest(m)
    ledger = Ledger(m.broker_ledger)
    oid = ledger.add_obligation("destroy", vmid=321, detail="test")
    ledger.close()

    class FakeBackend:
        def __init__(self, *_a, **_k):
            pass

        def lookup_vm(self, node, vmid):
            return None

        def close(self):
            pass

    import infra.appliance.backend as backend_mod
    monkeypatch.setattr(backend_mod, "LibvirtBackend", FakeBackend)

    evidence = tmp_path / "evidence.json"
    evidence.write_text(json.dumps({
        "obligation_id": oid, "vmid": 321, "observed": "absent",
        "operator": "test-operator", "timestamp": "2026-10-20T00:00:00Z"}))
    out = recovery_resolve(m, p, oid, evidence, uri="qemu:///session",
                           allow_tcg=True, fixture=True)
    assert out["resolved"] == oid
    check = Ledger(m.broker_ledger)
    assert check.open_obligations() == []
    assert any(a["kind"] == "operator-obligation-resolved"
               for a in check.audit_tail(10))
    check.close()

    ledger = Ledger(m.broker_ledger)
    oid2 = ledger.add_obligation("destroy", vmid=322, detail="still there")
    ledger.close()
    evidence2 = tmp_path / "evidence2.json"
    evidence2.write_text(json.dumps({
        "obligation_id": oid2, "vmid": 322, "observed": "absent",
        "operator": "test-operator", "timestamp": "2026-10-20T00:00:00Z"}))

    class PresentBackend(FakeBackend):
        def lookup_vm(self, node, vmid):
            return {"vmid": vmid, "active": True}

    monkeypatch.setattr(backend_mod, "LibvirtBackend", PresentBackend)
    with pytest.raises(Exception, match="still owns"):
        recovery_resolve(m, p, oid2, evidence2, uri="qemu:///session",
                         allow_tcg=True, fixture=True)
    check = Ledger(m.broker_ledger)
    assert any(o["id"] == oid2 for o in check.open_obligations())
    check.close()
