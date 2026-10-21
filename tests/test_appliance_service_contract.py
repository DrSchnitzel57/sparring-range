"""The managed-service installation contract (milestone 15).

The renderer can produce a beautiful set of files that no service could
actually use: a credential under a directory its reader cannot traverse, a
unit that loads an environment nobody writes, a front door that routes /api
to a prefix the API does not serve, a trust anchor the TLS bootstrap never
creates.  These tests pin the contract that the install gate checks.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from infra.dev.service_contract import contract_problems  # noqa: E402


def _key(tmp_path: pathlib.Path, name: str) -> pathlib.Path:
    path = tmp_path / f"{name}.pub"
    if not path.exists():
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                        "-C", f"sr-contract-{name}", "-f", str(tmp_path / name)],
                       check=True, capture_output=True)
    return path


def _manifest_file(tmp_path: pathlib.Path) -> pathlib.Path:
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
    (tmp_path / "model.key").write_text("contract-model-key\n")
    raw = {
        "schema_version": 1,
        "installation_id": "4f0e7a1c-8a59-4a4e-9b5d-74f0e7a1c444",
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
        "broker": {"socket": "/run/sparring-range/broker.sock",
                   "ledger": "/var/lib/sparring-range/broker-ledger.sqlite3",
                   "state_dir": "/var/lib/sparring-range"},
        "paths": {"images": "/var/lib/sparring-range/images",
                  "recordings": "/var/lib/sparring-range/recordings",
                  "secrets": "/etc/sparring-range/secrets"},
        "images": images,
        "access_keys": keys,
        "model": {"base_url": "http://127.0.0.1:8001/v1",
                  "alias": "sr-contract-model",
                  "api_key_file": str(tmp_path / "model.key")},
        "budgets": {"max_guests": 6, "max_vcpus": 12, "max_memory_mb": 12288,
                    "max_disk_gb": 44, "min_free_gb": 20},
        "backup": {"enabled": False, "destination": ""},
    }
    path = tmp_path / "appliance-manifest.json"
    path.write_text(json.dumps(raw, indent=2, sort_keys=True))
    return path


def test_the_rendered_installation_satisfies_the_service_contract(tmp_path):
    problems = contract_problems(_manifest_file(tmp_path))
    assert problems == [], problems


def test_a_credential_the_reader_cannot_reach_is_a_contract_violation(
        tmp_path, monkeypatch):
    """A 0600 capability under a 0700 directory is the defect this pins."""
    from deploy import appliance as installer

    monkeypatch.setattr(installer, "SECRET_DIR_MODE", 0o700)
    problems = contract_problems(_manifest_file(tmp_path))
    assert any("not traversable by its group" in p for p in problems), problems

    monkeypatch.setattr(installer, "SECRET_DIR_MODE", 0o757)
    problems = contract_problems(_manifest_file(tmp_path))
    assert any("world-traversable" in p for p in problems), problems


def test_a_shared_capability_file_is_a_contract_violation(tmp_path, monkeypatch):
    """The API and the supervisor may not read the SAME 0600 file."""
    from deploy import appliance as installer

    original = installer.render_supervisor_env

    def same_file(m, *, etc=installer.DEFAULT_ETC, prefix=installer.DEFAULT_PREFIX):
        text = original(m, etc=etc, prefix=prefix)
        return text.replace("worker-supervisor.token.srworker",
                            "worker-supervisor.token")

    monkeypatch.setattr(installer, "render_supervisor_env", same_file)
    problems = contract_problems(_manifest_file(tmp_path))
    assert any("SAME capability file" in p for p in problems), problems


def test_an_api_prefix_that_the_api_does_not_serve_is_a_violation(
        tmp_path, monkeypatch):
    """The API's routes are unprefixed: nginx must STRIP /api."""
    from deploy import appliance as installer

    original = installer.render_nginx_site

    def keep_prefix(m, lay):
        return original(m, lay).replace("proxy_pass http://127.0.0.1:8000/;",
                                        "proxy_pass http://127.0.0.1:8000/api/;")

    monkeypatch.setattr(installer, "render_nginx_site", keep_prefix)
    problems = contract_problems(_manifest_file(tmp_path))
    assert any("must be stripped" in p for p in problems), problems


def test_a_trust_anchor_the_bootstrap_never_creates_is_a_violation(
        tmp_path, monkeypatch):
    from deploy import appliance as installer

    original = installer.render_control_env

    def wrong_ca(m, *, etc=installer.DEFAULT_ETC, prefix=installer.DEFAULT_PREFIX):
        return original(m, etc=etc, prefix=prefix).replace(
            "tls/api-ca.crt", "tls/ingest-ca.crt")

    monkeypatch.setattr(installer, "render_control_env", wrong_ca)
    problems = contract_problems(_manifest_file(tmp_path))
    assert any("never creates" in p for p in problems), problems


def test_the_shared_secret_group_holds_only_the_entitled_readers():
    from deploy import appliance as installer

    members = {user for user, (_g, extras) in installer.USERS.items()
               if "sr-secrets" in extras}
    assert members == {"srrange", "srworker"}
