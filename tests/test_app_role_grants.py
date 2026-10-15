"""Plan 13 phase 8 production finds (2026-10-15 live install).

1. The app role is DML-only, but per-table grants rot on every schema
   change: the fresh 0015 schema answered `permission denied` to sr_app
   until standing grants + default privileges landed (0016).
2. The shipped broker example's literal `CHANGE` secret passed production
   validation (only ""/"CHANGE_ME" were rejected) — fail-open at boot.
"""
from __future__ import annotations

import pathlib
import re

REPO = pathlib.Path(__file__).resolve().parents[1]
VERSIONS = REPO / "srplatform/db/migrations/versions"


def _revisions():
    revs = {}
    for p in VERSIONS.glob("*.py"):
        text = p.read_text()
        m1 = re.search(r'^revision\s*=\s*"([^"]+)"', text, re.M)
        m2 = re.search(r'^down_revision\s*=\s*"([^"]+)"', text, re.M)
        if m1:
            revs[m1.group(1)] = (m2.group(1) if m2 else None, p.name)
    return revs


def test_migration_chain_is_linear_with_head_0016():
    revs = _revisions()
    children = {down for down, _ in revs.values() if down}
    heads = [r for r in revs if r not in children]
    assert heads == ["0017"], f"expected single head 0017, got {heads}"
    # walk from head to root: must visit every revision exactly once
    seen, cur = [], "0017"
    while cur is not None:
        assert cur in revs, f"missing revision file for {cur}"
        seen.append(cur)
        cur = revs[cur][0]
    assert len(seen) == len(revs) == 17, f"non-linear chain: {seen}"


def test_0016_grants_dml_and_default_privileges_without_ddl():
    text = (VERSIONS / "0016_app_role_dml_grants.py").read_text()
    up = text.split("def upgrade")[1].split("def downgrade")[0]
    for want in (
        "GRANT USAGE ON SCHEMA public",
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES",
        "GRANT USAGE, SELECT ON ALL SEQUENCES",
        "ALTER DEFAULT PRIVILEGES",
    ):
        assert want in up, f"0016 upgrade missing: {want}"
    assert "CREATE" not in up and "DROP" not in up, \
        "DDL must never be granted to the app role"
    assert re.search(r"GRANT (ALL|ALTER)", up) is None, \
        "no blanket/alter grants to the app role"


def test_change_placeholder_is_rejected_like_change_me():
    from srplatform.settings import Settings, validate_production
    import pytest
    s = Settings(
        _env_file=None, sr_env="production",
        broker_policy_file="/x/policy.json",
        broker_server_cert="/x/c", broker_server_key="/x/k",
        broker_tls_ca_file="/x/ca",
        proxmox_host="pve.internal", proxmox_token_id="sr-broker@pve!range",
        proxmox_token_secret="CHANGE", proxmox_tls_ca_file="/x/pve-ca")
    with pytest.raises(RuntimeError, match="Proxmox API token missing"):
        validate_production(s, "broker")
    c = Settings(
        _env_file=None, sr_env="production",
        broker_url="https://b:8443", broker_tls_ca_file="/x/ca",
        broker_client_cert="/x/c", broker_client_key="/x/k",
        runner_transport="ssh", runner_ssh_target="r@10.66.0.9",
        runner_ssh_known_hosts="/x/kh",
        postgres_url="postgresql+psycopg2://a:b@h/db",
        postgres_url_owner="postgresql+psycopg2://o:b@h/db",
        bastion_targets_known_hosts="/x/bkh",
        verifier_ssh_known_hosts="/x/vkh",
        api_base_url="https://api.range.internal",
        telemetry_ca_file="/x/api-ca.crt",
        proxmox_token_id="sr-broker@pve!range",
        proxmox_token_secret="CHANGE")
    with pytest.raises(RuntimeError, match="forbidden"):
        validate_production(c, "controller")



def test_0017_denies_mutation_of_immutable_history():
    text = (VERSIONS / "0017_app_role_least_privilege.py").read_text()
    up = text.split("def upgrade")[1].split("def downgrade")[0]
    for table in ("events", "uptime_samples", "recordings", "safety_records"):
        assert f'"{table}"' in text.split("APPEND_ONLY_TABLES")[1].split(")")[0], table
    assert 'REVOKE UPDATE, DELETE ON "{table}"' in up
    assert "REVOKE ALL ON alembic_version" in up
    assert "GRANT SELECT ON alembic_version" in up
    # no UPDATE/DELETE granted to anything in 0017, and no owner assumption
    assert "UPDATE, DELETE ON" not in up.replace("REVOKE UPDATE, DELETE", "")
    assert 'FOR ROLE "' not in text


def test_0016_has_no_hardcoded_owner():
    text = (VERSIONS / "0016_app_role_dml_grants.py").read_text()
    code = text.split('"""', 2)[-1]  # prose may name roles; SQL must not
    assert 'FOR ROLE "' not in code
    assert "sr_owner" not in code
