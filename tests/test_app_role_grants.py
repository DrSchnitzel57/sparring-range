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
    assert heads == ["0016"], f"expected single head 0016, got {heads}"
    # walk from head to root: must visit every revision exactly once
    seen, cur = [], "0016"
    while cur is not None:
        assert cur in revs, f"missing revision file for {cur}"
        seen.append(cur)
        cur = revs[cur][0]
    assert len(seen) == len(revs) == 16, f"non-linear chain: {seen}"


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


def _run_resolve(monkeypatch, prefix=None):
    import asyncio
    import srplatform.bastion.proxy as proxy
    from srplatform.settings import get_settings
    if prefix is None:
        monkeypatch.delenv("API_ROUTE_PREFIX", raising=False)
    else:
        monkeypatch.setenv("API_ROUTE_PREFIX", prefix)
    get_settings.cache_clear()
    seen = {}

    class FakeResp:
        status_code = 200

        def json(self):
            return {"token": "tok-x", "username": "ccdc-demo",
                    "session_id": None, "target_host": "h", "target_port": 22}

    class FakeClient:
        def __init__(self, *a, **k):
            seen.update(k)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, *a, **k):
            seen["url"] = url
            return FakeResp()

    import httpx
    real, httpx.AsyncClient = httpx.AsyncClient, FakeClient
    try:
        out = asyncio.run(proxy.api_resolve_token("tok-x"))
    finally:
        httpx.AsyncClient = real
        get_settings.cache_clear()
    return out, seen


def test_bastion_api_calls_verify_with_pinned_anchor(monkeypatch):
    out, seen = _run_resolve(monkeypatch)
    assert out and out["username"] == "ccdc-demo"
    assert seen.get("verify") is True, \
        "without a pinned anchor the client must use system verification (fail closed)"
    assert seen["url"].endswith("/tokens/tok-x"), seen["url"]


def test_bastion_api_calls_prepend_route_prefix(monkeypatch):
    # Live find 2026-10-15: without the LAN-frontend /api prefix the bastion
    # asks Next.js, eats a 404, and denies every login with valid credentials.
    out, seen = _run_resolve(monkeypatch, prefix="/api")
    assert out and out["username"] == "ccdc-demo"
    assert seen["url"].endswith("/api/tokens/tok-x"), seen["url"]


def test_baseline_explicit_ok_allowed_when_live_has_no_verdict(monkeypatch):
    import srplatform.api.app as appmod
    from srplatform.api.app import BaselineCheckIn

    recorded = {}

    class FakeDatapath:
        def __init__(self, verdict):
            self.verdict = verdict

        def baseline_status(self):
            return {"ok": self.verdict, "mechanism": "static"}

    class FakeSup:
        def __init__(self, verdict):
            self.datapath = FakeDatapath(verdict)

        def record(self, kind, ok, detail):
            recorded["kind"] = kind
            recorded["ok"] = ok

    class FakePrincipal:
        username = "op"

    import pytest
    # static datapath (verdict None): explicit operator ok is the evidence
    monkeypatch.setattr(appmod, "get_supervisor", lambda: FakeSup(None))
    out = appmod.safety_baseline_check(BaselineCheckIn(ok=True), FakePrincipal())
    assert out["ok"] is True and recorded == {"kind": "baseline_check", "ok": True}
    # a FAILED live verdict still cannot be overridden (audit R04)
    monkeypatch.setattr(appmod, "get_supervisor", lambda: FakeSup(False))
    with pytest.raises(Exception, match="cannot record a passed baseline"):
        appmod.safety_baseline_check(BaselineCheckIn(ok=True), FakePrincipal())
