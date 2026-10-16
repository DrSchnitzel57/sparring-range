"""Bastion guest-dial path (live finds 2026-10-15).

- Token resolution must bind owner + serve the deployment pin.
- The dial must prefer the API pin (fresh every login) over copied files,
  and report dial failures to the member instead of closing silently.
- Server-side callbacks (worker) and the CLI must survive the LAN
  frontend's /api mount.
"""
from __future__ import annotations

import types

import asyncssh
import pytest

# A REAL parseable pin: the old fake ("ssh-ed25519 AAAAPIN") could never
# catch the truncated-ref bug — asyncssh silently drops the unparseable
# line and the dial fails with HostKeyNotVerifiable (live find 2026-10-16).
_PIN_KEY = asyncssh.generate_private_key("ssh-ed25519")
PIN = _PIN_KEY.export_public_key().decode().strip()

TARGET = {
    "token": "tok-x", "username": "ccdc-demo", "session_id": "sess-1",
    "target_host": "10.66.0.9", "target_port": 22,
    "target_host_key": PIN,
}


def _resolve_ok(username):
    async def go(token):
        assert token == username
        return dict(TARGET)
    return go


async def _noop_sink(event):
    return None


def _stub_settings(**over):
    base = dict(recording_max_bytes=1024,
                bastion_targets_known_hosts="/f/kh",
                bastion_authorized_keys_file="",
                bastion_target_user="defender",
                bastion_client_key_path="/f/key",
                sr_env="dev", api_route_prefix="", api_tls_ca_file=None)
    base.update(over)
    return types.SimpleNamespace(**base)


class _Writer:
    def __init__(self):
        self.data = ""

    def write(self, s):
        self.data += s


class _Proc:
    def __init__(self, username="tok-x", command="echo hi"):
        self._username = username
        self.command = command
        self.width, self.height = 120, 32
        self.stdout, self.stderr = _Writer(), _Writer()
        self.code = None

    def get_extra_info(self, key):
        return {"username": self._username}[key]

    def exit(self, code):
        self.code = code


def _proxy(monkeypatch, tmp_path, target, settings_over=None):
    import srplatform.bastion.proxy as proxy
    from srplatform.bastion.proxy import BastionProxy
    monkeypatch.setattr(proxy, "get_settings",
                        lambda: _stub_settings(**(settings_over or {})))

    async def resolve(username):
        return dict(target) if target else None

    return BastionProxy(resolve, _noop_sink, recordings_dir=tmp_path / "rec",
                        host_key_path=tmp_path / "hostkey")


async def test_resolve_binds_owner_and_pin(monkeypatch):
    import httpx
    import srplatform.bastion.proxy as proxy
    from srplatform.settings import get_settings
    monkeypatch.delenv("API_ROUTE_PREFIX", raising=False)
    get_settings.cache_clear()
    seen = {}

    class FakeResp:
        status_code = 200

        def json(self):
            return dict(TARGET)

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

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    try:
        out = await proxy.api_resolve_token("tok-x")
    finally:
        get_settings.cache_clear()
    assert out["username"] == "ccdc-demo"
    assert out["target_host_key"] == PIN
    assert seen.get("verify") is True  # fail closed without an anchor
    assert seen["url"].endswith("/tokens/tok-x")


async def test_resolve_prepends_route_prefix(monkeypatch):
    import httpx
    import srplatform.bastion.proxy as proxy
    from srplatform.settings import get_settings
    monkeypatch.setenv("API_ROUTE_PREFIX", "/api")
    get_settings.cache_clear()
    seen = {}

    class FakeResp:
        status_code = 200

        def json(self):
            return dict(TARGET)

    class FakeClient:
        def __init__(self, *a, **k):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def get(self, url, *a, **k):
            seen["url"] = url
            return FakeResp()

    monkeypatch.setattr(httpx, "AsyncClient", FakeClient)
    try:
        out = await proxy.api_resolve_token("tok-x")
    finally:
        get_settings.cache_clear()
    assert out["username"] == "ccdc-demo"
    assert seen["url"].endswith("/api/tokens/tok-x")


async def test_dial_prefers_deployment_pin(monkeypatch, tmp_path):
    import asyncssh
    import srplatform.bastion.proxy as proxy
    captured = {}

    class _Refused:
        async def __aenter__(self):
            raise OSError("refused")

        async def __aexit__(self, *a):
            return False

    def fake_connect(*a, **k):
        captured.update(k)
        return _Refused()

    monkeypatch.setattr(asyncssh, "connect", fake_connect)
    p = _proxy(monkeypatch, tmp_path, TARGET)
    proc = _Proc()
    await p._handle_session(proc)
    assert captured["known_hosts"] == f"10.66.0.9 {PIN}".encode()
    assert proc.code == 255
    assert "target connection failed" in proc.stderr.data
    assert "OSError" in proc.stderr.data
    assert PIN.split()[1] not in proc.stderr.data  # never leak pin material


async def test_dial_refuses_truncated_display_ref_pin(monkeypatch, tmp_path):
    """Live find 2026-10-16: the API once served `host_key_ref` (the
    truncated display form) as the dial pin. asyncssh silently drops the
    unparseable known_hosts line, so EVERY dial failed
    HostKeyNotVerifiable while looking like a key mismatch."""
    import srplatform.bastion.proxy as proxy

    calls = []
    monkeypatch.setattr(asyncssh, "connect",
                        lambda *a, **k: calls.append(k))
    b64 = PIN.split()[1]
    ref = f"ssh-ed25519 {b64[:24]}…{b64[-8:]}"
    target = dict(TARGET, target_host_key=ref)
    p = _proxy(monkeypatch, tmp_path, target)
    proc = _Proc()
    await p._handle_session(proc)
    assert calls == [], "a malformed pin must never reach a dial"
    assert proc.code == 255
    assert "PinRefused" in proc.stderr.data
    assert b64 not in proc.stderr.data  # refuse without echoing material


async def test_real_dial_with_full_pin_succeeds(monkeypatch, tmp_path):
    """End-to-end regression for the same find: with the FULL pin the real
    dial (real asyncssh server, real host-key verification, real public-key
    auth) must reach the guest — never a mocked `asyncssh.connect`."""
    host_key = asyncssh.generate_private_key("ssh-ed25519")
    client_key = asyncssh.generate_private_key("ssh-ed25519")
    ck_path = tmp_path / "defender_key"
    client_key.write_private_key(ck_path)
    ck_path.chmod(0o600)
    client_pub = client_key.export_public_key()

    class _Server(asyncssh.SSHServer):
        def begin_auth(self, username):
            return True

        def public_key_auth_supported(self):
            return True

        async def validate_public_key(self, username, key):
            return username == "defender" and key.export_public_key() == client_pub

    async def _session(process):
        process.stdout.write("hi\n")
        process.exit(0)

    srv = await asyncssh.create_server(
        _Server, "127.0.0.1", 0, server_host_keys=[host_key],
        process_factory=_session)
    try:
        port = srv.sockets[0].getsockname()[1]
        target = dict(TARGET, target_host="127.0.0.1", target_port=port,
                      target_host_key=host_key.export_public_key().decode().strip())
        p = _proxy(monkeypatch, tmp_path, target,
                   settings_over={"bastion_client_key_path": str(ck_path)})
        proc = _Proc()
        await p._handle_session(proc)
    finally:
        srv.close()
        await srv.wait_closed()
    assert proc.code == 0, proc.stderr.data
    assert "hi" in proc.stdout.data


async def test_dial_falls_back_to_file_without_pin(monkeypatch, tmp_path):
    import asyncssh
    import srplatform.bastion.proxy as proxy
    captured = {}

    class _Refused:
        async def __aenter__(self):
            raise OSError("refused")

        async def __aexit__(self, *a):
            return False

    def fake_connect(*a, **k):
        captured.update(k)
        return _Refused()

    monkeypatch.setattr(asyncssh, "connect", fake_connect)
    target = {k: v for k, v in TARGET.items() if k != "target_host_key"}
    kh = tmp_path / "kh"
    kh.write_text("10.66.0.9 ssh-ed25519 AAAAOLD\n")
    p = _proxy(monkeypatch, tmp_path, target,
               settings_over={"bastion_targets_known_hosts": str(kh)})
    proc = _Proc()
    await p._handle_session(proc)
    assert captured["known_hosts"] == str(kh)
    assert proc.code == 255


async def test_missing_session_is_explained(monkeypatch, tmp_path):
    p = _proxy(monkeypatch, tmp_path, None)
    proc = _Proc()
    await p._handle_session(proc)
    assert proc.code == 1
    assert "no session attached" in proc.stderr.data


def test_worker_env_uses_internal_api():
    from srplatform.api.runs import _worker_env
    from srplatform.settings import Settings
    import types
    # explicitly configured internal API wins (production derived env)
    s = Settings(_env_file=None, internal_api_url="http://127.0.0.1:8000")
    run = types.SimpleNamespace(run_id="r1")
    assert _worker_env(s, "tok", "sess", "scen", run)["SR_API_BASE"] == \
        "http://127.0.0.1:8000"
    # otherwise the resolved serving URL follows the deployment (test
    # servers listen on ephemeral ports — a hardcoded default starves them)
    s2 = Settings(_env_file=None, api_base_url="http://127.0.0.1:9999",
                  api_route_prefix="/api")
    assert _worker_env(s2, "tok", "sess", "scen", run)["SR_API_BASE"] == \
        "http://127.0.0.1:9999/api"


def test_cli_base_appends_prefix(monkeypatch):
    from rangectl import client as cli
    from srplatform.settings import get_settings
    monkeypatch.setenv("API_ROUTE_PREFIX", "/api")
    get_settings.cache_clear()
    try:
        assert cli.base().endswith("/api")
    finally:
        get_settings.cache_clear()


def test_cli_base_default_unchanged(monkeypatch):
    from rangectl import client as cli
    from srplatform.settings import get_settings
    monkeypatch.delenv("API_ROUTE_PREFIX", raising=False)
    get_settings.cache_clear()
    try:
        assert not cli.base().endswith("/api")
    finally:
        get_settings.cache_clear()
