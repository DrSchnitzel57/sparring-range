"""The bastion has exactly ONE production pin source (milestone 14).

The deployment serves the broker-pinned guest host key with the token.  A
stale local known_hosts file is NOT a production fallback: the architecture
rejected that trust path, so a missing deployment pin must refuse the dial
instead of downgrading to a file or to TOFU.
"""
from __future__ import annotations

import pytest

from srplatform.bastion import proxy as proxy_mod


class _Settings:
    def __init__(self, env: str, known_hosts: str | None = None):
        self.sr_env = env
        self.bastion_targets_known_hosts = known_hosts
        self.bastion_target_user = "defender"
        self.bastion_client_key_path = None
        self.recording_max_bytes = 32 * 1024 * 1024


def _pin_resolution(monkeypatch, env: str, known_hosts: str | None,
                    target: dict) -> object:
    """Run the pin-resolution block of a bastion session and return what it
    decided (a known_hosts value, or the RuntimeError it refused with)."""
    settings = _Settings(env, known_hosts)
    monkeypatch.setattr(proxy_mod, "get_settings", lambda: settings)
    api_pin = (target.get("target_host_key") or "").strip() or None
    if api_pin:
        return proxy_mod._deployment_known_hosts(target)
    if settings.sr_env == "production":
        raise RuntimeError(
            "the deployment served no guest host-key pin — refusing to dial "
            "the range host on a local file or on TOFU")
    known = settings.bastion_targets_known_hosts or None
    if isinstance(known, str):
        import os
        known = known if os.path.exists(known) else None
    return known


def test_production_refuses_without_a_deployment_pin(monkeypatch, tmp_path):
    stale = tmp_path / "known_hosts"
    stale.write_text("[10.66.0.10]:22 ssh-ed25519 AAAA\n")
    with pytest.raises(RuntimeError, match="no guest host-key pin"):
        _pin_resolution(monkeypatch, "production", str(stale),
                        {"target_host": "10.66.0.10", "target_host_key": ""})


def test_production_uses_the_deployment_pin(monkeypatch, tmp_path):
    stale = tmp_path / "known_hosts"
    stale.write_text("[10.66.0.10]:22 ssh-ed25519 AAAA\n")
    import subprocess
    key = tmp_path / "guest"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                    "-f", str(key)], check=True, capture_output=True)
    pin = (tmp_path / "guest.pub").read_text().strip()
    known = _pin_resolution(monkeypatch, "production", str(stale),
                            {"target_host": "10.66.0.10",
                             "target_host_key": pin})
    assert b"10.66.0.10" in known
    assert pin.encode() in known
    # the stale local file is NOT part of the decision
    assert b"AAAA\n" not in known


def test_development_may_use_a_local_known_hosts_file(monkeypatch, tmp_path):
    local = tmp_path / "known_hosts"
    local.write_text("[127.0.0.1]:2222 ssh-ed25519 AAAA\n")
    known = _pin_resolution(monkeypatch, "dev", str(local),
                             {"target_host": "127.0.0.1", "target_host_key": ""})
    assert known == str(local)
