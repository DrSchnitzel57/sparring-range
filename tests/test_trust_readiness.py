"""Plan 13 phase 4 — trust, TLS and readiness gates (fast layer)."""
from __future__ import annotations

import pathlib
import ssl

import pytest

pathlib_repo = pathlib.Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------- #
# shipper explicit verified TLS
# --------------------------------------------------------------------------- #

def test_shipper_http_has_no_context_https_verifies(monkeypatch, tmp_path):
    import telemetry.shipper as sh
    monkeypatch.delenv("SR_TLS_CA_FILE", raising=False)
    assert sh._ssl_context("http://10.66.0.1:8000") is None
    ctx = sh._ssl_context("https://api.range.internal:8443")
    assert ctx is not None
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


def test_shipper_provisioned_ca_is_used_and_missing_ca_fails_closed(
        monkeypatch, tmp_path):
    import telemetry.shipper as sh
    ca = tmp_path / "ca.crt"
    # a real parseable CA is not needed to prove the file is OPENED:
    # create_default_context(cafile=...) raises on unreadable paths.
    monkeypatch.setenv("SR_TLS_CA_FILE", str(ca))
    with pytest.raises((FileNotFoundError, OSError)):
        sh._ssl_context("https://api.range.internal")
    monkeypatch.setenv("SR_TLS_CA_FILE", str(tmp_path / "absent-ca.crt"))
    with pytest.raises((FileNotFoundError, OSError)):
        sh._ssl_context("https://api.range.internal")


# --------------------------------------------------------------------------- #
# enrollment provisioning ships the public trust anchor
# --------------------------------------------------------------------------- #

class _S:
    api_base_url = "http://10.66.0.1:8000"
    telemetry_ca_file = None


def test_provision_command_plain_http_unchanged():
    from srplatform.scenario_engine.orchestrator import _provision_command
    cmd = _provision_command("web01", "tok", "nonce1", _S())
    assert "api-ca.crt" not in cmd and "SR_TLS_CA_FILE" not in cmd
    assert "SR_API_URL=http://10.66.0.1:8000" in cmd


def test_provision_command_https_provisions_ca(tmp_path):
    from srplatform.scenario_engine.orchestrator import _provision_command

    class S(_S):
        api_base_url = "https://api.range.internal"
        telemetry_ca_file = str(tmp_path / "api-ca.crt")

    (tmp_path / "api-ca.crt").write_text("-----BEGIN CERTIFICATE-----\nX\n")
    cmd = _provision_command("web01", "tok", "nonce1", S())
    assert "/etc/sparring-range/tls/api-ca.crt" in cmd
    assert "SR_TLS_CA_FILE=/etc/sparring-range/tls/api-ca.crt" in cmd


def test_provision_command_https_without_readable_ca_refuses(tmp_path):
    from srplatform.scenario_engine.orchestrator import _provision_command

    class S(_S):
        api_base_url = "https://api.range.internal"
        telemetry_ca_file = str(tmp_path / "missing-ca.crt")

    with pytest.raises(RuntimeError, match="trust anchor"):
        _provision_command("web01", "tok", "nonce1", S())


# --------------------------------------------------------------------------- #
# production validation: telemetry trust is mandatory
# --------------------------------------------------------------------------- #

def _prod_controller_settings(**over):
    from srplatform.settings import Settings
    base = dict(
        sr_env="production",
        broker_url="https://b:8443", broker_tls_ca_file="/x/ca",
        broker_client_cert="/x/c", broker_client_key="/x/k",
        runner_transport="ssh", runner_ssh_target="r@10.66.0.9",
        runner_ssh_known_hosts="/x/kh",
        postgres_url="postgresql+psycopg2://a:b@h/db",
        postgres_url_owner="postgresql+psycopg2://o:b@h/db",
        bastion_targets_known_hosts="/x/bkh",
        verifier_ssh_known_hosts="/x/vkh",
        api_base_url="https://api.range.internal",
        telemetry_ca_file="/x/api-ca.crt")
    base.update(over)
    return Settings(_env_file=None, **base)


def test_production_requires_https_api_and_trust_anchor():
    from srplatform.settings import validate_production
    validate_production(_prod_controller_settings(), "controller")  # passes
    with pytest.raises(RuntimeError, match="telemetry_ca_file"):
        validate_production(
            _prod_controller_settings(telemetry_ca_file=None), "controller")
    with pytest.raises(RuntimeError, match="https"):
        validate_production(
            _prod_controller_settings(api_base_url="http://api.range.internal"),
            "controller")
    with pytest.raises(RuntimeError, match="localhost"):
        validate_production(
            _prod_controller_settings(api_base_url="https://localhost"),
            "controller")


# --------------------------------------------------------------------------- #
# pin lifecycle: readiness refuses missing pins; teardown invalidates
# --------------------------------------------------------------------------- #

def test_readiness_refuses_unusable_pins():
    src = (pathlib_repo / "srplatform/verification_service.py").read_text()
    assert "host-key-pin" in src
    assert "host_key_ref" in src
    assert "unusable/missing host-key pin" in src


def test_teardown_unpublishes_pins_keeps_other_hosts(tmp_path, monkeypatch):
    import pathlib

    from srplatform.scenario_engine import orchestrator

    kh = tmp_path / "known_hosts"
    kh.write_text("10.66.0.9 ssh-ed25519 AAAAatk\n"
                  "10.66.0.10 ssh-ed25519 AAAAweb\n")
    other = tmp_path / "other"
    other.write_text("10.66.0.9 ssh-ed25519 AAAAatk\n")

    class _S:
        runner_ssh_known_hosts = str(kh)
        verifier_ssh_known_hosts = str(other)
        bastion_targets_known_hosts = ""

    monkeypatch.setattr("srplatform.settings.get_settings", lambda: _S())
    orchestrator._unpublish_pinned_host_key("10.66.0.9")
    assert kh.read_text() == "10.66.0.10 ssh-ed25519 AAAAweb\n"
    assert other.read_text() == ""


def test_destroy_paths_unpublish_pins():
    src = (pathlib_repo / "srplatform/scenario_engine/orchestrator.py") \
        .read_text()
    # both confirmed-removed paths invalidate the published pin
    assert src.count("_unpublish_pinned_host_key(") >= 3  # def + 2 call sites


# --------------------------------------------------------------------------- #
# SSH failure taxonomy + private key parse checks (plan 13 phase 4)
# --------------------------------------------------------------------------- #

def test_boot_wait_retries_ambiguous_255_but_not_definitive_failures():
    from srplatform.scenario_engine.orchestrator import _provision_with_boot_wait

    calls = []

    def chan_race(ip, cmd):
        calls.append(ip)
        return (255, "ssh: connect to host port 22: No route to host") \
            if len(calls) < 3 else (0, "ok")
    assert _provision_with_boot_wait(chan_race, "10.66.0.9", "c", 12) == (0, "ok")
    assert len(calls) == 3  # rode out the boot race

    auth_calls = []

    def chan_auth(ip, cmd):
        auth_calls.append(ip)
        return 255, "git@10.66.0.9: Permission denied (publickey)."
    code, tail = _provision_with_boot_wait(chan_auth, "10.66.0.9", "c", 30)
    assert code == 255 and len(auth_calls) == 1  # failed distinctly, no window
    assert "Permission denied" in tail

    pin_calls = []

    def chan_pin(ip, cmd):
        pin_calls.append(ip)
        return 255, "Host key verification failed."
    code, _ = _provision_with_boot_wait(chan_pin, "10.66.0.9", "c", 30)
    assert code == 255 and len(pin_calls) == 1


def test_private_key_parse_check_and_fingerprints(tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    from srplatform.settings import check_private_key, public_key_fingerprint

    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption())
    key_file = tmp_path / "id"
    key_file.write_bytes(pem)
    fp = check_private_key(str(key_file), "test key")
    assert fp.startswith("SHA256:")
    pub = key.public_key().public_bytes(
        serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
    assert public_key_fingerprint(pub.decode()) == fp  # halves agree
    with pytest.raises(ValueError, match="unusable"):
        bad = tmp_path / "bad"
        bad.write_text("not a key")
        check_private_key(str(bad), "test key")
    with pytest.raises(ValueError, match="unusable"):
        check_private_key(str(tmp_path / "absent"), "test key")


def test_production_rejects_unparseable_private_keys(tmp_path):
    from srplatform.settings import Settings, validate_production
    base = dict(
        sr_env="production",
        postgres_url="postgresql+psycopg2://a:b@h/db",
        postgres_url_owner="postgresql+psycopg2://o:b@h/db",
        broker_url="https://b:8443", broker_tls_ca_file="/x/ca",
        broker_client_cert="/x/c", broker_client_key="/x/k",
        runner_transport="ssh", runner_ssh_target="r@10.66.0.9",
        runner_ssh_known_hosts="/x/kh",
        bastion_targets_known_hosts="/x/bkh",
        verifier_ssh_known_hosts="/x/vkh",
        api_base_url="https://api.range.internal",
        telemetry_ca_file="/x/api-ca.crt")
    bad = tmp_path / "badkey"
    bad.write_text("garbage")
    with pytest.raises(RuntimeError, match="verifier key"):
        validate_production(Settings(_env_file=None,
                                     verifier_ssh_key_path=str(bad), **base))


def test_template_manifest_records_baked_key_fingerprints():
    src = (pathlib_repo / "infra/images/pve_template_build.py").read_text()
    assert "baked_key_fingerprints" in src
    assert "public_key_fingerprint" in src
