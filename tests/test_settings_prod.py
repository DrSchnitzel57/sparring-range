"""F23 + milestone 02: production mode fails CLOSED on misconfiguration,
with ROLE-SCOPED validation (worker/controller/broker). The controller must
NOT hold hypervisor credentials — only the broker does — and must present
mutual-TLS
client material. The operator-side half is the LIVE GATE list in
docs/FINDINGS_CHECKLIST.md."""
import pytest

from srplatform.settings import Settings


def _make_real_key() -> str:
    """A REAL parseable OpenSSH private key: production validation
    parse-checks configured keys (plan 13 phase 4), so the "correct
    config" fixture must ship real material."""
    import tempfile
    from pathlib import Path

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
    key = ed25519.Ed25519PrivateKey.generate()
    f = Path(tempfile.mkdtemp()) / "verifier"
    f.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption()))
    return str(f)


_REAL_KEY = _make_real_key()


def _prod(**overrides):
    base = dict(
        sr_env="production",
        postgres_url="postgresql+psycopg2://sr_app:real@db/sr",
        postgres_url_owner="postgresql+psycopg2://sr_owner:real@db/sr",
        broker_url="https://broker.lab:8443",
        broker_client_cert="/etc/sr/broker-client.pem",
        broker_client_key="/etc/sr/broker-client.key",
        broker_tls_ca_file="/etc/sr/broker-ca.pem",
        runner_transport="ssh", runner_ssh_target="runner@10.66.0.9",
        runner_ssh_key_path="/etc/sr/runner", runner_ssh_known_hosts="/etc/sr/kh",
        verifier_ssh_key_path=_REAL_KEY,
        verifier_ssh_known_hosts="/etc/sr/vkh",
        bastion_targets_known_hosts="/etc/sr/tkh",
        # plan 13 phase 4: guests dial HTTPS with a provisioned trust anchor
        api_base_url="https://api.range.internal",
        telemetry_ca_file="/etc/sr/api-ca.crt",
    )
    base.update(overrides)
    return Settings(_env_file=None, **base)


def _broker(**overrides):
    base = dict(
        sr_env="production",
        broker_policy_file="/etc/sr/broker-policy.json",
        broker_server_cert="/etc/sr/broker-server.pem",
        broker_server_key="/etc/sr/broker-server.key",
        broker_tls_ca_file="/etc/sr/broker-ca.pem",
    )
    base.update(overrides)
    return Settings(_env_file=None, **base)


def test_production_accepts_a_correct_config(monkeypatch):
    from srplatform import settings as s
    _ = _prod().sr_env          # constructible
    s.validate_production(_prod())   # no raise
    s.validate_production(_broker(), role="broker")   # broker validates itself


def test_production_rejects_placeholders_and_insecurities():
    from srplatform.settings import validate_production
    bad = {
        "missing broker URL": dict(broker_url=None),
        "missing client cert": dict(broker_client_cert=""),
        "local runner": dict(runner_transport="local-dev"),
        "runtime nft datapath": dict(datapath_controller="nft"),
        "unpinned runner keys": dict(runner_ssh_known_hosts=""),
        # plan 13 phase 4: telemetry trust is mandatory in production
        "plain-http guest API": dict(api_base_url="http://api.range.internal"),
        "localhost guest API": dict(api_base_url="https://localhost"),
        "no trust anchor": dict(telemetry_ca_file=None),
    }
    for label, over in bad.items():
        with pytest.raises(RuntimeError, match="production config invalid"):
            validate_production(_prod(**over))
        assert label


def test_production_broker_role_requires_its_own_boundary():
    from srplatform.settings import validate_production
    bad = {
        "no policy": dict(broker_policy_file=None),
        "no server cert": dict(broker_server_cert=None),
        "no CA": dict(broker_tls_ca_file=None),
    }
    for label, over in bad.items():
        with pytest.raises(RuntimeError, match="production BROKER config invalid"):
            validate_production(_broker(**over), role="broker")
        assert label


def test_unknown_role_is_rejected():
    from srplatform.settings import validate_production
    with pytest.raises(RuntimeError, match="unknown SR_PROCESS_ROLE"):
        validate_production(_prod(), role="imposter")


def test_dev_mode_is_not_silently_strict_or_lax_about_mode():
    # dev constructs with dev defaults; mode string is authoritative
    s = Settings(_env_file=None, sr_env="dev")
    assert s.sr_env == "dev"
