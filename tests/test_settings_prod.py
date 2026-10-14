"""F23 + milestone 02: production mode fails CLOSED on misconfiguration,
with ROLE-SCOPED validation (worker/controller/broker). The controller must
NOT hold PVE credentials — only the broker does — and must present mutual-TLS
client material. The operator-side half is the LIVE GATE list in
docs/FINDINGS_CHECKLIST.md."""
import pytest

from srplatform.settings import Settings


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
        verifier_ssh_key_path="/etc/sr/verifier",
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
        proxmox_host="pve.lab", proxmox_token_id="auto!sparring",
        proxmox_token_secret="real-secret", proxmox_tls_ca_file="/etc/pve.pem",
    )
    base.update(overrides)
    return Settings(_env_file=None, **base)


def test_production_accepts_a_correct_config(monkeypatch):
    from srplatform import settings as s
    monkeypatch.delenv("PROXMOX_INSECURE_LAB_OVERRIDE", raising=False)
    _ = _prod().sr_env          # constructible
    s.validate_production(_prod())   # no raise
    s.validate_production(_broker(), role="broker")   # broker validates itself


def test_production_rejects_placeholders_and_insecurities():
    from srplatform.settings import validate_production
    bad = {
        "missing broker URL": dict(broker_url=None),
        "missing client cert": dict(broker_client_cert=""),
        "PVE token on the controller": dict(proxmox_token_id="auto!sparring",
                                            proxmox_token_secret="leaked"),
        "TLS bypass": dict(proxmox_insecure_lab_override=True),
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
        "no PVE token": dict(proxmox_token_secret=""),
        "TLS bypass": dict(proxmox_insecure_lab_override=True),
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
