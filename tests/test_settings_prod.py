"""F23: production mode fails CLOSED on misconfiguration (automatable half;
the operator-side half is the LIVE GATE list in docs/FINDINGS_CHECKLIST.md)."""
import pytest

from srplatform.settings import Settings


def _prod(**overrides):
    base = dict(
        sr_env="production",
        postgres_url="postgresql+psycopg2://sr_app:real@db/sr",
        postgres_url_owner="postgresql+psycopg2://sr_owner:real@db/sr",
        proxmox_host="pve.lab", proxmox_token_id="auto!sparring",
        proxmox_token_secret="real-secret", proxmox_tls_ca_file="/etc/pve.pem",
        runner_transport="ssh", runner_ssh_target="runner@10.66.0.9",
        runner_ssh_key_path="/etc/sr/runner", runner_ssh_known_hosts="/etc/sr/kh",
        verifier_ssh_key_path="/etc/sr/verifier",
        bastion_targets_known_hosts="/etc/sr/tkh",
    )
    base.update(overrides)
    return Settings(_env_file=None, **base)


def test_production_accepts_a_correct_config(monkeypatch):
    from srplatform import settings as s
    monkeypatch.delenv("PROXMOX_INSECURE_LAB_OVERRIDE", raising=False)
    _ = _prod().sr_env          # constructible
    s.validate_production(_prod())   # no raise


def test_production_rejects_placeholders_and_insecurities():
    from srplatform.settings import validate_production
    bad = {
        "empty proxmox token": dict(proxmox_token_secret=""),
        "TLS bypass": dict(proxmox_insecure_lab_override=True),
        "local runner": dict(runner_transport="local-dev"),
        "unpinned runner keys": dict(runner_ssh_known_hosts=""),
    }
    for label, over in bad.items():
        with pytest.raises(RuntimeError, match="production config invalid"):
            validate_production(_prod(**over))
        assert label


def test_dev_mode_is_not_silently_strict_or_lax_about_mode():
    # dev constructs with dev defaults; mode string is authoritative
    s = Settings(_env_file=None, sr_env="dev")
    assert s.sr_env == "dev"
