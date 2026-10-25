"""Plan 18 second review — the clone authority owns artifact identity
(findings 2 and 6).

The API used to resolve the deployed artifact by RE-READING the on-disk
appliance manifest at clone time — a different object than the broker's
own loaded manifest — so a config swap between broker start and deploy
recorded bytes the broker would never deploy; and the setting that path
depended on (SR_APPLIANCE_MANIFEST_FILE) was never rendered into the API
environment, so on the real appliance the resolver silently returned
nothing. The fix moves the answer to the typed broker boundary:
the adapter that verifies the clone image reports the identity, the
service validates the shape, and the deploy path freezes only what the
broker confirms. No manifest path, secret, or libvirt access crosses the
boundary; absence is honest UNKNOWN.
"""
from __future__ import annotations

import pathlib

import pytest

from infra.dev import install_sequences as seq

SHA_A = "a" * 64


def _manifest(tmp_path):
    from infra.appliance.manifest import ApplianceManifest
    return ApplianceManifest.load(seq.build_manifest(tmp_path / "m"))


def _broker(tmp_path, adapter=None):
    from infra.proxmox_client import FakePVEHttp
    from infra.broker.testing import make_broker_over, policy_from_settings
    from srplatform.settings import get_settings
    client, service = make_broker_over(
        FakePVEHttp(), policy=policy_from_settings(get_settings()),
        ledger_path=str(tmp_path / "ledger.sqlite3"))
    if adapter is not None:
        service.pve = adapter
    return client, service


# --------------------------------------------------------------------------- #
# the manifest answers for its OWN loaded state (no disk re-read)               #
# --------------------------------------------------------------------------- #

def test_manifest_identity_comes_from_loaded_state_not_the_disk(tmp_path):
    from infra.appliance.backend import LibvirtBackend
    m = _manifest(tmp_path)
    backend = LibvirtBackend(m, policy=None, config=None)
    spec = next(iter(m.images.values()))
    art = backend.artifact_for_template(spec.template_id)
    assert art == {"role": spec.role, "template_vmid": spec.template_id,
                   "artifact_sha256": spec.sha256}
    # replace the manifest ON DISK (a newer, different release): the
    # loaded object the broker clones from still answers the old truth
    path = tmp_path / "m" / "appliance-manifest.json"
    candidates = [p for p in (tmp_path / "m").rglob("*.json")
                  if "manifest" in p.name]
    assert candidates
    candidates[0].write_text(candidates[0].read_text().replace(
        spec.sha256, SHA_A))
    assert backend.artifact_for_template(spec.template_id)["artifact_sha256"] \
        != SHA_A
    # an unapproved template is None, never a guess
    assert backend.artifact_for_template(999999) is None


# --------------------------------------------------------------------------- #
# the typed boundary validates and never invents                                #
# --------------------------------------------------------------------------- #

class _Adapter:
    def __init__(self, reply):
        self._reply = reply

    def artifact_for_template(self, template_vmid):
        return self._reply


def test_boundary_validates_identity_and_refuses_junk(tmp_path):
    m = _manifest(tmp_path)
    spec = next(iter(m.images.values()))
    good = {"role": spec.role, "template_vmid": spec.template_id,
            "artifact_sha256": spec.sha256}
    client, _service = _broker(tmp_path, _Adapter(good))
    # the client method is exposed over the boundary at all
    from infra.broker.server import CONTROL_OPS
    assert "artifact_for_template" in CONTROL_OPS
    assert client.artifact_for_template(spec.template_id) == good
    # a reply naming ANOTHER template is refused (swapped answer)
    from infra.broker.service import BrokerService
    for bad in (
        {**good, "template_vmid": spec.template_id + 1},
        {**good, "artifact_sha256": spec.sha256.upper()},
        {**good, "artifact_sha256": 12345},
        {**good, "template_vmid": True},
        {**good, "role": True},
        {"role": spec.role},
        None,
    ):
        client, _svc = _broker(tmp_path, _Adapter(bad))
        assert client.artifact_for_template(spec.template_id) is None


def test_adapter_without_identity_capability_is_unknown_not_error(tmp_path):
    """Legacy PVE adapters have no artifact manifest: the boundary says
    None (cron checks then stay UNKNOWN) and never fabricates an identity
    from, say, the VM template name."""
    client, _service = _broker(tmp_path)      # plain ProxmoxClient
    assert client.artifact_for_template(9001) is None


# --------------------------------------------------------------------------- #
# the un-wired API-side resolver is gone (finding 6)                            #
# --------------------------------------------------------------------------- #

def test_api_env_carries_no_manifest_knob_and_settings_has_none(tmp_path):
    from deploy import appliance as ap
    from infra.appliance.manifest import ApplianceManifest
    from srplatform.settings import get_settings
    m = ApplianceManifest.load(seq.build_manifest(tmp_path / "m"))
    control = ap.render_control_env(m, etc=pathlib.Path("/etc/sparring-range"))
    assert "SR_APPLIANCE_MANIFEST" not in control, \
        "the API must not receive an operator-manifest path"
    # the BROKER (the clone authority) does, and only it
    broker_env = ap.render_broker_env(m, etc=pathlib.Path("/etc/sparring-range"))
    assert "SR_APPLIANCE_MANIFEST=" in broker_env
    assert not hasattr(get_settings(), "appliance_manifest_file")
    import srplatform.verification_service as vs
    assert not hasattr(vs, "resolve_deployed_cron_artifact")
    # nothing in the shipped deployment code references the removed knob
    root = pathlib.Path(__file__).resolve().parents[1]
    for f in (root / "deploy" / "appliance.py",
              root / "srplatform" / "settings.py",
              root / "srplatform" / "verification_service.py"):
        assert "SR_APPLIANCE_MANIFEST_FILE" not in f.read_text()
        assert "appliance_manifest_file" not in f.read_text()


def test_recorded_cron_artifact_shape_is_strict(tmp_path):
    """Deploy-side normalization refuses any shape the broker must not
    have produced, and freezes a baseline ONLY from a pin binding the
    exact identity."""
    import infra.images.cron_baseline as cb
    import srplatform.verification_service as vs
    good = {"role": "mojang-web-local", "template_vmid": 9011,
            "artifact_sha256": "a" * 64}
    assert vs.recorded_cron_artifact(None, {}) == {}
    assert vs.recorded_cron_artifact({**good, "role": True}, {}) == {}
    assert vs.recorded_cron_artifact(
        {**good, "artifact_sha256": "A" * 64}, {}) == {}
    assert vs.recorded_cron_artifact({**good, "template_vmid": "9011"},
                                     {}) == {}
    # no pins binding it → identity WITHOUT a baseline (honest UNKNOWN)
    assert vs.recorded_cron_artifact(good, {}) == good
    pin = cb.build_pin("mojang-web-local", artifact_sha256="a" * 64,
                       artifact_version="v1", template_id=9011,
                       capture={"files": {"e2scrub_all": "b" * 64},
                                "root_crontab_sha256": None})
    art = vs.recorded_cron_artifact(good, {"mojang-web-local": pin})
    assert art["baseline"]["files"] == {"e2scrub_all": "b" * 64}
    assert art["baseline"]["baseline_sha256"] == cb.baseline_digest(
        {"e2scrub_all": "b" * 64}, None)
    # a pin for a different digest freezes NOTHING
    assert "baseline" not in vs.recorded_cron_artifact(
        {**good, "artifact_sha256": "c" * 64}, {"mojang-web-local": pin})
