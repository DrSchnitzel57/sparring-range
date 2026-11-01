"""Segment-lane authority from manifest to boot — the rendering gap.

The env lane is only real on the appliance if the segment lane SURVIVES
`render_policy` (manifest -> broker policy file), `AppliancePolicy.load`
and the boot-time `validate_manifest` cross-check. Before this test existed
the renderer silently DROPPED segments/max_nics: a segment-declaring
install booted a v1-only broker that then refused its own blueprint deploys
after the first clone. Proven end to end here, plus the two rules the lane
depends on:

  * the range network is declarable as a segment (range bridge + range
    CIDR only) — the closed address vocabulary then INCLUDES the flat
    lane, so declaring a lane never orphans v1 deploys;
  * a stale rendered policy (missing/changed segments) is a boot refusal,
    per the cross-check's own docstring;
  * the manifest->catalog mapping (profile -> template) is real
    authority: profiles resolve, default to role, duplicate refuse.
"""
from __future__ import annotations

import pytest

from infra.appliance.manifest import ApplianceManifest
from infra.appliance.policy import AppliancePolicy
from infra.broker.errors import PolicyViolation
from tests.test_appliance_contract import _manifest

SEG_LANE = [
    {"name": "range", "bridge": "srlab0", "cidr": "10.66.0.0/24"},
    {"name": "team", "bridge": "sr-team", "cidr": "172.17.0.0/24"},
    {"name": "transit", "bridge": "sr-transit", "cidr": "172.16.0.0/24"},
]


def _segmented(tmp_path, segments=None, max_nics=3) -> ApplianceManifest:
    tmp_path.mkdir(parents=True, exist_ok=True)
    raw = _manifest(tmp_path, verify_files=True)
    raw["network"]["segments"] = SEG_LANE if segments is None else segments
    raw["network"]["max_nics"] = max_nics
    return ApplianceManifest.from_dict(raw, verify_images=True,
                                       verify_model_key=False)


# ----------------------------------------------------- render -> load -> boot --
def test_render_policy_round_trips_the_segment_lane(tmp_path):
    from deploy.appliance import render_policy
    m = _segmented(tmp_path)
    derived = AppliancePolicy.from_manifest(m)
    text = render_policy(m)
    path = tmp_path / "broker-policy.json"
    path.write_text(text)
    loaded = AppliancePolicy.load(path)
    assert [(s.name, s.bridge, str(s.network)) for s in loaded.segments] == \
           [(s.name, s.bridge, str(s.network)) for s in derived.segments]
    assert loaded.max_nics == 3
    loaded.validate_manifest(m)  # exactly what brokerd.build does at boot
    # and the lane is LIVE on the loaded policy, not just present:
    from infra.broker.policy import check_nic_vector
    check_nic_vector(loaded, {
        "net0": "virtio,bridge=sr-team", "ipconfig0": "ip=172.17.0.9/24"},
        [{"segment": "team", "address": "172.17.0.9"}])


def test_declaring_segments_without_the_range_refuses_with_the_fix(tmp_path):
    raw = _manifest(tmp_path, verify_files=True)
    raw["network"]["segments"] = SEG_LANE[1:]  # range lane missing
    raw["network"]["max_nics"] = 2
    m = ApplianceManifest.from_dict(raw, verify_images=True,
                                    verify_model_key=False)
    with pytest.raises(PolicyViolation, match="add.*range"):
        AppliancePolicy.from_manifest(m)


def test_stale_rendered_policy_refused_at_boot(tmp_path):
    """The cross-check's promise: a manifest edit that was never re-rendered
    refuses boot rather than silently serving the old lane."""
    old = AppliancePolicy.from_manifest(_segmented(tmp_path / "old", segments=[], max_nics=1))
    new = _segmented(tmp_path / "new")

    def _seg_of(p):
        return [(s.name, s.bridge, str(s.network)) for s in (p.segments or ())]

    assert _seg_of(old) == []
    with pytest.raises(PolicyViolation, match="segment lane"):
        old.validate_manifest(new)
    # and vice versa: dropping segments from the manifest is drift too
    new_policy = AppliancePolicy.from_manifest(new)
    with pytest.raises(PolicyViolation, match="segment lane"):
        new_policy.validate_manifest(_segmented(tmp_path / "old", segments=[], max_nics=1))


def test_max_nics_drift_refused(tmp_path):
    old = AppliancePolicy.from_manifest(_segmented(tmp_path / "a", max_nics=2))
    new = _segmented(tmp_path / "b", max_nics=3)
    with pytest.raises(PolicyViolation, match="max_nics"):
        old.validate_manifest(new)


# ----------------------------------------------------------- flat-lane parity --
def test_flat_lane_still_deploys_under_a_segment_lane(tmp_path):
    """v1 flat guests live INSIDE the lane: the range segment keeps their
    addresses and net0 valid once check_ipconfig delegates."""
    p = AppliancePolicy.from_manifest(_segmented(tmp_path))
    p.check_ipconfig("ip=10.66.0.9/24")     # v1 pool address, /24 exact
    p.check_net0("virtio,bridge=srlab0")    # historical flat attach
    with pytest.raises(PolicyViolation, match="outside every"):
        p.check_ipconfig("ip=172.99.0.9/24")
    with pytest.raises(PolicyViolation, match="prefix"):
        p.check_ipconfig("ip=10.66.0.9/16")


def test_range_bridge_only_carries_the_range_network(tmp_path):
    raw = _manifest(tmp_path, verify_files=True)
    raw["network"]["segments"] = [
        {"name": "sneaky", "bridge": "srlab0", "cidr": "172.30.0.0/24"}]
    raw["network"]["max_nics"] = 2
    with pytest.raises(Exception, match="range_bridge"):
        ApplianceManifest.from_dict(raw, verify_images=True,
                                    verify_model_key=False)


# --------------------------------------------------- manifest catalog authority --
def test_manifest_catalog_is_the_profile_authority(tmp_path):
    raw = _manifest(tmp_path, verify_files=True)
    raw["images"]["attacker"]["profile"] = "kali-rolling"
    m = ApplianceManifest.from_dict(raw, verify_images=True,
                                    verify_model_key=False)
    cat = m.template_catalog()
    assert {"profile": "kali-rolling", "template_id": 9005,
            "role": "attacker"} in cat
    assert {c["profile"] for c in cat} == {
        "kali-rolling", "mojang-web-local", "mojang-web-db"}  # default = role
    assert m.image_for_profile("kali-rolling").role == "attacker"
    assert m.image_for_profile("attacker") is None  # explicit profile replaces it
    dup = _manifest(tmp_path, verify_files=True)
    dup["images"]["attacker"]["profile"] = "mojang-web-local"
    with pytest.raises(Exception, match="duplicate image profile"):
        ApplianceManifest.from_dict(dup, verify_images=True,
                                    verify_model_key=False)
