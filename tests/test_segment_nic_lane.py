"""Segment lane: closed multi-NIC validation (broker + appliance policy).

The v1 single-NIC policy must stay byte-identical (existing installs are
frozen contract), and the v2 segment lane may only ever attach guests to
ENUMERATED bridges with addresses inside ENUMERATED segment CIDRs — no
gateway, no tag tricks, no foreign bridges, no NIC count beyond max_nics.
Infrastructure-free: this is the allow-list boundary itself.
"""
from __future__ import annotations

import pytest

from infra.broker.errors import PolicyViolation
from infra.broker.policy import BrokerPolicy
from infra.appliance.policy import AppliancePolicy

SEGMENTS = [
    {"name": "inside-lan", "bridge": "sr-inside", "cidr": "172.20.240.0/24"},
    {"name": "transit", "bridge": "sr-transit", "cidr": "172.16.0.0/24"},
    {"name": "team", "bridge": "sr-team", "cidr": "172.17.0.0/24"},
]


def _broker_policy(**over):
    raw = {
        "node": "r740",
        "templates": [9011],
        "vmid_range": [200, 999],
        "storage": ["local-zfs"],
        "clone_mode": "full",
        "nic": {"bridge": "vmbr1", "vlan": 66},
        "provision": {"cidr": "10.66.0.0/24", "gateway": "10.66.0.1"},
        "limits": {"max_vms": 16},
        "segments": SEGMENTS,
        "max_nics": 3,
    }
    raw.update(over)
    return BrokerPolicy.from_dict(raw)


# ------------------------------------------------------------------- v1 lock --
def test_v1_policy_unchanged():
    from infra.broker.testing import make_test_policy
    p = make_test_policy()
    assert p.segments is None and p.max_nics == 1
    assert p.allowed_config_keys == frozenset({"ipconfig0", "net0", "tags", "name"})
    with pytest.raises(PolicyViolation):
        p.check_config_keys({"net1": "virtio,bridge=br0"})
    # the classic exact-NIC equality still rules net0
    p.check_net0("virtio,bridge=vmbr1,tag=66")
    with pytest.raises(PolicyViolation):
        p.check_net0("virtio,bridge=vmbr1,tag=67")


def test_max_nics_requires_segments():
    from infra.broker.testing import make_test_policy
    with pytest.raises(PolicyViolation, match="requires a segments list"):
        make_test_policy(max_nics=2)


# ------------------------------------------------------------------- v2 lane --
def test_segment_load_rules():
    p = _broker_policy()
    assert {s.name for s in p.segments} == {"inside-lan", "transit", "team"}
    assert "net2" in p.allowed_config_keys and "net3" not in p.allowed_config_keys
    for bad, needle in [
        ({"segments": [*SEGMENTS, dict(SEGMENTS[0], bridge="sr-dup")]}, "overlaps"),
        ({"segments": [dict(SEGMENTS[0], bridge="sr-inside"),
                       dict(SEGMENTS[1], bridge="sr-inside")]}, "duplicated"),
        ({"segments": [dict(SEGMENTS[0], bridge="vmbr1")]}, "provision bridge"),
        ({"segments": [dict(SEGMENTS[0], name="Inside_LAN")]}, "safe segment name"),
        ({"segments": [{"name": "x1", "bridge": "b", "cidr": "10.66.0.0/16",
                        "extra": 1}]}, "keys must be exactly"),
        ({"segments": [dict(SEGMENTS[0], cidr="172.20.240.0/31")], "max_nics": 1},
         "/<=30"),
        ({"segments": [dict(SEGMENTS[0], cidr="10.66.0.128/25")], "max_nics": 1},
         "overlaps the provision network"),
        ({"segments": SEGMENTS, "max_nics": 4}, "cannot exceed"),
        ({"segments": []}, "non-empty"),
    ]:
        with pytest.raises(PolicyViolation) as exc:
            _broker_policy(**bad)
        assert needle in str(exc.value), (needle, exc.value)


def test_segment_nic_and_address_checks():
    p = _broker_policy()
    p.check_nic_index(1, "virtio,bridge=sr-transit")
    p.check_nic_index(2, "virtio,bridge=sr-team")
    with pytest.raises(PolicyViolation, match="exact approved"):
        p.check_nic_index(1, "virtio,bridge=br0")
    with pytest.raises(PolicyViolation, match="exact approved"):
        p.check_nic_index(1, "virtio,bridge=sr-team,tag=7")
    with pytest.raises(PolicyViolation, match="outside the approved NIC lane"):
        p.check_nic_index(3, "virtio,bridge=sr-team")
    # net0 may now also be a segment bridge
    p.check_net0("virtio,bridge=sr-inside")

    p.check_ipconfig_index(1, "ip=172.16.0.5/24")
    with pytest.raises(PolicyViolation, match="prefix"):
        p.check_ipconfig_index(1, "ip=172.16.0.5/16")
    with pytest.raises(PolicyViolation, match="outside every"):
        p.check_ipconfig_index(1, "ip=10.99.0.5/24")
    with pytest.raises(PolicyViolation):
        p.check_ipconfig_index(1, "ip=172.16.0.5/24,gw=172.16.0.1")
    with pytest.raises(PolicyViolation, match="network/broadcast"):
        p.check_ipconfig_index(1, "ip=172.16.0.0/24")
    # ipconfig0 follows the same segment discipline
    p.check_ipconfig("ip=172.20.240.10/24")
    with pytest.raises(PolicyViolation, match="outside every"):
        p.check_ipconfig("ip=10.66.0.9/24")


def test_service_set_config_wires_the_lane():
    """The REAL BrokerService path (policy -> ledger -> fake backend) accepts
    a 3-NIC config on approved segments and refuses a foreign bridge
    WITHOUT ever reaching the backend."""
    from infra.broker.testing import make_fake_broker

    client, _service, http = make_fake_broker(policy=_broker_policy())
    client.clone_and_wait("r740", 9011, 210, "sr-labvm", full=True,
                          session_id="s1")
    client.set_config("r740", 210, session_id="s1",
                      net0="virtio,bridge=sr-inside", ipconfig0="ip=172.20.240.10/24",
                      net1="virtio,bridge=sr-transit", ipconfig1="ip=172.16.0.254/24",
                      net2="virtio,bridge=sr-team", ipconfig2="ip=172.17.0.1/24")
    cfg = http.vms[210].get("config", {})
    assert cfg.get("ipconfig2") == "ip=172.17.0.1/24"
    before = dict(cfg)
    with pytest.raises(PolicyViolation, match="not provisionable"):
        client.set_config("r740", 210, session_id="s1",
                          net3="virtio,bridge=br0")
    with pytest.raises(PolicyViolation, match="not provisionable"):
        client.set_config("r740", 210, session_id="s1",
                          ipconfig3="ip=10.0.0.1/24")
    with pytest.raises(PolicyViolation):
        client.set_config("r740", 210, session_id="s1",
                          net1="virtio,bridge=sr-transit,tag=99")
    assert dict(http.vms[210].get("config", {})) == before  # refusals wrote nothing


# ------------------------------------------------------------------ appliance --
def _appliance_policy(**over):
    raw = {
        "node": "4f0e7a1c-8a59-4a4e-9b5d-74f0e7a1c111",
        "templates": [9005, 9011, 9012],
        "vmid_range": [200, 999],
        "storage": ["appliance-local"],
        "clone_mode": "full",
        "nic": {"bridge": "srlab0"},
        "provision": {"cidr": "10.66.0.0/24", "gateway": "10.66.0.1"},
        "limits": {"max_vms": 16},
        "segments": SEGMENTS,
        "max_nics": 3,
    }
    raw.update(over)
    return AppliancePolicy.from_dict(raw)


def test_appliance_segment_lane():
    p = _appliance_policy()
    p.check_nic_index(1, "virtio,bridge=sr-inside")
    p.check_net0("virtio,bridge=sr-transit")
    with pytest.raises(PolicyViolation, match="exact approved"):
        p.check_nic_index(1, "virtio,bridge=srlab0")
    p.check_ipconfig("ip=172.17.0.2/24")
    with pytest.raises(PolicyViolation, match="outside every"):
        p.check_ipconfig("ip=10.66.0.9/24")
    # v1 appliance policy (no segments) refuses indexed keys
    legacy = _appliance_policy()
    raw_ok = AppliancePolicy.from_dict({
        "node": "4f0e7a1c-8a59-4a4e-9b5d-74f0e7a1c111",
        "templates": [9005], "vmid_range": [200, 999],
        "storage": ["appliance-local"], "clone_mode": "full",
        "nic": {"bridge": "srlab0"},
        "provision": {"cidr": "10.66.0.0/24", "gateway": "10.66.0.1"},
        "limits": {"max_vms": 6}})
    with pytest.raises(PolicyViolation):
        raw_ok.check_config_keys({"net1": "virtio,bridge=sr-inside"})
    assert legacy.max_nics == 3


def test_manifest_segment_validation(tmp_path):
    from infra.appliance.manifest import ApplianceManifest, ManifestError
    from tests.test_appliance_contract import _manifest
    raw = _manifest(tmp_path, verify_files=True)
    raw["network"]["segments"] = [
        {"name": "range", "cidr": "10.66.0.0/24", "bridge": "srlab0"},
        {"name": "inside-lan", "cidr": "172.20.240.0/24", "bridge": "sr-inside"},
        {"name": "transit", "cidr": "172.16.0.0/24", "bridge": "sr-transit"},
    ]
    raw["network"]["max_nics"] = 3
    m = ApplianceManifest.from_dict(raw, verify_images=True, verify_model_key=False)
    assert {s.name for s in m.network.segments} == \
        {"range", "inside-lan", "transit"}
    assert "sr-inside" in str(m.redacted())

    # appliance policy derives from the manifest (range segment present —
    # without it from_manifest refuses; see segment-lane-render tests)
    pol = AppliancePolicy.from_manifest(m)
    assert pol.segments and pol.max_nics == 3

    for mutate, needle in [
        (lambda d: d["network"]["segments"].append(
            {"name": "dup", "cidr": "172.20.240.128/25", "bridge": "sr-x"}),
         "overlaps"),
        (lambda d: d["network"]["segments"].append(
            {"name": "sneak", "cidr": "172.30.0.0/24", "bridge": "srlab0"}),
         "range_bridge"),
        (lambda d: d["network"].__setitem__("max_nics", 4), "cannot exceed"),
        (lambda d: d["network"]["segments"].append(
            {"name": "Inside", "cidr": "10.9.0.0/24", "bridge": "sr-y"}),
         "safe segment name"),
    ]:
        bad = _manifest(tmp_path, verify_files=True)
        bad["network"]["segments"] = list(raw["network"]["segments"][:2])
        bad["network"]["max_nics"] = 2
        mutate(bad)
        with pytest.raises(ManifestError) as exc:
            ApplianceManifest.from_dict(bad, verify_images=True, verify_model_key=False)
        assert needle in str(exc.value), (needle, str(exc.value))
