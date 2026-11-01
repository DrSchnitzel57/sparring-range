"""NIC-vector authority: the closed plan a guest's interfaces MUST match.

test_segment_nic_lane.py guards the per-field allow-list; this file guards the
layer added for environment deploys — the COMPLETE effective vector:

  * check_nic_vector binds each address to the segment of the bridge at the
    SAME index, pins the exact NIC count (patched-on-existing configs cannot
    smuggle an unplanned NIC), and refuses duplicate segments/addresses;
  * check_effective_nics compares a plan against an XML-derived reality read
    (count, order, per-index bridge, MAC shape/uniqueness) — never the
    claimed description;
  * per-NIC MACs are deterministic, index 0 stays byte-identical to the
    historical seed, and additional indices never reuse another MAC;
  * the multi-NIC seed binds addresses to NICs BY MAC, so an address cannot
    drift onto the wrong bridge, while single-NIC guests render the exact
    historical seed.
Infrastructure-free: pure policy + XML/seed codec.
"""
from __future__ import annotations

import ipaddress

import pytest

from infra.broker.errors import PolicyViolation
from infra.broker.policy import check_effective_nics, check_nic_vector

from tests.test_segment_nic_lane import SEGMENTS, _broker_policy

PLAN = [
    {"segment": "inside-lan", "address": "172.20.240.10"},
    {"segment": "transit", "address": "172.16.0.5"},
    {"segment": "team", "address": "172.17.0.77"},
]


def _cfg_for(plan):
    cfg = {}
    for i, spec in enumerate(plan):
        seg = next(s for s in SEGMENTS if s["name"] == spec["segment"])
        net = ipaddress.ip_network(seg["cidr"])
        cfg[f"net{i}"] = f"virtio,bridge={seg['bridge']}"
        cfg[f"ipconfig{i}"] = f"ip={spec['address']}/{net.prefixlen}"
    return cfg


def _mutate(cfg, key, value):
    out = dict(cfg)
    if value is None:
        out.pop(key, None)
    else:
        out[key] = value
    return out


# ------------------------------------------------------------ check_nic_vector --
def test_exact_vector_passes():
    check_nic_vector(_broker_policy(), _cfg_for(PLAN), PLAN)


def test_vector_without_segment_lane_refused():
    from infra.broker.testing import make_test_policy
    with pytest.raises(PolicyViolation, match="no segment lane"):
        check_nic_vector(make_test_policy(), {"net0": "virtio,bridge=vmbr1"},
                         [{"segment": "team", "address": "172.17.0.7"}])


@pytest.mark.parametrize("idx", [0, 1, 2])
def test_bridge_with_foreign_segments_address_refused(idx):
    """Approved bridge A + segment B's address is the central cross-wire."""
    cfg = _cfg_for(PLAN)
    other = {0: ("transit", "172.16.0.5"), 1: ("team", "172.17.0.77"),
             2: ("inside-lan", "172.20.240.10")}[idx]
    cfg[f"ipconfig{idx}"] = f"ip={other[1]}/24"
    with pytest.raises(PolicyViolation, match="DIFFERENT segment"):
        check_nic_vector(_broker_policy(), cfg, PLAN)


def test_bridge_not_exact_for_index_refused():
    cfg = _cfg_for(PLAN)
    cfg["net1"] = "virtio,bridge=sr-team"  # index-swap shape
    with pytest.raises(PolicyViolation, match="does not equal the exact"):
        check_nic_vector(_broker_policy(), cfg, PLAN)


def test_duplicate_segment_and_duplicate_address_refused():
    dup_seg = [PLAN[0], dict(PLAN[1], address="172.16.0.9"),
               {"segment": "inside-lan", "address": "10.9.9.9"}]
    with pytest.raises(PolicyViolation, match="appears twice"):
        check_nic_vector(_broker_policy(), _cfg_for(dup_seg), dup_seg)
    dup_addr = [PLAN[0], dict(PLAN[1], address="172.20.240.10")]
    with pytest.raises(PolicyViolation, match="duplicate address"):
        check_nic_vector(_broker_policy(), _cfg_for(dup_addr), dup_addr)


def test_network_and_broadcast_addresses_refused():
    for host in ("172.20.240.0", "172.20.240.255"):
        plan = [dict(PLAN[0], address=host)]
        with pytest.raises(PolicyViolation, match="network/broadcast"):
            check_nic_vector(_broker_policy(), _cfg_for(plan), plan)


def test_keys_beyond_declared_vector_refused_patched_on_existing():
    """net2/ipconfig2 keys on a 2-NIC plan — the patched-onto-existing-VM
    shape — are an unplanned NIC, never a free patch."""
    plan = PLAN[:2]
    cfg = _cfg_for(plan)
    for extra in ({"net2": "virtio,bridge=sr-team"},
                  {"ipconfig2": "ip=172.17.0.9/24"}):
        with pytest.raises(PolicyViolation, match="exceeds the declared"):
            check_nic_vector(_broker_policy(), {**cfg, **extra}, plan)


def test_missing_and_malformed_entries_refused():
    p = _broker_policy()
    with pytest.raises(PolicyViolation, match="1..3 NIC entries"):
        check_nic_vector(p, _cfg_for(PLAN), [])
    with pytest.raises(PolicyViolation, match="1..3 NIC entries"):
        check_nic_vector(p, _cfg_for(PLAN), [*PLAN, PLAN[0]])
    with pytest.raises(PolicyViolation, match="exactly"):
        check_nic_vector(p, _cfg_for(PLAN), [{"segment": "team",
                                              "address": "172.17.0.7",
                                              "bridge": "sr-team"}])
    bad = [dict(PLAN[0], address="not-an-ip")]
    with pytest.raises(PolicyViolation, match="not an IPv4"):
        check_nic_vector(p, _cfg_for(bad), bad)


# --------------------------------------------------------- check_effective_nics --
def _actual(bridges, macs=None):
    macs = macs or [f"52:54:00:00:00:0{i+1}" for i in range(len(bridges))]
    return {"nics": [{"index": i, "bridge": b, "mac": m}
                     for i, (b, m) in enumerate(zip(bridges, macs))]}


def test_effective_vector_matches_reality_passes():
    actual = _actual([s["bridge"] for s in SEGMENTS])
    check_effective_nics(_broker_policy(), actual, PLAN)


def test_effective_refuses_uncertain_reads():
    p = _broker_policy()
    with pytest.raises(PolicyViolation, match="uncertain"):
        check_effective_nics(p, {"_unavailable": "no XML"}, PLAN)
    with pytest.raises(PolicyViolation, match="recorded intent"):
        check_effective_nics(p, {"_nic_drift": "intent != xml",
                                 "nics": []}, PLAN)
    with pytest.raises(PolicyViolation, match="domain XML"):
        check_effective_nics(p, {"name": "vm"}, PLAN)


def test_effective_refuses_count_and_order_divergence():
    p = _broker_policy()
    with pytest.raises(PolicyViolation, match="interfaces, the plan has"):
        check_effective_nics(p, _actual(["sr-inside", "sr-transit"]), PLAN)
    swapped_order = {"nics": [
        {"index": 1, "bridge": "sr-transit", "mac": "52:54:00:00:00:01"},
        {"index": 0, "bridge": "sr-inside", "mac": "52:54:00:00:00:02"},
        {"index": 2, "bridge": "sr-team", "mac": "52:54:00:00:00:03"}]}
    with pytest.raises(PolicyViolation, match="interface order"):
        check_effective_nics(p, swapped_order, PLAN)


def test_effective_bridge_swap_names_the_other_segment():
    bridges = ["sr-inside", "sr-team", "sr-transit"]  # 1 and 2 swapped
    with pytest.raises(PolicyViolation) as exc:
        check_effective_nics(_broker_policy(), _actual(bridges), PLAN)
    assert "index swap?" in str(exc.value)
    foreign = ["sr-inside", "br9", "sr-team"]
    with pytest.raises(PolicyViolation, match="foreign bridge"):
        check_effective_nics(_broker_policy(), _actual(foreign), PLAN)


def test_effective_refuses_bad_macs():
    p = _broker_policy()
    bridges = [s["bridge"] for s in SEGMENTS]
    with pytest.raises(PolicyViolation, match="malformed"):
        check_effective_nics(p, _actual(bridges, ["52:54:00", "aa", "bb"]),
                             PLAN)
    with pytest.raises(PolicyViolation, match="duplicate mac"):
        check_effective_nics(p, _actual(bridges,
                                        ["52:54:00:00:00:01"] * 3), PLAN)


# ------------------------------------------------------------- backend codecs --
def test_per_nic_macs_deterministic_and_index0_is_historical():
    from infra.appliance.backend import _mac, _nic_mac
    assert _nic_mac("node-a", 210, 0) == _mac("node-a:210")  # v1 byte-exact
    assert _nic_mac("node-a", 210, 1) != _nic_mac("node-a", 210, 0)
    assert _nic_mac("node-a", 210, 1) == _nic_mac("node-a", 210, 1)
    assert _nic_mac("node-a", 211, 1) != _nic_mac("node-a", 210, 1)
    for i in range(3):
        assert _nic_mac("node-a", 210, i) != _nic_mac("node-b", 210, i)


def test_nics_from_xml_reports_every_interface_in_document_order():
    from infra.appliance.backend import LibvirtBackend
    xml = """<domain><devices>
      <interface type='bridge'><mac address='52:54:00:00:00:0A'/>
        <source bridge='sr-inside'/></interface>
      <interface type='bridge'><mac address='52:54:00:00:00:0B'/>
        <source bridge='sr-transit'/></interface>
      <interface type='user'><mac address='52:54:00:00:00:0C'/>
        <source/></interface>
    </devices></domain>"""
    nics = LibvirtBackend._nics_from_xml(xml)
    assert [(n["index"], n["bridge"], n["mac"]) for n in nics] == [
        (0, "sr-inside", "52:54:00:00:00:0a"),
        (1, "sr-transit", "52:54:00:00:00:0b"),
        (2, "", "52:54:00:00:00:0c")]  # fixture user-net: no bridge by design
    assert LibvirtBackend._nics_from_xml("not xml at all") == []


def test_config_from_never_trusts_the_claimed_description():
    """A description CLAIMING one layout while XML shows another is drift —
    reported, never silently reconciled."""
    from infra.appliance.backend import LibvirtBackend
    dom = type("D", (), {"XMLDesc": lambda s, f: (
        "<domain><devices><interface type='bridge'>"
        "<mac address='52:54:00:aa:aa:aa'/>"
        "<source bridge='sr-team'/></interface></devices></domain>"),
        "name": lambda s: "sr-vm", "UUID": lambda s: "u"})()
    backend = object.__new__(LibvirtBackend)  # codecs need no manifest state
    desc = {"vmid": 210, "name": "sr-vm", "net0": "virtio,bridge=sr-inside",
            "nics": [{"index": 0, "bridge": "sr-inside",
                      "mac": "52:54:00:aa:aa:aa"}]}
    cfg = backend._config_from(dom, desc)
    assert "_nic_drift" in cfg
    assert cfg["net0"] == "virtio,bridge=sr-team"  # XML wins over the claim


# ------------------------------------------------------------------ seed lane --
def test_multi_nic_seed_binds_addresses_by_mac(tmp_path):
    import yaml
    from infra.appliance.manifest import ApplianceManifest
    from infra.appliance.policy import AppliancePolicy  # noqa: F401
    from infra.appliance.seed import SeedInputs, render_network_config, \
        render_user_data
    from tests.test_appliance_contract import _manifest

    m = ApplianceManifest.from_dict(_manifest(tmp_path, verify_files=True),
                                    verify_images=True, verify_model_key=False)
    image = m.image_for_role("mojang-web-local")
    nics = (
        {"index": 0, "mac": "52:54:00:00:00:0A", "bridge": "sr-inside",
         "address": "172.20.240.10", "prefix": 24},
        {"index": 1, "mac": "52:54:00:00:00:0B", "bridge": "sr-transit",
         "address": "172.16.0.5", "prefix": 24},
    )
    inp = SeedInputs(manifest=m, image=image, vmid=212,
                     session_id="b" * 32, hostname="edge01",
                     address="172.20.240.10", prefix=24, nics=nics)
    doc = yaml.safe_load(render_network_config(inp))
    eth = doc["ethernets"]
    assert sorted(eth) == ["range-nic-0", "range-nic-1"]
    # THE binding: each address is attached to its planned MAC only.
    by_mac = {e["match"]["macaddress"]: e for e in eth.values()}
    assert by_mac["52:54:00:00:00:0a"]["addresses"] == ["172.20.240.10/24"]
    assert by_mac["52:54:00:00:00:0b"]["addresses"] == ["172.16.0.5/24"]
    assert all(e["dhcp4"] is False for e in eth.values())
    # The auditable in-guest ground truth names MAC → segment/address.
    bindings = render_user_data(inp)
    assert "/etc/sparring-range/nic-bindings" in bindings
    # (the tab-separated lines arrive YAML-escaped; assert on their parts)
    assert "52:54:00:00:00:0a" in bindings and "sr-inside" in bindings
    assert "172.16.0.5/24" in bindings  # only the bindings file carries NIC 1


def test_single_nic_seed_stays_the_historical_render(tmp_path):
    import yaml
    from infra.appliance.manifest import ApplianceManifest
    from infra.appliance.seed import SeedInputs, render_network_config
    from tests.test_appliance_contract import _manifest

    m = ApplianceManifest.from_dict(_manifest(tmp_path, verify_files=True),
                                    verify_images=True, verify_model_key=False)
    image = m.image_for_role("mojang-web-local")
    common = dict(manifest=m, image=image, vmid=213, session_id="c" * 32,
                  hostname="web02", address="10.66.0.12", prefix=24)
    legacy = yaml.safe_load(render_network_config(SeedInputs(**common)))
    one = yaml.safe_load(render_network_config(
        SeedInputs(nics=({"index": 0, "mac": "52:54:00:00:00:0A",
                          "bridge": "srlab0", "address": "10.66.0.12",
                          "prefix": 24},), **common)))
    assert legacy == one  # a single-leg vector never changes the v1 render
    assert "range-nic" in legacy["ethernets"]  # historical shape, by name match
