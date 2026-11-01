"""Routed upstream-vantage topology proofs for the Underpressure replica.

The bug class this pins: an external vantage attached ON-LINK to the public
VIP prefix would ARP the VIPs directly and never traverse the VyOS WAN DNAT,
the transit leg, or the perimeter firewall. These tests prove, purely from
the typed contracts (no packets, no KVM):

  * the ONLY path from an upstream vantage to a public service goes
    route -> edge DNAT -> transit -> perimeter -> LAN;
  * shortcuts (direct RFC addresses, non-forwarded ports, arbitrary
    cross-segment hops, egress) are denied for a NAMED reason each;
  * the blueprint refuses topologies that reintroduce the flaw.

Real packet/KVM confirmation remains a pending installed gate.
"""
from __future__ import annotations

import copy
from pathlib import Path

import pytest
import yaml

from srplatform import environment_specs as es
from srplatform.environment_specs import EnvironmentBlueprint, EnvironmentError

REPO = Path(__file__).resolve().parents[1]
ENV_DIR = REPO / "environments" / "underpressure-range"


@pytest.fixture(scope="module")
def bp() -> EnvironmentBlueprint:
    return es.load_environment("underpressure-range").blueprint


def _bp_doc() -> dict:
    return yaml.safe_load((ENV_DIR / "blueprint.yaml").read_text())


# --------------------------------------------------------------- vantage site --
def test_vantages_are_upstream_not_on_link(bp):
    red, scoring = bp.guest("red-entry"), bp.guest("scoring-vantage")
    assert [i.segment for i in red.interfaces] == ["wan"]
    assert [i.segment for i in scoring.interfaces] == ["wan"]
    wan = bp.segment("wan")
    assert wan.purpose.value == "simulated-wan"
    # NO default gateway on the vantage segment: reach is typed-route only
    assert wan.default_gateway is None
    # the VIP prefix owns no interface anywhere
    import ipaddress
    pub = bp.segment("public-nat")
    pub_net = ipaddress.ip_network(pub.cidr)
    for guest in bp.guests:
        for iface in guest.interfaces:
            if iface.ipv4.address:
                assert not (iface.segment == pub.name
                            and ipaddress.ip_address(iface.ipv4.address)
                            in pub_net)
    # and every vantage reaches every declared public forward by typed route
    fwd = bp.public_forwards
    assert fwd
    for vantage in (red, scoring):
        routes = [r for r in bp.routes if r.guest == vantage.name]
        for f in fwd:
            vip = ipaddress.ip_address(f.vip)
            covered = [r for r in routes if vip in ip_net(r.prefix)]
            assert covered, (vantage.name, f.label)
        assert all(r.via == str(bp.address_in("vyos-edge", "wan"))
                   for r in routes), \
            "vantage routes must point at the edge WAN (172.31.31.2)"


def ip_net(prefix: str):
    import ipaddress
    return ipaddress.ip_network(prefix, strict=True)


# ---------------------------------------------------------------- path proofs --
def test_public_service_path_traverses_the_real_route(bp):
    r = es.public_service_path(bp, "red-entry", "store-https")
    assert r.allowed, r.reason
    trail = " | ".join(r.hops)
    assert "route 172.25.31.10/32 via 172.31.31.2" in trail
    assert "vyos-edge: DNAT 172.25.31.10:443 -> 172.20.240.10:443" in trail
    assert "opnsense-fw" in trail                      # via the perimeter
    assert "deliver ecomm@inside-lan" in trail
    assert r.translated_dst == ("172.20.240.10", 443)
    # the scoring vantage uses the same honest path, not a management shortcut
    s = es.public_service_path(bp, "scoring-vantage", "database-sql")
    assert s.allowed, s.reason
    assert "DNAT 172.25.31.120:1433 -> 172.20.240.120:1433" in " | ".join(s.hops)


@pytest.mark.parametrize("label", [
    "store-https", "store-http", "mail-smtp", "mail-imaps", "mail-pop3s",
    "webmail-https", "directory-dns-tcp", "directory-dns-udp",
    "directory-ldap", "database-sql", "splunk-api",
])
def test_every_declared_forward_is_reachable_from_both_vantages(bp, label):
    for vantage in ("red-entry", "scoring-vantage"):
        r = es.public_service_path(bp, vantage, label)
        assert r.allowed, (vantage, label, r.reason, r.hops)


# ------------------------------------------------------------------ denials ----
def test_vantage_cannot_shortcut_to_the_rfc_address(bp):
    r = es.resolve(bp, "red-entry", "172.20.240.10", 443)
    assert not r.allowed
    assert "no route" in r.reason and "172.20.240.10" in r.reason


def test_undeclared_port_toward_a_vip_blackholes(bp):
    r = es.resolve(bp, "red-entry", "172.25.31.10", 22)
    assert not r.allowed
    assert "no public forward" in r.reason


def test_vantage_cannot_reach_the_team_segment(bp):
    r = es.resolve(bp, "red-entry", "172.17.0.2", 22)
    assert not r.allowed
    assert "no route" in r.reason


def test_egress_outside_the_simulation_is_containment_denied(bp):
    for src in ("red-entry", "webmail", "ad-dns"):
        r = es.resolve(bp, src, "8.8.8.8", 443)
        assert not r.allowed
        assert "outside every declared segment" in r.reason


@pytest.mark.parametrize("src", ["team-kali", "webmail", "ecomm", "splunk"])
def test_defender_side_never_reaches_platform_machines(bp, src):
    for dst in ("172.31.31.4", "172.31.31.5"):
        r = es.resolve(bp, src, dst, 22)
        assert not r.allowed
        assert "appliance rule denies" in r.reason


def test_internal_paths_still_work(bp):
    assert es.resolve(bp, "ecomm", "172.20.240.120", 1433).allowed
    assert es.resolve(bp, "team-kali", "172.20.240.20", 8000).allowed


# ---------------------------------------------------------- contract refusals --
def _reject(mut, needle):
    from pydantic import ValidationError
    doc = _bp_doc()
    mut(doc)
    with pytest.raises((ValidationError, EnvironmentError)) as exc:
        EnvironmentBlueprint.model_validate(doc)
    assert needle.lower() in str(exc.value).lower()


def test_vantage_on_the_vip_segment_is_refused():
    def mut(d):
        for g in d["guests"]:
            if g["name"] in ("red-entry", "scoring-vantage"):
                g["interfaces"][0]["segment"] = "public-nat"
                g["interfaces"][0]["ipv4"]["address"] = "172.25.31.250"
    _reject(mut, "on-link to the public-nat segment")


def test_vip_prefix_address_bound_to_an_interface_is_refused():
    def mut(d):
        # a workstation moves onto the VIP prefix: the prefix must stay routed
        for g in d["guests"]:
            if g["name"] == "webmail":
                g["interfaces"][0] = {"segment": "public-nat",
                                      "ipv4": {"mode": "static",
                                               "address": "172.25.31.15"}}
    _reject(mut, "never bound to an interface")


def test_route_via_a_free_text_gateway_is_refused():
    def mut(d):
        for r in d["routes"]:
            if r["guest"] == "red-entry":
                r["via"] = "172.31.31.9"  # nobody owns this address
    _reject(mut, "not a declared guest interface address")


def test_default_route_in_a_typed_contract_is_refused():
    def mut(d):
        d["routes"].append({"guest": "team-kali", "prefix": "0.0.0.0/0",
                            "via": "172.17.0.1"})
    _reject(mut, "non-default IPv4 network")


def test_forward_blackholing_at_its_executor_is_refused():
    def mut(d):
        # a firewall-role executor with no route to the target's segment
        for f in d["public_forwards"]:
            if f["label"] == "splunk-api":
                f["on_guest"] = "opnsense-fw"
                f["target_guest"] = "team-kali"
    _reject(mut, "blackhole")


def test_vantage_missing_the_vip_route_is_refused():
    def mut(d):
        d["routes"] = [r for r in d["routes"] if r["guest"] != "scoring-vantage"]
    _reject(mut, "no typed route covering public VIP")


def test_duplicate_service_path_is_refused():
    def mut(d):
        d["public_forwards"].append(dict(d["public_forwards"][0]))
    _reject(mut, "duplicates service path")


def test_attack_scope_must_cover_the_entry_position(tmp_path):
    root = tmp_path / "environments"
    root.mkdir()
    import shutil
    shutil.copytree(ENV_DIR, root / "underpressure-range")
    ap = root / "underpressure-range" / "attack.yaml"
    attack = yaml.safe_load(ap.read_text())
    attack["scope"]["allowed_segments"] = ["inside-lan"]
    ap.write_text(yaml.safe_dump(attack))
    with pytest.raises(EnvironmentError, match="allowed_segments"):
        es.load_environment("underpressure-range", directory=root)


def test_hop_trail_is_honest_about_the_perimeter_opening_policy(bp):
    # the permissive inner policy is labeled as the OPENING weakness it is —
    # never presented as a security property
    r = es.public_service_path(bp, "scoring-vantage", "store-https")
    assert any("permissive OPENING policy" in h for h in r.hops)
