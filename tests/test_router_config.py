"""Derived router configs: every declared public path must appear exactly.

These are text plans (the boot seed's input), so they are verified as DATA:
each blueprint `public_forward` yields its own DNAT rule with the same VIP,
VIP port, protocol, target address and target port; every typed route and the
masquerade exist; the syslog sink is the declared collector. A hand-typed lab
answer cannot drift from the plan because none is typed here.
"""
from __future__ import annotations

from srplatform.environment_specs import load_environment
from srplatform.environment_specs.router_config import (
    render_opnsense, render_vyos)

BP = load_environment("underpressure-range").blueprint


def _cmds(text: str) -> list[str]:
    return [line[len("set "):] for line in text.splitlines() if line.startswith("set ")]


def _has(cmds, *parts) -> bool:
    return any(all(p in c for p in parts) for c in cmds)


def test_every_public_forward_is_a_dnat_rule_with_its_own_values():
    cmds = _cmds(render_vyos(BP))
    for n, fwd in enumerate(BP.public_forwards, start=1):
        rule = f"nat destination rule {n * 10}"
        assert _has(cmds, rule, f"destination address '{fwd.vip}'")
        assert _has(cmds, rule, f"protocol '{fwd.protocol}'")
        assert _has(cmds, rule, f"destination port '{fwd.vip_port}'")
        assert _has(cmds, rule, f"translation port '{fwd.target_port}'")
        target = next(i.ipv4.address for i in BP.guest(fwd.target_guest).interfaces
                      if i.ipv4 and i.ipv4.address)
        assert _has(cmds, rule, f"translation address '{target}'")


def test_no_public_forward_is_missing_or_extra():
    rendered = render_vyos(BP)
    expected = len([f for f in BP.public_forwards if f.on_guest == "vyos-edge"])
    got = len({line.split()[4] for line in rendered.splitlines()
               if line.startswith("set nat destination rule")})
    assert got == expected
    # the blackhole contract: anything not declared is simply not DNATed
    assert "172.25.31.99" not in rendered


def test_interfaces_carry_the_blueprint_addresses_and_prefixes():
    cmds = _cmds(render_vyos(BP))
    guest = BP.guest("vyos-edge")
    for i, iface in enumerate(guest.interfaces):
        seg = next(s for s in BP.segments if s.name == iface.segment)
        prefix = seg.cidr.split("/")[1]
        assert _has(cmds, f"interfaces ethernet eth{i} address "
                    f"'{iface.ipv4.address}/{prefix}'")


def test_masquerade_and_typed_routes_are_present():
    cmds = _cmds(render_vyos(BP))
    wan_index = [i for i, iface in enumerate(BP.guest("vyos-edge").interfaces)
                 if iface.segment == "wan"][0]
    assert _has(cmds, "nat source rule 100 outbound-interface",
                f"eth{wan_index}")
    assert _has(cmds, "nat source rule 100 translation address 'masquerade'")
    for route in BP.routes:
        if route.guest == "vyos-edge":
            assert _has(cmds, "protocols static route", route.prefix,
                        f"next-hop '{route.via}'")


def test_edge_syslog_sinks_to_the_declared_collector_and_port():
    cmds = _cmds(render_vyos(BP))
    splunk = next(i.ipv4.address for i in BP.guest("splunk").interfaces
                  if i.ipv4 and i.ipv4.address)
    assert _has(cmds, f"syslog host {splunk}")
    assert _has(cmds, "syslog host", "port '5514'")


def test_opnsense_config_is_well_formed_xml_with_blueprint_addresses():
    import xml.etree.ElementTree as ET

    text = render_opnsense(BP)
    root = ET.fromstring(text)
    assert root.tag == "opnsense"
    addrs = [e.text for e in root.iter("ipaddr")]
    for iface in BP.guest("opnsense-fw").interfaces:
        assert iface.ipv4.address in addrs
    # deterministic reservations for the two workstation addresses
    ranges = [f"{e.find('from').text}-{e.find('to').text}"
              for e in root.iter("range")]
    assert "172.20.240.112-172.20.240.112" in ranges
    assert "172.20.240.113-172.20.240.113" in ranges
    # the reported permissive opening policy is reproduced, labelled in text
    rules = [r.find("descr").text for r in root.iter("rule")]
    assert {"permit LAN outbound", "permit WAN inbound"} <= set(rules)
