"""Router and firewall configurations DERIVED from the executable blueprint.

The typed contracts (`public_forwards`, `routes`, `segments`, `edges`) are the
only source: nothing here restates a lab answer by hand, so a config can never
drift from the plan the tests — and later the availability checks — bind to.
Rendering is pure text; provisioning/boot seeding delivers it to the guest.

VyOS 1.4 `config.boot` is the `set ...` command list VyOS itself accepts on
boot (VyOS reads it as a config script). Interface numbering follows the
blueprint's declared interface order, and the WAN interface is the segment
with purpose `simulated-wan` — never an index guessed from an address.
"""
from __future__ import annotations

import ipaddress

from .blueprint import EnvironmentBlueprint, SegmentPurpose


def guest_address(bp: EnvironmentBlueprint, name: str) -> str:
    for iface in bp.guest(name).interfaces:
        if iface.ipv4 is not None and iface.ipv4.address:
            return str(iface.ipv4.address)
    raise ValueError(f"guest {name!r} has no static address")


def _prefix_len(bp: EnvironmentBlueprint, segment_name: str) -> int:
    for seg in bp.segments:
        if seg.name == segment_name:
            return ipaddress.ip_network(seg.cidr, strict=False).prefixlen
    raise ValueError(f"blueprint declares no segment {segment_name!r}")


def _segment_purpose(bp: EnvironmentBlueprint, segment_name: str) -> SegmentPurpose:
    for seg in bp.segments:
        if seg.name == segment_name:
            return seg.purpose
    raise ValueError(f"blueprint declares no segment {segment_name!r}")


def render_vyos(bp: EnvironmentBlueprint, edge: str = "vyos-edge") -> str:
    """The edge's full `config.boot`: addressing, NAT, DNAT for every
    declared public path, the typed prefix routes, and syslog to the sink."""
    guest = bp.guest(edge)
    iface_of = {iface.segment: f"eth{i}"
                for i, iface in enumerate(guest.interfaces)}
    wan_if = next((iface_of[seg.name] for seg in bp.segments
                   if seg.purpose == SegmentPurpose.SIMULATED_WAN
                   and seg.name in iface_of), None)
    if wan_if is None:
        raise ValueError(
            f"edge {edge!r} has no interface on the simulated-wan segment — "
            f"the DNAT paths have nowhere to land")

    lines: list[str] = ["set system host-name '%s'" % guest.name,
                        "set system domain-name '%s'" % bp.domain,
                        "set service ssh port '22'",
                        # Default state policy: permit (reported permissive
                        # opening state; the perimeter carries the weakness).
                        "set firewall state-policy established action 'accept'",
                        "set firewall state-policy related action 'accept'"]

    for i, iface in enumerate(guest.interfaces):
        prefix = _prefix_len(bp, iface.segment)
        lines.append(f"set interfaces ethernet eth{i} address "
                     f"'{iface.ipv4.address}/{prefix}'")
        lines.append(f"set interfaces ethernet eth{i} description "
                     f"'{iface.segment}'")

    # Masquerade the private ranges out of the simulated WAN (the spec's
    # "Masquerade 172.16.0.0/12 out eth2"), never out of team.
    lines += [
        "set nat source rule 100 outbound-interface 'name %s'" % wan_if,
        "set nat source rule 100 source address '172.16.0.0/12'",
        "set nat source rule 100 translation address 'masquerade'",
        "set nat source rule 110 description 'replica masquerade'",
    ]

    # Every declared public path is one DNAT rule, numbered from the
    # blueprint's own list order so logs and tests refer to the same path.
    for n, fwd in enumerate(bp.public_forwards, start=1):
        if fwd.on_guest != edge:
            continue
        target = guest_address(bp, fwd.target_guest)
        lines += [
            f"set nat destination rule {n * 10} description '{fwd.label}'",
            f"set nat destination rule {n * 10} inbound-interface 'name {wan_if}'",
            f"set nat destination rule {n * 10} destination address '{fwd.vip}'",
            f"set nat destination rule {n * 10} protocol '{fwd.protocol}'",
            f"set nat destination rule {n * 10} destination port '{fwd.vip_port}'",
            f"set nat destination rule {n * 10} translation address '{target}'",
            f"set nat destination rule {n * 10} translation port '{fwd.target_port}'",
        ]

    # Typed prefix routes owned by this edge (the LAN prefix via the firewall).
    for route in bp.routes:
        if route.guest != edge:
            continue
        lines.append(f"set protocols static route {route.prefix} "
                     f"next-hop '{route.via}'")

    # Syslog edges sink to the declared collector on its declared port.
    for e in bp.edges:
        if e.kind.value != "syslog" or e.src != edge or e.port is None:
            continue
        host = guest_address(bp, e.dst)
        lines += [
            f"set system syslog host {host} facility all level 'info'",
            f"set system syslog host {host} port '{e.port}'",
            f"set system syslog host {host} protocol "
            f"'{e.protocol or 'udp'}'",
        ]

    return "\n".join(lines) + "\n"


def render_opnsense(bp: EnvironmentBlueprint, fw: str = "opnsense-fw") -> str:
    """A minimal `config.xml` for the perimeter substitute: interface
    addressing, the deterministic DHCP reservations the blueprint declares,
    and the reported permissive opening policy (LAN -> any, WAN -> LAN).

    Only the blueprint's own values appear; the PAN-OS substitution and its
    policy differences stay labeled in fidelity.yaml.
    """
    from xml.sax.saxutils import escape

    guest = bp.guest(fw)
    iface_of = {iface.segment: f"opt{i}"
                for i, iface in enumerate(guest.interfaces)}
    lan_seg = next((seg.name for seg in bp.segments
                    if seg.purpose == SegmentPurpose.INSIDE_LAN), None)
    lan_if = iface_of.get(lan_seg, "lan")

    netmask = lambda seg_name: ipaddress.ip_network(  # noqa: E731
        next(s.cidr for s in bp.segments if s.name == seg_name),
        strict=False).prefixlen

    parts: list[str] = [
        '<?xml version="1.0"?>',
        "<opnsense>",
        "  <system>",
        f"    <hostname>{escape(guest.name)}</hostname>",
        f"    <domain>{escape(bp.domain)}</domain>",
        f"    <timezone>UTC</timezone>",
        "  </system>",
        "  <interfaces>",
    ]
    for seg_name, dev in iface_of.items():
        addr = None
        for iface in guest.interfaces:
            if iface.segment == seg_name and iface.ipv4 and iface.ipv4.address:
                addr = str(iface.ipv4.address)
        if addr is None:
            continue
        parts += [
            f"    <{dev}>",
            f"      <if>{dev}</if>",
            f"      <ipaddr>{escape(addr)}</ipaddr>",
            f"      <subnet>{netmask(seg_name)}</subnet>",
            f"      <descr>{escape(seg_name)}</descr>",
            f"    </{dev}>",
        ]
    #: Deterministic reservations: the blueprint's own DHCP guests carry
    #: their reserved addresses even though their mode is dhcp. The pool
    #: range (172.20.240.112/29) only bounds ALLOCATION, it does not move a
    #: reservation; guessing hosts from the network address would break both.
    reserved = []
    for g in bp.guests:
        for iface in g.interfaces:
            mode = getattr(iface.ipv4, "mode", None) if iface.ipv4 else None
            mode = str(getattr(mode, "value", mode))
            if iface.segment == lan_seg and mode == "dhcp" \
                    and iface.ipv4.address:
                reserved.append(str(iface.ipv4.address))
    parts += ["  </interfaces>", "  <dhcpd>"]
    for host in reserved:
        parts += [f"    <{lan_if}>",
                  f"      <range><from>{host}</from><to>{host}</to></range>",
                  f"    </{lan_if}>"]
    parts += ["  </dhcpd>", "  <filter>",
              # reported opening policy: LAN -> any, WAN -> LAN permitted
              "    <rule><type>pass</type><interface>lan</interface>"
              "<protocol>any</protocol><descr>permit LAN outbound</descr></rule>",
              "    <rule><type>pass</type><interface>wan</interface>"
              "<protocol>any</protocol><descr>permit WAN inbound</descr></rule>",
              "  </filter>", "</opnsense>", ""]
    return "\n".join(parts)
