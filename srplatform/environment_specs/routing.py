"""Pure reachability model over the blueprint's TYPED routing contracts.

This is a model, not a packet engine: it answers "does this connection have
a declared path, and through which owned guests?" so tests and later
provisioning gates can PROVE the routed public path (upstream -> edge DNAT
-> transit -> perimeter -> LAN) and every denial (no route, no forward,
appliance deny rule, containment) before any KVM guest exists. Real packet
tests on the appliance remain the installed gate; this module is what keeps
the executable contract honest in the meantime.

Semantics (all derived from validated contracts, never free text):
  * an address outside every declared segment is containment-denied —
    egress means leaving the simulation, which the appliance refuses;
  * on-link delivery requires the destination address to be a DECLARED guest
    interface (the VIP prefix owns no interface, so a VIP is never
    "on-link" — clients cannot ARP their way around the edge);
  * non-router guests route only through typed GuestRoutes (plus the
    segment's declared default gateway, when that segment has one — never an
    invented default route on the upstream/vantage segment);
  * router/firewall-role guests forward between their approved segments;
    the perimeter substitute's permissive OPENING policy is exactly that, and
    stays labeled;
  * a PublicForward DNATs VIP:port -> target:port on its declared edge
    guest only, for the exact protocol/port; anything else toward the VIP
    blackholes;
  * appliance AccessDeny rules beat routing (defenders never reach the
    platform attacker or scoring vantage, even with a working default route).
"""
from __future__ import annotations

import ipaddress
from collections import deque
from dataclasses import dataclass

from .blueprint import EnvironmentBlueprint, GuestRole

FORWARDING_ROLES = frozenset({GuestRole.ROUTER, GuestRole.FIREWALL})
_MAX_HOPS = 12


@dataclass(frozen=True)
class PathResult:
    allowed: bool
    hops: tuple[str, ...]
    reason: str | None = None
    translated_dst: tuple[str, int] | None = None

    def __bool__(self) -> bool:  # convenience for tests/gates
        return self.allowed


def _segments_of(bp: EnvironmentBlueprint, guest) -> set[str]:
    return {i.segment for i in guest.interfaces}


def _on_segment(bp: EnvironmentBlueprint, guest, seg_name: str):
    for i in guest.interfaces:
        if i.segment == seg_name:
            return i
    return None


def _implicit_routes(bp: EnvironmentBlueprint, guest) -> list[tuple[int, str]]:
    """(prefixlen, via) for every segment the guest is on that declares a
    default gateway — the declared gateway IS the typed default route."""
    out: list[tuple[int, str]] = []
    for i in guest.interfaces:
        seg = bp.segment(i.segment)
        if seg.default_gateway:
            out.append((0, seg.default_gateway))
    return out


def _next_hop_for(bp: EnvironmentBlueprint, guest, dst: ipaddress.IPv4Address):
    """Longest-match over typed routes + declared default gateways.
    Returns the via address, or None when no route exists."""
    best_len = -1
    best_via: str | None = None
    for r in bp.routes:
        if r.guest != guest.name:
            continue
        net = ipaddress.ip_network(r.prefix, strict=True)
        if dst in net and net.prefixlen > best_len:
            best_len, best_via = net.prefixlen, r.via
    for plen, via in _implicit_routes(bp, guest):
        if plen > best_len:
            best_len, best_via = plen, via
    return best_via


def _forwarder_edges(bp: EnvironmentBlueprint) -> dict[tuple[str, str], str]:
    """(segA, segB) -> forwarding guest for every pair of segments a
    router/firewall guest bridges."""
    edges: dict[tuple[str, str], str] = {}
    for g in bp.guests:
        if g.role not in FORWARDING_ROLES:
            continue
        segs = sorted(_segments_of(bp, g))
        for a in segs:
            for b in segs:
                if a != b:
                    edges[(a, b)] = g.name
    return edges


def _forward_hop_label(bp: EnvironmentBlueprint, guest, src_seg: str,
                       dst_seg: str) -> str:
    if guest.role == GuestRole.FIREWALL:
        return (f"{guest.name}: forward {src_seg}->{dst_seg} "
                f"(permissive OPENING policy — a training weakness, not a "
                f"security claim)")
    return f"{guest.name}: forward {src_seg}->{dst_seg}"


def resolve(bp: EnvironmentBlueprint, src_guest: str, dst: str,
            port: int = 0, protocol: str = "tcp") -> PathResult:
    """Trace the connection src_guest -> dst:port/protocol through the
    declared contracts. Returns the ordered hop trail plus the post-DNAT
    destination when the edge translated it."""
    cur_guest = bp.guest(src_guest)
    cur_dst = ipaddress.ip_address(dst)
    hops: list[str] = [f"{cur_guest.name}: origin"]
    translated: tuple[str, int] | None = None
    arrival: str | None = None  # segment the packet entered cur_guest on
    seen: set[tuple[str, str]] = set()

    for _ in range(_MAX_HOPS):
        key = (cur_guest.name, str(cur_dst))
        if key in seen:
            return PathResult(False, tuple(hops), "routing loop — no exit")
        seen.add(key)

        seg = bp.segment_containing(cur_dst)
        if seg is None:
            return PathResult(
                False, tuple(hops),
                f"{cur_dst} is outside every declared segment: the appliance "
                f"denies egress from the simulation (containment, not a route)")
        owner = bp.guest_owning(cur_dst)

        # appliance deny rules beat delivery and routing alike
        src_segs = [arrival] if arrival else sorted(_segments_of(bp, cur_guest))
        for d in bp.access_denies:
            src_hit = d.src == cur_guest.name or d.src in src_segs
            dst_hit = (owner is not None and d.dst == owner.name) or d.dst == seg.name
            if src_hit and dst_hit and (owner is None or owner.name != cur_guest.name):
                return PathResult(
                    False, tuple(hops),
                    f"appliance rule denies {d.src} -> {d.dst}: {d.reason}")

        # on-link delivery to a declared interface address
        if owner is not None and seg.name in _segments_of(bp, cur_guest):
            if owner.name == cur_guest.name:
                hops.append(f"deliver {owner.name}@{seg.name} (self)")
                return PathResult(True, tuple(hops), None,
                                  translated or (str(cur_dst), port))
            if cur_guest.role == GuestRole.FIREWALL and arrival is not None:
                # a forwarded connection crossing the perimeter substitute:
                # label WHICH policy admits it (the permissive opening)
                hops.append(_forward_hop_label(bp, cur_guest, arrival,
                                               seg.name))
            hops.append(f"{cur_guest.name}: deliver {owner.name}@{seg.name}")
            return PathResult(True, tuple(hops), None,
                              translated or (str(cur_dst), port))

        # DNAT on the declared edge guest (exact vip:port/proto only)
        if cur_guest.role in FORWARDING_ROLES:
            fwd = next((f for f in bp.public_forwards
                        if f.on_guest == cur_guest.name
                        and cur_dst == ipaddress.ip_address(f.vip)
                        and port == f.vip_port
                        and protocol == f.protocol), None)
            if fwd is not None:
                tgt = bp.guest(fwd.target_guest)
                taddr = next((ipaddress.ip_address(i.ipv4.address)
                              for i in tgt.interfaces if i.ipv4.address), None)
                if taddr is None:
                    return PathResult(False, tuple(hops),
                                      f"forward {fwd.label!r} target has no "
                                      f"static address")
                hops.append(f"{cur_guest.name}: DNAT {fwd.vip}:{fwd.vip_port} "
                            f"-> {taddr}:{fwd.target_port} [{fwd.label}]")
                cur_dst = taddr
                translated = (str(taddr), fwd.target_port)
                continue
            # no forward matched: toward the VIP prefix this blackholes here
            vip_prefix_hit = any(
                cur_dst == ipaddress.ip_address(f.vip)
                for f in bp.public_forwards if f.on_guest == cur_guest.name)
            if vip_prefix_hit:
                return PathResult(
                    False, tuple(hops),
                    f"{cur_guest.name} has no public forward for "
                    f"{cur_dst}:{port}/{protocol} — the service path is not "
                    f"declared, so it does not exist")
            if seg.purpose.value == "public-nat":
                return PathResult(
                    False, tuple(hops),
                    f"{cur_dst} is in the routed public prefix but no forward "
                    f"matches {cur_dst}:{port}/{protocol}")

            # router forwarding: shortest bridged path to the target segment
            if seg.name in _segments_of(bp, cur_guest):
                src_seg = arrival or sorted(_segments_of(bp, cur_guest))[0]
                hops.append(_forward_hop_label(bp, cur_guest, src_seg, seg.name))
                arrival = seg.name
                # now deliver on-link
                if owner is not None:
                    hops.append(f"{cur_guest.name}: deliver "
                                f"{owner.name}@{seg.name}")
                    return PathResult(True, tuple(hops), None,
                                      translated or (str(cur_dst), port))
                continue
            edges = _forwarder_edges(bp)
            nxt = _bridge_to(bp, edges, cur_guest, seg.name)
            if nxt is not None:
                nguest, via_seg, from_seg = nxt
                hops.append(f"{cur_guest.name}: forward {from_seg} via "
                            f"{nguest} -> {seg.name}")
                cur_guest = bp.guest(nguest)
                arrival = via_seg
                continue
            return PathResult(
                False, tuple(hops),
                f"no forwarding path bridges {cur_guest.name} to segment "
                f"{seg.name}")

        # non-forwarding guest: typed routes / declared gateway only
        via = _next_hop_for(bp, cur_guest, cur_dst)
        if via is None:
            return PathResult(
                False, tuple(hops),
                f"no route inside {cur_guest.name}: {cur_dst} is not on-link "
                f"with a declared interface and no typed route (or declared "
                f"segment gateway) matches — the replica has no invented "
                f"default route")
        nh = bp.guest_owning(via)
        if nh is None:
            return PathResult(False, tuple(hops),
                              f"typed next hop {via} names no guest interface")
        if nh.name == cur_guest.name:
            return PathResult(False, tuple(hops),
                              f"route loop: {cur_guest.name} points at itself")
        via_seg = bp.segment_containing(via)
        hops.append(f"{cur_guest.name}: route {cur_dst}/32 via {via}")
        cur_guest = nh
        arrival = via_seg.name if via_seg else None

    return PathResult(False, tuple(hops), "hop budget exceeded")


def _bridge_to(bp: EnvironmentBlueprint, edges, cur_guest, target_seg: str):
    """BFS the segment graph over forwarding guests; returns
    (next_guest, entered_via_seg, from_seg) or None."""
    own = _segments_of(bp, cur_guest)
    q: deque[tuple[str, str, str]] = deque()
    for s in sorted(own):
        for (a, _b), gname in edges.items():
            if a == s and gname != cur_guest.name:
                q.append((gname, s, s))
    seen: set[str] = set()
    while q:
        gname, entered, from_seg = q.popleft()
        g = bp.guest(gname)
        if target_seg in _segments_of(bp, g):
            return gname, entered, from_seg
        if gname in seen:
            continue
        seen.add(gname)
        for s in sorted(_segments_of(bp, g)):
            for (a, _b), other in edges.items():
                if a == s and other != gname:
                    q.append((other, s, from_seg))
    return None


def public_service_path(bp: EnvironmentBlueprint, vantage_guest: str,
                        forward_label: str, protocol: str | None = None
                        ) -> PathResult:
    """Convenience: resolve the declared public service path a scoring/attack
    vantage uses for one named forward."""
    fwd = next((f for f in bp.public_forwards if f.label == forward_label),
               None)
    if fwd is None:
        return PathResult(False, (), f"no public forward labelled "
                                     f"{forward_label!r}")
    return resolve(bp, vantage_guest, fwd.vip, fwd.vip_port,
                   protocol or fwd.protocol)
