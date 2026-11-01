"""Operator deployment policy — the broker's allowlist boundary.

The broker accepts ONLY typed operations that this policy fully determines:
one node, an enumerated template set, a bounded VMID range, named storages,
one clone mode, ONE exact NIC (bridge + VLAN), provisioning fields from a
closed set with values inside the range network, and aggregate CPU/RAM/disk
limits across everything the broker owns. There is deliberately no way to
express "any path", "any bridge", "extra config keys", mounts, passthrough,
or privilege flags — such requests cannot be represented, let alone pass.

A missing, malformed, unknown-key, or self-contradictory policy file is a
LOAD-TIME failure: the broker refuses to start (fail closed).
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .errors import PolicyViolation

_REQUIRED = ("node", "templates", "vmid_range", "storage", "clone_mode",
             "nic", "provision", "limits")
_ALLOWED_TOP = set(_REQUIRED) | {"name_prefix", "tag_pattern", "lease_ttl_s",
                                  "heartbeat_interval_s", "segments", "max_nics"}
_ALLOWED_LIMITS = {"max_vms", "cores_per_vm", "memory_mb_per_vm", "disk_gb_per_vm",
                   "max_total_cores", "max_total_memory_mb", "max_total_disk_gb"}
_ALLOWED_SEGMENT_KEYS = {"name", "bridge", "cidr"}
_SEGMENT_NAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,31}$")


def parse_segments(raw_segments, *, provision_bridge: str,
                   provision_net: ipaddress.IPv4Network, bad):
    """Validate the closed segment list shared by both broker lanes.
    `bad(why)` raises the lane-appropriate PolicyViolation."""
    if not isinstance(raw_segments, list) or not raw_segments:
        raise bad("segments must be a non-empty list of segment objects")
    specs: list[SegmentSpec] = []
    seen_bridges: set[str] = set()
    seen_nets: list[tuple[str, ipaddress.IPv4Network]] = []
    for i, s in enumerate(raw_segments):
        if not isinstance(s, dict) or set(s) != _ALLOWED_SEGMENT_KEYS:
            raise bad(f"segments[{i}] keys must be exactly "
                      f"{sorted(_ALLOWED_SEGMENT_KEYS)}")
        sname = s["name"]
        if not isinstance(sname, str) or not _SEGMENT_NAME_RE.fullmatch(sname):
            raise bad(f"segments[{i}].name {sname!r} is not a safe segment name")
        sbridge = s["bridge"]
        if (not isinstance(sbridge, str)
                or not re.fullmatch(r"[A-Za-z0-9._-]{1,15}", sbridge)
                or sbridge == "lo"):
            raise bad(f"segments[{i}].bridge must be one exact safe bridge name")
        if sbridge == provision_bridge:
            raise bad(f"segments[{i}].bridge repeats the provision bridge")
        if sbridge in seen_bridges:
            raise bad(f"segments[{i}].bridge {sbridge!r} duplicated")
        seen_bridges.add(sbridge)
        try:
            snet = ipaddress.ip_network(s["cidr"], strict=True)
        except ValueError as e:
            raise bad(f"segments[{i}].cidr invalid: {e}") from e
        if not isinstance(snet, ipaddress.IPv4Network) or snet.prefixlen > 30:
            raise bad(f"segments[{i}].cidr must be a strict IPv4 /<=30")
        for other, onet in seen_nets:
            if snet.overlaps(onet):
                raise bad(f"segments[{i}] ({sname}) overlaps segment {other}")
        seen_nets.append((sname, snet))
        if snet != provision_net and snet.overlaps(provision_net):
            raise bad(f"segment {sname} overlaps the provision network without "
                      f"being equal to it")
        specs.append(SegmentSpec(name=sname, bridge=sbridge, network=snet))
    return tuple(specs)
# The closed set of VM config fields the broker may ever write. Anything
# else (mounts, hostpci, cpulimit tricks, startup ordering, agent exec)
# is unrepresentable.
ALLOWED_CONFIG_KEYS = frozenset({"ipconfig0", "net0", "tags", "name"})
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
_TAG_RE_DEFAULT = re.compile(r"^srsess-[0-9a-f]{32}$")


@dataclass(frozen=True)
class SegmentSpec:
    """One APPROVED lab segment (Underpressure multi-NIC lane). The broker
    can attach guests ONLY to enumerated segment bridges and address ONLY
    inside enumerated segment CIDRs. Bridge objects never come from
    scenario/model data — this list is loaded from the operator policy."""
    name: str
    bridge: str
    network: ipaddress.IPv4Network


@dataclass(frozen=True)
class BrokerPolicy:
    node: str
    templates: tuple[int, ...]
    vmid_min: int
    vmid_max: int
    storage: tuple[str, ...]
    clone_mode: str                      # "linked" | "full"
    bridge: str
    vlan: int
    network: ipaddress.IPv4Network
    gateway: ipaddress.IPv4Address
    limits: dict = field(default_factory=dict)
    name_prefix: str = "sr-"
    tag_pattern: str = _TAG_RE_DEFAULT.pattern
    lease_ttl_s: int = 30
    heartbeat_interval_s: int = 5
    # Segment lane (None = classic single-NIC policy, unchanged behavior).
    segments: tuple[SegmentSpec, ...] | None = None
    max_nics: int = 1

    # ------------------------------------------------------------------ load ---
    @classmethod
    def load(cls, path: str | Path) -> "BrokerPolicy":
        p = Path(path)
        try:
            raw = json.loads(p.read_text())
        except FileNotFoundError as e:
            raise PolicyViolation(f"broker policy file missing: {p}") from e
        except (OSError, json.JSONDecodeError) as e:
            raise PolicyViolation(f"broker policy unreadable ({p}): {e}") from e
        return cls.from_dict(raw, source=str(p))

    @classmethod
    def from_dict(cls, raw: dict, source: str = "<dict>") -> "BrokerPolicy":
        def bad(why: str) -> PolicyViolation:
            return PolicyViolation(f"broker policy invalid ({source}): {why}")
        if not isinstance(raw, dict):
            raise bad("top level must be an object")
        unknown = set(raw) - _ALLOWED_TOP
        if unknown:
            raise bad(f"unknown keys {sorted(unknown)}")
        missing = [k for k in _REQUIRED if k not in raw]
        if missing:
            raise bad(f"missing keys {missing}")
        node = raw["node"]
        if not isinstance(node, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", node):
            raise bad("node must be a single exact PVE node name")
        templates = raw["templates"]
        if (not isinstance(templates, list) or not templates
                or not all(isinstance(t, int) and 100 <= t <= 999999 for t in templates)):
            raise bad("templates must be a non-empty list of VMIDs")
        vr = raw["vmid_range"]
        if (not isinstance(vr, list) or len(vr) != 2
                or not all(isinstance(v, int) and 100 <= v <= 999999 for v in vr)
                or vr[0] > vr[1]):
            raise bad("vmid_range must be [low, high] inside [100, 999999]")
        storage = raw["storage"]
        if (not isinstance(storage, list) or not storage
                or not all(isinstance(s, str) and re.fullmatch(r"[A-Za-z0-9._-]+", s)
                           for s in storage)):
            raise bad("storage must be a non-empty list of exact storage ids")
        if raw["clone_mode"] not in ("linked", "full"):
            raise bad("clone_mode must be 'linked' or 'full'")
        nic = raw["nic"]
        if (not isinstance(nic, dict) or set(nic) != {"bridge", "vlan"}
                or not isinstance(nic.get("bridge"), str)
                or not re.fullmatch(r"[A-Za-z0-9._-]+", str(nic.get("bridge")))
                or not isinstance(nic.get("vlan"), int) or not 2 <= nic["vlan"] <= 4094):
            raise bad("nic must be exactly {bridge, vlan(2..4094)} — one fixed NIC")
        prov = raw["provision"]
        if not isinstance(prov, dict) or set(prov) != {"cidr", "gateway"}:
            raise bad("provision must be exactly {cidr, gateway}")
        try:
            net = ipaddress.ip_network(prov["cidr"], strict=True)
            gw = ipaddress.ip_address(prov["gateway"])
        except ValueError as e:
            raise bad(f"provision network invalid: {e}") from e
        if not isinstance(net, ipaddress.IPv4Network) or gw not in net:
            raise bad("provision must be an IPv4 network with its gateway inside")
        limits = raw["limits"]
        if not isinstance(limits, dict):
            raise bad("limits must be an object")
        lunknown = set(limits) - _ALLOWED_LIMITS
        if lunknown:
            raise bad(f"unknown limits {sorted(lunknown)}")
        for k, v in limits.items():
            if not isinstance(v, int) or v < 1:
                raise bad(f"limits.{k} must be a positive integer")
        if "max_vms" not in limits:
            raise bad("limits.max_vms is required")
        prefix = raw.get("name_prefix", "sr-")
        if not re.fullmatch(r"[a-z0-9._-]{0,32}", prefix):
            raise bad("name_prefix must be lowercase-safe")
        tag_re = raw.get("tag_pattern", _TAG_RE_DEFAULT.pattern)
        try:
            re.compile(tag_re)
        except re.error as e:
            raise bad(f"tag_pattern not a regex: {e}") from e
        ttl = raw.get("lease_ttl_s", 30)
        hb = raw.get("heartbeat_interval_s", 5)
        if not isinstance(ttl, int) or ttl < 5 or not isinstance(hb, int) or hb < 1 or hb >= ttl:
            raise bad("lease_ttl_s >= 5 and 1 <= heartbeat_interval_s < lease_ttl_s required")
        segments: tuple[SegmentSpec, ...] | None = None
        max_nics = raw.get("max_nics", 1)
        if "segments" in raw:
            segments = parse_segments(raw["segments"], provision_bridge=nic["bridge"],
                                      provision_net=net, bad=bad)
            if not isinstance(max_nics, int) or isinstance(max_nics, bool) \
                    or not 1 <= max_nics <= 8:
                raise bad("max_nics must be an integer in [1, 8]")
            if max_nics > len(segments):
                raise bad("max_nics cannot exceed the number of segments")
        elif max_nics != 1:
            raise bad("max_nics > 1 requires a segments list")
        return cls(node=node, templates=tuple(sorted(set(templates))),
                   vmid_min=vr[0], vmid_max=vr[1], storage=tuple(storage),
                   clone_mode=raw["clone_mode"], bridge=nic["bridge"], vlan=nic["vlan"],
                   network=net, gateway=gw, limits=limits, name_prefix=prefix,
                   tag_pattern=tag_re, lease_ttl_s=ttl, heartbeat_interval_s=hb,
                   segments=segments, max_nics=max_nics)

    # ---------------------------------------------------------------- checks ---
    def check_node(self, node: str) -> None:
        if node != self.node:
            raise PolicyViolation(f"node {node!r} is not the policy node {self.node!r}")

    def check_vmid(self, vmid: int) -> None:
        if not isinstance(vmid, int) or not self.vmid_min <= vmid <= self.vmid_max:
            raise PolicyViolation(f"VMID {vmid!r} outside bounded range "
                                  f"[{self.vmid_min}, {self.vmid_max}]")

    def check_template(self, vmid: int) -> None:
        if vmid not in self.templates:
            raise PolicyViolation(f"template {vmid} is not in the approved set "
                                  f"{list(self.templates)}")

    def check_clone_mode(self, full: bool) -> None:
        want_full = self.clone_mode == "full"
        if bool(full) != want_full:
            raise PolicyViolation(f"clone mode must be {self.clone_mode!r}")

    def check_name(self, name: str) -> None:
        if not isinstance(name, str) or not _NAME_RE.fullmatch(name) \
                or not name.startswith(self.name_prefix):
            raise PolicyViolation(f"name {name!r} outside policy "
                                  f"(prefix {self.name_prefix!r}, safe charset)")

    def check_config_keys(self, cfg: dict) -> None:
        extra = set(cfg) - self.allowed_config_keys
        if extra:
            raise PolicyViolation(f"config keys not provisionable by policy: {sorted(extra)}")

    @property
    def allowed_config_keys(self) -> frozenset[str]:
        if self.max_nics <= 1:
            return ALLOWED_CONFIG_KEYS
        keys = {"name", "tags"}
        for i in range(self.max_nics):
            keys.add(f"net{i}")
            keys.add(f"ipconfig{i}")
        return frozenset(keys)

    def segment(self, name: str) -> SegmentSpec:
        if not self.segments:
            raise PolicyViolation("this policy has no segment lane")
        for seg in self.segments:
            if seg.name == name:
                return seg
        raise PolicyViolation(f"segment {name!r} is not approved")

    def check_nic_index(self, idx: int, value: str) -> None:
        """Additional NICs (index >= 1) may exist ONLY on an enumerated
        appliance bridge; the value must byte-equal the exact segment NIC
        spec. Foreign bridges/tags/models are unrepresentable."""
        if not self.segments or idx >= self.max_nics:
            raise PolicyViolation(f"net{idx} is outside the approved NIC lane "
                                  f"(segments={bool(self.segments)}, "
                                  f"max_nics={self.max_nics})")
        for seg in self.segments:
            if value == self._nic_for(seg):
                return
        raise PolicyViolation(f"net{idx} {value!r} is not an exact approved "
                              f"segment bridge spec")

    def check_ipconfig_index(self, idx: int, value: str) -> None:
        """Additional NIC addresses must lie inside an APPROVED segment with
        its exact prefix and never carry a gateway."""
        if not self.segments or idx >= self.max_nics:
            raise PolicyViolation(f"ipconfig{idx} is outside the approved NIC lane")
        if "gw=" in (value or ""):
            raise PolicyViolation("ipconfig must not carry gw= — lab guests get "
                                  "no gateway from the broker; routing is the "
                                  "lab's own routers' business")
        m = re.fullmatch(r"ip=([0-9.]+)/(\d+)", value or "")
        if not m:
            raise PolicyViolation(f"ipconfig{idx} must be 'ip=<addr>/<prefix>' (no gateway)")
        addr, prefix = ipaddress.ip_address(m.group(1)), int(m.group(2))
        if addr.version != 4:
            raise PolicyViolation("only IPv4 addresses are provisionable")
        for seg in self.segments:
            if addr in seg.network:
                if prefix != seg.network.prefixlen:
                    raise PolicyViolation(
                        f"ipconfig{idx} prefix /{prefix} does not match segment "
                        f"{seg.name} prefix /{seg.network.prefixlen}")
                if addr in (seg.network.network_address, seg.network.broadcast_address):
                    raise PolicyViolation(f"ipconfig{idx} address {addr} is a "
                                          f"network/broadcast address of {seg.name}")
                return
        raise PolicyViolation(f"ipconfig{idx} address {addr} is outside every "
                              f"approved segment")

    def _nic_for(self, seg: SegmentSpec) -> str:
        return f"virtio,bridge={seg.bridge}"

    def check_net0(self, net0: str) -> None:
        if self.segments and any(net0 == self._nic_for(s) for s in self.segments):
            return  # segment lane: NIC0 may be any approved segment bridge
        if net0 != self.net0_expected:
            raise PolicyViolation(f"net0 {net0!r} does not equal the exact policy NIC "
                                  f"{self.net0_expected!r}")

    def check_ipconfig(self, ipconfig0: str) -> None:
        """Cloned guests are ON-LINK ONLY (plan 13 phase 4): the typed
        config REFUSES a gateway, so no clone ever installs a default route
        toward the host — WAN/management egress cannot even be attempted by
        guest configuration. Everything a guest legitimately reaches (the
        controller's range address, the bastion, peer range hosts) is
        on-link within the range network."""
        if "gw=" in (ipconfig0 or ""):
            raise PolicyViolation(
                "ipconfig0 must not carry gw= — range guests are on-link "
                "only; a default route is refused by policy")
        m = re.fullmatch(r"ip=([0-9.]+)/(\d+)", ipconfig0 or "")
        if not m:
            raise PolicyViolation("ipconfig0 must be 'ip=<addr>/<prefix>' "
                                  "(no gateway)")
        if self.segments:
            # Segment lane: the address belongs to an approved segment with
            # its exact prefix (still never a gateway).
            self.check_ipconfig_index(0, ipconfig0)
            return
        addr, prefix = m.group(1), int(m.group(2))
        ip = ipaddress.ip_address(addr)
        if ip.version != 4 or ip not in self.network \
                or ip == self.gateway or ip == self.network.network_address \
                or ip == self.network.broadcast_address:
            raise PolicyViolation(f"address {addr} outside range network {self.network}")
        if prefix != self.network.prefixlen:
            raise PolicyViolation(f"prefix /{prefix} does not match range network "
                                  f"/{self.network.prefixlen}")

    def check_tags(self, tags: str) -> None:
        rx = re.compile(self.tag_pattern)
        parts = [t for t in re.split(r"[;]", tags or "") if t]
        if not parts or not all(rx.fullmatch(t) for t in parts):
            raise PolicyViolation(f"tags {tags!r} must all match {self.tag_pattern!r}")

    def check_capacity(self, active_count: int) -> None:
        max_vms = self.limits["max_vms"]
        if active_count + 1 > max_vms:
            raise PolicyViolation(f"aggregate limit: {active_count} VMs already owned, "
                                  f"max_vms={max_vms}")

    @property
    def net0_expected(self) -> str:
        return f"virtio,bridge={self.bridge},tag={self.vlan}"

    def per_vm_budget(self) -> tuple[int, int, int]:
        l = self.limits
        return (l.get("cores_per_vm", 4), l.get("memory_mb_per_vm", 8192),
                l.get("disk_gb_per_vm", 48))
