"""Typed environment blueprint — segments, guests, resources, dependencies.

Closed-world by construction: every vocabulary (segment purposes, OS kinds,
firmware, bootstrap transports, service ids, edge kinds) is an enum here,
addresses must belong to their segment, dependencies must resolve and stay
acyclic, and the aggregate guest reservation must fit the declared outer
budget. The broker/API later consume ONLY these validated objects; there
are no free-form network strings, no arbitrary device arguments, and no
way to name a bridge from scenario or model data (bridges are an operator
installation concern bound to segment NAMES by the appliance manifest).

Values never imply capacity: `resource_policy` records the planned outer
budget so the blueprint can PROVE its own aggregate reservation fits;
actual host capacity remains a preflight gate.
"""
from __future__ import annotations

import ipaddress
import re
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ENVIRONMENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
NAME_RE = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
HOSTNAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,14}$")  # NetBIOS/DNS-safe labels


class EnvironmentError(ValueError):
    def __init__(self, issues: list[str]):
        self.issues = issues
        super().__init__("; ".join(issues))


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SegmentPurpose(str, Enum):
    INSIDE_LAN = "inside-lan"        # defender workstation LAN
    TRANSIT = "transit"              # firewall <-> router transit
    TEAM = "team"                    # team-attached segment (e.g. Kali)
    SIMULATED_WAN = "simulated-wan"  # router WAN leg toward simulated upstream
    PUBLIC_NAT = "public-nat"        # routed public prefix (DNAT VIPs live here)
    RED = "red"                      # external red-team / AI attacker entry
    SCORING = "scoring"              # trusted scoring vantage attachment


class OsKind(str, Enum):
    LINUX = "linux"
    FREEBSD = "freebsd"    # OPNsense-class appliances: FreeBSD userland, not
                           # Linux — bootstrap/readiness paths differ materially
    WINDOWS = "windows"
    ROUTER = "router"


class Firmware(str, Enum):
    BIOS = "bios"
    EFI = "efi"
    EFI_TPM = "efi-tpm"


class BootstrapTransport(str, Enum):
    QGA_SSH = "qga-ssh"       # Linux: QGA host-key path + pinned SSH
    QGA_WINRM = "qga-winrm"   # Windows: QGA first-boot identity over WinRM
    QGA_ONLY = "qga-only"     # agent channel only (hardened Linux)
    SERIAL_SEED = "serial-seed"  # routers without QGA: bounded first-boot
                                 # identity read through the appliance-owned
                                 # seed/storage channel (no network TOFU)


class AddressMode(str, Enum):
    STATIC = "static"
    DHCP = "dhcp"


class GuestRole(str, Enum):
    """Closed image-role vocabulary the appliance may provide. Extending it
    means extending the appliance manifest role set and golden builds
    TOGETHER (mirrors the SUPPORTED_SERVICES discipline)."""
    ROUTER = "router"
    FIREWALL = "firewall"
    LINUX_SERVER = "linux-server"
    MAIL_SERVER = "mail-server"
    SPLUNK_SERVER = "splunk-server"
    WINDOWS_DC = "windows-dc"
    WINDOWS_SQL = "windows-sql"
    LINUX_DESKTOP = "linux-desktop"
    WINDOWS_DESKTOP = "windows-desktop"
    ATTACKER = "attacker"            # privileged platform attacker template
    TEAM_TOOLING = "team-tooling"    # defender/member tooling VM (e.g. team
                                     # Kali): member-accessible, NEVER the
                                     # platform attacker role
    RED_ENTRY = "red-entry"
    SCORING = "scoring"


class ServiceId(str, Enum):
    """Guest services a blueprint may declare. These are PREBUILT TEMPLATE
    CONTRACTS (readiness-checked later), not installers."""
    SSH = "ssh"
    NGINX = "nginx"
    NOPCOMMERCE = "nopcommerce"
    POSTFIX = "postfix"
    DOVECOT = "dovecot"
    ROUNDCUBE = "roundcube"
    SPLUNK = "splunk"
    SPLUNK_FORWARDER = "splunk-forwarder"
    SYSLOG_RECEIVER = "syslog-receiver"
    ACTIVE_DIRECTORY = "active-directory"
    DNS = "dns"
    MSSQL = "mssql"
    WINRM = "winrm"
    SSSD_AD = "sssd-ad"
    CA_FILESHARE = "ca-fileshare"
    CUPS = "cups"
    AVAHI = "avahi"
    CHRONY = "chrony"


class EdgeKind(str, Enum):
    DNS = "dns"
    LDAP = "ldap"
    KERBEROS = "kerberos"
    SMB = "smb"
    WINRM = "winrm"
    SQL = "sql"
    HTTP = "http"
    HTTPS = "https"
    SMTP = "smtp"
    IMAP = "imap"
    POP3 = "pop3"
    SYSLOG = "syslog"
    NAT = "nat"
    ROUTES = "routes"
    DHCP = "dhcp"
    NTP = "ntp"


class Segment(Strict):
    name: str = Field(pattern=NAME_RE.pattern)
    purpose: SegmentPurpose
    cidr: str
    # Operator installation binds the approved bridge for each segment NAME;
    # scenarios and models can never choose bridges. The blueprint only
    # declares WHICH segment exists and its isolation properties.
    appliance_bridge_prefix_safe: bool = True
    dhcp_pool: str | None = None
    default_gateway: str | None = None
    dns_servers: list[str] = []
    # Outer containment: guest traffic must never reach the physical LAN /
    # model host / real WAN through this segment. True = appliance-enforced
    # deny except approved paths.
    egress_denied: bool = True

    @field_validator("cidr")
    @classmethod
    def _cidr(cls, v: str) -> str:
        net = ipaddress.ip_network(v, strict=True)
        if net.version != 4 or net.prefixlen > 30:
            raise ValueError("segment cidr must be a strict IPv4 /<=30 network")
        return str(net)

    @field_validator("dhcp_pool")
    @classmethod
    def _pool(cls, v: str | None) -> str | None:
        if v is None:
            return None
        net = ipaddress.ip_network(v, strict=False)
        if net.version != 4:
            raise ValueError("dhcp_pool must be IPv4")
        return str(net)

    @field_validator("default_gateway", "dns_servers")
    @classmethod
    def _addr(cls, v: Any) -> Any:
        if isinstance(v, str):
            ipaddress.ip_address(v)
        elif isinstance(v, list):
            for item in v:
                ipaddress.ip_address(item)
        return v


class Address(Strict):
    mode: AddressMode
    address: str | None = None

    @field_validator("address")
    @classmethod
    def _addr(cls, v: str | None) -> str | None:
        if v is not None:
            ipaddress.ip_address(v)
        return v


class Interface(Strict):
    segment: str = Field(pattern=NAME_RE.pattern)
    ipv4: Address


class Resources(Strict):
    vcpus: int = Field(ge=1, le=32)
    memory_mb: int = Field(ge=256, le=131072)
    disk_gb: int = Field(ge=1, le=2048)


class BootProfile(Strict):
    firmware: Firmware = Firmware.BIOS
    bootstrap: BootstrapTransport = BootstrapTransport.QGA_SSH
    # Pinned artifact reference name (resolved through the appliance image
    # registry at install time; never a path or URL).
    image_profile: str = Field(pattern=r"^[a-z][a-z0-9._-]{1,63}$")


class Guest(Strict):
    name: str = Field(pattern=HOSTNAME_RE.pattern)
    display_name: str = Field(min_length=1, max_length=120)
    role: GuestRole
    os: OsKind
    interfaces: list[Interface] = Field(min_length=1, max_length=4)
    resources: Resources
    boot: BootProfile
    depends_on: list[str] = []
    services: list[ServiceId] = []
    # Lab-only opening credentials classification: guests in a vulnerable
    # opening state carry DISPOSED lab defaults; never platform accounts.
    lab_only_defaults: bool = False

    @field_validator("depends_on")
    @classmethod
    def _dep_names(cls, v: list[str]) -> list[str]:
        for item in v:
            if not re.fullmatch(NAME_RE.pattern, item):
                raise ValueError(f"depends_on entry {item!r} is not a guest name")
        return v

    @field_validator("interfaces")
    @classmethod
    def _unique_segments(cls, v: list[Interface]) -> list[Interface]:
        seen = [i.segment for i in v]
        if len(seen) != len(set(seen)):
            raise ValueError("guest cannot attach twice to the same segment")
        return v


class ServiceEdge(Strict):
    """One declared dependency/routing edge. Kind is closed; endpoints are
    guest names (or a segment for nat/routes edges)."""
    kind: EdgeKind
    src: str
    dst: str
    detail: str = Field(min_length=1, max_length=300)
    port: int | None = Field(default=None, ge=1, le=65535)
    protocol: Literal["tcp", "udp"] | None = None


class DnsRecord(Strict):
    name: str = Field(min_length=1, max_length=253)
    type: Literal["A", "CNAME", "MX", "SRV"]
    value: str = Field(min_length=1, max_length=253)
    preference: int | None = Field(default=None, ge=0, le=65535)


class ResourcePolicy(Strict):
    """Declared outer budget + oversubscription rules. The blueprint must fit
    its OWN policy; a mismatch is a validation failure, not a runtime
    surprise."""
    outer_memory_mb: int = Field(ge=4096)
    outer_vcpus: int = Field(ge=1, le=512)
    controller_reserve_mb: int = Field(ge=1024)
    headroom_reserve_mb: int = Field(ge=0)
    # Guest vCPU totals may exceed physical vCPUs only under an explicit
    # aggregate CPU limit; memory is NEVER oversubscribed.
    aggregate_cpu_limit_percent: int = Field(ge=50, le=400)


class EnvironmentBlueprint(Strict):
    schema_version: Literal[1] = 1
    id: str = Field(pattern=ENVIRONMENT_ID_RE.pattern)
    name: str = Field(min_length=1, max_length=120)
    domain: str = Field(min_length=4, max_length=253)
    description: str = Field(min_length=1, max_length=2000)
    # Fidelity/attack/checks documents are separate files in the environment
    # directory; the blueprint lists its version so sessions can pin exactly
    # what they deployed.
    version: int = Field(ge=1)
    resource_policy: ResourcePolicy
    segments: list[Segment] = Field(min_length=1)
    guests: list[Guest] = Field(min_length=1)
    edges: list[ServiceEdge] = []
    dns_records: list[DnsRecord] = []

    # ------------------------------------------------------------ validate --
    @model_validator(mode="after")
    def _cross(self) -> "EnvironmentBlueprint":
        issues: list[str] = []
        where = f"environment {self.id}"

        seg_names = [s.name for s in self.segments]
        if len(seg_names) != len(set(seg_names)):
            issues.append(f"{where}: duplicate segment names")
        segments = {s.name: s for s in self.segments}
        for s in self.segments:
            net = ipaddress.ip_network(s.cidr)
            if s.dhcp_pool:
                pool = ipaddress.ip_network(s.dhcp_pool, strict=False)
                if not pool.subnet_of(net):
                    issues.append(f"{where}: segment {s.name}: dhcp_pool {pool} "
                                  f"outside cidr {net}")
            if s.default_gateway:
                gw = ipaddress.ip_address(s.default_gateway)
                if gw not in net:
                    issues.append(f"{where}: segment {s.name}: default_gateway "
                                  f"{gw} outside cidr {net}")
            for d in s.dns_servers:
                if ipaddress.ip_address(d) not in net:
                    issues.append(f"{where}: segment {s.name}: dns server {d} "
                                  f"outside cidr {net}")

        # segment CIDRs must not overlap each other
        nets = [(s.name, ipaddress.ip_network(s.cidr)) for s in self.segments]
        for i in range(len(nets)):
            for j in range(i + 1, len(nets)):
                if nets[i][1].overlaps(nets[j][1]):
                    issues.append(f"{where}: segments {nets[i][0]} and "
                                  f"{nets[j][0]} overlap")

        guest_names = [g.name for g in self.guests]
        if len(guest_names) != len(set(guest_names)):
            issues.append(f"{where}: duplicate guest names")
        guests = {g.name: g for g in self.guests}

        used_addresses: list[tuple[str, ipaddress.IPv4Address]] = []
        for g in self.guests:
            for iface in g.interfaces:
                seg = segments.get(iface.segment)
                if seg is None:
                    issues.append(f"{where}: guest {g.name}: interface names "
                                  f"unknown segment {iface.segment!r}")
                    continue
                if iface.ipv4.mode == AddressMode.DHCP:
                    if not seg.dhcp_pool:
                        issues.append(
                            f"{where}: guest {g.name}: interface on segment "
                            f"{seg.name} uses dhcp but segment declares no pool")
                    if iface.ipv4.address is not None:
                        # a DHCP reservation: the address must still belong to
                        # the segment and stay collision-free
                        addr = ipaddress.ip_address(iface.ipv4.address)
                        net = ipaddress.ip_network(seg.cidr)
                        if addr not in net:
                            issues.append(f"{where}: guest {g.name}: dhcp "
                                          f"reservation {addr} outside segment "
                                          f"{seg.name} ({net})")
                        for other, oaddr in used_addresses:
                            if addr == oaddr:
                                issues.append(f"{where}: dhcp reservation {addr} "
                                              f"used by both {other} and {g.name}")
                        used_addresses.append((g.name, addr))
                    continue
                if iface.ipv4.address is None:
                    issues.append(f"{where}: guest {g.name}: static interface on "
                                  f"{seg.name} requires an address")
                    continue
                addr = ipaddress.ip_address(iface.ipv4.address)
                net = ipaddress.ip_network(seg.cidr)
                if addr not in net:
                    issues.append(f"{where}: guest {g.name}: address {addr} "
                                  f"outside segment {seg.name} ({net})")
                if addr in (net.network_address, net.broadcast_address):
                    issues.append(f"{where}: guest {g.name}: address {addr} is a "
                                  f"network/broadcast address of {seg.name}")
                for other, oaddr in used_addresses:
                    if addr == oaddr:
                        issues.append(f"{where}: address {addr} used by both "
                                      f"{other} and {g.name}")
                used_addresses.append((g.name, addr))
            for dep in g.depends_on:
                if dep not in guests:
                    issues.append(f"{where}: guest {g.name}: depends_on unknown "
                                  f"guest {dep!r}")
                if dep == g.name:
                    issues.append(f"{where}: guest {g.name} depends on itself")

        # dependency cycles (iterative DFS with a per-path state set)
        state: dict[str, int] = {}  # 0 = visiting, 1 = done

        def _walk(start: str, path: list[str]) -> None:
            state[start] = 0
            path.append(start)
            for dep in guests[start].depends_on:
                if dep not in guests:
                    continue
                if state.get(dep) == 0:
                    cycle = " -> ".join(path[path.index(dep):] + [dep])
                    issues.append(f"{where}: dependency cycle: {cycle}")
                elif dep not in state:
                    _walk(dep, path)
            path.pop()
            state[start] = 1

        for g in self.guests:
            if g.name not in state:
                _walk(g.name, [])

        # a declared default gateway must be owned by exactly one guest
        # interface (the router/firewall guest that serves it)
        for s in self.segments:
            if not s.default_gateway:
                continue
            gw = ipaddress.ip_address(s.default_gateway)
            owners = [name for name, addr in used_addresses if addr == gw]
            if len(owners) != 1:
                issues.append(
                    f"{where}: segment {s.name}: default gateway {gw} must be "
                    f"bound to exactly one guest interface (found {len(owners)})")

        for e, edge in enumerate(self.edges):
            for side in ("src", "dst"):
                val = getattr(edge, side)
                if val not in guests and val not in segments:
                    issues.append(f"{where}: edges[{e}] ({edge.kind.value}): "
                                  f"{side} {val!r} names neither a guest nor a "
                                  f"segment")

        for r, rec in enumerate(self.dns_records):
            if rec.type == "A":
                try:
                    ipaddress.ip_address(rec.value)
                except ValueError:
                    issues.append(f"{where}: dns_records[{r}]: A value "
                                  f"{rec.value!r} is not an address")

        # aggregate reservation must fit the declared policy
        rp = self.resource_policy
        total_mem = sum(g.resources.memory_mb for g in self.guests)
        cap = rp.outer_memory_mb - rp.controller_reserve_mb - rp.headroom_reserve_mb
        if total_mem > cap:
            issues.append(
                f"{where}: guest memory total {total_mem} MB exceeds the policy "
                f"guest capacity {cap} MB (outer {rp.outer_memory_mb} MB minus "
                f"controller {rp.controller_reserve_mb} MB minus headroom "
                f"{rp.headroom_reserve_mb} MB)")
        total_disk = sum(g.resources.disk_gb for g in self.guests)
        if total_disk > 1024 * 16:
            issues.append(f"{where}: guest disk total {total_disk} GB exceeds the "
                          f"16 TB blueprint ceiling")

        if issues:
            raise ValueError("\n".join(issues))
        return self

    # -------------------------------------------------------------- access --
    def segment(self, name: str) -> Segment:
        for s in self.segments:
            if s.name == name:
                return s
        raise EnvironmentError([f"unknown segment {name!r}"])

    def guest(self, name: str) -> Guest:
        for g in self.guests:
            if g.name == name:
                return g
        raise EnvironmentError([f"unknown guest {name!r}"])

    def address_in(self, guest_name: str, segment_name: str) -> ipaddress.IPv4Address | None:
        g = self.guest(guest_name)
        for iface in g.interfaces:
            if iface.segment == segment_name and iface.ipv4.address:
                return ipaddress.ip_address(iface.ipv4.address)
        return None

    def reservation(self) -> dict:
        """Aggregate guest-side reservation (MB/GB/units) for preflight and
        broker capacity checks."""
        return {
            "guests": len(self.guests),
            "memory_mb_total": sum(g.resources.memory_mb for g in self.guests),
            "vcpus_total": sum(g.resources.vcpus for g in self.guests),
            "disk_gb_total": sum(g.resources.disk_gb for g in self.guests),
            "outer_memory_mb": self.resource_policy.outer_memory_mb,
            "outer_vcpus": self.resource_policy.outer_vcpus,
            "aggregate_cpu_limit_percent":
                self.resource_policy.aggregate_cpu_limit_percent,
        }

    def provision_order(self) -> list[str]:
        """Dependency order: guests appear only after all guests they depend
        on (ties keep blueprint declaration order). Assumes validated acyclic
        graphs."""
        remaining = {g.name: set(g.depends_on) for g in self.guests}
        order: list[str] = []
        while remaining:
            ready = [n for n, deps in remaining.items() if deps <= set(order)]
            if not ready:
                raise EnvironmentError([f"environment {self.id}: unresolvable "
                                        "dependency order"])
            for n in sorted(ready):
                order.append(n)
                remaining.pop(n)
        return order
