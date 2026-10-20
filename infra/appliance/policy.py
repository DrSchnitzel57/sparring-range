"""Appliance broker policy — same typed-operation discipline as the PVE broker.

The appliance has no Proxmox tag/VLAN machinery: inner guests attach to ONE
fixed isolated Linux bridge.  The closed set of configurable fields, the
bounded internal VMID namespace (used as the durable broker key while libvirt
domains get UUIDs), image allowlist and aggregate budgets are otherwise the
same fail-closed contract.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from infra.broker.errors import PolicyViolation
from infra.broker.policy import ALLOWED_CONFIG_KEYS

_REQUIRED = ("node", "templates", "vmid_range", "storage", "clone_mode",
             "nic", "provision", "limits")
_ALLOWED_TOP = set(_REQUIRED) | {"name_prefix", "tag_pattern", "lease_ttl_s",
                                  "heartbeat_interval_s"}
_ALLOWED_LIMITS = {"max_vms", "cores_per_vm", "memory_mb_per_vm", "disk_gb_per_vm",
                   "max_total_cores", "max_total_memory_mb", "max_total_disk_gb"}
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")
_TAG_RE_DEFAULT = r"^srsess-[0-9a-f]{32}$"


@dataclass(frozen=True)
class AppliancePolicy:
    node: str
    templates: tuple[int, ...]
    vmid_min: int
    vmid_max: int
    storage: tuple[str, ...]
    clone_mode: str
    bridge: str
    network: ipaddress.IPv4Network
    gateway: ipaddress.IPv4Address
    limits: dict = field(default_factory=dict)
    name_prefix: str = "sr-"
    tag_pattern: str = _TAG_RE_DEFAULT
    lease_ttl_s: int = 30
    heartbeat_interval_s: int = 5

    @classmethod
    def load(cls, path: str | Path) -> "AppliancePolicy":
        p = Path(path)
        try:
            raw = json.loads(p.read_text())
        except FileNotFoundError as exc:
            raise PolicyViolation(f"appliance policy missing: {p}") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise PolicyViolation(f"appliance policy unreadable ({p}): {exc}") from exc
        return cls.from_dict(raw, source=str(p))

    @classmethod
    def from_dict(cls, raw: dict, source: str = "<dict>") -> "AppliancePolicy":
        def bad(why: str) -> PolicyViolation:
            return PolicyViolation(f"appliance policy invalid ({source}): {why}")
        if not isinstance(raw, dict):
            raise bad("top level must be an object")
        unknown = set(raw) - _ALLOWED_TOP
        if unknown:
            raise bad(f"unknown keys {sorted(unknown)}")
        missing = [k for k in _REQUIRED if k not in raw]
        if missing:
            raise bad(f"missing keys {missing}")
        node = raw["node"]
        if not isinstance(node, str) or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._-]*", node):
            raise bad("node must be the single appliance installation id")
        templates = raw["templates"]
        if (not isinstance(templates, list) or not templates
                or not all(isinstance(t, int) and 1 <= t <= 999999
                           for t in templates)):
            raise bad("templates must be a non-empty list of image ids")
        vr = raw["vmid_range"]
        if (not isinstance(vr, list) or len(vr) != 2
                or not all(isinstance(v, int) and 1 <= v <= 999999 for v in vr)
                or vr[0] > vr[1]):
            raise bad("vmid_range must be [low, high]")
        storage = raw["storage"]
        if (not isinstance(storage, list) or not storage
                or not all(isinstance(s, str)
                           and re.fullmatch(r"[A-Za-z0-9._-]+", s) for s in storage)):
            raise bad("storage must be a non-empty list of exact storage ids")
        if raw["clone_mode"] not in ("full",):
            raise bad("clone_mode must be 'full' (fresh overlay from a verified base)")
        nic = raw["nic"]
        if (not isinstance(nic, dict) or set(nic) != {"bridge"}
                or not isinstance(nic.get("bridge"), str)
                or not re.fullmatch(r"[A-Za-z0-9._-]{1,15}", str(nic.get("bridge")))
                or nic["bridge"] == "lo"):
            raise bad("nic must be exactly {bridge} — one fixed isolated NIC")
        prov = raw["provision"]
        if not isinstance(prov, dict) or set(prov) != {"cidr", "gateway"}:
            raise bad("provision must be exactly {cidr, gateway}")
        try:
            net = ipaddress.ip_network(prov["cidr"], strict=True)
            gw = ipaddress.ip_address(prov["gateway"])
        except ValueError as exc:
            raise bad(f"provision network invalid: {exc}") from exc
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
        if not isinstance(prefix, str) or not re.fullmatch(r"[a-z0-9._-]{0,32}", prefix):
            raise bad("name_prefix must be lowercase-safe")
        tag_re = raw.get("tag_pattern", _TAG_RE_DEFAULT)
        try:
            re.compile(tag_re)
        except re.error as exc:
            raise bad(f"tag_pattern not a regex: {exc}") from exc
        ttl = raw.get("lease_ttl_s", 30)
        hb = raw.get("heartbeat_interval_s", 5)
        if (not isinstance(ttl, int) or ttl < 5 or not isinstance(hb, int)
                or hb < 1 or hb >= ttl):
            raise bad("lease_ttl_s >= 5 and 1 <= heartbeat_interval_s < lease_ttl_s required")
        return cls(node=node, templates=tuple(sorted(set(templates))),
                   vmid_min=vr[0], vmid_max=vr[1], storage=tuple(storage),
                   clone_mode="full", bridge=nic["bridge"], network=net,
                   gateway=gw, limits=limits, name_prefix=prefix,
                   tag_pattern=tag_re, lease_ttl_s=ttl,
                   heartbeat_interval_s=hb)

    # ---------------------------------------------------------------- checks ---
    def check_node(self, node: str) -> None:
        if node != self.node:
            raise PolicyViolation(f"node {node!r} is not the appliance {self.node!r}")

    def check_vmid(self, vmid: int) -> None:
        if not isinstance(vmid, int) or not self.vmid_min <= vmid <= self.vmid_max:
            raise PolicyViolation(f"VMID {vmid!r} outside bounded range "
                                  f"[{self.vmid_min}, {self.vmid_max}]")

    def check_template(self, vmid: int) -> None:
        if vmid not in self.templates:
            raise PolicyViolation(f"template {vmid} is not in the approved set "
                                  f"{list(self.templates)}")

    def check_clone_mode(self, full: bool) -> None:
        if not full:
            raise PolicyViolation("appliance clones are fresh full overlays; "
                                  "linked clones are refused")

    def check_name(self, name: str) -> None:
        if not isinstance(name, str) or not _NAME_RE.fullmatch(name) \
                or not name.startswith(self.name_prefix):
            raise PolicyViolation(f"name {name!r} outside policy "
                                  f"(prefix {self.name_prefix!r}, safe charset)")

    def check_config_keys(self, cfg: dict) -> None:
        extra = set(cfg) - ALLOWED_CONFIG_KEYS
        if extra:
            raise PolicyViolation(f"config keys not provisionable by policy: {sorted(extra)}")

    def check_net0(self, net0: str) -> None:
        if net0 != self.net0_expected:
            raise PolicyViolation(f"net0 {net0!r} does not equal the exact policy NIC "
                                  f"{self.net0_expected!r}")

    def check_ipconfig(self, ipconfig0: str) -> None:
        if "gw=" in (ipconfig0 or ""):
            raise PolicyViolation(
                "ipconfig0 must not carry gw= — inner guests are on-link only; "
                "a default route is refused by policy")
        m = re.fullmatch(r"ip=([0-9.]+)/(\d+)", ipconfig0 or "")
        if not m:
            raise PolicyViolation("ipconfig0 must be 'ip=<addr>/<prefix>' (no gateway)")
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
            raise PolicyViolation(f"aggregate limit: {active_count} guests already owned, "
                                  f"max_vms={max_vms}")

    @property
    def net0_expected(self) -> str:
        return f"virtio,bridge={self.bridge}"

    def per_vm_budget(self) -> tuple[int, int, int]:
        limits = self.limits
        return (limits.get("cores_per_vm", 4),
                limits.get("memory_mb_per_vm", 8192),
                limits.get("disk_gb_per_vm", 48))

    def validate_manifest(self, manifest) -> None:
        """Cross-check the two operator inputs at broker boot.

        They are loaded separately so the installer can validate a manifest
        without libvirt and the broker can load a policy without the image
        cache, but they must describe the SAME appliance. A mismatch is a
        load-time refusal, never a runtime surprise.
        """
        if self.node != manifest.installation_id:
            raise PolicyViolation(
                f"policy node {self.node!r} is not manifest installation "
                f"{manifest.installation_id!r}")
        if self.bridge != manifest.network.range_bridge:
            raise PolicyViolation("policy NIC bridge does not match manifest range_bridge")
        if self.network != manifest.network.range_cidr:
            raise PolicyViolation("policy provision network does not match manifest range_cidr")
        if self.gateway != manifest.network.range_gateway:
            raise PolicyViolation("policy gateway does not match manifest range_gateway")
        image_ids = {image.template_id for image in manifest.images.values()}
        if set(self.templates) != image_ids:
            raise PolicyViolation(
                f"policy templates {sorted(self.templates)} do not equal the "
                f"manifest image ids {sorted(image_ids)}")
        max_vms = min(self.limits["max_vms"], manifest.budgets.max_guests)
        if max_vms < 1:
            raise PolicyViolation("no guest capacity after combining policy and manifest")
        if self.limits.get("memory_mb_per_vm", 0) > manifest.budgets.max_memory_mb:
            raise PolicyViolation("policy per-VM memory exceeds manifest budget")
        if self.limits.get("disk_gb_per_vm", 0) > manifest.budgets.max_disk_gb:
            raise PolicyViolation("policy per-VM disk exceeds manifest budget")
