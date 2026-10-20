"""Strict appliance manifest: the only input the installer and broker trust.

The manifest is operator-owned, versioned and secret-free.  Every value that
selects a capability (network, bridge, image, key reference, budget, socket)
is validated here, before any service starts.  Unknown keys and inline
credentials are load-time failures, never ignored:
a typo must not silently disable isolation, and a pasted token must not end
up in an installer log or a Git-tracked file.

Public-key *references* are paths; private keys never appear in the manifest
and are read only by the process named in the architecture.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import pathlib
import re
import uuid
from dataclasses import dataclass, field
from typing import Mapping

from .errors import ManifestError

SCHEMA_VERSION = 1
_SCHEMA_KEYS = {
    "schema_version", "installation_id", "appliance", "network", "urls",
    "broker", "paths", "images", "access_keys", "model", "budgets", "backup",
}
_ROLE_RE = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
_BRIDGE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_PLACEHOLDERS = re.compile(
    r"(CHANGEME|change[-_ ]?me|<[^>]*>|example\.(com|net|org)|"
    r"REPLACE|TODO|dummy|not-a-)", re.IGNORECASE)
_SECRETY = re.compile(
    r"(pass(word|phrase)?|secret|token|api[_-]?key|private[_-]?key|credential)",
    re.IGNORECASE)


def _bad(why: str) -> ManifestError:
    return ManifestError(f"appliance manifest invalid: {why}")


def _need_obj(raw, key, *, required=True) -> dict:
    if key not in raw:
        if required:
            raise _bad(f"missing {key}")
        return {}
    value = raw[key]
    if not isinstance(value, dict):
        raise _bad(f"{key} must be an object")
    return value


def _closed(obj: Mapping, allowed: set[str], where: str) -> None:
    unknown = set(obj) - allowed
    if unknown:
        raise _bad(f"unknown keys in {where}: {sorted(unknown)}")


def _str(obj, key, where, *, required=True, allow_empty=False) -> str:
    if key not in obj:
        if required:
            raise _bad(f"missing {where}.{key}")
        return ""
    value = obj[key]
    if not isinstance(value, str):
        raise _bad(f"{where}.{key} must be a string")
    if not value and not allow_empty:
        raise _bad(f"{where}.{key} must not be empty")
    if _PLACEHOLDERS.search(value):
        raise _bad(f"{where}.{key} contains a placeholder: {value!r}")
    return value


def _int(obj, key, where, *, low=0, high=None) -> int:
    if key not in obj:
        raise _bad(f"missing {where}.{key}")
    value = obj[key]
    if not isinstance(value, int) or isinstance(value, bool):
        raise _bad(f"{where}.{key} must be an integer")
    if value < low or (high is not None and value > high):
        bound = f"[{low}, {high}]" if high is not None else f">= {low}"
        raise _bad(f"{where}.{key} outside {bound}: {value}")
    return value


def _abs_path(value: str, where: str) -> str:
    p = pathlib.Path(value)
    if not p.is_absolute():
        raise _bad(f"{where} must be an absolute path: {value!r}")
    return str(p)


def _check_secret_free(obj, path="manifest") -> None:
    """Recursively reject inline credential-looking fields/values.

    A value is allowed to be a *path* to a secret (``*_file``), never the
    secret itself.  This is deliberately conservative: a false positive is
    a manifest edit, a false negative is a leaked credential.
    """
    if isinstance(obj, dict):
        for key, value in obj.items():
            key_s = str(key)
            reference_name = (key_s in {"secrets", "access_keys"}
                              or key_s.endswith(("_file", "_path", "_dir")))
            if _SECRETY.search(key_s) and not reference_name:
                raise _bad(f"inline credential-like field {path}.{key} is forbidden; "
                           "use an operator-owned file reference")
            _check_secret_free(value, f"{path}.{key}")
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            _check_secret_free(value, f"{path}[{i}]")
    elif isinstance(obj, str):
        # PEM blocks are the clearest accidental paste.
        if ("BEGIN " in obj and "PRIVATE KEY" in obj) or re.search(
                r"(?i)\b(password|passwd|token|secret)\s*[:=]\s*\S+", obj):
            raise _bad(f"inline credential-looking value at {path} is forbidden")


@dataclass(frozen=True)
class AccessKey:
    role: str
    path: str


@dataclass(frozen=True)
class ImageSpec:
    role: str
    template_id: int
    path: str
    sha256: str
    size_bytes: int
    disk_gb: int
    memory_mb: int
    vcpus: int

    def verify_file(self) -> None:
        p = pathlib.Path(self.path)
        if not p.is_file():
            raise _bad(f"image {p} is missing")
        actual = hashlib.sha256(p.read_bytes()).hexdigest()
        if actual != self.sha256:
            raise _bad(f"image {p} sha256 mismatch: expected {self.sha256}, got {actual}")
        if p.stat().st_size != self.size_bytes:
            raise _bad(f"image {p} size mismatch: expected {self.size_bytes}")


@dataclass(frozen=True)
class Network:
    lan_cidr: ipaddress.IPv4Network
    range_cidr: ipaddress.IPv4Network
    range_bridge: str
    range_gateway: ipaddress.IPv4Address
    controller_range_ip: ipaddress.IPv4Address
    bastion_address: ipaddress.IPv4Address
    ingest_address: ipaddress.IPv4Address
    ingest_port: int
    management_cidr: ipaddress.IPv4Network
    lan_address: ipaddress.IPv4Address | None = None


@dataclass(frozen=True)
class Budgets:
    max_guests: int
    max_vcpus: int
    max_memory_mb: int
    max_disk_gb: int
    min_free_gb: int


@dataclass(frozen=True)
class ApplianceManifest:
    schema_version: int
    installation_id: str
    images: Mapping[str, ImageSpec]
    access_keys: Mapping[str, AccessKey]
    network: Network
    budgets: Budgets
    broker_socket: str
    broker_ledger: str
    state_dir: str
    images_dir: str
    recordings_dir: str
    secrets_dir: str
    public_url: str
    internal_url: str
    ingest_url: str
    model_base_url: str
    model_alias: str
    model_api_key_file: str
    backup_enabled: bool = False
    backup_destination: str | None = None
    source: str = "<dict>"
    raw: dict = field(default_factory=dict, repr=False, compare=False)

    # ------------------------------------------------------------------ load ---
    @classmethod
    def load(cls, path: str | pathlib.Path, *, verify_images: bool = False):
        p = pathlib.Path(path)
        try:
            raw = json.loads(p.read_text())
        except FileNotFoundError as exc:
            raise ManifestError(f"appliance manifest missing: {p}") from exc
        except (OSError, json.JSONDecodeError) as exc:
            raise ManifestError(f"appliance manifest unreadable ({p}): {exc}") from exc
        return cls.from_dict(raw, source=str(p), verify_images=verify_images)

    @classmethod
    def from_dict(cls, raw: dict, *, source: str = "<dict>",
                  verify_images: bool = False):
        if not isinstance(raw, dict):
            raise _bad("top level must be an object")
        _closed(raw, _SCHEMA_KEYS, "manifest")
        if raw.get("schema_version") != SCHEMA_VERSION:
            raise _bad(f"schema_version must be {SCHEMA_VERSION}")
        _check_secret_free(raw)

        try:
            iid = str(uuid.UUID(str(raw.get("installation_id"))))
        except (ValueError, TypeError, AttributeError) as exc:
            raise _bad("installation_id must be a UUID") from exc

        appliance = _need_obj(raw, "appliance")
        _closed(appliance, {"hostname", "timezone"}, "appliance")
        hostname = _str(appliance, "hostname", "appliance")
        if not _HOST_RE.fullmatch(hostname):
            raise _bad("appliance.hostname is not a DNS hostname")
        _str(appliance, "timezone", "appliance", required=False, allow_empty=True)

        net_raw = _need_obj(raw, "network")
        _closed(net_raw, {
            "lan_cidr", "lan_address", "range_cidr", "range_bridge",
            "range_gateway", "controller_range_ip", "bastion_address",
            "ingest_address", "ingest_port", "management_cidr"}, "network")
        try:
            lan = ipaddress.ip_network(_str(net_raw, "lan_cidr", "network"),
                                       strict=True)
            rng = ipaddress.ip_network(_str(net_raw, "range_cidr", "network"),
                                       strict=True)
            mgmt = ipaddress.ip_network(_str(net_raw, "management_cidr", "network"),
                                        strict=True)
            if not all(isinstance(n, ipaddress.IPv4Network) for n in (lan, rng, mgmt)):
                raise ValueError("only IPv4 networks are supported")
            gw = ipaddress.ip_address(_str(net_raw, "range_gateway", "network"))
            ctl = ipaddress.ip_address(_str(net_raw, "controller_range_ip", "network"))
            bast = ipaddress.ip_address(_str(net_raw, "bastion_address", "network"))
            ing = ipaddress.ip_address(_str(net_raw, "ingest_address", "network"))
            lan_addr = (ipaddress.ip_address(net_raw["lan_address"])
                        if net_raw.get("lan_address") else None)
        except ValueError as exc:
            raise _bad(f"network address/CIDR invalid: {exc}") from exc
        bridge = _str(net_raw, "range_bridge", "network")
        if not _BRIDGE_RE.fullmatch(bridge) or bridge == "lo":
            raise _bad("network.range_bridge is not a safe bridge name")
        for label, addr in (("range_gateway", gw), ("controller_range_ip", ctl),
                            ("bastion_address", bast), ("ingest_address", ing)):
            if addr not in rng:
                raise _bad(f"network.{label} must lie inside range_cidr")
        if gw == rng.network_address or gw == rng.broadcast_address:
            raise _bad("range_gateway must be a usable host address")
        for label, addr in (("controller_range_ip", ctl), ("bastion_address", bast),
                            ("ingest_address", ing)):
            if addr == rng.network_address or addr == rng.broadcast_address:
                raise _bad(f"network.{label} must be a usable host address")
        if lan_addr is not None and lan_addr not in lan:
            raise _bad("network.lan_address must lie inside lan_cidr")
        if rng.overlaps(lan) or rng.overlaps(mgmt) or lan.overlaps(mgmt):
            raise _bad("lane/range/management networks must not overlap")
        if rng.is_loopback or lan.is_loopback or mgmt.is_loopback:
            raise _bad("loopback is not a valid appliance network")
        port = _int(net_raw, "ingest_port", "network", low=1, high=65535)

        urls = _need_obj(raw, "urls")
        _closed(urls, {"public", "internal", "ingest"}, "urls")
        public = _str(urls, "public", "urls")
        internal = _str(urls, "internal", "urls")
        ingest_url = _str(urls, "ingest", "urls")
        for label, url in (("public", public), ("internal", internal),
                           ("ingest", ingest_url)):
            if not re.match(r"^https?://[^/\s]+", url):
                raise _bad(f"urls.{label} must be an http(s) URL")
        if not internal.startswith(("http://127.0.0.1", "http://localhost")):
            raise _bad("urls.internal must be loopback (co-located trusted processes)")

        broker = _need_obj(raw, "broker")
        _closed(broker, {"socket", "ledger", "state_dir"}, "broker")
        sock = _abs_path(_str(broker, "socket", "broker"), "broker.socket")
        ledger = _abs_path(_str(broker, "ledger", "broker"), "broker.ledger")
        state = _abs_path(_str(broker, "state_dir", "broker"), "broker.state_dir")
        if not sock.endswith(".sock"):
            raise _bad("broker.socket must name a Unix socket")

        paths = _need_obj(raw, "paths")
        _closed(paths, {"images", "recordings", "secrets"}, "paths")
        images_dir = _abs_path(_str(paths, "images", "paths"), "paths.images")
        recordings = _abs_path(_str(paths, "recordings", "paths"), "paths.recordings")
        secrets = _abs_path(_str(paths, "secrets", "paths"), "paths.secrets")

        images_raw = _need_obj(raw, "images")
        if not isinstance(images_raw, dict) or not images_raw:
            raise _bad("images must be a non-empty object")
        images: dict[str, ImageSpec] = {}
        ids: set[int] = set()
        for role, item in images_raw.items():
            if not _ROLE_RE.fullmatch(str(role)) or not isinstance(item, dict):
                raise _bad(f"images.{role} must be a role object")
            _closed(item, {"template_id", "path", "sha256", "size_bytes",
                           "disk_gb", "memory_mb", "vcpus"}, f"images.{role}")
            tid = _int(item, "template_id", f"images.{role}", low=1, high=999999)
            if tid in ids:
                raise _bad(f"duplicate template_id {tid}")
            ids.add(tid)
            image = ImageSpec(
                role=str(role), template_id=tid,
                path=_abs_path(_str(item, "path", f"images.{role}"),
                               f"images.{role}.path"),
                sha256=_str(item, "sha256", f"images.{role}").lower(),
                size_bytes=_int(item, "size_bytes", f"images.{role}", low=1),
                disk_gb=_int(item, "disk_gb", f"images.{role}", low=1, high=512),
                memory_mb=_int(item, "memory_mb", f"images.{role}", low=256, high=65536),
                vcpus=_int(item, "vcpus", f"images.{role}", low=1, high=64),
            )
            if not re.fullmatch(r"[0-9a-f]{64}", image.sha256):
                raise _bad(f"images.{role}.sha256 must be 64 lowercase hex chars")
            if verify_images:
                image.verify_file()
            images[str(role)] = image
        required_roles = {"attacker", "mojang-web-local", "mojang-web-db"}
        missing_roles = required_roles - set(images)
        if missing_roles:
            raise _bad(f"images missing required roles {sorted(missing_roles)}")

        keys_raw = _need_obj(raw, "access_keys")
        if not isinstance(keys_raw, dict) or not keys_raw:
            raise _bad("access_keys must be a non-empty object")
        keys: dict[str, AccessKey] = {}
        for role, value in keys_raw.items():
            if not _ROLE_RE.fullmatch(str(role)):
                raise _bad(f"access_keys.{role} is not a role name")
            path = _abs_path(value, f"access_keys.{role}") if isinstance(value, str) \
                else None
            if path is None:
                raise _bad(f"access_keys.{role} must be an absolute path")
            keys[str(role)] = AccessKey(str(role), path)

        required_key_roles = {"runner", "bastion", "mgmt"}
        missing_key_roles = required_key_roles - set(keys)
        if missing_key_roles:
            raise _bad(f"access_keys missing role public keys "
                       f"{sorted(missing_key_roles)}")

        model = _need_obj(raw, "model")
        _closed(model, {"base_url", "alias", "api_key_file"}, "model")
        base_url = _str(model, "base_url", "model")
        if not re.match(r"^https?://[^/\s]+", base_url):
            raise _bad("model.base_url must be an http(s) URL")
        alias = _str(model, "alias", "model")
        if not re.fullmatch(r"[A-Za-z0-9._/:-]{1,128}", alias):
            raise _bad("model.alias must be a safe model identifier")
        api_key_file = _abs_path(_str(model, "api_key_file", "model"),
                                 "model.api_key_file")

        budget_raw = _need_obj(raw, "budgets")
        _closed(budget_raw, {"max_guests", "max_vcpus", "max_memory_mb",
                             "max_disk_gb", "min_free_gb"}, "budgets")
        budgets = Budgets(
            max_guests=_int(budget_raw, "max_guests", "budgets", low=1, high=16),
            max_vcpus=_int(budget_raw, "max_vcpus", "budgets", low=1, high=128),
            max_memory_mb=_int(budget_raw, "max_memory_mb", "budgets", low=256),
            max_disk_gb=_int(budget_raw, "max_disk_gb", "budgets", low=1),
            min_free_gb=_int(budget_raw, "min_free_gb", "budgets", low=0),
        )
        if budgets.max_guests > len(images) * 4:
            raise _bad("budgets.max_guests is implausibly large for the image set")
        if sum(i.vcpus for i in images.values()) > budgets.max_vcpus:
            raise _bad("image vcpu totals exceed budgets.max_vcpus")
        if sum(i.memory_mb for i in images.values()) > budgets.max_memory_mb:
            raise _bad("image memory totals exceed budgets.max_memory_mb")
        if sum(i.disk_gb for i in images.values()) > budgets.max_disk_gb:
            raise _bad("image disk totals exceed budgets.max_disk_gb")

        backup = _need_obj(raw, "backup", required=False)
        _closed(backup, {"enabled", "destination"}, "backup")
        enabled = bool(backup.get("enabled", False))
        dest = backup.get("destination")
        if enabled:
            if not isinstance(dest, str) or not dest:
                raise _bad("backup.destination is required when backup is enabled")
            dest = _abs_path(dest, "backup.destination")
        elif dest not in (None, ""):
            raise _bad("backup.destination must be empty when backup is disabled")

        manifest = cls(
            schema_version=SCHEMA_VERSION, installation_id=iid, images=images,
            access_keys=keys,
            network=Network(
                lan_cidr=lan, range_cidr=rng, range_bridge=bridge,
                range_gateway=gw, controller_range_ip=ctl, bastion_address=bast,
                ingest_address=ing, ingest_port=port, management_cidr=mgmt,
                lan_address=lan_addr),
            budgets=budgets, broker_socket=sock, broker_ledger=ledger,
            state_dir=state, images_dir=images_dir, recordings_dir=recordings,
            secrets_dir=secrets, public_url=public, internal_url=internal,
            ingest_url=ingest_url, model_base_url=base_url, model_alias=alias,
            model_api_key_file=api_key_file, backup_enabled=enabled,
            backup_destination=dest, source=source, raw=raw)
        manifest.check_key_material()
        return manifest

    # ---------------------------------------------------------------- checks ---
    def check_key_material(self) -> None:
        """References must be public keys, readable, and never private keys."""
        for role, key in self.access_keys.items():
            p = pathlib.Path(key.path)
            if not p.is_file():
                raise _bad(f"access_keys.{role} file is missing: {p}")
            try:
                text = p.read_text()
            except OSError as exc:
                raise _bad(f"access_keys.{role} unreadable: {exc}") from exc
            if "PRIVATE KEY" in text:
                raise _bad(f"access_keys.{role} must be a PUBLIC key, not a private key")
            lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
            if not lines or not (lines[0].startswith(("ssh-", "ecdsa-", "sk-"))
                                 or lines[0].startswith("restrict ")):
                raise _bad(f"access_keys.{role} is not an OpenSSH public key")
        model_key = pathlib.Path(self.model_api_key_file)
        if not model_key.is_file():
            raise _bad(f"model.api_key_file is missing: {model_key}")
        if not model_key.read_text().strip():
            raise _bad("model.api_key_file is empty")

    @property
    def roles(self) -> tuple[str, ...]:
        return tuple(sorted(self.images))

    def image_for_template(self, template_id: int) -> ImageSpec | None:
        for image in self.images.values():
            if image.template_id == template_id:
                return image
        return None

    def image_for_role(self, role: str) -> ImageSpec:
        try:
            return self.images[role]
        except KeyError as exc:
            raise _bad(f"unknown image role {role!r}") from exc

    def public_key_for(self, role: str) -> str:
        if role not in self.access_keys:
            raise _bad(f"no access key for role {role!r}")
        return pathlib.Path(self.access_keys[role].path).read_text().strip()

    def ensure_state_dirs(self) -> None:
        for d in (pathlib.Path(self.state_dir), pathlib.Path(self.recordings_dir),
                  pathlib.Path(self.images_dir)):
            d.mkdir(parents=True, exist_ok=True)

    def redacted(self) -> dict:
        """A plan/status view with no key material or secret paths' contents."""
        return {
            "schema_version": self.schema_version,
            "installation_id": self.installation_id,
            "range_cidr": str(self.network.range_cidr),
            "range_bridge": self.network.range_bridge,
            "broker_socket": self.broker_socket,
            "images": {role: {"template_id": i.template_id,
                              "sha256": i.sha256, "disk_gb": i.disk_gb,
                              "memory_mb": i.memory_mb, "vcpus": i.vcpus}
                       for role, i in sorted(self.images.items())},
            "access_key_roles": sorted(self.access_keys),
            "budgets": vars(self.budgets),
            "backup_enabled": self.backup_enabled,
        }
