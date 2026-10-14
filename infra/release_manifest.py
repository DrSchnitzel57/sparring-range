"""Versioned release manifest — the single non-secret deployment input.

Plan 13 phase 1: one versioned manifest describes the intended release
(service VM identities/addresses, bridge/VLAN/CIDR, templates/roles/
checksums, bounded clone VMIDs, storage/clone policy, budgets/headroom,
public/internal/ingest URLs, trust identities, model alias, state paths and
an optional backup destination). Every consumer (env files, broker policy,
systemd services, template builds, the installer) is DERIVED from it, so
drifting hand-edited inputs are structurally impossible.

Hard rules enforced here (fail closed, before any side effect):

* No secret material. Keys that look like credentials are rejected and the
  manifest only references locally protected input files by path.
* Placeholders (``CHANGE_ME``/``<...>``) and unsupported versions are errors.
* Overlapping addresses or VMIDs, unbounded VMID ranges, missing template
  checksums and unsafe capacity/headroom are errors.
* The installer inventory distinguishes ABSENT / MATCHING / CONFLICTING /
  UNREADABLE; anything but a fully MATCHING inventory (plus sufficient
  capacity and a supported version) refuses to proceed. A storage label
  alone (e.g. ``local-zfs``) is never proof of safety — only the observed
  free capacity, quota and headroom numbers are.

Historical candidate values (node ``pve``, bridge ``srrange``, VLAN 66,
storage ``local-zfs``, VMIDs 9005/9011/9012/9100-9199) are EXAMPLES in
``deploy/manifest.example.json``; the loader never assumes them.
"""
from __future__ import annotations

import dataclasses
import ipaddress
import json
import pathlib
import re
from typing import Any, Mapping

MANIFEST_VERSION = 1
SUPPORTED_MANIFEST_VERSIONS = (1,)
SUPPORTED_CLONE_MODES = ("full", "linked")

# Roles whose templates the release requires; checksums are mandatory.
REQUIRED_TEMPLATE_ROLES = ("attacker", "mojang-web-local", "mojang-web-db")

_PLACEHOLDER_RE = re.compile(r"(CHANGE[_ ]ME|TODO|<[^<>]+>)", re.IGNORECASE)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,62}$")

# Any key whose (leaf) name matches this may never appear in the manifest:
# secrets stay in locally protected files referenced via ``secret_inputs``.
_SECRET_KEY_RE = re.compile(
    r"(password|passwd|secret|token|private[_-]?key|api[_-]?key|credential)",
    re.IGNORECASE,
)

VMID_RANGE_MAX_SPAN = 256  # clone VMIDs must be a bounded, auditable window


class ManifestError(ValueError):
    """The manifest is invalid; the installer must refuse before effects."""


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise ManifestError(msg)


def _walk_no_secrets(node: Any, path: str = "manifest") -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if path == "manifest" and key == "secret_inputs":
                continue  # name -> protected-path map; values are paths only
            if _SECRET_KEY_RE.search(str(key)):
                raise ManifestError(
                    f"{path}.{key}: secret material is forbidden in the "
                    "manifest; reference a locally protected file under "
                    "secret_inputs instead"
                )
            _walk_no_secrets(value, f"{path}.{key}")
    elif isinstance(node, list):
        for i, value in enumerate(node):
            _walk_no_secrets(value, f"{path}[{i}]")
    elif isinstance(node, str):
        if _PLACEHOLDER_RE.search(node):
            raise ManifestError(f"{path}: placeholder value {node!r}")


def _url(value: str, *, field: str, require_https: bool = True) -> str:
    _require(isinstance(value, str) and "://" in value,
             f"{field}: must be an absolute URL")
    scheme, _, rest = value.partition("://")
    _require(scheme in ({"https"} if require_https else {"https", "http"}),
             f"{field}: scheme must be {'https' if require_https else 'http(s)'}")
    _require(bool(rest) and " " not in value, f"{field}: malformed URL")
    return value


def _ip(value: str, *, field: str) -> ipaddress.IPv4Address:
    try:
        return ipaddress.ip_address(value)
    except ValueError as exc:  # pragma: no cover - error text is the point
        raise ManifestError(f"{field}: {value!r} is not an IP address") from exc


@dataclasses.dataclass(frozen=True)
class TemplatePin:
    role: str
    vmid: int
    sha256: str


@dataclasses.dataclass(frozen=True)
class ServiceVm:
    name: str
    vmid: int
    ip: str


@dataclasses.dataclass(frozen=True)
class ReleaseManifest:
    """Validated view of one intended release. Frozen: consumers cannot drift."""

    raw: Mapping[str, Any] = dataclasses.field(repr=False)

    # structure helpers -----------------------------------------------------
    def _p(self, *keys: str) -> Any:
        node: Any = self.raw
        for key in keys:
            node = node[key]
        return node

    # typed accessors used by every consumer --------------------------------
    @property
    def version(self) -> int:
        return int(self._p("manifest_version"))

    @property
    def release_revision(self) -> str:
        return str(self._p("release", "revision"))

    @property
    def pve_node(self) -> str:
        return str(self._p("pve", "node"))

    @property
    def bridge(self) -> str:
        return str(self._p("network", "bridge"))

    @property
    def vlan(self) -> int:
        return int(self._p("network", "vlan"))

    @property
    def range_network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(str(self._p("network", "range_cidr")))

    @property
    def range_gateway(self) -> ipaddress.IPv4Address:
        return ipaddress.ip_address(str(self._p("network", "gateway")))

    @property
    def storage(self) -> str:
        return str(self._p("storage", "name"))

    @property
    def clone_mode(self) -> str:
        return str(self._p("storage", "clone_mode"))

    @property
    def vmid_range(self) -> tuple[int, int]:
        lo, hi = self._p("pve", "clone_vmid_range")
        return int(lo), int(hi)

    @property
    def templates(self) -> tuple[TemplatePin, ...]:
        return tuple(
            TemplatePin(role, int(spec["vmid"]), str(spec["sha256"]))
            for role, spec in sorted(self._p("templates").items())
        )

    def template_for(self, role: str) -> TemplatePin:
        for pin in self.templates:
            if pin.role == role:
                return pin
        raise ManifestError(f"template role {role!r} missing from manifest")

    @property
    def service_vms(self) -> dict[str, ServiceVm]:
        return {
            role: ServiceVm(str(spec["name"]), int(spec["vmid"]), str(spec["ip"]))
            for role, spec in self._p("service_vms").items()
        }

    @property
    def budgets(self) -> dict[str, int]:
        return {k: int(v) for k, v in self._p("budgets").items()}

    @property
    def headroom(self) -> dict[str, int]:
        return {k: int(v) for k, v in self._p("headroom").items()}

    @property
    def urls(self) -> dict[str, str]:
        return {k: str(v) for k, v in self._p("urls").items()}

    @property
    def trust(self) -> dict[str, Any]:
        return dict(self._p("trust"))

    @property
    def model(self) -> dict[str, str]:
        return {k: str(v) for k, v in self._p("model").items()}

    @property
    def state_paths(self) -> dict[str, str]:
        return {k: str(v) for k, v in self._p("state_paths").items()}

    @property
    def backup(self) -> dict[str, Any]:
        return dict(self._p("backup"))

    @property
    def secret_inputs(self) -> dict[str, str]:
        return {k: str(v) for k, v in self._p("secret_inputs").items()}


def validate_manifest(raw: Mapping[str, Any]) -> ReleaseManifest:
    """Fail closed on every structural/overlap/placeholder problem. Returns
    a frozen :class:`ReleaseManifest` only when the whole document is sound."""
    _require(isinstance(raw, dict), "manifest must be a JSON object")
    _walk_no_secrets(raw)

    version = raw.get("manifest_version")
    _require(version in SUPPORTED_MANIFEST_VERSIONS,
             f"unsupported manifest_version {version!r} "
             f"(supported: {SUPPORTED_MANIFEST_VERSIONS})")

    release = raw.get("release") or {}
    _require(isinstance(release.get("revision"), str) and release["revision"],
             "release.revision (exact source revision) is required")

    # --- PVE / network -----------------------------------------------------
    pve = raw.get("pve") or {}
    _require(isinstance(pve.get("node"), str) and _NAME_RE.fullmatch(pve["node"]),
             "pve.node must be an exact non-empty node name")
    lo_hi = pve.get("clone_vmid_range")
    _require(isinstance(lo_hi, list) and len(lo_hi) == 2,
             "pve.clone_vmid_range [lo, hi] is required (bounded window)")
    lo, hi = (int(lo_hi[0]), int(lo_hi[1]))
    _require(100 <= lo <= hi <= 999_999, f"clone VMID window {lo_hi} out of range")
    _require(hi - lo + 1 <= VMID_RANGE_MAX_SPAN,
             f"clone VMID window spans {hi - lo + 1}; maximum "
             f"{VMID_RANGE_MAX_SPAN} (bounded, auditable)")

    net = raw.get("network") or {}
    _require(isinstance(net.get("bridge"), str)
             and _NAME_RE.fullmatch(net["bridge"]),
             "network.bridge must name the operator-owned bridge (never assumed)")
    vlan = net.get("vlan")
    _require(isinstance(vlan, int) and 2 <= vlan <= 4094,
             "network.vlan must be 2..4094 (broker policy NIC requirement)")
    try:
        cidr = ipaddress.ip_network(str(net.get("range_cidr")), strict=True)
    except ValueError as exc:
        raise ManifestError(f"network.range_cidr invalid: {exc}") from exc
    gw = _ip(str(net.get("gateway")), field="network.gateway")
    _require(gw in cidr, "network.gateway must lie inside range_cidr")

    # --- storage / clone policy --------------------------------------------
    sto = raw.get("storage") or {}
    _require(isinstance(sto.get("name"), str) and _NAME_RE.fullmatch(sto["name"]),
             "storage.name required (a label alone is never capacity proof)")
    _require(sto.get("clone_mode") in SUPPORTED_CLONE_MODES,
             f"storage.clone_mode must be one of {SUPPORTED_CLONE_MODES}")

    # --- templates ----------------------------------------------------------
    templates = raw.get("templates")
    _require(isinstance(templates, dict) and templates,
             "templates must map every required role to {vmid, sha256}")
    missing = [r for r in REQUIRED_TEMPLATE_ROLES if r not in templates]
    _require(not missing, f"templates missing required roles: {missing}")
    template_vmids: list[int] = []
    for role, spec in templates.items():
        _require(isinstance(spec, dict), f"templates.{role} must be an object")
        vmid = int(spec.get("vmid", -1))
        _require(100 <= vmid <= 999_999, f"templates.{role}.vmid invalid")
        digest = str(spec.get("sha256", ""))
        _require(_SHA256_RE.fullmatch(digest) is not None,
                 f"templates.{role}.sha256 must be 64 hex chars (imported "
                 "artifact checksum is mandatory, never assumed)")
        template_vmids.append(vmid)
    _require(len(set(template_vmids)) == len(template_vmids),
             "template VMIDs must be distinct")

    # --- service VMs ---------------------------------------------------------
    svc = raw.get("service_vms")
    _require(isinstance(svc, dict) and svc, "service_vms must not be empty")
    svc_vmids: list[int] = []
    svc_ips: list[ipaddress.IPv4Address] = []
    for role, spec in svc.items():
        _require(isinstance(spec, dict), f"service_vms.{role} must be an object")
        _require(_NAME_RE.fullmatch(str(spec.get("name", ""))),
                 f"service_vms.{role}.name invalid")
        vmid = int(spec.get("vmid", -1))
        _require(100 <= vmid <= 999_999, f"service_vms.{role}.vmid invalid")
        svc_vmids.append(vmid)
        svc_ips.append(_ip(str(spec.get("ip")), field=f"service_vms.{role}.ip"))
    _require(len(set(svc_vmids)) == len(svc_vmids),
             "service VM VMIDs must be distinct")
    overlap = sorted(set(svc_vmids) & set(template_vmids))
    _require(not overlap, f"service VM VMIDs overlap template VMIDs: {overlap}")
    window = set(range(lo, hi + 1))
    clash = sorted(window & (set(svc_vmids) | set(template_vmids)))
    _require(not clash,
             f"clone VMID window overlaps reserved VMIDs: {clash}")

    # --- budgets / headroom ---------------------------------------------------
    budgets = raw.get("budgets") or {}
    for key in ("max_vms", "guest_vcpus", "guest_ram_mb", "guest_disk_gb",
                "disk_gb_total"):
        _require(isinstance(budgets.get(key), int) and budgets[key] > 0,
                 f"budgets.{key} must be a positive integer")
    headroom = raw.get("headroom") or {}
    for key in ("min_free_gb", "min_reserve_gb"):
        _require(isinstance(headroom.get(key), int) and headroom[key] >= 0,
                 f"headroom.{key} must be a nonnegative integer")

    # --- URLs / trust / model ---------------------------------------------------
    urls = raw.get("urls") or {}
    public = _url(str(urls.get("public_https", "")), field="urls.public_https")
    internal = _url(str(urls.get("internal_api", "")),
                    field="urls.internal_api", require_https=False)
    ingest = _url(str(urls.get("ingest", "")), field="urls.ingest")
    _require(len({public, internal, ingest}) == 3,
             "urls.public_https/internal_api/ingest must be three distinct "
             "listeners (LAN HTTPS, trusted-process internal, guest ingest)")
    trust = raw.get("trust") or {}
    sans = trust.get("san_ips")
    _require(isinstance(sans, list) and sans,
             "trust.san_ips must list every address the public certificate "
             "must be valid for")
    for san in sans:
        _ip(str(san), field="trust.san_ips")
    _require(isinstance(trust.get("ca_identity"), str) and trust["ca_identity"],
             "trust.ca_identity required (which CA the consumers must trust)")
    model = raw.get("model") or {}
    _require(isinstance(model.get("alias"), str) and model["alias"],
             "model.alias required (operator-verified endpoint alias)")
    # The inference endpoint lives on the trusted control-plane network
    # (outside the range); http is permitted there, https is preferred.
    _url(str(model.get("base_url", "")), field="model.base_url",
         require_https=False)

    # --- state paths / backup / secrets ---------------------------------------
    paths = raw.get("state_paths") or {}
    for key in ("data_dir", "recordings_dir", "safety_state_file"):
        value = paths.get(key)
        _require(isinstance(value, str) and value.startswith("/"),
                 f"state_paths.{key} must be an absolute writable path "
                 "(never relative to a read-only checkout)")
    backup = raw.get("backup") or {}
    _require(isinstance(backup.get("enabled"), bool),
             "backup.enabled must be an explicit true/false (never absent: "
             "unconfigured backups must be conspicuous, not silent)")
    if backup["enabled"]:
        _require(isinstance(backup.get("destination"), str)
                 and backup["destination"].startswith("/"),
                 "backup.destination (absolute protected path) required when "
                 "backup.enabled")
    else:
        _require("destination" not in backup or backup.get("destination") in (None, ""),
                 "backup.destination set while backup.enabled is false")
    secrets = raw.get("secret_inputs")
    _require(isinstance(secrets, dict) and secrets,
             "secret_inputs must map each required secret to a locally "
             "protected file path")
    for name, path in secrets.items():
        _require(str(path).startswith("/"),
                 f"secret_inputs.{name} must be an absolute path")

    return ReleaseManifest(raw=dict(raw))


def load_manifest(path: str | pathlib.Path) -> ReleaseManifest:
    p = pathlib.Path(path)
    try:
        raw = json.loads(p.read_text())
    except FileNotFoundError as exc:
        raise ManifestError(f"manifest not found: {p}") from exc
    except json.JSONDecodeError as exc:
        raise ManifestError(f"manifest {p} is not valid JSON: {exc}") from exc
    return validate_manifest(raw)


# ---------------------------------------------------------------------------
# Installer inventory classification (plan phase 1)
# ---------------------------------------------------------------------------

ABSENT = "absent"
MATCHING = "matching"
CONFLICTING = "conflicting"
UNREADABLE = "unreadable"


def classify_resource(expected: Mapping[str, Any], observed: Any) -> str:
    """Classify one observed resource against its expected identity.

    ``observed`` is ``None`` for a confirmed-absent read, a mapping with an
    ``"error"`` key when the read itself failed (an error is NEVER absence),
    or the observed resource mapping. A match requires every expected field
    to be present and equal — a name alone never establishes ownership.
    """
    if isinstance(observed, Mapping) and "error" in observed:
        return UNREADABLE
    if observed is None:
        return ABSENT
    if not isinstance(observed, Mapping):
        return UNREADABLE
    for key, value in expected.items():
        if observed.get(key) != value:
            return CONFLICTING
    return MATCHING


def assess_capacity(free_gb: int | None, required_gb: int,
                    headroom: Mapping[str, int]) -> dict[str, Any]:
    """Capacity is a measured number, never a storage label. ``free_gb`` of
    ``None`` means the probe could not read it — that is unsafe, not zero."""
    if free_gb is None:
        return {"safe": False, "reason": "free capacity unreadable"}
    need = required_gb + int(headroom.get("min_free_gb", 0)) \
        + int(headroom.get("min_reserve_gb", 0))
    if free_gb < need:
        return {"safe": False,
                "reason": f"free {free_gb} GiB < required {need} GiB "
                          f"(payload {required_gb} + headroom)"}
    return {"safe": True, "reason": f"free {free_gb} GiB >= {need} GiB"}


def inventory_report(manifest: ReleaseManifest,
                     observed: Mapping[str, Any],
                     pve_version: str | None,
                     storage_free_gb: int | None) -> dict[str, Any]:
    """Full pre-flight inventory. ``observed`` maps resource keys (``vm:<id>``,
    ``bridge:<name>``, ``storage:<name>``) to observed mappings/None. Refuses
    (``safe_to_apply=False``) on any conflict, unreadable resource, missing
    input, unsupported PVE version, overlapping identity or unsafe capacity.
    """
    classifications: dict[str, str] = {}
    for pin in manifest.templates:
        key = f"vm:{pin.vmid}"
        classifications[key] = classify_resource(
            {"name": f"tpl-{pin.role}", "template": 1}, observed.get(key))
    for role, svc in manifest.service_vms.items():
        key = f"vm:{svc.vmid}"
        classifications[key] = classify_resource(
            {"name": svc.name}, observed.get(key))
    classifications[f"bridge:{manifest.bridge}"] = classify_resource(
        {"vlan": manifest.vlan}, observed.get(f"bridge:{manifest.bridge}"))

    reasons: list[str] = []
    for key, state in classifications.items():
        if state in (CONFLICTING, UNREADABLE):
            reasons.append(f"{key} is {state}")
    if pve_version is None:
        reasons.append("PVE version unreadable")
    capacity = assess_capacity(storage_free_gb,
                               manifest.budgets["disk_gb_total"],
                               manifest.headroom)
    if not capacity["safe"]:
        reasons.append(f"storage {manifest.storage}: {capacity['reason']}")
    return {
        "classifications": classifications,
        "capacity": capacity,
        "pve_version": pve_version,
        "safe_to_apply": not reasons,
        "refusal_reasons": reasons,
    }


# ---------------------------------------------------------------------------
# Source-of-truth map: manifest -> every consumer artifact (plan phase 1)
# ---------------------------------------------------------------------------

def render_broker_policy(manifest: ReleaseManifest) -> dict[str, Any]:
    """Broker policy file content derived from the manifest (no secrets).
    Emitted in exactly the schema ``infra.broker.policy.BrokerPolicy.from_dict``
    validates fail-closed — the broker re-validates; this render never bypasses
    it."""
    lo, hi = manifest.vmid_range
    budgets = manifest.budgets
    return {
        "node": manifest.pve_node,
        "templates": sorted(p.vmid for p in manifest.templates),
        "vmid_range": [lo, hi],
        "storage": [manifest.storage],
        "clone_mode": manifest.clone_mode,
        "nic": {"bridge": manifest.bridge, "vlan": manifest.vlan},
        "provision": {"cidr": str(manifest.range_network),
                      "gateway": str(manifest.range_gateway)},
        "name_prefix": "sr-",
        "limits": {
            "max_vms": budgets["max_vms"],
            "cores_per_vm": budgets["guest_vcpus"],
            "memory_mb_per_vm": budgets["guest_ram_mb"],
            "disk_gb_per_vm": budgets["guest_disk_gb"],
            "max_total_cores": budgets["guest_vcpus"] * budgets["max_vms"],
            "max_total_memory_mb": budgets["guest_ram_mb"] * budgets["max_vms"],
            "max_total_disk_gb": budgets["disk_gb_total"],
        },
    }


def render_env(manifest: ReleaseManifest, role: str) -> dict[str, str]:
    """Role-specific environment fragments derived from the manifest.

    Owner-DB credentials appear only for the offline ``migration`` role and
    PVE credentials never appear at all (they live on the broker via
    ``secret_inputs`` files); the worker fragment stays minimal.
    """
    urls = manifest.urls
    paths = manifest.state_paths
    common = {
        "SR_DATA_DIR": paths["data_dir"],
        "SR_SAFETY_STATE_FILE": paths["safety_state_file"],
        "SR_RECORDINGS_DIR": paths["recordings_dir"],
    }
    if role == "controller":
        return {
            **common,
            "SR_PROCESS_ROLE": "controller",
            "API_BASE_URL": urls["internal_api"],
            "SR_PUBLIC_BASE_URL": urls["public_https"],
            "SR_INGEST_URL": urls["ingest"],
            "SR_RANGE_BRIDGE": manifest.bridge,
            "SR_RANGE_VLAN": str(manifest.vlan),
            "SR_MODEL_BASE_URL": manifest.model["base_url"],
            "SR_MODEL_ALIAS": manifest.model["alias"],
        }
    if role == "broker":
        return {
            **common,
            "SR_PROCESS_ROLE": "broker",
            "BROKER_POLICY_FILE": f"{paths['data_dir']}/broker-policy.json",
            "BROKER_LEDGER_PATH": f"{paths['data_dir']}/broker/ledger.sqlite3",
        }
    if role == "worker":
        return {
            "SR_PROCESS_ROLE": "worker",
            "API_BASE_URL": urls["internal_api"],
        }
    if role == "migration":
        return {
            "SR_PROCESS_ROLE": "migration",
            "SR_DATA_DIR": paths["data_dir"],
        }
    raise ManifestError(f"unknown role {role!r}")


SOURCE_OF_TRUTH_MAP = """\
Release manifest source-of-truth map (plan 13 phase 1)
=======================================================

One validated manifest (deploy/manifest.example.json, schema-checked by
infra/release_manifest.py) is the ONLY non-secret deployment input:

  manifest field                -> derived consumer artifact
  -----------------------------------------------------------------
  pve.*, network.*, storage.*  -> broker policy (render_broker_policy;
                                  infra/broker/policy.py validates it again)
  templates.*                  -> template import verification (checksum)
                                  + scenario template VMIDs
  pve.clone_vmid_range         -> broker policy vmid_range + orchestrator
  budgets.* / headroom.*       -> broker capacity ceilings + installer
                                  pre-flight capacity gate (measured free
                                  capacity, never the storage label)
  urls.public_https            -> nginx listener + certificate SAN +
                                  member-facing base URL
  urls.internal_api            -> API bind, worker/bastion API_BASE_URL
  urls.ingest                  -> controller range-address HTTPS ingest
                                  listener (enrollment/ingest routes only)
  trust.san_ips/ca_identity    -> bootstrap_tls.sh inputs + guest public
                                  trust material
  model.base_url/alias         -> controller model gateway configuration
  state_paths.*                -> systemd ReadWritePaths + SR_DATA_DIR /
                                  SR_SAFETY_STATE_FILE / SR_RECORDINGS_DIR
                                  (absolute; never relative to a checkout)
  backup.enabled/destination   -> backup tooling configuration + status
                                  reporting (optional, conspicuous)
  secret_inputs.*              -> local protected files read by the
                                  operator installer only; never rendered
                                  into env/policy/logs
  release.revision             -> packaged service-VM revision/digests
                                  (mixed revisions refused)

render_env(role) emits the minimal per-role fragment; the installer
(phase 8) writes env files, broker policy and service config exclusively
from these renderings.
"""
