#!/usr/bin/env python3
"""Ubuntu/KVM appliance installer and operator console.

The legacy ``deploy/install.sh`` installs a control-plane VM that drives an
outer Proxmox host.  This installer is the appliance replacement: one Ubuntu
24.04 host, one local typed broker over a Unix peer-UID socket, libvirt/KVM
full VMs on a fixed isolated bridge, and separate service UIDs.

Design rules enforced here:

* The manifest and the derived broker policy are the only inputs.  Both are
  strict, secret-free, and cross-checked before any effect.
* Rendering is pure and deterministic: ``plan`` twice is byte-identical, which
  makes an idempotent rerun provable.  ``apply`` writes only files it owns and
  never regenerates an existing private key or token.
* No outer Proxmox credential exists anywhere in this path.  The API gets a
  Unix socket path, not libvirt, not ``/dev/kvm``, not a host shell.
* ``doctor``/``status`` are read-only.  ``recovery`` is an explicit local
  operator command, never an HTTP endpoint; resolving an obligation requires
  fresh evidence that the backend no longer owns the resource.

Usage::

    python deploy/appliance.py validate --manifest M
    python deploy/appliance.py plan     --manifest M [--prefix PREFIX]
    python deploy/appliance.py apply    --manifest M [--prefix PREFIX] [--dry-run]
    python deploy/appliance.py status   --manifest M [--json]
    python deploy/appliance.py doctor   --manifest M [--json]
    python deploy/appliance.py upgrade  --manifest M --payload BUNDLE [--db-url URL]
    python deploy/appliance.py upgrade  --manifest M --restore-config ATTEMPT
    python deploy/appliance.py recovery status --manifest M
    python deploy/appliance.py recovery reconcile --manifest M
"""

from __future__ import annotations

import argparse
import grp
import json
import os
import pathlib
import pwd
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.parse
from dataclasses import dataclass, field

ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from infra.appliance.manifest import ApplianceManifest  # noqa: E402
from infra.appliance.netrules import (nft_scope_problems, render_networkd,
                                      render_nftables)  # noqa: E402
from infra.appliance.policy import AppliancePolicy  # noqa: E402

DEFAULT_PREFIX = pathlib.Path("/opt/sparring-range")
DEFAULT_ETC = pathlib.Path("/etc/sparring-range")
DEFAULT_STATE = pathlib.Path("/var/lib/sparring-range")
DEFAULT_RUN = pathlib.Path("/run/sparring-range")

UNITS = ("sr-appliance-broker.service", "sr-api.service",
         "sr-appliance-ingest.service", "sr-worker-supervisor.service",
         "sr-bastion.service", "sr-web.service")
# The range firewall loader runs nft for exactly one file-scoped table.  It
# is NOT one of the business services (it is root by necessity — nft needs
# CAP_NET_ADMIN), so it stays outside UNITS, which the identity contract
# audits, but it is installed, enabled and reported alongside them.
NETRULES_UNIT = "sr-appliance-netrules.service"
GROUPS = ("srrange", "srbastion", "sr-broker-clients", "sringest", "srworker",
          "srweb", "sr-secrets")
USERS = {
    # existing accepted identities: API/controller, bastion
    # srrange is in sr-secrets: it must READ the worker-supervisor
    # capability it validates, and the supervisor must read its own copy.
    "srrange": ("srrange", ("sr-broker-clients", "srbastion", "sr-secrets")),
    "srbastion": ("srbastion", ()),
    # appliance-only identities
    "srbroker": ("sr-broker-clients", ()),
    "sringest": ("sringest", ()),
    "srworker": ("srworker", ("sr-secrets",)),
    "srweb": ("srweb", ()),
}


class InstallError(RuntimeError):
    pass


# The secrets directory: traversable by the identities that hold a
# credential in it (the API and the worker supervisor), never by the rest.
SECRET_DIR_MODE = 0o750
SECRET_DIR_GROUP = "sr-secrets"

# The bastion's own directory: it holds the keys and the service token the
# bastion reads, and it is traversable by the bastion's group.
SSH_DIR_MODE = 0o750
SSH_DIR_GROUP = "srbastion"


# --------------------------------------------------------------------------- #
# pure rendering                                                              #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class RenderedFile:
    path: pathlib.Path
    content: str
    mode: int = 0o644
    owner: str = "root"
    group: str = "root"


@dataclass
class Plan:
    files: list[RenderedFile] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    units: list[str] = field(default_factory=list)

    def by_path(self) -> dict[pathlib.Path, RenderedFile]:
        return {f.path: f for f in self.files}


@dataclass(frozen=True)
class Layout:
    """Where the installer writes.

    ``root`` is the filesystem root the installation is applied to.  The
    default "/" is the real appliance; any other root is a SANDBOX, which is
    what the install gate uses to exercise the real sequences (clean, rerun,
    reboot, populated upgrade, failure recovery) without root and without
    touching the host.
    """

    root: pathlib.Path = pathlib.Path("/")
    prefix: pathlib.Path = DEFAULT_PREFIX
    etc: pathlib.Path = DEFAULT_ETC
    state: pathlib.Path = DEFAULT_STATE
    run: pathlib.Path = DEFAULT_RUN
    units_dir: pathlib.Path = pathlib.Path("/etc/systemd/system")
    network_dir: pathlib.Path = pathlib.Path("/etc/systemd/network")
    nftables_dir: pathlib.Path = pathlib.Path("/etc/nftables.d")
    nginx_dir: pathlib.Path = pathlib.Path("/etc/nginx/sites-available")

    @property
    def sandboxed(self) -> bool:
        return pathlib.Path(self.root) != pathlib.Path("/")

    @property
    def receipt(self) -> pathlib.Path:
        return self.etc / "install-receipt.json"


def default_layout(*, root: pathlib.Path = pathlib.Path("/"),
                   prefix: pathlib.Path | None = None,
                   etc: pathlib.Path | None = None) -> Layout:
    root = pathlib.Path(root)
    prefix = pathlib.Path(prefix) if prefix else root / "opt/sparring-range"
    etc = pathlib.Path(etc) if etc else root / "etc/sparring-range"
    return Layout(root=root, prefix=prefix, etc=etc,
                  state=root / "var/lib/sparring-range",
                  run=root / "run/sparring-range",
                  units_dir=root / "etc/systemd/system",
                  network_dir=root / "etc/systemd/network",
                  nftables_dir=root / "etc/nftables.d",
                  nginx_dir=root / "etc/nginx/sites-available")


def _atomic_write(path: pathlib.Path, content: str, mode: int,
                  uid: int, gid: int) -> bool:
    """Write only when bytes differ.  Never chmod/chown through a symlink."""
    path = pathlib.Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise InstallError(f"refusing symlinked parent {path.parent}")
    old = None
    try:
        if path.is_symlink():
            raise InstallError(f"refusing symlinked target {path}")
        old = path.read_text()
    except FileNotFoundError:
        old = None
    if old == content:
        os.chmod(path, mode)
        try:
            os.chown(path, uid, gid)
        except PermissionError:
            pass
        return False
    fd, tmpname = tempfile.mkstemp(prefix=f".{path.name}.",
                                   dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmpname, mode)
        try:
            os.chown(tmpname, uid, gid)
        except PermissionError:
            pass
        os.replace(tmpname, path)
    finally:
        try:
            os.unlink(tmpname)
        except FileNotFoundError:
            pass
    return True


def _env_lines(values: list[tuple[str, object]]) -> str:
    out = ["# Generated by deploy/appliance.py from the signed-off manifest.",
           "# Do not edit: re-render with `appliance.py apply`. Secrets live in",
           "# control-plane.env / protected secret files, never here."]
    for key, value in values:
        text = str(value)
        if "\n" in text or "\x00" in text:
            raise InstallError(f"environment value for {key} is not single-line")
        out.append(f"{key}={text}")
    return "\n".join(out) + "\n"


def render_control_env(m: ApplianceManifest, *, etc: pathlib.Path = DEFAULT_ETC,
                       prefix: pathlib.Path = DEFAULT_PREFIX) -> str:
    by_role = {role: m.image_for_role(role).template_id for role in
               ("attacker", "mojang-web-local", "mojang-web-db")}
    return _env_lines([
        ("SR_ENV", "production"),
        ("SR_BROKER_SOCKET", m.broker_socket),
        ("SR_WORKER_DISPATCH", "supervisor"),
        ("SR_WORKER_SUPERVISOR_TOKEN_FILE",
         str(etc / "secrets/worker-supervisor.token")),
        ("SR_API_BASE_URL", m.public_url),
        ("SR_INTERNAL_API_URL", m.internal_url),
        ("SR_TELEMETRY_INGEST_URL", m.ingest_url),
        # The ingest server certificate is issued by the API CA, so that is
        # the trust anchor the guests are enrolled with — and the telemetry
        # client pins it.  The API-plane anchor is nginx's own surface
        # (https.crt), NOT api-ca: they sign different certificates.
        ("SR_TELEMETRY_CA_FILE", str(etc / "tls/api-ca.crt")),
        ("SR_API_TLS_CA_FILE", str(etc / "tls/https.crt")),
        ("SR_RECORDINGS_DIR", m.recordings_dir),
        ("SR_SAFETY_STATE_FILE", str(pathlib.Path(m.state_dir) / "controller" / "safety_state.json")),
        ("SR_BASTION_HOST_KEY_PATH", str(etc / "ssh/bastion_ed25519")),
        ("SR_BASTION_AUTHORIZED_KEYS_FILE", str(etc / "ssh/authorized_keys")),
        # RUNTIME host pins live under the STATE directory, never under
        # /etc (plan 18): every appliance unit runs with ProtectSystem=strict
        # — /etc is read-only for the services that must WRITE fresh
        # generation pins — and the API publishes them while the file
        # owner's umask can differ from the installer's. The API is the only
        # writer; the runner/verifier/bastion clients read the same files.
        ("SR_BASTION_TARGETS_KNOWN_HOSTS",
         str(pathlib.Path(m.state_dir) / "known_hosts/range_hosts")),
        ("SR_RANGE_BRIDGE", m.network.range_bridge),
        # The appliance's inner range is a plain isolated bridge: no VLAN tag
        # (the broker policy accepts exactly one NIC specification).
        ("SR_RANGE_VLAN", "0"),
        ("SR_RANGE_CIDR", str(m.network.range_cidr)),
        ("SR_RANGE_GATEWAY", str(m.network.range_gateway)),
        ("SR_CONTROLLER_RANGE_IP", str(m.network.controller_range_ip)),
        ("SR_BASTION_ADDRESS", str(m.network.bastion_address)),
        ("SR_MANAGEMENT_CIDR", str(m.network.management_cidr)),
        # The API must never present a PVE credential.  These names remain only
        # because the shared settings model still has legacy fields; the values
        # are the installation id and a bounded local namespace, not PVE.
        ("SR_PROXMOX_NODE", m.installation_id),
        ("SR_DEPLOY_VMID_BASE", "200"),
        ("SR_DEPLOY_CLONE_MODE", "full"),
        ("SR_TEMPLATE_VMID_ATTACKER", by_role["attacker"]),
        ("SR_TEMPLATE_VMID_MOJANG_WEB", by_role["mojang-web-local"]),
        ("SR_TEMPLATE_VMID_MOJANG_DB", by_role["mojang-web-db"]),
        ("SR_LLM_BASE_URL", m.model_base_url),
        ("SR_LLM_MODEL_RED", m.model_alias),
        ("SR_LLM_MODEL_COACH", m.model_alias),
        # nginx routes /api/* to the API and everything else to Next; the
        # web build bakes the same prefix, so server-side API clients must
        # prepend it.
        ("SR_API_ROUTE_PREFIX", "/api"),
        ("SR_RUNNER_TRANSPORT", "ssh"),
        # Fixed attacker management address inside the isolated range. The
        # broker injects the runner public key; the private key remains a
        # srworker-readable file and never enters the API/model env.
        ("SR_RUNNER_SSH_TARGET", f"attacker@{m.network.range_cidr.network_address + 9}"),
        ("SR_RUNNER_SSH_KEY_PATH", str(etc / "secrets/worker_runner_key")),
        ("SR_RUNNER_SSH_KNOWN_HOSTS",
         str(pathlib.Path(m.state_dir) / "known_hosts/range_hosts")),
        ("SR_VERIFIER_SSH_KEY_PATH", str(etc / "secrets/verifier_key")),
        ("SR_VERIFIER_SSH_KNOWN_HOSTS",
         str(pathlib.Path(m.state_dir) / "known_hosts/range_hosts")),
        # The model credential is the API's alone (plan 18): a file
        # reference, never the value, and never in a shared environment.
        # The renderer only names the path the operator provisioned; the
        # installer keeps it root:srrange 0640.
        ("SR_LLM_API_KEY_FILE", m.model_api_key_file),
        # Members connect to the bastion over the REACHABLE LAN address
        # (plan 18): the range-side bastion_address is a planning address
        # that may name no interface at all. Rendered hints use this.
        ("SR_BASTION_PUBLIC_ADDRESS",
         str(m.network.lan_address) if m.network.lan_address else ""),
        # Trusted cron pins (plan 18): a release artifact bound to the
        # built-image digest. The path is always named; a missing file is
        # honest UNKNOWN, never a filename-based guess. The release build
        # places it via `python3 -m infra.images.cron_baseline capture`.
        ("SR_CRON_BASELINE_FILE",
         str(pathlib.Path(m.state_dir) / "cron-baselines.json")),
        # The match scheduler (ready expiry, deadline cleanup, startup
        # reconciliation) is part of a working appliance, not an option.
        ("SR_MATCH_SCHEDULER_ENABLED", "1"),
        ("SR_MATCH_SCHEDULER_INTERVAL_S", "15"),
        ("SR_WORKER_POLL_S", "2"),
        ("SR_WORKER_HEARTBEAT_S", "5"),
        ("SR_WORKER_CLAIM_TIMEOUT_S", "120"),
    ])


def render_broker_env(m: ApplianceManifest,
                      *, etc: pathlib.Path = DEFAULT_ETC) -> str:
    return _env_lines([
        ("SR_APPLIANCE_MANIFEST", str(etc / "appliance-manifest.json")),
        ("SR_APPLIANCE_POLICY", str(etc / "appliance-policy.json")),
        # libvirt's session/system URI is selected by the unit; the broker
        # itself makes no settings/DB/API call.
        ("LIBVIRT_DEFAULT_URI", "qemu:///system"),
    ])


def render_supervisor_env(m: ApplianceManifest,
                          *, etc: pathlib.Path = DEFAULT_ETC,
                          prefix: pathlib.Path = DEFAULT_PREFIX) -> str:
    return _env_lines([
        ("SR_API_BASE", m.internal_url),
        # The supervisor reads its OWN 0600 copy: the capability is never
        # shared through a group-readable file.
        ("SR_WORKER_SUPERVISOR_TOKEN_FILE",
         str(etc / "secrets/worker-supervisor.token.srworker")),
        # The match scheduler (ready expiry, deadline cleanup, startup
        # reconciliation) is part of a working appliance, not an option.
        ("SR_MATCH_SCHEDULER_ENABLED", "1"),
        ("SR_MATCH_SCHEDULER_INTERVAL_S", "15"),
        ("SR_WORKER_POLL_S", "2"),
        ("SR_WORKER_HEARTBEAT_S", "5"),
        ("PYTHONPATH", str(prefix)),
    ])


def render_bastion_env(m: ApplianceManifest, *,
                       etc: pathlib.Path = DEFAULT_ETC,
                       prefix: pathlib.Path = DEFAULT_PREFIX) -> str:
    """The recording bastion's environment.

    The bastion holds ONLY what it uses: the API it reports to and its trust
    anchor, the member's authorized keys, its own host key and the key it
    presents when it dials the practice guests.  It never sees the
    worker-supervisor capability (the API's credential) and never sees the
    database credential.
    """
    return _env_lines([
        ("SR_ENV", "production"),
        ("SR_API_BASE_URL", m.public_url),
        ("SR_API_ROUTE_PREFIX", "/api"),
        # The trust anchor MUST be what the API surface actually presents:
        # public_url is served by nginx with the self-signed tls/https.crt,
        # while api-ca.crt signs only the ingest listener's certificate.
        # Anchoring the bastion on api-ca made every callback fail the TLS
        # handshake (plan 18 review); the telemetry anchor stays api-ca.
        ("SR_API_TLS_CA_FILE", str(etc / "tls/https.crt")),
        ("SR_BASTION_AUTHORIZED_KEYS_FILE", str(etc / "ssh/authorized_keys")),
        ("SR_BASTION_HOST_KEY_PATH", str(etc / "ssh/bastion_ed25519")),
        ("SR_BASTION_CLIENT_KEY_PATH", str(etc / "ssh/bastion_client_ed25519")),
        # The bastion READS the runtime pins the API publishes; they live
        # under the state tree (plan 18) because ProtectSystem=strict makes
        # /etc read-only for the writer.  Same file, one authority.
        ("SR_BASTION_TARGETS_KNOWN_HOSTS",
         str(pathlib.Path(m.state_dir) / "known_hosts/range_hosts")),
        ("SR_RECORDINGS_DIR", m.recordings_dir),
        # The bastion's SERVICE token: a secret in the bastion's OWN file
        # (0600, root:srbastion), never in a shared environment. The API
        # issues it (POST /admin/service_tokens, scope "bastion"); the
        # operator writes it here.
        # The bastion's OWN directory (0750 root:srbastion): the token must
        # be reachable by the identity that reads it.  The secrets
        # directory is root:sr-secrets, which srbastion may not traverse.
        ("SR_BASTION_TOKEN_FILE", str(etc / "ssh/bastion.token")),
    ])


def render_ingest_env(m: ApplianceManifest, *,
                      etc: pathlib.Path = DEFAULT_ETC,
                      prefix: pathlib.Path = DEFAULT_PREFIX) -> str:
    """The guest-facing ingest listener's environment.

    The listener terminates TLS with the provisioned ingest certificate and
    writes telemetry.  It holds no supervisor capability and no bastion key.
    """
    return _env_lines([
        ("SR_ENV", "production"),
        ("SR_TELEMETRY_CA_FILE", str(etc / "tls/api-ca.crt")),
        ("SR_API_TLS_CA_FILE", str(etc / "tls/api-ca.crt")),
    ])


def render_policy(m: ApplianceManifest) -> str:
    policy = AppliancePolicy.from_manifest(m)
    raw = {
        "node": policy.node,
        "templates": list(policy.templates),
        "vmid_range": [policy.vmid_min, policy.vmid_max],
        "storage": list(policy.storage),
        "clone_mode": policy.clone_mode,
        "nic": {"bridge": policy.bridge},
        "provision": {"cidr": str(policy.network),
                      "gateway": str(policy.gateway)},
        "limits": policy.limits,
        "name_prefix": policy.name_prefix,
        "tag_pattern": policy.tag_pattern,
        "lease_ttl_s": policy.lease_ttl_s,
        "heartbeat_interval_s": policy.heartbeat_interval_s,
    }
    return json.dumps(raw, indent=2, sort_keys=True) + "\n"


def _unit_from_template(name: str, *, user: str | None = None,
                        group: str | None = None,
                        extra: str = "",
                        env_files: list[str] | None = None) -> str:
    """Render a systemd unit from its template.

    ``env_files`` REPLACES the template's EnvironmentFile lines: a service
    must load exactly the environment that belongs to it, never the
    controller's (a credential it cannot read would stop it, and a
    credential it can read is a credential it should not hold).
    """
    text = (ROOT / "deploy" / "systemd" / name).read_text()
    if user:
        import re
        text = re.sub(r"^User=.*$", f"User={user}", text, flags=re.M)
    if group:
        import re
        text = re.sub(r"^Group=.*$", f"Group={group}", text, flags=re.M)
    if env_files is not None:
        lines = [ln for ln in text.splitlines()
                 if not ln.startswith("EnvironmentFile=")]
        # the environment files go where the template had them: right after
        # the last Environment= line, or after the [Service] header.
        idx = max((i for i, ln in enumerate(lines)
                   if ln.startswith("Environment=")), default=None)
        if idx is None:
            idx = max((i for i, ln in enumerate(lines)
                       if ln.startswith("[Service]")), default=0)
        for offset, env_file in enumerate(env_files):
            lines.insert(idx + 1 + offset, f"EnvironmentFile={env_file}")
        text = "\n".join(lines) + "\n"
    if extra:
        # Insert additional Environment lines after the last EnvironmentFile.
        lines = text.splitlines()
        idx = max((i for i, line in enumerate(lines)
                   if line.startswith("Environment=")), default=None)
        if idx is None:
            idx = max((i for i, line in enumerate(lines)
                       if line.startswith("EnvironmentFile=")), default=4)
        lines.insert(idx + 1, extra)
        text = "\n".join(lines) + "\n"
    return text


def render_broker_unit(m: ApplianceManifest, *,
                       etc: pathlib.Path = DEFAULT_ETC,
                       prefix: pathlib.Path = DEFAULT_PREFIX) -> str:
    return f"""[Unit]
Description=sparring-range appliance broker (local libvirt, typed ops)
After=network-online.target libvirtd.service {NETRULES_UNIT}
Wants=network-online.target libvirtd.service
# The broker is the ONLY process with a libvirt socket and /dev/kvm access.
# Fail-closed ordering (plan 18): no guest may exist before the range's
# own isolation table is loaded; if the loader fails, the broker does not
# start and the range stays closed.
Requires=libvirtd.service {NETRULES_UNIT}

[Service]
Type=exec
User=srbroker
Group=sr-broker-clients
SupplementaryGroups=libvirt kvm
RuntimeDirectory=sparring-range
RuntimeDirectoryMode=0750
EnvironmentFile={etc}/broker.env
WorkingDirectory={prefix}
ExecStart={prefix}/.venv/bin/python -m infra.appliance.brokerd \\
  --manifest {etc}/appliance-manifest.json \\
  --policy {etc}/appliance-policy.json \\
  --uri qemu:///system --allowed-uid srrange
Restart=always
RestartSec=3
# NoNewPrivileges plus a fixed filesystem view: the broker cannot rewrite
# images or read controller/bastion/worker secrets.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths={m.state_dir}
PrivateDevices=false
DeviceAllow=/dev/kvm rw
DeviceAllow=/dev/net/tun rw
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
UMask=0077

[Install]
WantedBy=multi-user.target
"""


def render_ingest_unit(m: ApplianceManifest, *,
                       etc: pathlib.Path = DEFAULT_ETC,
                       prefix: pathlib.Path = DEFAULT_PREFIX) -> str:
    return f"""[Unit]
Description=sparring-range guest telemetry ingest (separate UID)
After=network-online.target postgresql.service
Wants=network-online.target
Requires=postgresql.service

[Service]
Type=exec
User=sringest
Group=sringest
EnvironmentFile={etc}/control-plane.ingest.env
EnvironmentFile=-{etc}/control-plane.env
Environment=SR_API_INGEST_ONLY=1
Environment=SR_PROCESS_ROLE=ingest
WorkingDirectory={prefix}
ExecStart={prefix}/.venv/bin/uvicorn srplatform.api.app:app \\
  --host {m.network.controller_range_ip} --port {m.network.ingest_port} \\
  --ssl-keyfile {etc}/tls/ingest-server.key \\
  --ssl-certfile {etc}/tls/ingest-server.crt
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths={m.state_dir}
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
"""


def _appliance_node_binary() -> str:
    """The SELECTED appliance Node runtime for unit rendering. Thin seam
    so the renderer keeps its no-service-imports discipline; the plan and
    its probe live in appliance_services, the single authority shared by
    the build, the unit ExecStart and the per-UID verification."""
    from deploy import appliance_services as svc
    return svc.node_runtime_plan()["binary"]


def render_worker_unit(m) -> str:
    """The worker supervisor unit with its state directory bound to THIS
    installation (plan 18 review): the unit REQUIRES the directory in its
    mount namespace, _ensure_dirs provisions exactly this path, and a
    silently diverging template would reintroduce the missing-directory
    startup failure. For the default layout this is byte-identical to the
    template."""
    text = _unit_from_template("sr-worker-supervisor.service")
    want = str(pathlib.Path(m.state_dir) / "worker")
    lines, seen = [], False
    for ln in text.splitlines():
        if ln.startswith("ReadWritePaths="):
            ln = f"ReadWritePaths={want}"
            seen = True
        lines.append(ln)
    if not seen:
        raise InstallError("sr-worker-supervisor.service lost its "
                           "ReadWritePaths contract")
    return "\n".join(lines) + "\n"


def render_web_unit(lay: Layout, node_binary: str) -> str:
    """The Next.js frontend, served as its own service identity on loopback.

    nginx terminates TLS and routes /api/* to the API; the frontend never
    listens on the LAN and never holds an infrastructure credential.
    ``node_binary`` is the SELECTED appliance runtime (node_runtime_plan)
    — the exact binary the build used and per-UID verification probed
    (second review, finding 5: provisioning Node 22 while this unit exec'd
    another path shipped an unsupported frontend behind green checks).
    """
    return f"""[Unit]
Description=sparring-range web frontend (Next.js, loopback only)
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=srweb
Group=srweb
WorkingDirectory={lay.prefix}/web
EnvironmentFile=-{lay.etc}/control-plane.env
Environment=PORT=3000
Environment=HOSTNAME=127.0.0.1
Environment=NODE_ENV=production
ExecStart={node_binary} {lay.prefix}/web/node_modules/next/dist/bin/next start -p 3000 -H 127.0.0.1
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadOnlyPaths={lay.prefix}/web
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
"""


def render_nginx_site(m: ApplianceManifest, lay: Layout) -> str:
    """The public HTTPS front door.

    Only the public plane is exposed: the API under /api/ and the frontend
    everywhere else.  The ingest listener is NOT proxied - it lives on the
    isolated inner bridge and is reached by the guests only.
    """
    host = urllib.parse.urlsplit(m.public_url).hostname or "localhost"
    return f"""# Rendered by deploy/appliance.py - do not hand-edit.
server {{
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name {host};

    ssl_certificate     {lay.etc}/tls/https.crt;
    ssl_certificate_key {lay.etc}/tls/https.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;

    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options SAMEORIGIN always;
    add_header Referrer-Policy no-referrer always;

    # The API's routes are UNPREFIXED (/auth/login, /sessions, ...). The
    # /api prefix is the public path the clients use, so it is STRIPPED here.
    location /api/ {{
        proxy_pass http://127.0.0.1:8000/;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }}

    location / {{
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }}
}}
"""


def render_netrules_unit(lay: Layout) -> str:
    """The boot loader for the appliance's OWN firewall table (plan 18).

    Live find: the operator applied the rules once in the maintenance
    window and a reboot silently lost them — the range came up unisolated.
    This unit reloads exactly the one rendered file at boot: it runs
    `nft -c` (parse/validate) first, then `nft -f` of that single file.  It
    NEVER runs `flush ruleset`, never touches another table or chain, and
    never executes operator-authored text at runtime — the file is the
    installer's own render, validated at render time (see
    netrules.nft_scope_problems).

    There is deliberately NO ExecStop: stopping this unit while guest VMs
    are alive would delete the table and silently remove the range's
    isolation — the exact failure mode this unit exists to prevent.  The
    table persists past a unit stop; the only way the rules change is a
    re-`ExecStart`, and `nft -f` of a file that declares the table replaces
    the whole table atomically in one batch, so a reload is never a
    delete-then-add window.  Removal of the table is an explicit operator
    action in the maintenance window, never a side effect of `systemctl
    stop` or a package upgrade.

    It is deliberately root: nft needs CAP_NET_ADMIN; no service identity
    of the range may hold it."""
    nft = lay.nftables_dir / "sr-appliance.nft"
    return f"""[Unit]
Description=sparring-range range firewall (loads ONLY its own inet table)
Documentation=file://{nft}
After=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
# Validate before loading: a corrupt render must fail this unit (and with
# it the broker, which Requires it), never boot into a half-loaded range.
ExecStartPre=/usr/sbin/nft -c -f {nft}
# Table-scoped by construction: the file adds/deletes ONLY inet
# sr_appliance, and `nft -f` applies it as ONE atomic batch — a reload
# replaces the table in a single kernel transaction. There is no
# flush-ruleset path and no stop-time teardown in this installation:
# isolation outlives unit stop, so a stop can never open a window.
ExecStart=/usr/sbin/nft -f {nft}
TimeoutStartSec=30
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
RestrictAddressFamilies=AF_NETLINK

[Install]
WantedBy=multi-user.target
"""


def render_files(m: ApplianceManifest, *,
                 prefix: pathlib.Path = DEFAULT_PREFIX,
                 etc: pathlib.Path = DEFAULT_ETC,
                 layout: Layout | None = None) -> Plan:
    lay = layout or default_layout(prefix=prefix, etc=etc)
    files = [
        RenderedFile(lay.etc / "appliance-manifest.json",
                     json.dumps(m.raw, indent=2, sort_keys=True) + "\n", 0o644),
        RenderedFile(lay.etc / "appliance-policy.json", render_policy(m), 0o644),
        RenderedFile(lay.etc / "control-plane.derived.env",
                     render_control_env(m, etc=lay.etc, prefix=lay.prefix),
                     0o640, "root", "srrange"),
        RenderedFile(lay.etc / "broker.env",
                     render_broker_env(m, etc=lay.etc),
                     0o640, "root", "sr-broker-clients"),
        RenderedFile(lay.etc / "control-plane.bastion.env",
                     render_bastion_env(m, etc=lay.etc, prefix=lay.prefix),
                     0o640, "root", "srbastion"),
        RenderedFile(lay.etc / "control-plane.ingest.env",
                     render_ingest_env(m, etc=lay.etc, prefix=lay.prefix),
                     0o640, "root", "sringest"),
        RenderedFile(lay.etc / "worker-supervisor.env",
                     render_supervisor_env(m, etc=lay.etc, prefix=lay.prefix),
                     0o640, "root", "srworker"),
        RenderedFile(lay.network_dir / "10-srlab.netdev",
                     render_networkd(m).split("\n\n", 1)[0] + "\n", 0o644),
        RenderedFile(lay.network_dir / "20-srlab.network",
                     render_networkd(m).split("\n\n", 1)[1], 0o644),
        RenderedFile(lay.nftables_dir / "sr-appliance.nft",
                     render_nftables(m), 0o644),
        RenderedFile(lay.units_dir / NETRULES_UNIT,
                     render_netrules_unit(lay), 0o644),
        RenderedFile(lay.units_dir / "sr-appliance-broker.service",
                     render_broker_unit(m, etc=lay.etc, prefix=lay.prefix), 0o644),
        RenderedFile(lay.units_dir / "sr-appliance-ingest.service",
                     render_ingest_unit(m, etc=lay.etc, prefix=lay.prefix), 0o644),
        RenderedFile(lay.units_dir / "sr-worker-supervisor.service",
                     render_worker_unit(m), 0o644),
        RenderedFile(lay.units_dir / "sr-api.service",
                     _unit_from_template("sr-api.service"), 0o644),
        RenderedFile(lay.units_dir / "sr-bastion.service",
                     _unit_from_template(
                         "sr-bastion.service",
                         env_files=[str(lay.etc / "control-plane.bastion.env")],
                         extra="Environment=SR_PROCESS_ROLE=bastion"),
                     0o644),
        RenderedFile(lay.units_dir / "sr-web.service",
                     render_web_unit(lay, _appliance_node_binary()), 0o644),
        RenderedFile(lay.nginx_dir / "sparring-range.conf",
                     render_nginx_site(m, lay), 0o644),
    ]
    actions = [
        "create groups: " + ", ".join(GROUPS),
        "create users: " + ", ".join(sorted(USERS)),
        "add srrange to sr-broker-clients and srbastion groups",
        "ensure state/images/recordings/secrets directories",
        "generate worker supervisor capability if absent (0600 srworker)",
        "install the pinned native packages (libvirt/QEMU, PostgreSQL, nginx, "
        "nftables) — real appliances only",
        "create the appliance venv from the locked requirements — real "
        "appliances only",
        "create the database roles and run `alembic upgrade head` as the owner "
        "— real appliances only",
        "provision the TLS material and onboard the member keys — real "
        "appliances only",
        "daemon-reload; enable --now " + " ".join([*UNITS, NETRULES_UNIT]),
        "apply fixed networkd bridge and nftables rules once; the rules are "
        "reloaded at every boot by " + NETRULES_UNIT + " (own table only)",
    ]
    # Fail closed at RENDER time: a ruleset that could touch anything but
    # its own table must never reach disk, let alone the loader service.
    scope_problems = nft_scope_problems(render_nftables(m))
    if scope_problems:
        raise InstallError("rendered firewall violates its own-table scope: "
                           + "; ".join(scope_problems))
    return Plan(files=files, actions=actions, units=list(UNITS))


def plan_document(plan: Plan, m: ApplianceManifest) -> str:
    lines = ["appliance plan for " + m.installation_id,
             "range " + str(m.network.range_cidr) + " bridge "
             + m.network.range_bridge,
             "broker socket " + m.broker_socket, "", "actions:"]
    lines += ["  - " + a for a in plan.actions]
    lines += ["", "files:"]
    for f in plan.files:
        lines.append(f"  {oct(f.mode)} {f.owner}:{f.group} {f.path}")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# privileged effects (explicit, narrow)                                       #
# --------------------------------------------------------------------------- #

class Runner:
    def __init__(self, *, dry_run: bool = False):
        self.dry_run = dry_run

    def __call__(self, *cmd: str, check: bool = True,
                env: dict | None = None,
                cwd: str | None = None) -> subprocess.CompletedProcess:
        printable = " ".join(str(c) for c in cmd)
        # Progress belongs on stderr: stdout carries the machine-readable
        # result of the command.
        print(("DRY: " if self.dry_run else "$ ") + printable, file=sys.stderr,
              flush=True)
        if self.dry_run:
            return subprocess.CompletedProcess(list(cmd), 0, "", "")
        environ = {**os.environ, **(env or {})}
        # subprocess requires every environment value to be a str; an
        # IPv4Address (live find 2026-10-23: HTTPS_IP reached the TLS
        # bootstrap as a real IPv4Address and died inside subprocess with a
        # message naming nothing) must fail HERE, naming the key, and never
        # mid-script.
        for key, value in environ.items():
            if not isinstance(value, str):
                raise InstallError(
                    f"environment value for {key!r} is {type(value).__name__}, "
                    f"not str: convert explicitly at the call site "
                    f"(str({key})) rather than at the process boundary")
        r = subprocess.run([str(c) for c in cmd], capture_output=True,
                           text=True, env=environ, cwd=cwd)
        if check and r.returncode != 0:
            raise InstallError(f"{printable} failed ({r.returncode}): "
                               f"{(r.stderr or r.stdout)[-800:]}")
        return r


def _ensure_group(name: str, run: Runner) -> None:
    try:
        grp.getgrnam(name)
        return
    except KeyError:
        run("groupadd", "--system", name)


def _ensure_user(name: str, group: str, run: Runner) -> None:
    try:
        pwd.getpwnam(name)
    except KeyError:
        run("useradd", "--system", "--gid", group, "--home-dir",
            "/nonexistent", "--shell", "/usr/sbin/nologin", name)


def _ids(name: str) -> tuple[int, int]:
    try:
        pw = pwd.getpwnam(name)
    except KeyError:
        return 0, 0
    return pw.pw_uid, pw.pw_gid


def _ensure_dirs(m: ApplianceManifest, run: Runner, lay: Layout) -> None:
    # The state directory is SHARED (plan 18 review): the broker creates and
    # journals its ledger directly inside, the API reads anchors/pins and
    # writes only inside its own 0700 controller / 0755 known_hosts
    # subtrees, and runner/bastion/worker merely TRAVERSE to world-readable
    # pins (the API chmods published pins 0644).  0751 owner srbroker =
    # write for the ledger, traverse-without-enumeration for everyone else
    # — narrow, and it widens no group.  When the ledger lives elsewhere the
    # shared parent is left ALONE and the ledger directory gets its own
    # srbroker-owned entry; two entries must never fight over one
    # directory's ownership on every apply.
    ledger_parent = pathlib.Path(m.broker_ledger).parent
    ledger_in_state = ledger_parent.resolve() == pathlib.Path(
        m.state_dir).resolve()
    entries = [
            (pathlib.Path(m.state_dir), 0o751, "srbroker", "srrange"),
            (pathlib.Path(m.images_dir), 0o755, "root", "root"),
            (pathlib.Path(m.recordings_dir), 0o750, "srbastion", "srbastion"),
            # The secrets directory is traversable by the two identities
            # that hold a credential in it (the API and the supervisor);
            # every file inside keeps its own 0600 ownership.
            (pathlib.Path(m.secrets_dir), SECRET_DIR_MODE, "root",
             SECRET_DIR_GROUP),
            (pathlib.Path(m.state_dir) / "controller", 0o700, "srrange", "srrange"),
            # The worker supervisor's private state directory (plan 18
            # review): sr-worker-supervisor.service REQUIRES
            # ReadWritePaths=<state>/worker — a missing directory breaks
            # the unit's mount namespace before ExecStart, and the shared
            # state parent (0751) only ever provides TRAVERSAL, never the
            # child.  Dedicated, srworker-owned, 0750: nothing else may
            # write what the supervisor will execute state from.
            (pathlib.Path(m.state_dir) / "worker", 0o750, "srworker",
             "srworker"),
            # Runtime host pins live under state (plan 18): the API is the
            # only writer (ProtectSystem=strict makes /etc read-only for it),
            # the runner/verifier/bastion clients only need read access, and
            # public host keys carry no secret.
            (pathlib.Path(m.state_dir) / "known_hosts", 0o755, "srrange",
             "srrange"),
            (lay.run, 0o750, "srbroker", "sr-broker-clients"),
            (lay.etc / "tls", 0o755, "root", "root"),
            (lay.etc / "ssh", SSH_DIR_MODE, "root", SSH_DIR_GROUP)]
    if not ledger_in_state:
        entries.append((ledger_parent, 0o750, "srbroker",
                        "sr-broker-clients"))
    for path, mode, user, group in entries:
        if lay.sandboxed:
            # A sandbox install cannot create system identities; the mode is
            # still enforced so the receipt describes the intended layout.
            run("install", "-d", "-m", oct(mode)[2:], str(path))
        else:
            run("install", "-d", "-m", oct(mode)[2:], "-o", user, "-g", group,
                str(path))


def _write_files(files: list[RenderedFile], run: Runner,
                 lay: Layout) -> list[str]:
    changed = []
    for f in files:
        uid, gid = _ids(f.owner)
        if f.group != f.owner:
            try:
                gid = grp.getgrnam(f.group).gr_gid
            except KeyError:
                gid = _ids(f.owner)[1]
        if lay.sandboxed:
            uid = gid = os.getuid()
        if run.dry_run:
            print(f"DRY: write {oct(f.mode)} {f.owner}:{f.group} {f.path}",
                  file=sys.stderr)
            changed.append(str(f.path))
            continue
        if _atomic_write(f.path, f.content, f.mode, uid, gid):
            changed.append(str(f.path))
    return changed


def _ensure_supervisor_token(etc: pathlib.Path, run: Runner,
                             lay: Layout) -> str:
    """Provision the worker-supervisor capability.

    The capability is a SECRET and the production settings refuse a
    group- or world-readable token file, so it cannot be shared through one
    file: the API and the supervisor each get their OWN 0600 copy of the
    SAME value (the API must compare what it is given, the supervisor must
    present what it holds).  An existing installation is never re-keyed.
    """
    api_path = etc / "secrets/worker-supervisor.token"
    worker_path = etc / "secrets/worker-supervisor.token.srworker"
    if run.dry_run:
        # A DRY RUN MUST NOT WRITE: not the capability, not its ownership,
        # not the supervisor's copy.
        print(f"DRY: provision {api_path} + {worker_path} (0600 each)",
              file=sys.stderr)
        return "would create" if not api_path.exists() else "preserved"
    existing = [p for p in (api_path, worker_path) if p.exists()]
    if existing:
        values = {p.read_text().strip() for p in existing}
        if any(len(v) < 32 for v in values):
            raise InstallError(f"existing {api_path} is too short; rotate it "
                               "explicitly rather than silently replacing it")
        if len(values) != 1:
            raise InstallError(
                f"the supervisor capability copies disagree "
                f"({api_path} vs {worker_path}) — restore one of them "
                "instead of letting the installer choose")
        token = values.pop()
        _atomic_write(api_path, token + "\n", 0o600,
                      os.getuid() if lay.sandboxed else _ids("srrange")[0],
                      os.getuid() if lay.sandboxed else _ids("srrange")[1])
        _atomic_write(worker_path, token + "\n", 0o600,
                      os.getuid() if lay.sandboxed else _ids("srworker")[0],
                      os.getuid() if lay.sandboxed else _ids("srworker")[1])
        return "preserved"
    token = secrets.token_urlsafe(48)
    api_path.parent.mkdir(parents=True, exist_ok=True)
    if lay.sandboxed:
        api_uid = api_gid = worker_uid = worker_gid = os.getuid()
    else:
        api_uid, api_gid = _ids("srrange")
        worker_uid, worker_gid = _ids("srworker")
    _atomic_write(api_path, token + "\n", 0o600, api_uid, api_gid)
    _atomic_write(worker_path, token + "\n", 0o600, worker_uid, worker_gid)
    return "created"


def _ingest_sans(m: ApplianceManifest) -> str:
    """The SANs the guest-facing ingest certificate must carry.

    The guests reach the ingest listener on the isolated range by IP; the
    public name is added when the installation has one.  Without these the
    bootstrap script SKIPS the ingest certificate and the guests can never
    enroll.
    """
    sans = [f"IP:{m.network.ingest_address}"]
    host = urllib.parse.urlsplit(m.public_url).hostname
    if host and not host.replace(".", "").isdigit():
        sans.append(f"DNS:{host}")
    return " ".join(sans)


def _receipt(m: ApplianceManifest, plan: Plan, lay: Layout) -> dict:
    """A digest-only record of what the installation consists of.

    It contains NO secret: the worker capability is recorded as a digest, and
    the file digests are what the install gate compares against to prove a
    rerun changed nothing and a repair restored exactly what was intended.
    """
    import hashlib

    def sha(text: str) -> str:
        return hashlib.sha256(text.encode()).hexdigest()

    files = {}
    for f in plan.files:
        files[str(f.path)] = {"sha256": sha(f.content), "mode": f"{f.mode:04o}"}
    token_path = lay.etc / "secrets/worker-supervisor.token"
    receipt = {
        "installation_id": m.installation_id,
        "manifest_sha256": sha(json.dumps(m.raw, indent=2, sort_keys=True)),
        "policy_sha256": sha(render_policy(m)),
        "files": files,
    }
    if token_path.exists():
        receipt["supervisor_token_sha256"] = sha(token_path.read_text())
    return receipt


def storage_headroom_problem(free_bytes: int, image_bytes: int,
                             min_free_gb: int) -> str | None:
    """Pure pre-flight: does the images filesystem still have room?

    Live practice 2026-10-23: a nearly-full appliance accepted the image
    copy and only failed later, mid-clone, with generic I/O errors.  The
    rule stated HERE (and checked before apply's effects) is: the space
    already occupied by the release images PLUS the operator's configured
    free-space floor must fit in the current free space.  Returns None
    when fine, otherwise an actionable one-liner naming the numbers."""
    need = int(min_free_gb) * 1024**3 + int(image_bytes)
    if int(free_bytes) >= need:
        return None
    return (f"images filesystem has {int(free_bytes) / 1024**3:.1f} GiB free "
            f"but needs {need / 1024**3:.1f} GiB "
            f"({int(image_bytes) / 1024**3:.1f} GiB of images already placed "
            f"plus a {min_free_gb} GiB floor for guest clones) - free space "
            "or point images at a larger filesystem before installing")


def apply_plan(m: ApplianceManifest, plan: Plan, *,
               prefix: pathlib.Path = DEFAULT_PREFIX,
               etc: pathlib.Path = DEFAULT_ETC,
               layout: Layout | None = None,
               dry_run: bool = False) -> dict:
    lay = layout or default_layout(prefix=prefix, etc=etc)
    run = Runner(dry_run=dry_run)
    if not dry_run and not lay.sandboxed and os.geteuid() != 0:
        raise InstallError("apply requires root (use --dry-run for a plan, "
                           "or --system-root for a sandbox installation)")
    if not lay.sandboxed:
        for g in GROUPS:
            _ensure_group(g, run)
        for user, (group, extras) in USERS.items():
            _ensure_user(user, group, run)
            for extra in extras:
                run("usermod", "-a", "-G", extra, user, check=False)
    _ensure_dirs(m, run, lay)
    token_action = _ensure_supervisor_token(lay.etc, run, lay)
    if not lay.sandboxed and not dry_run:
        # The operator's runtime environment is read by the API, the ingest
        # listener and the bastion: it must be readable by them and by
        # nobody else. Its CONTENT is the operator's; only the ownership
        # and the mode are the installer's business.
        runtime_env = lay.etc / "control-plane.env"
        if runtime_env.is_file():
            run("chown", "root:srrange", str(runtime_env), check=False)
            run("chmod", "0640", str(runtime_env), check=False)
        # The MODEL credential belongs to the API identity alone (plan 18):
        # 0640 root:srrange. Not the supervisor (srworker), not the bastion,
        # not the broker; the API requests every model call through its own
        # gateway, so no other identity needs it.
        model_key = pathlib.Path(m.model_api_key_file)
        if model_key.is_file():
            run("chown", "root:srrange", str(model_key), check=False)
            run("chmod", "0640", str(model_key), check=False)
    services: dict = {}
    if not lay.sandboxed and not dry_run:
        # Storage headroom BEFORE any effect (plan 18): a nearly-full
        # images filesystem must refuse the installation here, naming the
        # numbers, not fail later mid-clone with generic I/O errors.
        probe = pathlib.Path(m.images_dir)
        while not probe.is_dir() and probe != probe.parent:
            probe = probe.parent
        image_bytes = sum(
            int(img.size_bytes) for img in m.images.values()
            if pathlib.Path(img.path).is_file())
        problem = storage_headroom_problem(
            shutil.disk_usage(str(probe)).free, image_bytes,
            m.budgets.min_free_gb)
        if problem:
            raise InstallError(problem)
        # The REAL service steps.  A sandbox install renders the same files
        # and proves the sequences, but it never pretends the services ran.
        from deploy import appliance_services as svc
        source = ROOT
        if not (source / "requirements.lock").is_file():
            raise InstallError(f"missing {source / 'requirements.lock'}")
        services["native_packages"] = svc.ensure_native_dependencies(run)
        # Node BEFORE the web build (plan 18): Ubuntu 24.04's Node 18 cannot
        # build or start Next 16; the pinned LTS is fetched, digest-checked
        # and installed here rather than hand-installed mid-hand-off.
        services["node"] = svc.ensure_node_runtime(run)
        services["venv"] = str(svc.ensure_venv(
            run, prefix=lay.prefix, source=source))
        # A rendered unit is not a process (plan 18): every service identity
        # must ACTUALLY execute what its unit execs, verified per real UID
        # before apply claims success (the umask-027 venv passed every
        # rendered check and still died 203/EXEC on first start).
        services["runtime_verification"] = svc.verify_service_runtime(
            run, pathlib.Path(services["venv"]),
            node_binary=services["node"]["binary"])
        services["database"] = svc.ensure_database(
            run, prefix=lay.prefix, env_file=lay.etc / "control-plane.env",
            sandboxed=lay.sandboxed)
        services["tls"] = svc.ensure_tls(
            run, etc=lay.etc, public_ip=m.network.lan_address or "127.0.0.1",
            ingest_sans=_ingest_sans(m))
        # The MEMBERS' public keys are written for the recording bastion in
        # the bastion's own format: "<username> <public-key>".  The username
        # is the login the member uses: the bastion's token login resolves
        # the session owner's username, so a key registered under a machine
        # role ("runner") would never authenticate a person.
        member_keys = [(username, key)
                       for username, key in m.member_public_keys().items()]
        services["onboarding"] = svc.onboard_operator(
            run, etc=lay.etc, authorized_keys=member_keys)
        services["bastion_token"] = svc.ensure_bastion_token_file(
            run, etc=lay.etc, sandboxed=lay.sandboxed)
        services["service_keys"] = svc.ensure_service_keys(
            run, etc=lay.etc, sandboxed=lay.sandboxed,
            access_keys={role: m.access_keys[role].path
                         for role in m.access_keys})
        services["web"] = svc.ensure_web_build(run, source=source,
                                               public_url=m.public_url,
                                               node_binary=
                                               services["node"]["binary"])
        # the public front door: enable the rendered site and reload nginx
        run("ln", "-sfn", str(lay.nginx_dir / "sparring-range.conf"),
            str(lay.nginx_dir.parent / "sites-enabled/sparring-range.conf"),
            check=False)
        run("nginx", "-t", check=False)
        run("systemctl", "reload", "nginx", check=False)
    changed = _write_files(plan.files, run, lay)
    receipt = _receipt(m, plan, lay)
    if not dry_run:
        _atomic_write(lay.receipt, json.dumps(receipt, indent=2, sort_keys=True)
                      + "\n", 0o644, os.getuid(), os.getgid())
    if not lay.sandboxed:
        run("systemctl", "daemon-reload", check=False)
        _apply_sysctls(run)
        # Network artifacts are installed but not applied to the host by this
        # command: the operator applies them during the approved maintenance
        # window after reviewing the generated rules.  The netrules LOADER is
        # enabled too — once the operator starts it (or reboots), the range
        # isolation survives restarts instead of silently vanishing.
        for unit in [*plan.units, NETRULES_UNIT]:
            run("systemctl", "enable", unit, check=False)
    return {"changed": changed, "supervisor_token": token_action,
            "services": services, "dry_run": dry_run}


def _resolve_binary(name: str) -> str | None:
    """Locate a system binary by absolute path.

    A bare lookup through the inherited PATH failed on the appliance
    (live find 2026-10-23: `systemd-sysctl` is in /usr/bin, and the sudo
    PATH of a non-login shell did not contain it).  Searching the standard
    absolute locations never depends on the caller's PATH, and a failure
    names the binary instead of dying inside exec with a bare
    FileNotFoundError.
    """
    found = shutil.which(name)
    if found:
        return found
    for base in ("/usr/bin", "/bin", "/usr/sbin", "/sbin"):
        p = pathlib.Path(base) / name
        if p.is_file() and os.access(p, os.X_OK):
            return str(p)
    return None


def _apply_sysctls(run: Runner) -> None:
    """Apply the system sysctl configuration by absolute path (plan 18).

    Not fatal on failure (the same contract as the old bare call), but the
    failure is LOUD and names the exact remediation, so a half-applied
    network configuration is never mistaken for a complete one."""
    binary = _resolve_binary("systemd-sysctl")
    if binary is None:
        print("WARNING: systemd-sysctl not found in PATH or /usr/bin; run "
              "`systemd-sysctl` manually after installing systemd",
              file=sys.stderr)
        return
    result = run(binary, check=False)
    if result.returncode != 0:
        print("WARNING: systemd-sysctl exited "
              f"{result.returncode}: {(result.stderr or result.stdout)[-200:]}; "
              "review /etc/sysctl.d/ before relying on those settings",
              file=sys.stderr)


# --------------------------------------------------------------------------- #
# read-only status/doctor                                                     #
# --------------------------------------------------------------------------- #

def _unit_state(unit: str) -> str:
    r = subprocess.run(["systemctl", "is-active", unit],
                       capture_output=True, text=True)
    return (r.stdout or r.stderr).strip() or f"exit {r.returncode}"


def _broker_status(m: ApplianceManifest) -> dict:
    try:
        from infra.broker.client import BrokerClient, HttpTransport
        client = BrokerClient(HttpTransport(f"unix://{m.broker_socket}"))
        return {"ok": True, "inventory": client.inventory()}
    except Exception as exc:  # noqa: BLE001 — status reports, never crashes
        return {"ok": False, "error": str(exc)[:300]}


def status(m: ApplianceManifest, *, as_json: bool = False) -> dict:
    data = {
        "installation_id": m.installation_id,
        "units": {u: _unit_state(u) for u in (*UNITS, NETRULES_UNIT)},
        "broker": _broker_status(m),
        "paths": {
            "broker_socket": m.broker_socket,
            "ledger": m.broker_ledger,
            "state": m.state_dir,
            "recordings": m.recordings_dir,
        },
    }
    if as_json:
        print(json.dumps(data, indent=2, sort_keys=True))
    else:
        for unit, state in data["units"].items():
            print(f"{unit}: {state}")
        broker = data["broker"]
        print("broker: " + ("healthy" if broker["ok"] else broker["error"]))
    return data


def doctor(m: ApplianceManifest, *, as_json: bool = False) -> dict:
    checks: list[dict] = []

    def add(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    add("root manifest", pathlib.Path(m.source).is_file(), m.source)
    add("broker socket directory",
        pathlib.Path(m.broker_socket).parent.is_dir(),
        str(pathlib.Path(m.broker_socket).parent))
    add("image files", all(pathlib.Path(i.path).is_file()
                           for i in m.images.values()),
        ", ".join(i.path for i in m.images.values()))
    add("model key file", pathlib.Path(m.model_api_key_file).is_file(),
        m.model_api_key_file)
    add("access key files", all(pathlib.Path(k.path).is_file()
                                for k in m.access_keys.values()),
        ", ".join(sorted(m.access_keys)))
    for unit in UNITS:
        state = _unit_state(unit)
        add(f"unit {unit}", state == "active", state)
    add("broker reachable", _broker_status(m)["ok"])
    # libvirt/KVM visibility is a broker-UID concern; a root doctor can still
    # report it without granting the API anything.
    try:
        from infra.appliance.backend import LibvirtBackend  # noqa: F401
        add("libvirt python binding", True)
    except Exception as exc:  # noqa: BLE001
        add("libvirt python binding", False, str(exc)[:200])
    add("/dev/kvm present", pathlib.Path("/dev/kvm").exists(),
        "nested KVM requires a hardware-accelerated outer VM")
    add("systemd-networkd", shutil.which("networkctl") is not None)
    add("nftables", shutil.which("nft") is not None)
    if as_json:
        print(json.dumps(checks, indent=2, sort_keys=True))
    else:
        for c in checks:
            print(("[ok]  " if c["ok"] else "[FAIL] ") + c["check"]
                  + (f" — {c['detail']}" if c["detail"] else ""))
    return {"ok": all(c["ok"] for c in checks), "checks": checks}


# --------------------------------------------------------------------------- #
# operator recovery (local, evidence-bound)                                   #
# --------------------------------------------------------------------------- #

def firstboot_report(m: ApplianceManifest, layout: Layout) -> dict:
    """A read-only health report for a freshly installed appliance.

    The operator runs this in THEIR virtual machine: it answers "is the
    appliance actually up?" without guessing, and without printing anything
    secret.  Every check names what it looked at and what it saw.

    Staged first boot (plan 18): the hand-off deliberately leaves the
    bridge, the nftables rules and the service starts to the operator's
    maintenance window.  While the bridge does not exist yet, every check
    downstream of those manual steps is reported PENDING — visibly, with the
    exact remediation — instead of a wall of FAILs that hides the two things
    that are genuinely broken.  Once the manual steps are done, the same
    checks become real pass/fail again.  Machine-readable semantics
    (review finding: the CLI's exit 3 was honest, the JSON was not): a
    pending check reports ``ok: false`` WITH ``pending: true`` — pending is
    never folded into ok.  The overall ``ok`` is true ONLY when every check
    genuinely passed; ``failed`` names the genuine failures separately from
    ``pending``, so a consumer reading only ``ok`` can never mistake a
    half-installed appliance for a healthy one, and one reading ``failed``
    can tell "broken" from "not my window yet".
    """
    import socket as _socket
    import urllib.error
    import urllib.request

    checks: list[dict] = []
    bridge_ready = pathlib.Path("/sys/class/net/"
                                f"{m.network.range_bridge}").exists()

    def add(name: str, ok: bool, detail: str = "",
            pending_if_manual: bool = False) -> None:
        pending = bool(pending_if_manual and not bridge_ready and not ok)
        checks.append({"check": name, "ok": bool(ok),
                       "pending": pending, "detail": detail[:200]})

    add("manifest", True, m.installation_id)
    add("broker socket", pathlib.Path(m.broker_socket).exists(), m.broker_socket,
        pending_if_manual=True)
    broker = _broker_status(m)
    add("broker answers", broker.get("ok", False),
        "inventory" if broker.get("ok") else str(broker.get("error", ""))[:120],
        pending_if_manual=True)

    def http(url: str) -> tuple[bool, str]:
        try:
            with urllib.request.urlopen(url, timeout=8) as r:
                body = r.read(400).decode("utf-8", "replace")
                return 200 <= r.status < 300, body
        except urllib.error.HTTPError as exc:
            return False, f"HTTP {exc.code}"
        except Exception as exc:  # noqa: BLE001
            return False, f"{type(exc).__name__}"

    ok_health, body = http(m.internal_url.rstrip("/") + "/healthz")
    add("api /healthz", ok_health, body, pending_if_manual=True)
    ok_ready, body = http(m.internal_url.rstrip("/") + "/readyz")
    add("api /readyz", ok_ready, body, pending_if_manual=True)

    def tcp(host: str, port: int) -> bool:
        try:
            with _socket.create_connection((host, port), timeout=5):
                return True
        except OSError:
            return False

    ingest = m.network.ingest_address
    add("ingest listener",
        bool(ingest) and tcp(str(ingest), int(m.network.ingest_port)),
        f"{ingest}:{m.network.ingest_port}" if ingest else "not configured",
        pending_if_manual=True)
    # The bastion listens on every appliance address, but the RANGE-side
    # bastion address may name no local interface at all (it is a range
    # planning address); the reachable check is the appliance's own LAN
    # address (or loopback), the one members are told to use
    # (live find 2026-10-23: `.2:2222` on the range never answers, so a
    # healthy bastion failed firstboot forever).
    bastion_probe = str(m.network.lan_address) if m.network.lan_address \
        else "127.0.0.1"
    add("bastion listener", tcp(bastion_probe, 2222),
        f"{bastion_probe}:2222 "
        f"(range-side {m.network.bastion_address}; members connect via the "
        "LAN address)",
        pending_if_manual=True)
    for unit in (*UNITS, NETRULES_UNIT):
        state = _unit_state(unit)
        add(f"unit {unit}", state == "active", state, pending_if_manual=True)
    add("isolated bridge", bridge_ready,
        m.network.range_bridge if bridge_ready else
        f"{m.network.range_bridge} missing — apply step-6 networkd + reload",
        pending_if_manual=True)
    add("nftables rules", shutil.which("nft") is not None,
        "nft is required for the range isolation rules")
    for role, image in sorted(m.images.items()):
        path = pathlib.Path(image.path)
        add(f"image {role}", path.is_file(),
            f"{path} ({path.stat().st_size if path.is_file() else 0} bytes)")
    add("TLS material", (layout.etc / "tls").is_dir(),
        str(layout.etc / "tls"))
    add("bastion keys", (layout.etc / "ssh" / "authorized_keys").is_file(),
        str(layout.etc / "ssh" / "authorized_keys"))
    add("worker capability",
        (layout.etc / "secrets" / "worker-supervisor.token").is_file(),
        str(layout.etc / "secrets" / "worker-supervisor.token"))
    return {"ok": all(c["ok"] for c in checks),
            "failed": [c["check"] for c in checks
                       if not c["ok"] and not c.get("pending")],
            "pending": [c["check"] for c in checks if c.get("pending")],
            "checks": checks,
            "installation_id": m.installation_id}


def _ledger(m: ApplianceManifest):
    from infra.broker.ledger import Ledger
    return Ledger(m.broker_ledger)


def recovery_status(m: ApplianceManifest) -> dict:
    ledger = _ledger(m)
    try:
        return {
            "latch": ledger.get_latch(),
            "lease": ledger.get_lease(),
            "pending_intents": ledger.pending_intents(),
            "active_claims": ledger.active_claims(),
            "open_obligations": ledger.open_obligations(),
            "audit_tail": ledger.audit_tail(20),
        }
    finally:
        ledger.close()


def recovery_reconcile(m: ApplianceManifest, policy: AppliancePolicy, *,
                       uri: str = "qemu:///system", allow_tcg: bool = False,
                       fixture: bool = False) -> dict:
    from infra.appliance.backend import BackendConfig, LibvirtBackend
    backend = LibvirtBackend(
        m, policy, BackendConfig(uri=uri, allow_tcg=allow_tcg,
                                 fixture_mode=fixture))
    ledger = _ledger(m)
    try:
        findings = []
        for claim in ledger.active_claims():
            try:
                seen = backend.lookup_vm(policy.node, int(claim["vmid"]))
            except Exception as exc:  # noqa: BLE001 — uncertainty is a finding
                seen = {"unknown": str(exc)[:200]}
            findings.append({"claim": claim, "backend": seen})
        return {"pending_intents": ledger.pending_intents(),
                "active_claims": findings,
                "open_obligations": ledger.open_obligations(),
                "note": "inspection only; nothing was replayed or released"}
    finally:
        ledger.close()
        backend.close()


def recovery_resolve(m: ApplianceManifest, policy: AppliancePolicy,
                     obligation_id: int, evidence_path: pathlib.Path, *,
                     uri: str = "qemu:///system", allow_tcg: bool = False,
                     fixture: bool = False) -> dict:
    """Resolve one obligation ONLY after fresh backend absence evidence.

    Evidence is a JSON object written by the operator with the fields
    ``obligation_id``, ``vmid``, ``observed`` (``absent`` or ``destroyed``),
    ``operator``, and ``timestamp``.  The backend is read again here; a stale
    or mismatched file cannot release a reservation.
    """
    try:
        evidence = json.loads(pathlib.Path(evidence_path).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise InstallError(f"evidence file unreadable: {exc}") from exc
    required = {"obligation_id", "vmid", "observed", "operator", "timestamp"}
    if not required.issubset(evidence):
        raise InstallError(f"evidence missing {sorted(required - set(evidence))}")
    if int(evidence["obligation_id"]) != int(obligation_id):
        raise InstallError("evidence belongs to a different obligation")
    if evidence["observed"] not in ("absent", "destroyed"):
        raise InstallError("evidence must prove the resource is absent/destroyed")
    ledger = _ledger(m)
    try:
        open_obs = {o["id"]: o for o in ledger.open_obligations()}
        if obligation_id not in open_obs:
            raise InstallError(f"obligation {obligation_id} is not open")
        vmid = int(evidence["vmid"])
        if open_obs[obligation_id].get("vmid") not in (None, vmid):
            raise InstallError("evidence vmid does not match the obligation")
        from infra.appliance.backend import BackendConfig, LibvirtBackend
        backend = LibvirtBackend(
            m, policy, BackendConfig(uri=uri, allow_tcg=allow_tcg,
                                     fixture_mode=fixture))
        try:
            seen = backend.lookup_vm(policy.node, vmid)
        finally:
            backend.close()
        if seen is not None:
            raise InstallError(f"backend still owns VMID {vmid}: {seen}")
        ledger.resolve_obligation(obligation_id)
        ledger.audit("operator-obligation-resolved", {
            "obligation_id": obligation_id, "vmid": vmid,
            "evidence": str(evidence_path),
            "operator": evidence["operator"], "timestamp": evidence["timestamp"],
            "rechecked_absent": True})
        return {"resolved": obligation_id, "vmid": vmid}
    finally:
        ledger.close()


# --------------------------------------------------------------------------- #
# CLI                                                                         #
# --------------------------------------------------------------------------- #

def _under_root(path: str, root: pathlib.Path) -> str:
    """Map an absolute manifest path into the installation root.

    A sandbox installation must not create anything on the host, so every
    absolute path the manifest names (state, images, recordings, secrets,
    ledger, broker socket) is re-rooted.  The manifest itself is untouched:
    the operator's file keeps describing the real appliance.
    """
    p = pathlib.Path(path)
    if not p.is_absolute():
        return path
    return str(root / p.relative_to("/"))


def sandbox_manifest(m: ApplianceManifest, root: pathlib.Path) -> ApplianceManifest:
    """A copy of the manifest whose absolute paths live under ``root``."""
    if root == pathlib.Path("/"):
        return m
    import dataclasses
    return dataclasses.replace(
        m,
        broker_socket=_under_root(m.broker_socket, root),
        broker_ledger=_under_root(m.broker_ledger, root),
        state_dir=_under_root(m.state_dir, root),
        images_dir=_under_root(m.images_dir, root),
        recordings_dir=_under_root(m.recordings_dir, root),
        secrets_dir=_under_root(m.secrets_dir, root),
    )


def verify_install(m: ApplianceManifest, layout: Layout) -> dict:
    """Compare the installed files with the install receipt.

    The receipt is written by ``apply`` and records the digest and mode of
    every file the installation owns.  A later verification therefore answers
    "is what is on disk still exactly what was installed?" without trusting a
    flag, a timestamp or an environment assertion.
    """
    import hashlib
    receipt_path = layout.receipt
    if not receipt_path.exists():
        return {"ok": False, "error": f"no install receipt at {receipt_path}",
                "drift": []}
    try:
        receipt = json.loads(receipt_path.read_text())
    except (OSError, ValueError) as exc:
        return {"ok": False, "error": f"install receipt unreadable: {exc}",
                "drift": []}
    drift: list[dict] = []
    for path, expect in sorted(receipt.get("files", {}).items()):
        p = pathlib.Path(path)
        if not p.exists():
            drift.append({"path": path, "problem": "missing"})
            continue
        actual = hashlib.sha256(p.read_bytes()).hexdigest()
        if actual != expect["sha256"]:
            drift.append({"path": path, "problem": "content",
                          "expected": expect["sha256"], "actual": actual})
            continue
        mode = f"{p.stat().st_mode & 0o777:04o}"
        if mode != expect["mode"]:
            drift.append({"path": path, "problem": "mode",
                          "expected": expect["mode"], "actual": mode})
    return {"ok": not drift, "drift": drift,
            "files": len(receipt.get("files", {})),
            "manifest_sha256": receipt.get("manifest_sha256")}


def _layout(args) -> Layout:
    """The installation layout for the requested (possibly sandboxed) root."""
    root = pathlib.Path(getattr(args, "system_root", "/"))
    prefix = getattr(args, "prefix", None)
    etc = getattr(args, "etc", None)
    if prefix and pathlib.Path(prefix).is_absolute() and root != pathlib.Path("/"):
        # an explicit absolute prefix stays outside the sandbox only when the
        # operator asked for it; a sandbox keeps everything under its root.
        prefix = None
    if etc and pathlib.Path(etc).is_absolute() and root != pathlib.Path("/"):
        etc = None
    return default_layout(root=root, prefix=prefix, etc=etc)


def _load(args) -> tuple[ApplianceManifest, AppliancePolicy]:
    # Applying or upgrading the appliance ALWAYS verifies the base image
    # digests: a drifted image must be refused before any effect, not
    # discovered later when a guest is cloned from it.
    verify = bool(getattr(args, "verify_images", False)) or \
        getattr(args, "cmd", "") in ("apply", "upgrade")
    m = ApplianceManifest.load(args.manifest, verify_images=verify)
    if args.policy:
        p = AppliancePolicy.load(args.policy)
    else:
        p = AppliancePolicy.from_manifest(m)
    p.validate_manifest(m)
    return m, p


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="deploy/appliance.py")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--manifest", required=True)
        p.add_argument("--policy", help="pre-rendered policy (default: derive "
                                       "from the manifest)")
        p.add_argument("--verify-images", action="store_true",
                       help="hash every base image before acting")
        p.add_argument("--system-root", default="/",
                       help="filesystem root the installation is applied to; "
                            "any other root is a SANDBOX (no root, no system "
                            "identities, nothing outside that root is touched)")

    pv = sub.add_parser("validate")
    common(pv)
    pv.add_argument("--json", action="store_true")

    pp = sub.add_parser("plan")
    common(pp)
    pp.add_argument("--prefix", default=str(DEFAULT_PREFIX))
    pp.add_argument("--etc", default=str(DEFAULT_ETC))
    pp.add_argument("--json", action="store_true")

    pa = sub.add_parser("apply")
    common(pa)
    pa.add_argument("--prefix", default=str(DEFAULT_PREFIX))
    pa.add_argument("--etc", default=str(DEFAULT_ETC))
    pa.add_argument("--dry-run", action="store_true")

    pvf = sub.add_parser("verify")
    common(pvf)
    pvf.add_argument("--json", action="store_true")

    pf = sub.add_parser("firstboot")
    common(pf)
    pf.add_argument("--json", action="store_true")

    ps = sub.add_parser("status")
    common(ps)
    ps.add_argument("--json", action="store_true")

    pd = sub.add_parser("doctor")
    common(pd)
    pd.add_argument("--json", action="store_true")

    pu = sub.add_parser("upgrade")
    common(pu)
    pu.add_argument("--prefix", default=str(DEFAULT_PREFIX))
    pu.add_argument("--etc", default=str(DEFAULT_ETC))
    pu.add_argument("--payload",
                    help="the release bundle to upgrade to (built by "
                         "deploy/bundle.py; carries the MANIFEST upgrade "
                         "contract and forward migrations)")
    pu.add_argument("--db-url", help="database owner URL (default: "
                                     "$POSTGRES_URL_OWNER)")
    pu.add_argument("--resume", metavar="ATTEMPT",
                    help="resume one specific journaled attempt instead of "
                         "starting new work")
    pu.add_argument("--restore-config", metavar="ATTEMPT",
                    help="config-only restore from an attempt's verified "
                         "backup; issues NO service action — nothing is "
                         "started or resumed")
    pu.add_argument("--pg-dump-bin", help="pg_dump binary or wrapper for the "
                                          "preserving database backup")
    pu.add_argument("--python-exe", help="interpreter used for alembic "
                                         "(default: this interpreter)")
    pu.add_argument("--dry-run", action="store_true")

    pr = sub.add_parser("recovery")
    pr.add_argument("action", choices=("status", "reconcile", "resolve"))
    pr.add_argument("--manifest", required=True)
    pr.add_argument("--policy")
    pr.add_argument("--verify-images", action="store_true")
    pr.add_argument("--obligation", type=int)
    pr.add_argument("--evidence")
    pr.add_argument("--uri", default="qemu:///system")
    pr.add_argument("--allow-tcg", action="store_true")
    pr.add_argument("--fixture", action="store_true")
    pr.add_argument("--json", action="store_true")

    args = ap.parse_args(argv)
    try:
        m, policy = _load(args)
        if args.cmd == "validate":
            data = m.redacted() | {"policy": {
                "node": policy.node, "templates": list(policy.templates),
                "vmid_range": [policy.vmid_min, policy.vmid_max],
                "bridge": policy.bridge, "limits": policy.limits}}
            if args.json:
                print(json.dumps(data, indent=2, sort_keys=True))
            else:
                print(f"manifest/policy valid: {m.installation_id} "
                      f"{m.network.range_cidr} broker {m.broker_socket}")
        elif args.cmd == "plan":
            lay = _layout(args)
            plan = render_files(sandbox_manifest(m, lay.root), layout=lay)
            if args.json:
                print(json.dumps({"actions": plan.actions,
                                  "files": [{"path": str(f.path),
                                             "mode": oct(f.mode)} for f in plan.files]},
                                 indent=2, sort_keys=True))
            else:
                print(plan_document(plan, m), end="")
        elif args.cmd == "apply":
            lay = _layout(args)
            sm = sandbox_manifest(m, lay.root)
            plan = render_files(sm, layout=lay)
            out = apply_plan(sm, plan, layout=lay, dry_run=args.dry_run)
            print(json.dumps(out, indent=2, sort_keys=True))
        elif args.cmd == "upgrade":
            # The preserving in-place upgrade runs through the release
            # engine: journal first, private config + database backups,
            # verified staged payload, per-file atomic activation, proven
            # forward-only migrations, config re-render, version stamp,
            # ordered service reload. Data, keys and the ledger are never
            # deleted or recreated, and unknown in-flight work is refused
            # until it is resolved — never silently.
            from deploy import upgrade as engine
            lay = _layout(args)
            if args.restore_config:
                out = engine.restore_config(m, lay, args.restore_config,
                                            dry_run=args.dry_run)
                print(json.dumps(out, indent=2, sort_keys=True))
                return 0
            if not args.payload:
                ap.error(
                    "upgrade requires --payload (a built release bundle): "
                    "the preserving upgrade backs up, verifies and migrates "
                    "against that artifact; config re-rendering alone is "
                    "`apply`, and calling that an upgrade would be a lie")
            payload = engine.ReleasePayload(pathlib.Path(args.payload))
            db_url = args.db_url or os.environ.get("POSTGRES_URL_OWNER")
            restart_hook = None
            if not lay.sandboxed:
                runner = Runner(dry_run=args.dry_run)

                def restart_hook(units, _r=runner):  # engine contract
                    for unit in units:
                        _r("systemctl", "restart", unit, check=False)
            out = engine.run_upgrade(
                m, lay, payload, db_url=db_url, resume=args.resume,
                dry_run=args.dry_run, python_exe=args.python_exe,
                pg_dump_bin=args.pg_dump_bin, restart_hook=restart_hook)
            print(json.dumps(out, indent=2, sort_keys=True))
        elif args.cmd == "firstboot":
            lay = _layout(args)
            report = firstboot_report(sandbox_manifest(m, lay.root), lay)
            if args.json:
                print(json.dumps(report, indent=2, sort_keys=True))
            else:
                for c in report["checks"]:
                    mark = ("[PEND] " if c.get("pending")
                            else ("[ok]   " if c["ok"] else "[FAIL] "))
                    print(mark + c["check"]
                          + (f" - {c['detail']}" if c["detail"] else ""))
            if report["failed"]:
                return 1
            if report["pending"]:
                print("firstboot PENDING: the operator manual steps "
                      "(network reload, nft apply, service starts) are not "
                      "complete; re-run firstboot after finishing them",
                      file=sys.stderr)
                return 3
            return 0
        elif args.cmd == "verify":
            lay = _layout(args)
            out = verify_install(sandbox_manifest(m, lay.root), lay)
            if args.json:
                print(json.dumps(out, indent=2, sort_keys=True))
            else:
                for d in out.get("drift", []):
                    print(f"[DRIFT] {d['path']}: {d['problem']}")
                print("install verified" if out.get("ok")
                      else f"install drift: {len(out.get('drift', []))} file(s)")
            if not out.get("ok"):
                return 1
        elif args.cmd == "status":
            status(m, as_json=args.json)
        elif args.cmd == "doctor":
            out = doctor(m, as_json=args.json)
            return 0 if out["ok"] else 1
        elif args.cmd == "recovery":
            if args.action == "status":
                out = recovery_status(m)
            elif args.action == "reconcile":
                out = recovery_reconcile(m, policy, uri=args.uri,
                                         allow_tcg=args.allow_tcg,
                                         fixture=args.fixture)
            else:
                if args.obligation is None or not args.evidence:
                    raise InstallError("resolve requires --obligation and --evidence")
                out = recovery_resolve(m, policy, args.obligation,
                                       pathlib.Path(args.evidence),
                                       uri=args.uri, allow_tcg=args.allow_tcg,
                                       fixture=args.fixture)
            print(json.dumps(out, indent=2, sort_keys=True, default=str))
        return 0
    except Exception as exc:  # noqa: BLE001 — CLI must fail with a clear reason
        print(f"appliance installer: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
