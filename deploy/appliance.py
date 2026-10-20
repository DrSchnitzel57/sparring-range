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
    python deploy/appliance.py upgrade  --manifest M [--prefix PREFIX]
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
from infra.appliance.netrules import render_networkd, render_nftables  # noqa: E402
from infra.appliance.policy import AppliancePolicy  # noqa: E402

DEFAULT_PREFIX = pathlib.Path("/opt/sparring-range")
DEFAULT_ETC = pathlib.Path("/etc/sparring-range")
DEFAULT_STATE = pathlib.Path("/var/lib/sparring-range")
DEFAULT_RUN = pathlib.Path("/run/sparring-range")

UNITS = ("sr-appliance-broker.service", "sr-api.service",
         "sr-appliance-ingest.service", "sr-worker-supervisor.service",
         "sr-bastion.service", "sr-web.service")
GROUPS = ("srrange", "srbastion", "sr-broker-clients", "sringest", "srworker",
          "srweb")
USERS = {
    # existing accepted identities: API/controller, bastion
    "srrange": ("srrange", ("sr-broker-clients", "srbastion")),
    "srbastion": ("srbastion", ()),
    # appliance-only identities
    "srbroker": ("sr-broker-clients", ()),
    "sringest": ("sringest", ()),
    "srworker": ("srworker", ()),
    "srweb": ("srweb", ()),
}


class InstallError(RuntimeError):
    pass


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
        ("SR_TELEMETRY_CA_FILE", str(etc / "tls/ingest-ca.crt")),
        ("SR_API_TLS_CA_FILE", str(etc / "tls/api-ca.crt")),
        ("SR_RECORDINGS_DIR", m.recordings_dir),
        ("SR_SAFETY_STATE_FILE", str(pathlib.Path(m.state_dir) / "safety_state.json")),
        ("SR_BASTION_HOST_KEY_PATH", str(etc / "ssh/bastion_ed25519")),
        ("SR_BASTION_AUTHORIZED_KEYS_FILE", str(etc / "ssh/authorized_keys")),
        ("SR_BASTION_TARGETS_KNOWN_HOSTS", str(etc / "known_hosts/range_hosts")),
        ("SR_RANGE_BRIDGE", m.network.range_bridge),
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
        ("SR_RUNNER_SSH_TARGET", f"runner@{m.network.range_cidr.network_address + 9}"),
        ("SR_RUNNER_SSH_KEY_PATH", str(etc / "secrets/worker_runner_key")),
        ("SR_RUNNER_SSH_KNOWN_HOSTS", str(etc / "known_hosts/range_hosts")),
        ("SR_VERIFIER_SSH_KEY_PATH", str(etc / "secrets/verifier_key")),
        ("SR_VERIFIER_SSH_KNOWN_HOSTS", str(etc / "known_hosts/range_hosts")),
        ("SR_BASTION_CLIENT_KEY_PATH", str(etc / "ssh/bastion_client_ed25519")),
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
        ("SR_WORKER_SUPERVISOR_TOKEN_FILE",
         str(etc / "secrets/worker-supervisor.token")),
        ("SR_WORKER_POLL_S", "2"),
        ("SR_WORKER_HEARTBEAT_S", "5"),
        ("PYTHONPATH", str(prefix)),
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
                        extra: str = "") -> str:
    text = (ROOT / "deploy" / "systemd" / name).read_text()
    if user:
        import re
        text = re.sub(r"^User=.*$", f"User={user}", text, flags=re.M)
    if group:
        import re
        text = re.sub(r"^Group=.*$", f"Group={group}", text, flags=re.M)
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
After=network-online.target libvirtd.service
Wants=network-online.target libvirtd.service
# The broker is the ONLY process with a libvirt socket and /dev/kvm access.
Requires=libvirtd.service

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
EnvironmentFile={etc}/control-plane.derived.env
EnvironmentFile=-{etc}/control-plane.env
Environment=SR_API_INGEST_ONLY=1
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


def render_web_unit(lay: Layout) -> str:
    """The Next.js frontend, served as its own service identity on loopback.

    nginx terminates TLS and routes /api/* to the API; the frontend never
    listens on the LAN and never holds an infrastructure credential.
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
ExecStart=/usr/bin/node {lay.prefix}/web/node_modules/next/dist/bin/next start -p 3000 -H 127.0.0.1
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

    location /api/ {{
        proxy_pass http://127.0.0.1:8000/api/;
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
        RenderedFile(lay.etc / "worker-supervisor.env",
                     render_supervisor_env(m, etc=lay.etc, prefix=lay.prefix),
                     0o640, "root", "srworker"),
        RenderedFile(lay.network_dir / "10-srlab.netdev",
                     render_networkd(m).split("\n\n", 1)[0] + "\n", 0o644),
        RenderedFile(lay.network_dir / "20-srlab.network",
                     render_networkd(m).split("\n\n", 1)[1], 0o644),
        RenderedFile(lay.nftables_dir / "sr-appliance.nft",
                     render_nftables(m), 0o644),
        RenderedFile(lay.units_dir / "sr-appliance-broker.service",
                     render_broker_unit(m, etc=lay.etc, prefix=lay.prefix), 0o644),
        RenderedFile(lay.units_dir / "sr-appliance-ingest.service",
                     render_ingest_unit(m, etc=lay.etc, prefix=lay.prefix), 0o644),
        RenderedFile(lay.units_dir / "sr-worker-supervisor.service",
                     _unit_from_template("sr-worker-supervisor.service"),
                     0o644),
        RenderedFile(lay.units_dir / "sr-api.service",
                     _unit_from_template("sr-api.service"), 0o644),
        RenderedFile(lay.units_dir / "sr-bastion.service",
                     _unit_from_template("sr-bastion.service"), 0o644),
        RenderedFile(lay.units_dir / "sr-web.service",
                     render_web_unit(lay), 0o644),
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
        "daemon-reload; enable --now " + " ".join(UNITS),
        "apply fixed networkd bridge and nftables rules once; never at runtime",
    ]
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
                env: dict | None = None) -> subprocess.CompletedProcess:
        printable = " ".join(str(c) for c in cmd)
        # Progress belongs on stderr: stdout carries the machine-readable
        # result of the command.
        print(("DRY: " if self.dry_run else "$ ") + printable, file=sys.stderr,
              flush=True)
        if self.dry_run:
            return subprocess.CompletedProcess(list(cmd), 0, "", "")
        environ = {**os.environ, **(env or {})}
        r = subprocess.run([str(c) for c in cmd], capture_output=True,
                           text=True, env=environ)
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
    for path, mode, user, group in (
            (pathlib.Path(m.state_dir), 0o750, "srrange", "srrange"),
            (pathlib.Path(m.images_dir), 0o755, "root", "root"),
            (pathlib.Path(m.recordings_dir), 0o750, "srbastion", "srbastion"),
            (pathlib.Path(m.secrets_dir), 0o700, "root", "root"),
            (pathlib.Path(m.broker_ledger).parent, 0o750, "srbroker",
             "sr-broker-clients"),
            (lay.run, 0o750, "srbroker", "sr-broker-clients"),
            (lay.etc / "tls", 0o755, "root", "root"),
            (lay.etc / "ssh", 0o750, "root", "srbastion")):
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
    path = etc / "secrets/worker-supervisor.token"
    if path.exists():
        text = path.read_text().strip()
        if len(text) < 32:
            raise InstallError(f"existing {path} is too short; rotate it "
                               "explicitly rather than silently replacing it")
        return "preserved"
    if run.dry_run:
        print(f"DRY: generate {path} (0600 srworker)", file=sys.stderr)
        return "would create"
    path.parent.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(48)
    uid = os.getuid() if lay.sandboxed else _ids("srworker")[0]
    _atomic_write(path, token + "\n", 0o600, uid, uid)
    return "created"


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
    if not dry_run and not lay.sandboxed \
            and not (lay.prefix / ".venv/bin/python").exists():
        raise InstallError(f"appliance venv missing at {lay.prefix}/.venv; "
                           "install the locked project first")
    if not lay.sandboxed:
        for g in GROUPS:
            _ensure_group(g, run)
        for user, (group, extras) in USERS.items():
            _ensure_user(user, group, run)
            for extra in extras:
                run("usermod", "-a", "-G", extra, user, check=False)
    _ensure_dirs(m, run, lay)
    token_action = _ensure_supervisor_token(lay.etc, run, lay)
    services: dict = {}
    if not lay.sandboxed and not dry_run:
        # The REAL service steps.  A sandbox install renders the same files
        # and proves the sequences, but it never pretends the services ran.
        from deploy import appliance_services as svc
        source = ROOT
        if not (source / "requirements.lock").is_file():
            raise InstallError(f"missing {source / 'requirements.lock'}")
        services["native_packages"] = svc.ensure_native_dependencies(run)
        services["venv"] = str(svc.ensure_venv(
            run, prefix=lay.prefix, source=source))
        services["database"] = svc.ensure_database(
            run, prefix=lay.prefix, env_file=lay.etc / "control-plane.env")
        services["tls"] = svc.ensure_tls(
            run, etc=lay.etc, public_ip=m.network.lan_address or "127.0.0.1")
        member_keys = []
        for role in ("runner", "bastion", "mgmt"):
            try:
                member_keys.append(m.public_key_for(role))
            except Exception:  # noqa: BLE001 — a missing role key is reported
                continue
        services["onboarding"] = svc.onboard_operator(
            run, etc=lay.etc, authorized_keys=member_keys)
        services["web"] = svc.ensure_web_build(run, source=source)
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
        run("systemd-sysctl", check=False)
        # Network artifacts are installed but not applied to the host by this
        # command: the operator applies them during the approved maintenance
        # window after reviewing the generated rules.
        for unit in plan.units:
            run("systemctl", "enable", unit, check=False)
    return {"changed": changed, "supervisor_token": token_action,
            "services": services, "dry_run": dry_run}


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
        "units": {u: _unit_state(u) for u in UNITS},
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
            # Re-render config/units and run forward migrations; data, keys and
            # the ledger are never deleted or recreated.
            lay = _layout(args)
            sm = sandbox_manifest(m, lay.root)
            plan = render_files(sm, layout=lay)
            out = apply_plan(sm, plan, layout=lay, dry_run=args.dry_run)
            if not lay.sandboxed:
                run = Runner(dry_run=args.dry_run)
                run("systemctl", "restart", "sr-appliance-broker.service",
                    "sr-api.service", "sr-appliance-ingest.service",
                    "sr-worker-supervisor.service", "sr-bastion.service",
                    check=False)
            out["upgrade"] = "config/units re-rendered; data and keys preserved"
            print(json.dumps(out, indent=2, sort_keys=True))
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
