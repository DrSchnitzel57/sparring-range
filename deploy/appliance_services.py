"""Real service provisioning for the appliance installer.

The installer's plan lists what an installation does.  These are the actual
effects, each with a verifiable outcome — the plan must never claim a step
that does not happen:

  * the pinned native packages (libvirt/QEMU, PostgreSQL, nginx, nftables);
  * the LOCKED Python environment for the appliance prefix;
  * the database roles and the forward migrations, run as the OWNER role;
  * the TLS material for the public and ingest planes;
  * the local operator onboarding (the bastion's authorized keys and the
    first operator account hook).

Everything here needs root and is therefore skipped in a sandbox install; the
sandbox still renders the same files, so the install gate can prove the
SEQUENCES without pretending the services ran.
"""
from __future__ import annotations

import os
import pathlib
import shlex

# Pinned by the release.  The appliance needs no Proxmox client, no outer
# token and no hypervisor tooling beyond these.
NATIVE_PACKAGES = (
    "libvirt-daemon-system", "libvirt-daemon-driver-qemu", "libvirt-clients",
    "qemu-system-x86", "qemu-utils", "postgresql", "nginx", "nftables",
    "git", "python3-venv", "python3-dev", "build-essential",
)


def native_packages() -> list[str]:
    return list(NATIVE_PACKAGES)


def ensure_native_dependencies(run) -> list[str]:
    """Install the pinned native packages.  Returns what was installed."""
    run("apt-get", "update", check=False)
    run("apt-get", "install", "-y", "--no-install-recommends",
        *NATIVE_PACKAGES)
    return list(NATIVE_PACKAGES)


def ensure_venv(run, *, prefix: pathlib.Path, source: pathlib.Path) -> pathlib.Path:
    """Create the appliance's Python environment from the LOCKED requirements.

    The lock file is the only source of dependency versions: the installer
    never resolves floating versions, and the application itself is installed
    without dependencies so the lock stays authoritative.
    """
    venv = prefix / ".venv"
    lock = source / "requirements.lock"
    if not lock.is_file():
        raise RuntimeError(f"missing {lock} — the locked dependency set is "
                           "required for an appliance installation")
    if not (venv / "bin/python").exists():
        run("python3", "-m", "venv", str(venv))
    run(str(venv / "bin/pip"), "install", "--upgrade", "pip")
    run(str(venv / "bin/pip"), "install", "-r", str(lock))
    run(str(venv / "bin/pip"), "install", "--no-deps", "-e", str(source))
    return venv


def _read_env_file(path: pathlib.Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip()
    return values


def ensure_database(run, *, prefix: pathlib.Path, env_file: pathlib.Path,
                    app_role: str = "sr_app") -> dict:
    """Create the database roles and run the forward migrations as the owner.

    The OWNER role owns the schema; the APP role is DML-only (migration 0016
    installs the standing grants).  The owner URL is the operator's secret and
    is never rendered into a generated file.
    """
    values = _read_env_file(env_file)
    owner_url = os.environ.get("SR_POSTGRES_URL_OWNER") or values.get(
        "SR_POSTGRES_URL_OWNER", "")
    if not owner_url:
        raise RuntimeError(
            "SR_POSTGRES_URL_OWNER is required to migrate the appliance "
            "database (put it in the operator's control-plane.env)")
    app_url = os.environ.get("SR_POSTGRES_URL") or values.get("SR_POSTGRES_URL", "")
    database = "sparring_range"
    if "/" in owner_url:
        tail = owner_url.split("/", 1)[1]
        database = tail.split("?", 1)[0]

    # Roles and the database: idempotent, and never a password in a log.
    run("su", "postgres", "-c",
        f"psql -v ON_ERROR_STOP=1 -d postgres -tAc \"SELECT 1 FROM pg_roles "
        f"WHERE rolname='{app_role}'\" | grep -q 1 || psql -v ON_ERROR_STOP=1 "
        f"-d postgres -c \"CREATE ROLE {app_role} LOGIN\"",
        check=False)
    run("su", "postgres", "-c",
        f"psql -v ON_ERROR_STOP=1 -d postgres -tAc \"SELECT 1 FROM pg_database "
        f"WHERE datname='{database}'\" | grep -q 1 || psql -v ON_ERROR_STOP=1 "
        f"-d postgres -c \"CREATE DATABASE {database} OWNER "
        f"{_owner_role(owner_url)}\"",
        check=False)
    # Forward migrations, always as the owner.
    alembic = prefix / ".venv/bin/alembic"
    if not alembic.exists():
        raise RuntimeError(f"missing {alembic} — the venv must exist before "
                           "the migrations run")
    run(str(alembic), "upgrade", "head",
        env={"SR_POSTGRES_URL_OWNER": owner_url,
             "SR_POSTGRES_URL": app_url or owner_url,
             "DB_APP_ROLE": app_role,
             "PATH": os.environ.get("PATH", "/usr/bin:/bin")})
    return {"database": database, "app_role": app_role,
            "migrated_with_owner_url": True}


def _owner_role(url: str) -> str:
    """The role name inside a SQLAlchemy URL (no password ever leaves here)."""
    tail = url.split("://", 1)[-1]
    userinfo = tail.split("@", 1)[0]
    return userinfo.split(":", 1)[0] or "sr_owner"


def ensure_tls(run, *, etc: pathlib.Path, public_ip: str) -> dict:
    """Provision the TLS material for the public and ingest planes.

    The existing bootstrap script owns generation: it never regenerates an
    existing identity, and the CA signing key stays root-only.
    """
    tls_dir = etc / "tls"
    ssh_dir = etc / "ssh"
    tls_dir.mkdir(parents=True, exist_ok=True)
    ssh_dir.mkdir(parents=True, exist_ok=True)
    env = {
        "SR_TLS_DIR": str(tls_dir),
        "SR_SSH_DIR": str(ssh_dir),
        "SR_SSH_GROUP": "srbastion",
        "HTTPS_IP": public_ip,
        "SR_TLS_ROTATE": "0",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    }
    run("bash", str(_bootstrap_script()), env=env)
    return {"tls_dir": str(tls_dir), "ssh_dir": str(ssh_dir)}


def _bootstrap_script() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parent / "bootstrap_tls.sh"


def onboard_operator(run, *, etc: pathlib.Path, authorized_keys: list[str]) -> dict:
    """Install the member's public keys for the recording bastion.

    Only PUBLIC keys are written; the private halves stay with their owner.
    """
    target = etc / "ssh" / "authorized_keys"
    existing = []
    if target.is_file():
        existing = [ln for ln in target.read_text().splitlines() if ln.strip()]
    merged = list(existing)
    for key in authorized_keys:
        key = key.strip()
        if key and key not in merged:
            merged.append(key)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(merged) + ("\n" if merged else ""))
    run("chmod", "0640", str(target))
    run("chown", "root:srbastion", str(target))
    return {"authorized_keys": len(merged), "path": str(target)}


def ensure_web_build(run, *, source: pathlib.Path) -> dict:
    """Build the frontend from its LOCKED dependencies.

    Next 16 needs a recent Node; the installer refuses an old runtime instead
    of building something that cannot start.
    """
    web = source / "web"
    lock = web / "package-lock.json"
    if not lock.is_file():
        raise RuntimeError(f"missing {lock} — the frontend lock file is "
                           "required for an appliance installation")
    version = _node_version()
    if version is None:
        raise RuntimeError("node is not installed — the appliance needs Node "
                           "20.9 or newer for the frontend build")
    if version < (20, 9):
        raise RuntimeError(f"node {version[0]}.{version[1]} is too old — the "
                           "frontend needs Node 20.9 or newer")
    run("npm", "ci", cwd=str(web))
    run("npm", "run", "build", cwd=str(web))
    return {"node": ".".join(str(v) for v in version), "lock": str(lock)}


def _node_version() -> tuple[int, int] | None:
    try:
        import subprocess
        out = subprocess.run(["node", "--version"], capture_output=True,
                             text=True, timeout=30).stdout.strip()
        parts = out.lstrip("v").split(".")
        return (int(parts[0]), int(parts[1]))
    except Exception:  # noqa: BLE001 — a missing node is reported, not guessed
        return None


def quote_all(args) -> str:
    return " ".join(shlex.quote(str(a)) for a in args)
