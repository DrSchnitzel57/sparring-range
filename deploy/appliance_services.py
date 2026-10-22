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
import subprocess

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
                    owner_env_file: pathlib.Path | None = None,
                    app_role: str = "sr_app") -> dict:
    """Create the database roles and run the forward migrations as the owner.

    The SCHEMA OWNER credential is deliberately separate from the runtime
    credential: the API, the ingest listener, the bastion and the web service
    all load the operator's ``control-plane.env``, so an owner URL there
    would hand the schema owner to every service.  The owner URL therefore
    lives in its own root-only file (or the environment of a manual run) and
    is used here and nowhere else.

    The URL is parsed, never split on "/" (that would put the credentials
    into the "database name"), and it never appears in a command line or a
    log: it is passed to Alembic through the ENVIRONMENT.
    """
    owner_env_file = owner_env_file or (env_file.parent / "secrets" /
                                        "db-owner.env")
    owner_values = _read_env_file(owner_env_file)
    owner_url = os.environ.get("SR_POSTGRES_URL_OWNER") or \
        owner_values.get("SR_POSTGRES_URL_OWNER") or \
        owner_values.get("POSTGRES_URL_OWNER")
    if not owner_url:
        raise RuntimeError(
            f"no schema-owner database URL: put SR_POSTGRES_URL_OWNER in "
            f"{owner_env_file} (0600, root only). It is used ONLY to run the "
            f"migrations and is never written into a file a service loads.")
    owner = _parse_url(owner_url)
    database = owner["database"]
    app_url = os.environ.get("SR_POSTGRES_URL") or \
        _read_env_file(env_file).get("SR_POSTGRES_URL")
    app = _parse_url(app_url) if app_url else None

    # Roles: the owner owns the schema, the app role is DML-only (the
    # standing grants are installed by the migrations themselves).
    _psql_as_postgres(run, [
        f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname="
        f"'{owner['user']}') THEN CREATE ROLE {owner['user']} LOGIN "
        f"PASSWORD '{owner['password']}'; END IF; END $$;"])
    if app and app["user"] != owner["user"]:
        _psql_as_postgres(run, [
            f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname="
            f"'{app['user']}') THEN CREATE ROLE {app['user']} LOGIN "
            f"PASSWORD '{app['password']}'; END IF; END $$;"])
    # \gexec must not be followed by a semicolon: it is a psql
    # meta-command, not SQL.
    _psql_as_postgres(run, [
        f"SELECT 'CREATE DATABASE {database} OWNER {owner['user']}' "
        f"WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname="
        f"'{database}')\n\\gexec"])

    # Forward migrations, always as the owner, always through the environment.
    alembic = prefix / ".venv/bin/alembic"
    if not alembic.exists():
        raise RuntimeError(f"missing {alembic} — the venv must exist before "
                           "the migrations run")
    run(str(alembic), "upgrade", "head",
        env={"POSTGRES_URL_OWNER": owner_url,
             "DB_APP_ROLE": app_role,
             "PATH": os.environ.get("PATH", "/usr/bin:/bin")})
    return {"database": database, "owner_role": owner["user"],
            "app_role": app_role, "migrated_with_owner_url": True,
            "owner_url_file": str(owner_env_file)}


def _parse_url(url: str) -> dict:
    """Parse a SQLAlchemy/psycopg URL into its parts (never logged)."""
    import urllib.parse

    parsed = urllib.parse.urlsplit(url.replace("postgresql+psycopg2://",
                                               "postgresql://", 1))
    if not parsed.hostname:
        raise RuntimeError("the database URL has no host")
    return {"user": parsed.username or "",
            "password": parsed.password or "",
            "host": parsed.hostname,
            "port": parsed.port or 5432,
            "database": (parsed.path or "/").lstrip("/") or "sparring_range"}


def _psql_as_postgres(run, statements: list[str]) -> None:
    """Run SQL as the local postgres superuser.

    The SQL goes through a temporary file, never a command line: it contains
    the role password and quotes that would not survive a shell.  The file is
    owned by the postgres user and 0600, because psql runs AS postgres: a
    root-only file would be unreadable and the statement would silently do
    nothing.

    The statements are written EXACTLY as given: appending a semicolon would
    turn a psql meta-command (\\gexec) into invalid input.

    A failing statement is an error, never a warning: the installation must
    not continue with roles that were never created.
    """
    import pwd as _pwd
    import tempfile

    try:
        pg = _pwd.getpwnam("postgres")
    except KeyError:
        pg = None
    for statement in statements:
        fd, name = tempfile.mkstemp(prefix="sr-sql-", suffix=".sql")
        try:
            with os.fdopen(fd, "w") as fh:
                fh.write(statement if statement.endswith("\n")
                         else statement + "\n")
            os.chmod(name, 0o600)
            if pg is not None:
                try:
                    os.chown(name, pg.pw_uid, pg.pw_gid)
                except OSError as exc:
                    raise RuntimeError(
                        f"cannot hand the SQL file to the postgres user: "
                        f"{exc}") from exc
            run("su", "postgres", "-c",
                "psql -v ON_ERROR_STOP=1 -d postgres -f "
                + shlex.quote(name), check=True)
        finally:
            try:
                os.unlink(name)
            except OSError:
                pass


def ensure_tls(run, *, etc: pathlib.Path, public_ip: str,
               ingest_sans: str = "") -> dict:
    """Provision the TLS material for the public and ingest planes.

    The existing bootstrap script owns generation: it never regenerates an
    existing identity, and the CA signing key stays root-only.

    ``ingest_sans`` is REQUIRED: without it the bootstrap script skips the
    guest-facing ingest certificate, and the guests can never enroll (the
    script says so and continues).
    """
    tls_dir = etc / "tls"
    ssh_dir = etc / "ssh"
    tls_dir.mkdir(parents=True, exist_ok=True)
    ssh_dir.mkdir(parents=True, exist_ok=True)
    if not ingest_sans.strip():
        raise RuntimeError(
            "no INGEST_SANS: the guest-facing ingest certificate would be "
            "skipped and the guests could never enroll")
    env = {
        "SR_TLS_DIR": str(tls_dir),
        "SR_SSH_DIR": str(ssh_dir),
        "SR_SSH_GROUP": "srbastion",
        "HTTPS_IP": public_ip,
        "INGEST_SANS": ingest_sans,
        "SR_TLS_ROTATE": "0",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    }
    run("bash", str(_bootstrap_script()), env=env)
    return {"tls_dir": str(tls_dir), "ssh_dir": str(ssh_dir),
            "ingest_sans": ingest_sans}


def _bootstrap_script() -> pathlib.Path:
    return pathlib.Path(__file__).resolve().parent / "bootstrap_tls.sh"


def onboard_operator(run, *, etc: pathlib.Path,
                     authorized_keys: list) -> dict:
    """Install the member's public keys for the recording bastion.

    The bastion's loader expects ``<username> <public-key>`` lines: it maps
    a login name to the keys it accepts.  A bare key line would be read as
    the username "ssh-ed25519" and no member could ever authenticate.

    Only PUBLIC keys are written; the private halves stay with their owner.
    ``authorized_keys`` is a list of ``(username, public_key)`` pairs.
    """
    target = etc / "ssh" / "authorized_keys"
    existing = []
    if target.is_file():
        existing = [ln for ln in target.read_text().splitlines() if ln.strip()]
    merged = list(existing)
    seen = set(merged)
    for item in authorized_keys:
        if isinstance(item, str):  # a bare key: refuse, do not guess
            raise RuntimeError(
                "the bastion needs '<username> <public-key>' lines; a bare "
                "key would be registered under the username 'ssh-ed25519'")
        username, key = item
        username = str(username).strip()
        key = str(key).strip()
        if not username or not key:
            continue
        line = f"{username} {key}"
        if line not in seen:
            merged.append(line)
            seen.add(line)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("\n".join(merged) + ("\n" if merged else ""))
    run("chmod", "0640", str(target))
    run("chown", "root:srbastion", str(target))
    return {"authorized_keys": len(merged), "path": str(target),
            "users": sorted({ln.split(" ", 1)[0] for ln in merged})}


# The appliance's own MACHINE credentials: the key pairs the services
# present on the isolated range.  They are the PRIVATE halves of the
# operator's three key pairs (runner, bastion, mgmt) whose PUBLIC halves are
# baked into the guest templates — a key the guests do not accept is not a
# working key, so the private half that goes with the shipped images is the
# one that belongs here.
SERVICE_KEYS = (
    # (name, relative path, owning user, owning group, comment,
    #  the operator key whose private half belongs here)
    ("runner", "secrets/worker_runner_key", "srworker", "srworker",
     "sparring-range-runner", "runner"),
    ("verifier", "secrets/verifier_key", "srrange", "srrange",
     "sparring-range-verifier", "mgmt"),
    ("bastion-client", "ssh/bastion_client_ed25519", "srbastion", "srbastion",
     "sparring-range-bastion-client", "bastion"),
)


def _public_line(path) -> str:
    """The public half of a key file, without the comment."""
    try:
        text = pathlib.Path(path).read_text().strip()
    except OSError:
        return ""
    return text.split()[1] if len(text.split()) > 1 else ""


def _public_half(private_path) -> str:
    """The public half that belongs to a private key file.

    The private key is the authority: ``ssh-keygen -y`` derives the public
    half from it.  A ``.pub`` file next to it is only a hint and is NEVER
    used as a substitute: a CORRUPTED private key would then "match" a
    public half it cannot produce, and the broken pair would be installed
    and accepted again on the next run.  A key that cannot be read is an
    error, not a silent pass.
    """
    out = subprocess.run(["ssh-keygen", "-y", "-f", str(private_path)],
                         capture_output=True, text=True, timeout=30)
    detail = (out.stderr or out.stdout or "").strip()[:200]
    if out.returncode != 0 or not out.stdout.strip():
        raise RuntimeError(
            f"the private key {private_path} cannot be read"
            + (f": {detail}" if detail else ""))
    parts = out.stdout.strip().split()
    if len(parts) < 2:
        raise RuntimeError(f"the private key {private_path} produced no "
                           "public half")
    return parts[1]


def ensure_bastion_token_file(run, *, etc: pathlib.Path,
                              sandboxed: bool = False) -> dict:
    """Provision the file the bastion reads its service token from.

    The token is issued by the API (POST /admin/service_tokens, scope
    "bastion") and is shown once; the operator writes it here. The file is
    created empty and 0600: the bastion refuses to start without a token
    (its callbacks would be refused and no member could authenticate), so an
    empty file fails loudly instead of silently.
    """
    import grp as _grp
    import pwd as _pwd

    # The file lives in the BASTION'S OWN directory (0750 root:srbastion):
    # a secret under the shared secrets directory is unreachable for an
    # identity that is not in sr-secrets, and a 0600 root-owned file is
    # unreadable by the service as well.
    path = etc / "ssh" / "bastion.token"
    path.parent.mkdir(parents=True, exist_ok=True)
    created = False
    if not path.exists():
        path.write_text("")
        created = True
    run("chmod", "0640", str(path), check=False)
    if not sandboxed:
        try:
            uid = _pwd.getpwnam("root").pw_uid
            gid = _grp.getgrnam("srbastion").gr_gid
            run("chown", f"{uid}:{gid}", str(path), check=False)
        except KeyError:
            pass
    return {"path": str(path), "created": created,
            "mode": "0640", "owner": "root:srbastion",
            "note": "put the API's bastion service token in this file "
                    "(POST /admin/service_tokens with scope 'bastion')"}


def ensure_service_keys(run, *, etc: pathlib.Path,
                        sandboxed: bool = False,
                        access_keys: dict | None = None) -> dict:
    """Provision the machine key pairs the services use on the range.

    Each key belongs to the identity that USES it: the runner key is read by
    the worker (srworker), the verifier key by the API (srrange), the bastion
    dial key by the bastion (srbastion).  The files stay 0600 and the PUBLIC
    halves are reported, because the guest templates must be built with those
    public halves.

    When the operator's private half is next to the public key in the
    manifest (the normal case: ``<key>.pub`` and ``<key>``), THAT key is
    installed — it is the one the shipped images accept.  Only when it is
    missing is a fresh pair generated, and then the public half is reported
    so the operator can rebuild the templates with it.

    An existing key is never replaced: the installer preserves it (and its
    ownership) so a rerun cannot break a live installation.
    """
    import grp as _grp
    import pwd as _pwd
    import shutil

    out: dict = {}
    for name, rel, owner, group, comment, principal in SERVICE_KEYS:
        path = etc / rel
        created = False
        source = ""
        public = (access_keys or {}).get(principal)
        expected = _public_line(public) if public else ""
        if path.exists():
            # A RERUN must validate what is already installed: a key that
            # was copied by an earlier, failed run must not be accepted
            # because the file exists.
            installed = _public_half(path)
            if expected and installed != expected:
                raise RuntimeError(
                    f"{path} is not the private half of {public}: the guest "
                    "templates would refuse it")
        else:
            private = None
            if public:
                stem = str(public)[:-4] if str(public).endswith(".pub") \
                    else str(public)
                candidate = pathlib.Path(stem)
                if candidate.is_file():
                    private = candidate
            if private is not None:
                # The private half must belong to the public half the
                # templates have baked in — CHECKED BEFORE THE COPY, so a
                # mismatched pair never reaches the appliance.
                offered = _public_half(private)
                if expected and offered != expected:
                    raise RuntimeError(
                        f"{private} is not the private half of {public}: the "
                        "guest templates would refuse it")
                path.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(private, path)
                os.chmod(path, 0o600)
                source = str(private)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C",
                    comment, "-f", str(path))
                created = True
        try:
            uid = _pwd.getpwnam(owner).pw_uid
            gid = _grp.getgrnam(group).gr_gid
        except KeyError:
            uid = gid = -1
        if uid >= 0 and not sandboxed:
            run("chown", f"{uid}:{gid}", str(path), check=False)
        run("chmod", "0600", str(path), check=False)
        public = ""
        pub_path = pathlib.Path(str(path) + ".pub")
        if pub_path.is_file():
            public = pub_path.read_text().strip()
            run("chmod", "0644", str(pub_path), check=False)
        out[name] = {"path": str(path), "owner": owner, "group": group,
                     "created": created, "public": public,
                     "installed_from": source,
                     # a generated key does not match the shipped templates:
                     # the operator must rebuild them with this public half
                     "template_key_must_be_rebuilt": created}
    return out


def ensure_web_build(run, *, source: pathlib.Path,
                     public_url: str = "") -> dict:
    """Build the frontend from its LOCKED dependencies.

    Next 16 needs a recent Node; the installer refuses an old runtime instead
    of building something that cannot start.

    ``NEXT_PUBLIC_API_URL`` is BAKED INTO the bundle at build time: without
    it the browser would talk to http://localhost:8000 — the operator's own
    machine, not the appliance.  The public URL carries the /api prefix that
    nginx strips again.
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
    api_url = ""
    if public_url:
        api_url = public_url.rstrip("/") + "/api"
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    if api_url:
        env["NEXT_PUBLIC_API_URL"] = api_url
    run("npm", "ci", cwd=str(web), env=env)
    run("npm", "run", "build", cwd=str(web), env=env)
    return {"node": ".".join(str(v) for v in version), "lock": str(lock),
            "next_public_api_url": api_url}


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
