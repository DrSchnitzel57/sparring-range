"""Real service provisioning for the appliance installer.

The installer's plan lists what an installation does.  These are the actual
effects, each with a verifiable outcome — the plan must never claim a step
that does not happen:

  * the pinned native packages (libvirt/QEMU, PostgreSQL, nginx, nftables,
    the distro libvirt Python bindings, and a Node runtime that satisfies
    the frontend);
  * the LOCKED Python environment for the appliance prefix, WITH the narrow
    same-ABI native binding exposure the broker needs and with per-service
    execution actually verified (not inferred from Type=exec uptime);
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
import shutil
import subprocess
import tempfile

# Pinned by the release.  The appliance needs no Proxmox client, no outer
# token and no hypervisor tooling beyond these.  python3-libvirt is the
# broker's ONLY libvirt binding (plan 18: it was missing, and the isolated
# venv cannot see the distro module without the narrow exposure below);
# curl/ca-certificates/xz-utils serve the pinned Node provisioning.
NATIVE_PACKAGES = (
    "libvirt-daemon-system", "libvirt-daemon-driver-qemu", "libvirt-clients",
    "python3-libvirt", "qemu-system-x86", "qemu-utils", "postgresql",
    "nginx", "nftables", "git", "python3-venv", "python3-dev",
    "build-essential", "acl", "curl", "ca-certificates", "xz-utils",
)

# The frontend's floor (package.json engines) and the runtime the appliance
# provisions when the distro one is older.  Ubuntu 24.04 ships Node 18
# (18.19.1); Next 16 needs >= 20.9 (live find 2026-10-23: the operator had
# to install Node 22 by hand mid-hand-off).  Pinned, checksum-verified,
# installed under /usr/local — the distro package is never fought over.
NODE_MIN_VERSION = (20, 9)
NODE_PIN_VERSION = "22.23.4"
NODE_PIN_SHA256_LINUX_X64 = (
    "1805bcd35e6815559bd2eb97db438d3fdb0eb3a5e6a977b7c1badca76337e9ce")
NODE_URL_TEMPLATE = ("https://nodejs.org/dist/v{version}/"
                     "node-v{version}-linux-x64.tar.xz")
# Explicit runtime mode for the Node provisioning (plan 18: no silent
# network dependency during an installation):
#   auto     — keep a new-enough node, otherwise provision the pinned one
#   require  — NEVER provision; refuse when the runtime is too old (the
#              operator supplies Node out of band)
#   provision— always install the pinned runtime, even if node is new
NODE_MODE_ENV = "SR_APPLIANCE_NODE_MODE"

# The distro modules the broker imports, and the binary module each one
# loads (python3-libvirt ships libvirt.py + libvirtmod.<abi>.so and
# libvirt_qemu.py + libvirtmod_qemu.<abi>.so — the names do not follow one
# mechanical rule, so the pairing is explicit, not derived).
NATIVE_BINDINGS = (("libvirt", "libvirtmod"),
                   ("libvirt_qemu", "libvirtmod_qemu"))
DIST_PACKAGES = pathlib.Path("/usr/lib/python3/dist-packages")


def native_packages() -> list[str]:
    return list(NATIVE_PACKAGES)


def ensure_native_dependencies(run) -> list[str]:
    """Install the pinned native packages.  Returns what was installed."""
    run("apt-get", "update", check=False)
    run("apt-get", "install", "-y", "--no-install-recommends",
        *NATIVE_PACKAGES)
    return list(NATIVE_PACKAGES)


def _node_version() -> tuple[int, int] | None:
    try:
        out = subprocess.run(["node", "--version"], capture_output=True,
                             text=True, timeout=30).stdout.strip()
        parts = out.lstrip("v").split(".")
        return (int(parts[0]), int(parts[1]))
    except Exception:  # noqa: BLE001 — a missing node is reported, not guessed
        return None


def _node_at(binary: str) -> tuple[int, int] | None:
    """Version of one EXPLICIT binary — the same question the unit will
    answer at ExecStart time, never a PATH-dependent guess."""
    try:
        out = subprocess.run([binary, "--version"], capture_output=True,
                             text=True, timeout=30).stdout.strip()
        parts = out.lstrip("v").split(".")
        return (int(parts[0]), int(parts[1]))
    except Exception:  # noqa: BLE001 — absent/unusable binary is not a runtime
        return None


def dedicated_node_binary() -> str:
    """The pinned runtime's own binary — the appliance NEVER depends on,
    and never overwrites, another application's /usr/local/bin/node."""
    return (f"/usr/local/lib/nodejs/node-v{NODE_PIN_VERSION}-linux-x64"
            "/bin/node")


def node_runtime_plan(mode: str | None = None, *,
                      candidates: tuple[str, ...] | None = None,
                      probe=None) -> dict:
    """ONE explicitly selected Node runtime for the whole appliance
    (second review, finding 5): the frontend build, the ACTUAL service
    ExecStart and the per-UID identity verification must all name the
    SAME supported binary. A path constant baked into a unit template is
    not a runtime selection — provisioning Node 22 while the unit still
    exec'd the distro's Node 18 rendered a green installer next to a
    frontend that could never start.

    ``provision`` mode → always the dedicated pinned runtime. Otherwise
    the first candidate (dedicated pinned binary, then /usr/local/bin,
    then /usr/bin) that ACTUALLY reports a supported version is kept;
    when none does, ``require`` refuses and ``auto`` provisions.
    ``candidates``/``probe`` are the fixture seam so the selection is
    testable without mutating the real filesystem."""
    probe = probe or _node_at
    mode = (mode if mode is not None
            else os.environ.get(NODE_MODE_ENV) or "auto").strip().lower()
    if mode not in ("auto", "require", "provision"):
        raise RuntimeError(
            f"{NODE_MODE_ENV}={mode!r} is not one of auto|require|provision")
    dedicated = dedicated_node_binary()
    if mode != "provision":
        for cand in (candidates
                     or (dedicated, "/usr/local/bin/node", "/usr/bin/node")):
            version = probe(cand)
            if version and version >= NODE_MIN_VERSION:
                return {"mode": mode, "action": "kept", "binary": cand,
                        "version": version}
        if mode == "require":
            raise RuntimeError(
                "no candidate runtime satisfies the frontend floor "
                f"{node_version_str(NODE_MIN_VERSION)}; "
                f"{NODE_MODE_ENV}=require forbids provisioning — install a "
                "supported Node out of band and re-run")
    return {"mode": mode, "action": "provision", "binary": dedicated}


def node_version_str(version) -> str:
    return ".".join(str(v) for v in version)


def node_action(mode: str | None, version: tuple[int, int] | None) -> str:
    """Pure runtime-mode decision: 'kept' | 'require' | 'provision'."""
    mode = (mode or "auto").strip().lower()
    if mode not in ("auto", "require", "provision"):
        raise RuntimeError(
            f"{NODE_MODE_ENV}={mode!r} is not one of auto|require|provision")
    recent = version is not None and version >= NODE_MIN_VERSION
    if mode == "provision":
        return "provision"
    if recent:
        return "kept"
    if mode == "require":
        raise RuntimeError(
            f"node {'is missing' if version is None else '.'.join(map(str, version))} "
            f"does not satisfy the frontend floor {'.'.join(map(str, NODE_MIN_VERSION))}; "
            f"{NODE_MODE_ENV}=require forbids provisioning — install a supported "
            "Node (20.9+) out of band and re-run")
    return "provision"


def ensure_node_runtime(run, *, mode: str | None = None) -> dict:
    """Guarantee the appliance's SELECTED Node runtime actually exists and
    satisfies the frontend floor.

    Ubuntu 24.04's Node (18.19.1) is older than Next 16's floor; the pinned
    LTS is downloaded, SHA-256 verified against the release-pinned digest,
    and installed under /usr/local/lib/nodejs.  Nothing is fetched when a
    real candidate already satisfies, and the mode makes even that
    dependency explicit (require = operator's job).  The /usr/local/bin
    symlinks are operator CONVENIENCE only and never clobber a foreign
    binary — the appliance unit execs the selected binary path directly
    (second review, finding 5).
    """
    plan = node_runtime_plan(mode)
    if plan["action"] == "kept":
        return {"node": "kept", "version": plan["version"],
                "binary": plan["binary"]}
    version = NODE_PIN_VERSION
    url = NODE_URL_TEMPLATE.format(version=version)
    digest = NODE_PIN_SHA256_LINUX_X64
    install_dir = f"/usr/local/lib/nodejs/node-v{version}-linux-x64"
    if not os.path.isdir(install_dir):
        # PRIVATE staging (review finding): a predictable shared-temp path
        # downloaded AS ROOT before verification is a symlink/overwrite and
        # cross-application collision hazard — another app's runtime file
        # (or a planted symlink) must never be what curl writes through or
        # sha256sum reads.  mkdtemp is 0700, owned by this invocation and
        # unguessable; the staging dir is removed whatever happens.
        staging = tempfile.mkdtemp(prefix="sr-node-")
        os.chmod(staging, 0o700)
        tarball = os.path.join(staging, f"node-v{version}-linux-x64.tar.xz")
        try:
            run("curl", "-fsSL", "--retry", "3", "-o", tarball, url)
            # Integrity BEFORE extraction: a corrupted or substituted
            # archive never touches the filesystem.  The digest is
            # release-pinned, so a fetch from an untrusted mirror cannot
            # change what is installed.
            check = run("sha256sum", tarball, check=False)
            actual = (check.stdout or "").split()[0] if check.stdout else ""
            if check.returncode != 0 or actual != digest:
                raise RuntimeError(
                    f"node download failed integrity: expected {digest}, "
                    f"got {actual or 'unreadable'} for {url}")
            run("mkdir", "-p", "/usr/local/lib/nodejs")
            run("tar", "-xJf", tarball, "-C", "/usr/local/lib/nodejs")
        finally:
            shutil.rmtree(staging, ignore_errors=True)
    for name in ("node", "npm", "npx"):
        link = f"/usr/local/bin/{name}"
        target = f"{install_dir}/bin/{name}"
        if os.path.islink(link):
            # refresh OUR symlink; a foreign one (another application's
            # runtime) is never replaced — the appliance unit execs the
            # selected binary path directly, so it needs none of these.
            if not os.readlink(link).startswith("/usr/local/lib/nodejs/"):
                continue
        elif os.path.exists(link):
            continue
        run("ln", "-sfn", target, link)
    # Verify the SELECTED runtime (what the unit will exec), not whatever
    # PATH happens to resolve.  When the dedicated tree really exists its
    # own report is the only acceptable answer; the PATH probe remains the
    # fallback for fixture/sandbox runs that record commands instead of
    # executing them.
    binary = plan["binary"]
    after = _node_at(binary) if os.path.exists(binary) else _node_version()
    if after is None or after < NODE_MIN_VERSION:
        raise RuntimeError(
            f"selected runtime {binary!r} still reports {after!r}; it does "
            f"not satisfy the frontend floor {node_version_str(NODE_MIN_VERSION)}")
    return {"node": "provisioned", "version": after, "pinned": version,
            "binary": binary, "sha256_verified": digest}


def _venv_paths(venv: pathlib.Path) -> dict[str, str]:
    """Ask the venv's own interpreter where its modules live and what ABI
    tag it expects.  The answer comes from the interpreter, never from the
    installer's python, so the ABI check compares like with like."""
    probe = (
        "import json, sys, sysconfig\n"
        "print(json.dumps({"
        "'purelib': sysconfig.get_paths()['purelib'],"
        "'cache_tag': sys.implementation.cache_tag,"
        "'executable': sys.executable}))\n"
    )
    out = subprocess.run([str(venv / "bin/python"), "-c", probe],
                         capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        raise RuntimeError(f"cannot interrogate {venv}/bin/python: "
                           f"{(out.stderr or out.stdout)[-300:]}")
    import json
    return json.loads(out.stdout)


def _expose_native_bindings(run, venv: pathlib.Path) -> dict:
    """Narrowly expose the distro libvirt bindings inside the venv (plan 18).

    The broker unit runs the venv python and imports libvirt; the venv is
    deliberately NOT created with --system-site-packages (that would hand
    every distro module — and every future distro-module CVE surface — to
    every appliance service).  Instead exactly the binding modules are
    exposed, and only when the distro binary module's ABI tag matches the
    venv's own cache tag: a mismatched libvirtmod would fail at import with
    a confusing undefined-symbol, so a mismatch is refused with the exact
    remediation instead.
    """
    paths = _venv_paths(venv)
    purelib = pathlib.Path(paths["purelib"])
    cache_tag = paths["cache_tag"]  # e.g. cpython-312
    if not DIST_PACKAGES.is_dir():
        raise RuntimeError(
            f"{DIST_PACKAGES} is missing — install python3-libvirt")
    exposed: dict[str, list[str]] = {}
    for module, stem in NATIVE_BINDINGS:
        pure = DIST_PACKAGES / f"{module}.py"
        if not pure.is_file():
            raise RuntimeError(
                f"{pure} is missing — install python3-libvirt (the broker's "
                "only libvirt binding); the venv stays isolated otherwise")
        binaries = sorted(DIST_PACKAGES.glob(f"{stem}.{cache_tag}-*.so"))
        if not binaries:
            raise RuntimeError(
                f"no {stem} binary module for ABI tag {cache_tag!r} in "
                f"{DIST_PACKAGES} — python3-libvirt was built for a different "
                "Python; install the build matching the appliance venv python")
        targets = [pure] + binaries
        for source in targets:
            target = purelib / source.name
            if target.is_symlink():
                if target.readlink() == str(source):
                    continue
                target.unlink()
            elif target.exists():
                # A REAL file inside the venv belongs to the venv; never
                # silently replace what pip installed.
                continue
            target.symlink_to(source)
        exposed[module] = [t.name for t in targets]
    # Prove it: the venv python must actually import both modules now.  An
    # exposure that does not import is an installation failure, not a
    # runtime surprise.
    imp = "import " + ", ".join(m for m, _ in NATIVE_BINDINGS)
    run(str(venv / "bin/python"), "-c", imp)
    return {"cache_tag": cache_tag, "exposed": exposed,
            "dist_packages": str(DIST_PACKAGES)}


def verify_service_runtime(run, venv: pathlib.Path, *,
                           node_binary: str | None = None) -> dict:
    """Verify the RUNTIME, per real UID: each service identity must be able
    to execute what its unit will exec (plan 18; live find 2026-10-23: a
    hand-off run under umask 027 produced a root-only 0750 .venv and every
    unit but root's died with status=203/EXEC — service uptime was checked,
    per-UID execution never was).

    This makes the checks real: runuser executes as the actual identity.
    A failure names the identity and the exact remediation.  For srweb
    the probed binary is EXACTLY the one the web unit execs (the selected
    appliance runtime), never a PATH-dependent stand-in — otherwise a
    passing probe could certify a different binary than the service runs
    (second review, finding 5)."""
    problems: list[str] = []
    results: dict[str, str] = {}
    python = str(venv / "bin/python")
    for user in ("srrange", "srbroker", "sringest", "srworker", "srbastion",
                 "srweb"):
        probe = [python, "-c", "pass"]
        code = run("runuser", "-u", user, "--", *probe, check=False).returncode
        if code != 0:
            problems.append(
                f"{user} cannot execute {python} (exit {code}) — systemd "
                "would fail with 203/EXEC; run "
                f"`chmod a+rX` on the parent directories of {venv}")
        results[user] = "exec" if code == 0 else f"exit {code}"
    # the broker additionally imports its libvirt binding, as its own UID
    code = run("runuser", "-u", "srbroker", "--", python, "-c",
               "import libvirt, libvirt_qemu", check=False).returncode
    if code != 0:
        problems.append(
            f"srbroker cannot import libvirt in {venv} (exit {code}) — the "
            "native binding exposure failed")
    results["srbroker/libvirt"] = "import" if code == 0 else f"exit {code}"
    node = node_binary or node_runtime_plan()["binary"]
    code = run("runuser", "-u", "srweb", "--", node, "--version",
               check=False).returncode
    if code != 0:
        problems.append(f"srweb cannot execute {node} (exit {code})")
    results["srweb/node"] = "exec" if code == 0 else f"exit {code}"
    if problems:
        raise RuntimeError("service runtime verification failed:\n  - "
                           + "\n  - ".join(problems))
    return {"uid_checks": results, "node_binary": node}


def _create_venv(run, venv: pathlib.Path) -> None:
    """Create the venv with a REAL interpreter backend, in priority order:
    the distro ``python3 -m venv`` (the appliance contract — the native
    package list carries ``python3-venv``), else ``uv venv --seed`` for
    hosts whose only Python came with uv (development/CI machines built
    this way); both produce a pip-bearing venv. No silent third option:
    a host with neither gets the exact missing package named."""
    probe = subprocess.run(["python3", "-c", "import ensurepip"],
                           capture_output=True, text=True, timeout=60)
    if probe.returncode == 0:
        run("python3", "-m", "venv", str(venv))
        return
    uv = shutil.which("uv")
    if uv:
        run(uv, "venv", "--seed", str(venv))
        return
    raise RuntimeError(
        "cannot create a Python venv: python3 lacks ensurepip "
        "(install the python3-venv package) and uv is not present — the "
        "appliance will not fabricate an environment it cannot build")


def ensure_venv(run, *, prefix: pathlib.Path, source: pathlib.Path,
                broker_bindings: bool = True) -> pathlib.Path:
    """Create the appliance's Python environment from the LOCKED requirements.

    The lock file is the only source of dependency versions: the installer
    never resolves floating versions, and the application itself is installed
    without dependencies so the lock stays authoritative.  Two runtime
    contracts are then enforced (plan 18), because a rendered unit is not a
    process:

    * the venv tree must be traversable and readable BY THE SERVICE UIDS —
      created under the caller's umask it was 0750 root-only and every
      unit died 203/EXEC — so creation runs under an explicit 0o022 umask,
      the tree is opened with a+rX (never write), and per-UID execution is
      actually verified;
    * the broker's libvirt binding is exposed narrowly (same ABI, named
      modules only), not by enabling system site packages.
    """
    venv = prefix / ".venv"
    lock = source / "requirements.lock"
    if not lock.is_file():
        raise RuntimeError(f"missing {lock} — the locked dependency set is "
                           "required for an appliance installation")
    if not (venv / "bin/python").exists():
        old = os.umask(0o022)
        try:
            _create_venv(run, venv)
        finally:
            os.umask(old)
    run(str(venv / "bin/pip"), "install", "--upgrade", "pip")
    run(str(venv / "bin/pip"), "install", "-r", str(lock))
    run(str(venv / "bin/pip"), "install", "--no-deps", "-e", str(source))
    # Read/execute for every identity (never write): the venv contains no
    # secret — credentials live under /etc and /var state with their own
    # ownership. This is the exact, narrow repair for the umask-027 203/EXEC
    # failure; it is deliberately NOT applied to anything else.
    run("chmod", "-R", "a+rX", str(venv))
    if broker_bindings:
        # the broker unit imports libvirt from this venv; a sandbox has no
        # broker and no host libvirt, and faking the binding there would
        # prove nothing (the appliance install keeps this REQUIRED)
        _expose_native_bindings(run, venv)
    return venv


#: Environment variables that carry OWNER/SECRET database credentials.
#: They are stripped from the INHERITED environment of every privileged
#: child (round-3 finding 5: the owner URL an operator exported in the
#: upgrade shell was inherited by venv-build, frontend and native helper
#: processes for no reason). A call site that AUTHORIZES a channel passes
#: the variable explicitly in ``env=`` — explicit wins, ambient never.
OWNER_ONLY_ENV = frozenset({
    "POSTGRES_URL_OWNER",
    "SR_POSTGRES_URL_OWNER",
    "SR_PG_UPGRADE_URL",
    "SR_PG_SECRET_URL",
    "PGPASSWORD",
    "PGPASSFILE",
})


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


def _write_secret_file_securely(path: pathlib.Path, content: str) -> None:
    """Round-3 finding 6: a secret file must never EXIST with loose
    permissions, not even for the microseconds between write and chmod
    (the previous ``write_text`` + ``chmod/chown check=False`` had
    exactly that window and failed SILENTLY when securing failed).
    Contract: create with ``O_CREAT|O_EXCL`` mode 0600 from the first
    byte, fsync, then rename atomically into place. There is no window
    where a permissive file holds the secret, and a failed securing or
    rename raises — fail closed, never a half-protected credential.
    """
    import os
    tmp = path.with_name(path.name + f".tmp.{os.getpid()}")
    fd = None
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.write(fd, content.encode())
        os.fsync(fd)
        os.close(fd)
        fd = None
        # atomic publish that NEVER replaces an existing destination:
        # a credential file is either created here or nothing happens
        try:
            os.link(tmp, path)
        except FileExistsError as exc:
            raise RuntimeError(
                f"{path} already exists — refusing to overwrite an "
                "existing credential file") from exc
        os.unlink(tmp)
        # directory entry durability: after a crash the file is either
        # fully there or not at all
        dfd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except Exception as exc:  # noqa: BLE001 — fail closed, loudly
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise RuntimeError(
            f"could not provision {path} with restrictive permissions — "
            f"refusing to leave a credential unprotected: {exc}") from exc


def _verify_secret_file(path: pathlib.Path, *, sandboxed: bool) -> int:
    """Post-write verification AND drift repair toward the hard floor:
    0600, and on a real (non-sandboxed, root) install also root:root.
    A file that cannot be secured raises; nothing downstream may proceed
    with a readable credential-store URL on disk."""
    import os
    st = path.stat()
    mode = st.st_mode & 0o777
    if mode & 0o077:
        os.chmod(path, 0o600)
        mode = 0o600
    if mode != 0o600:
        raise RuntimeError(f"{path} must be exactly 0600, got {oct(mode)}")
    if not sandboxed and os.geteuid() == 0:
        if st.st_uid != 0 or st.st_gid != 0:
            os.chown(path, 0, 0)
        st = path.stat()
        if st.st_uid != 0 or st.st_gid != 0:
            raise RuntimeError(f"{path} must be owned by root:root")
    return mode


def ensure_database(run, *, prefix: pathlib.Path, env_file: pathlib.Path,
                    owner_env_file: pathlib.Path | None = None,
                    app_role: str = "sr_app",
                    secret_role: str = "sr_secret",
                    sandboxed: bool = False) -> dict:
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

    Round-2 finding 10: the credential-store identity (migration 0021
    GRANTs to it — the migration FAILS if the role does not exist) is
    provisioned HERE, not left as manual SQL the operator must have run
    before the migration. A fresh install gets a generated password in
    the API-only file ``secrets/db-secret.env`` — 0600 root:root, created
    atomically with restrictive permissions and verified (round-3
    finding 6). systemd loads it as root for sr-api.service ONLY; no
    service USER — ingest, bastion, worker, web — may read it, and the
    operator's control-plane.env is not its home either. An existing
    file or an explicit ``SR_PG_SECRET_URL`` in the environment is
    honored, and the role is created from it.
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

    # --- the credential-store identity (plan 19 secret contract) ------
    secret_env_file = env_file.parent / "secrets" / "db-secret.env"
    secret_url = os.environ.get("SR_PG_SECRET_URL") or \
        _read_env_file(secret_env_file).get("SR_PG_SECRET_URL")
    secret_generated = secret_url is None
    if secret_generated:
        if getattr(run, "dry_run", False):
            secret_url = (f"postgresql+psycopg2://{secret_role}:"
                          f"<generated>@{owner['host']}:{owner['port']}/"
                          f"{database}")  # placeholder: never used, never
                                          # written on a dry run
        else:
            import secrets as _secrets
            secret_url = (f"postgresql+psycopg2://{secret_role}:"
                          f"{_secrets.token_urlsafe(24)}@"
                          f"{owner['host']}:{owner['port']}/{database}")
    secret = _parse_url(secret_url)
    _psql_as_postgres(run, [
        f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname="
        f"'{secret['user']}') THEN CREATE ROLE {secret['user']} LOGIN "
        f"PASSWORD '{secret['password']}';"
        f"ELSIF '{str(secret_generated).lower()}' = 'true' THEN "
        f"ALTER ROLE {secret['user']} WITH LOGIN "
        f"PASSWORD '{secret['password']}'; END IF; END $$;"])
    # An operator-PROVIDED URL never overwrites the file's content, and a
    # dry run never writes anything; a GENERATED password must reach the
    # API through its file — and (round-3 finding 6) that file is 0600
    # root:root: systemd reads EnvironmentFile as ROOT before dropping
    # privileges, so NO service user must be able to read it. Group
    # access is exactly what leaked the URL toward the ingest identity
    # before; ownership/mode are verified (and repaired toward the floor)
    # after every install, and a file that cannot be secured aborts the
    # install — fail closed, no check=False wishes. (If the role already
    # existed, the ALTER above realigned it — the file and the role are
    # then consistent, which is what a rerun after a lost file needs.)
    if not getattr(run, "dry_run", False):
        secret_env_file.parent.mkdir(parents=True, exist_ok=True)
        if not secret_env_file.exists():
            _write_secret_file_securely(secret_env_file, (
                "# API-only identity for the provider-credential table "
                "ONLY\n# (migration 0021 onward). systemd loads it as "
                "root for\n# sr-api.service ONLY — no service USER may "
                "read this file:\n# 0600 root:root, delivered through "
                "the unit environment.\n"
                f"SR_PG_SECRET_URL={secret_url}\n"))
        _verify_secret_file(secret_env_file, sandboxed=sandboxed)

    # Forward migrations, always as the owner, always through the environment.
    alembic = prefix / ".venv/bin/alembic"
    if not alembic.exists():
        raise RuntimeError(f"missing {alembic} — the venv must exist before "
                           "the migrations run")
    run(str(alembic), "upgrade", "head",
        env={"POSTGRES_URL_OWNER": owner_url,
             "DB_APP_ROLE": app_role,
             "DB_SECRET_ROLE": secret["user"],
             "PATH": os.environ.get("PATH", "/usr/bin:/bin")})
    return {"database": database, "owner_role": owner["user"],
            "app_role": app_role, "migrated_with_owner_url": True,
            "owner_url_file": str(owner_env_file),
            "secret_role": secret["user"],
            "secret_url_file": str(secret_env_file),
            "secret_role_generated": bool(secret_generated),
            "secret_url_in_returned_data": False}


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
        "SR_INGEST_GROUP": "sringest",
        "HTTPS_IP": str(public_ip),
        "INGEST_SANS": ingest_sans,
        "SR_TLS_ROTATE": "0",
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    }
    run("bash", str(_bootstrap_script()), env=env)
    problems, deferred = tls_readiness_problems(etc)
    if problems:
        raise RuntimeError("TLS material is not service-readable: "
                           + "; ".join(problems))
    return {"tls_dir": str(tls_dir), "ssh_dir": str(ssh_dir),
            "ingest_sans": ingest_sans,
            "tls_readability": "verified",
            "tls_readability_deferred": deferred}


# The trust map every service unit was rendered against: (identity, files)
# that identity must be able to READ with its real uid/gid — not root's.
TLS_TRUST_MAP: tuple[tuple[str, tuple[str, ...]], ...] = (
    # the ingest listener terminates TLS for enrolled guests
    ("sringest", ("ingest-server.key", "ingest-server.crt", "api-ca.crt")),
    # the API pins its telemetry + API-plane anchors
    ("srrange", ("api-ca.crt", "https.crt", "ca.crt")),
    # the bastion pins the API surface it reports to (nginx's https.crt)
    ("srbastion", ("api-ca.crt", "https.crt")),
    # the frontend's proxy and the web identity need no TLS material
)


def _service_membership(name: str) -> tuple[int, int, set[int]] | None:
    """(uid, gid, groups) of a service identity, or None when the identity
    does not exist on this machine (sandbox install, dev box)."""
    import grp
    import pwd
    try:
        pw = pwd.getpwnam(name)
    except KeyError:
        return None
    groups = {g.gr_gid for g in grp.getgrall() if name in g.gr_mem}
    return pw.pw_uid, pw.pw_gid, groups


# POSIX access-bit semantics shared by the readability math below.
import stat as _STAT


def _posix_readable(st, uid: int, gid: int, groups: set[int]) -> bool:
    """Real POSIX access-bit logic for a service identity — owner bits,
    then group bits, then other bits.  This is deliberately NOT
    os.access(): as root, os.access lies about every file on disk."""
    mode = _STAT.S_IMODE(st.st_mode)
    if st.st_uid == uid:
        return bool(mode & _STAT.S_IRUSR)
    if st.st_gid == gid or st.st_gid in groups:
        return bool(mode & _STAT.S_IRGRP)
    return bool(mode & _STAT.S_IROTH)


def tls_readiness_problems(etc: pathlib.Path) -> tuple[list[str], list[str]]:
    """Owner/group/mode readability check of the rendered trust map for
    every REAL service identity that already exists on this machine.

    Scope honesty (second review): this is POSIX PERMISSION-BIT MATH on
    the tls files themselves — it does NOT model parent-directory
    traversal, ACLs, or the live mount namespace, so it is an install-
    time consistency gate, NOT proof of installed-service access.  A
    missing identity (sandbox) is reported as deferred, never silently
    passed; real per-UID access on the appliance stays an explicit
    installed-systemd recheck (the same boundary verify_service_runtime
    draws for executability)."""
    problems: list[str] = []
    deferred: list[str] = []
    for identity, files in TLS_TRUST_MAP:
        member = _service_membership(identity)
        if member is None:
            deferred.append(identity)
            continue
        uid, gid, groups = member
        for fname in files:
            path = pathlib.Path(etc) / "tls" / fname
            try:
                st = path.stat()
            except OSError:
                problems.append(f"{identity} cannot stat tls/{fname}")
                continue
            if not _posix_readable(st, uid, gid, groups):
                problems.append(
                    f"{identity} (uid {uid}) cannot read tls/{fname} "
                    f"(owner {st.st_uid}:{st.st_gid}, mode "
                    f"{_STAT.S_IMODE(st.st_mode):#o})")
    return problems, deferred


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
                     public_url: str = "",
                     node_binary: str | None = None) -> dict:
    """Build the frontend from its LOCKED dependencies.

    Next 16 needs a recent Node; the installer refuses an old runtime instead
    of building something that cannot start.  The build runs with the
    SELECTED appliance runtime at the FRONT of PATH — the same binary the
    web unit execs — so a green build can never certify a different Node
    than the service actually starts (second review, finding 5).

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
    binary = node_binary or node_runtime_plan()["binary"]
    version = _node_at(binary)
    if version is None:
        raise RuntimeError(f"selected runtime {binary!r} is not runnable — "
                           "the appliance needs Node "
                           f"{node_version_str(NODE_MIN_VERSION)} or newer "
                           "for the frontend build")
    if version < NODE_MIN_VERSION:
        raise RuntimeError(
            f"selected runtime {binary!r} reports "
            f"{node_version_str(version)} — the frontend needs "
            f"{node_version_str(NODE_MIN_VERSION)} or newer")
    api_url = ""
    if public_url:
        api_url = public_url.rstrip("/") + "/api"
    bindir = os.path.dirname(binary)
    path_dirs = [bindir] + [d for d
                            in os.environ.get("PATH",
                                              "/usr/bin:/bin").split(":")
                            if d and d != bindir]
    env = {"PATH": ":".join(path_dirs)}
    if api_url:
        env["NEXT_PUBLIC_API_URL"] = api_url
    run("npm", "ci", cwd=str(web), env=env)
    run("npm", "run", "build", cwd=str(web), env=env)
    return {"node": node_version_str(version), "binary": binary,
            "lock": str(lock), "next_public_api_url": api_url}


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
