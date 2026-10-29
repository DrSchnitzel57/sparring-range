"""Preserving in-place appliance upgrade (milestone 21).

The upgrade replaces the RUNTIME of an installed appliance with a verified
release payload while preserving everything the operator and the members
own: configuration, keys, the database, recordings, and anything the range
does not own on disk.  The design rules (agreed in ARCHITECTURE section K,
all fail closed):

* staged before live: the payload is copied into a private staging area
  under the attempt directory and verified file-by-file against the
  bundle manifest before ANY live file is touched;
* forward-only migrations: an applied revision that the payload does not
  contain is unsupported drift and is REFUSED — never guessed, never
  reversed;
* quiesced or nothing: a latched range, an armed lease, pending intents,
  active claims or open obligations all mean work exists; the upgrade
  refuses instead of running underneath it, and it never starts, stops or
  resumes a guest itself;
* private backups with a durable manifest: the configuration tree and a
  real ``pg_dump`` of the database are stored mode-0700 under the state
  directory before mutation, recorded with digests (URLs are stored with
  any credential REDACTED — no secret enters a manifest or log);
* resumable stages, unknown work preserved: every stage is journalled;
  a half-finished migration is either PROVEN complete or PROVEN absent by
  re-reading ``alembic_version`` — anything else stays in progress for a
  human, and a second upgrade cannot start around it;
* restore never resumes: restoring config from a backup is a file
  operation; this module issues no start/restart command on the restore
  path, so a restored system comes back quiesced by construction.

The sandbox/real split follows the installer: under ``--system-root`` the
same stages run for real against files, a real PostgreSQL and real
alembic, but no systemd interaction is pretended; on a real appliance the
caller additionally supplies hooks that recreate the venv, rebuild the
web UI and restart the units in order.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.parse

MANIFEST_NAME = "MANIFEST.json"
VERSION_FILE_NAME = "release-version.json"

STAGES = ("backup", "stage", "activate", "migrate", "finalize")


class UpgradeError(RuntimeError):
    pass


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def redact_url(url: str) -> str:
    """A database URL without any credential material (for manifests)."""
    try:
        parsed = urllib.parse.urlsplit(url)
        if not parsed.password:
            return url
        netloc = parsed.hostname or ""
        if parsed.port:
            netloc += f":{parsed.port}"
        user = parsed.username or ""
        return urllib.parse.urlunsplit(
            (parsed.scheme, f"{user}:***@{netloc}" if user else netloc,
             parsed.path, parsed.query, parsed.fragment))
    except ValueError:
        return "***"


# --------------------------------------------------------------------------- #
# migration-chain reading (payload + live database)                           #
# --------------------------------------------------------------------------- #

def migration_revisions(versions_dir: pathlib.Path) -> dict[str, str | None]:
    """revision -> down_revision for every alembic file (AST, not imports)."""
    out: dict[str, str | None] = {}
    for path in sorted(pathlib.Path(versions_dir).glob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        rev, down = None, None
        for node in tree.body:
            if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                continue
            target = node.targets[0]
            name = getattr(target, "id", None) or getattr(target, "target", None)
            if isinstance(target, ast.AnnAssign):
                name = getattr(target.target, "id", None)
                value = target.value
            else:
                value = node.value
            if name == "revision" and isinstance(value, ast.Constant):
                rev = str(value.value)
            elif name == "down_revision" and isinstance(value, ast.Constant):
                down = None if value.value is None else str(value.value)
        if rev is None:
            raise UpgradeError(f"{path.name} declares no `revision`")
        out[rev] = down
    return out


def migration_heads(versions_dir: pathlib.Path) -> set[str]:
    revs = migration_revisions(versions_dir)
    downs = {d for d in revs.values() if d}
    return {r for r in revs if r not in downs}


def db_heads(db_url: str) -> set[str]:
    """The revision(s) the live database currently reports."""
    from sqlalchemy import create_engine, text
    engine = create_engine(db_url)
    try:
        with engine.connect() as conn:
            try:
                rows = conn.execute(
                    text("SELECT version_num FROM alembic_version")
                ).scalars().all()
            except Exception:  # noqa: BLE001 — no table yet = no revisions
                rows = []
    finally:
        engine.dispose()
    return set(rows)


def _legacy_duplicate_markers(db_url: str) -> bool:
    """True only if operation_outputs provably holds 2+ truncation
    markers for one operation — the exact 0025-era condition that makes
    0026's unique partial index un-creatable (F3). Absence of the table
    or of duplicates answers False (0026 may then only fail for real
    reasons, which are never skipped)."""
    from sqlalchemy import create_engine, text
    engine = create_engine(db_url)
    try:
        with engine.connect() as conn:
            try:
                row = conn.execute(text(
                    "SELECT 1 FROM operation_outputs "
                    "WHERE kind = 'truncated' "
                    "GROUP BY run_id, op_id HAVING count(*) > 1 LIMIT 1"
                )).first()
            except Exception:  # noqa: BLE001 — no table: not the F3 case
                return False
    finally:
        engine.dispose()
    return row is not None


def _chain_between(versions_dir: pathlib.Path, from_heads: set[str],
                   to_head: str) -> list[str] | None:
    """Ascending single-parent revision path from ``from_heads`` to
    ``to_head``, or None when the graph is not a single linear path
    (then the caller falls back to a plain ``upgrade head``)."""
    revs = migration_revisions(versions_dir)
    if len(from_heads) != 1:
        return None
    chain: list[str] = []
    rev: str | None = to_head
    while rev and rev not in from_heads:
        if rev not in revs:
            return None
        chain.append(rev)
        rev = revs[rev]
    if rev is None and to_head not in from_heads:
        return None
    chain.reverse()
    # linearity: every step's parent is the previous step
    for a, b in zip(chain, chain[1:]):
        if revs.get(b) != a:
            return None
    if chain and revs.get(chain[0]) not in from_heads:
        return None
    return chain


# --------------------------------------------------------------------------- #
# the release payload (a built bundle directory)                              #
# --------------------------------------------------------------------------- #

#: The REQUIRED runtime contract (milestone 21 review rounds 3–4): a
#: payload that hashes whatever its own untrusted manifest lists lets the
#: manifest itself omit pieces of the release. This is the TRUSTED release
#: definition DERIVED FROM THE EXECUTION SURFACE — the dependency/build
#: locks, the alembic script contract (alembic refuses to run a chain
#: without its env.py), every module a shipped unit's ExecStart executes,
#: and the upgrade/installer engine those units' lifecycle depends on.
#: Migrations additionally require a NON-EMPTY versions tree carrying the
#: contract head (checked in verify()). These are what the services must
#: be able to RUN after activation; missing pieces are refused before
#: anything qualifies — never self-declared by the artifact being verified.
REQUIRED_RUNTIME_CONTRACT = (
    "requirements.lock",
    "pyproject.toml",
    "web/package.json",
    "web/package-lock.json",
    "alembic.ini",
    "srplatform/db/migrations/env.py",
    "srplatform/api/app.py",
    "srplatform/worker_supervisor.py",
    "srplatform/bastion/proxy.py",
    "infra/appliance/brokerd.py",
    "deploy/upgrade.py",
    "deploy/appliance.py",
    "deploy/appliance_services.py",
    "deploy/bundle.py",
)


class ReleasePayload:
    """The upgrade payload: a bundle directory with MANIFEST.json digests."""

    def __init__(self, directory: pathlib.Path):
        from deploy import bundle
        self.dir = pathlib.Path(directory).resolve()
        manifest_path = self.dir / MANIFEST_NAME
        if not manifest_path.is_file():
            raise UpgradeError(
                f"{self.dir} has no {MANIFEST_NAME}: the upgrade payload is a "
                "built release bundle (deploy/bundle.py build), not a loose "
                "directory")
        def _no_dupes(pairs):
            # a hand-edited manifest must not smuggle a second entry for a
            # runtime path (last-wins would silently skip digest checks)
            seen = set()
            for key, _ in pairs:
                if key in seen:
                    raise UpgradeError(
                        f"{MANIFEST_NAME} has a duplicate key {key!r}")
                seen.add(key)
            return dict(pairs)
        self.manifest = json.loads(manifest_path.read_text(),
                                   object_pairs_hook=_no_dupes)
        self.revision = str(self.manifest.get("revision") or "unknown")
        self.files = self.manifest.get("files") or {}
        if not self.files:
            raise UpgradeError(f"{manifest_path} lists no files")
        if not self.manifest.get("upgrade"):
            raise UpgradeError(
                "the bundle declares no `upgrade` contract: it predates "
                "milestone 21 and must be rebuilt before it can upgrade an "
                "appliance (no silent acceptance of unversioned payloads)")
        self.runtime = {rel: str(entry["sha256"])
                        for rel, entry in sorted(self.files.items())
                        if bundle.is_runtime(rel)}
        if not self.runtime:
            raise UpgradeError("the bundle carries no runtime files")
        self.sha256 = hashlib.sha256(
            json.dumps(self.files, sort_keys=True).encode()).hexdigest()

    def _verify_contract(self) -> list[str]:
        """Validate the UPGRADE CONTRACT itself (milestone 21 review): a
        truthy ``upgrade`` key is not enough — the contract must name the
        engine and migrations paths, carry this bundle version, and agree
        with the manifest's revision, or the payload is not for this
        appliance and never qualifies for quiescence or a no-op answer."""
        from deploy import bundle as bundle_mod
        problems: list[str] = []
        contract = self.manifest.get("upgrade") or {}
        if contract.get("bundle_version") != bundle_mod.BUNDLE_VERSION:
            problems.append(
                f"upgrade contract bundle_version "
                f"{contract.get('bundle_version')!r} is not this release's "
                f"{bundle_mod.BUNDLE_VERSION}: pre-21/foreign payloads are "
                "refused, rebuild the bundle")
        if contract.get("engine") != "deploy/upgrade.py":
            problems.append(f"upgrade contract engine "
                            f"{contract.get('engine')!r} is not deploy/upgrade.py")
        if contract.get("revision") != self.revision:
            problems.append(
                f"upgrade contract revision {contract.get('revision')!r} "
                f"does not match the manifest revision {self.revision!r}")
        mig = str(contract.get("migrations") or "")
        if not mig or not (self.dir / mig).is_dir():
            problems.append(f"upgrade contract migrations {mig!r} is not a "
                            "directory in the payload")
        return problems

    def verify(self) -> None:
        """Full payload verification BEFORE any qualification decision —
        dry-run, no-op and mutating paths all pass through here. Digests,
        the contract, path safety and duplicates are ALL checked here;
        nothing about the appliance is consulted first."""
        problems = self._verify_contract()
        inventory = self.manifest.get("files") or {}
        for rel in REQUIRED_RUNTIME_CONTRACT:
            if rel not in inventory:
                problems.append(
                    f"required runtime contract entry missing from the "
                    f"manifest inventory: {rel}")
        migs = sorted((self.dir / "srplatform/db/migrations/versions")
                      .glob("0*.py")) if (
                          self.dir / "srplatform/db/migrations/versions"
                      ).is_dir() else []
        if not migs:
            problems.append("required runtime contract: the payload carries "
                            "no migration versions")
        for rel in inventory:
            p = pathlib.Path(rel)
            if p.is_absolute() or ".." in p.parts:
                problems.append(f"manifest path escapes the payload: {rel}")
        for rel, want in self.runtime.items():
            path = self.dir / rel
            if path.is_symlink():
                problems.append(f"symlink in the payload tree: {rel}")
            elif not path.is_file():
                problems.append(f"missing: {rel}")
            elif _sha256(path) != want:
                problems.append(f"digest mismatch: {rel}")
        if problems:
            raise UpgradeError(
                "upgrade payload failed verification: "
                + "; ".join(problems[:5])
                + (f" (+{len(problems) - 5} more)" if len(problems) > 5 else ""))

    def versions_dir(self) -> pathlib.Path:
        return self.dir / "srplatform/db/migrations/versions"


# --------------------------------------------------------------------------- #
# the journal                                                                 #
# --------------------------------------------------------------------------- #

class Journal:
    """Filesystem journal: one directory per attempt, atomic JSON updates.

    A journal is never deleted by this module, and an attempt in state
    ``in-progress`` blocks every new attempt: work of unknown completion is
    retained, not discarded (plan 21: no unknown work is discarded).
    """

    def __init__(self, etc: pathlib.Path):
        self.root = pathlib.Path(etc) / "upgrade"

    def attempts(self) -> dict[str, dict]:
        out = {}
        if not self.root.is_dir():
            return out
        for child in sorted(self.root.iterdir()):
            journal = child / "journal.json"
            if journal.is_file():
                try:
                    out[child.name] = json.loads(journal.read_text())
                except json.JSONDecodeError:
                    out[child.name] = {"status": "corrupt",
                                       "journal": str(journal)}
        return out

    def in_progress(self, exclude: str | None = None) -> list[str]:
        return [a for a, j in self.attempts().items()
                if j.get("status") != "done" and a != exclude]

    def path(self, attempt: str) -> pathlib.Path:
        return self.root / attempt

    def load(self, attempt: str) -> dict:
        journal = self.path(attempt) / "journal.json"
        if not journal.is_file():
            raise UpgradeError(f"no journal for attempt {attempt!r}")
        return json.loads(journal.read_text())

    def _save(self, attempt: str, data: dict) -> None:
        directory = self.path(attempt)
        directory.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=str(directory), prefix=".journal.")
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh, indent=2, sort_keys=True)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, directory / "journal.json")

    def create(self, *, meta: dict) -> str:
        attempt = f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}" \
                  f"-{hashlib.sha256(str(meta).encode()).hexdigest()[:8]}"
        data = dict(meta)
        data.update({"attempt": attempt, "status": "in-progress",
                     "started_at": _now(), "stages": {}})
        self._save(attempt, data)
        return attempt

    def mark(self, attempt: str, stage: str, status: str, **detail) -> dict:
        data = self.load(attempt)
        entry = data.setdefault("stages", {}).setdefault(stage, {})
        if status == "started" and any(
                key not in ("status", "at", "prior")
                for key in entry) or (
                status == "started" and entry.get("status") in
                ("failed", "started")):
            # LIVE-02: re-entering a stage (the normal resume path after a
            # failure) must not leave the PREVIOUS attempt's facts —
            # especially `error` — sitting in the stage entry, where they
            # read as a current unresolved failure after the eventual
            # success. They move to the entry's `prior` list instead: the
            # evidence is retained, only its presentation changes.
            entry.setdefault("prior", []).append(
                {k: v for k, v in entry.items() if k != "prior"})
            for key in list(entry):
                if key not in ("status", "at", "prior"):
                    del entry[key]
        entry.update({"status": status, "at": _now()})
        entry.update({k: (redact_url(v) if isinstance(v, str) and "://" in v
                          else v) for k, v in detail.items()})
        self._save(attempt, data)
        return data

    def finish(self, attempt: str, **detail) -> dict:
        data = self.load(attempt)
        data["status"] = "done"
        data["finished_at"] = _now()
        data.update(detail)
        self._save(attempt, data)
        return data


# --------------------------------------------------------------------------- #
# helpers over the installed layout                                           #
# --------------------------------------------------------------------------- #

def version_file(layout) -> pathlib.Path:
    return layout.etc / VERSION_FILE_NAME


def installed_version(layout) -> dict:
    path = version_file(layout)
    if path.is_file():
        return json.loads(path.read_text())
    return {}


def _copy_tree_private(src: pathlib.Path, dst: pathlib.Path,
                       *, exclude_rel: str | None = None) -> dict:
    """Copy a config tree into the private backup area.

    Symlinks are recorded, never followed (a config tree must not pull
    /root into the backup). Modes are kept but stripped of group/other
    bits: the backup lives mode-0700 under the state directory.

    ``exclude_rel`` skips the journal tree (the attempt's OWN directory
    changes every stage — it mkstemp-replaces while the backup runs — and
    NO attempt journal is config: a config restore must never roll back
    journals, including the one that records the restore).

    The manifest records the ORIGINAL ownership and permission bits
    separately from the privacy-reduced copy the backup itself stores:
    restoring a service-readable 0640 file as 0600 breaks the service that
    reads it, so the truth lives here and the copy stays private.
    """
    entries: dict[str, dict] = {}
    dst.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(dst, 0o700)
    for path in sorted(src.rglob("*")):
        rel = str(path.relative_to(src))
        if exclude_rel and (rel == exclude_rel
                            or rel.startswith(exclude_rel + "/")):
            continue
        if path.name.startswith(".journal."):
            continue  # transient mkstemp siblings are never files
        if path.is_symlink():
            entries[rel] = {"skipped_symlink": os.readlink(path)}
            continue
        if not path.is_file():
            continue
        target = dst / rel
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        # digest BEFORE the write, from the SOURCE: an external writer
        # racing this snapshot makes the digest refuse the restore, it
        # can never bake a mismatch into the backup manifest.
        src_sha = _sha256(path)
        st = path.stat()
        shutil.copyfile(path, target)
        os.chmod(target, st.st_mode & 0o777 & ~0o077)
        entries[rel] = {"sha256": src_sha,
                        "mode": f"{st.st_mode & 0o777:04o}",
                        "backup_mode": f"{st.st_mode & 0o777 & ~0o077:04o}",
                        "uid": st.st_uid, "gid": st.st_gid,
                        "bytes": target.stat().st_size}
    return entries


def _restore_tree(backup: pathlib.Path, manifest: dict, dst: pathlib.Path,
                  *, dry_run: bool) -> list[str]:
    """Restore in TWO PASSES: pass one validates the COMPLETE backup —
    every inventory entry's bytes, digest, metadata and path safety — and
    pass two only writes. A corrupt late file must leave the tree
    byte-identical, never leave earlier files already replaced.

    Ownership and mode come from the manifest's ORIGINAL values (never
    from the privacy-reduced backup copy); unsafe paths or metadata fail
    closed, and ownership is restored only where the caller is entitled
    (root, or already the recorded owner) — never by privilege invention."""
    files = manifest.get("files") or {}
    problems: list[str] = []
    planned: list[tuple[str, dict, pathlib.Path, int, int]] = []
    for rel, meta in sorted(files.items()):
        if meta.get("skipped_symlink") is not None:
            continue  # recorded, never followed, never restored as a file
        p = pathlib.PurePosixPath(rel)
        if p.is_absolute() or ".." in p.parts or not rel:
            problems.append(f"unsafe backup path {rel!r}")
            continue
        mode_raw = str(meta.get("mode", ""))
        try:
            if len(mode_raw) != 4 or any(c not in "01234567" for c in mode_raw):
                raise ValueError(mode_raw)
            mode = int(mode_raw, 8)
        except ValueError:
            problems.append(f"backup entry {rel} has unparseable mode "
                            f"{mode_raw!r}")
            continue
        uid, gid = meta.get("uid"), meta.get("gid")
        if uid is None or gid is None or not isinstance(uid, int) \
                or not isinstance(gid, int) or uid < 0 or gid < 0:
            problems.append(f"backup entry {rel} lacks valid ownership "
                            f"(uid={uid!r} gid={gid!r})")
            continue
        src = backup / rel
        if not src.is_file() or src.is_symlink():
            problems.append(f"backup missing {rel}")
            continue
        if _sha256(src) != meta.get("sha256"):
            problems.append(f"backup digest mismatch {rel}")
            continue
        planned.append((rel, meta, dst / rel, mode))
    if problems:
        raise UpgradeError(
            "restore refused BEFORE any write — the backup is not intact: "
            + "; ".join(problems[:5])
            + (f" (+{len(problems) - 5} more)" if len(problems) > 5 else ""))

    if dry_run:
        return [str(target) for _, _, target, _ in planned]
    restored = []
    for rel, meta, target, mode in planned:
        src = backup / rel
        uid, gid = int(meta["uid"]), int(meta["gid"])
        if os.geteuid() != 0:
            # a non-root restore may only replace its OWN files, keeps the
            # owner it shares with the target, and never chowns to someone
            # else (that would be privilege guessing, not restoring)
            cur = os.stat(target) if target.exists() else None
            if cur is not None and cur.st_uid != os.geteuid():
                raise UpgradeError(
                    f"refusing to replace {rel}: owned by uid "
                    f"{cur.st_uid}, restore runs as uid {os.geteuid()} — "
                    "run the restore as root")
            uid = os.geteuid()
            gid = gid if cur is None or cur.st_gid == gid else cur.st_gid
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(target.name + ".sr-restore")
        shutil.copyfile(src, tmp)
        os.chmod(tmp, mode)
        os.chown(tmp, uid, gid)
        os.replace(tmp, target)
        after = os.stat(target)
        if after.st_mode & 0o777 != mode:
            raise UpgradeError(f"restored {rel} has mode "
                               f"{after.st_mode & 0o777:04o}, not {mode:04o}")
        restored.append(str(target))
    return restored


class _OwnerCredential:
    """A database owner URL, held so the SECRET never reaches any argv.

    ``pg_dump``/``psql`` accept the password through ``PGPASSFILE`` (a
    0600 file the process creates in a private temporary directory and
    removes afterwards); everything else that appears in a process's
    command line is readable by every local process for its whole
    lifetime — the operator's owner credential must never live there.
    Endpoints (host/port/database/user) are not secrets and are what the
    child's argv carries."""

    def __init__(self, db_url: str):
        # Parsed with SQLAlchemy's URL parser — the SAME one the installed
        # application uses — because the installer writes driver-qualified
        # URLs (``postgresql+psycopg2://`` in deploy/hand_off.sh) and a
        # naive urlsplit treats "+psycopg2" as part of the scheme and
        # refuses the installer's own format (round-3 finding 5). Going
        # through the real parser also means percent-encoded passwords and
        # database names, and bracketed IPv6 hosts, decode exactly the way
        # the application's children will send them to the pg tools.
        from sqlalchemy.engine import make_url
        try:
            url = make_url(db_url)
        except Exception as exc:  # noqa: BLE001 — naming a URL is not a leak
            raise UpgradeError(
                "the owner database URL is not parseable as a database URL: "
                f"{type(exc).__name__}: {str(exc)[:160]}") from exc
        if not url.drivername or \
                url.drivername.split("+", 1)[0] not in ("postgresql",
                                                        "postgres") \
                or not url.host or not url.database:
            raise UpgradeError(
                "the owner database URL must be a TCP postgresql URL "
                "(scheme, host and database; a driver suffix like "
                "+psycopg2 is accepted): the preserving backup cannot pass "
                "credentials by any other channel")
        if url.password is None or url.username is None:
            raise UpgradeError("the owner URL carries no username:password — "
                               "the PGPASSFILE channel needs both")
        self.host = url.host
        self.port = str(url.port or 5432)
        self.database = url.database
        self.user = url.username
        self._password = url.password
        self._passfile: pathlib.Path | None = None

    def env(self) -> dict[str, str]:
        """Environment additions for the child: PGPASSFILE only. Never
        PGPASSWORD (visible in the same-uid process environment) and never
        the URL itself."""
        import tempfile
        if self._passfile is None:
            directory = pathlib.Path(tempfile.mkdtemp(prefix="sr-pgpass-"))
            os.chmod(directory, 0o700)
            self._passfile = directory / "pgpass"
            escaped = self._password.replace("\\", "\\\\").replace(":", "\\:")
            self._passfile.write_text(
                f"{self.host}:{self.port}:{self.database}:"
                f"{self.user}:{escaped}\n")
            os.chmod(self._passfile, 0o600)
        return {"PGPASSFILE": str(self._passfile)}

    def close(self) -> None:
        import shutil
        if self._passfile is not None:
            shutil.rmtree(self._passfile.parent, ignore_errors=True)
            self._passfile = None

    def __enter__(self) -> "_OwnerCredential":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()


def _dump_endpoint_args(cred: _OwnerCredential) -> list[str]:
    return ["-h", cred.host, "-p", cred.port, "-U", cred.user,
            "-d", cred.database]


def _resolve_dump_binary(override: str | None) -> list[str]:
    """The pg_dump invocation. The override is a path to a binary or
    wrapper that accepts the exact argv ``[bin, '-h', HOST, '-p', PORT,
    '-U', USER, '-d', DB, '--format=custom', '--file', OUT]`` and reads
    the password from the ``PGPASSFILE`` its environment carries (the
    upgrade gate uses a wrapper around a real pg_dump inside its own
    fixture container; nothing synthetic is dumped either way — the
    artifact is a restoreable custom-format dump). NO credential ever
    appears in the child's argv.
    """
    if override:
        binary = pathlib.Path(override)
        if not binary.is_file() or not os.access(binary, os.X_OK):
            raise UpgradeError(f"--pg-dump-bin {override} is not executable")
        return [str(binary)]
    found = shutil.which("pg_dump")
    if not found:
        for base in ("/usr/bin", "/usr/lib/postgresql/latest/bin"):
            candidate = pathlib.Path(base) / "pg_dump"
            if candidate.is_file():
                found = str(candidate)
                break
    if not found:
        raise UpgradeError(
            "pg_dump is required for the preserving database backup "
            "(install postgresql-client, or pass --pg-dump-bin)")
    return [found]


# --------------------------------------------------------------------------- #
# preflight                                                                   #
# --------------------------------------------------------------------------- #

#: run statuses that mean durable work EXISTS (mirrors the database's own
#: "one active run per session" invariant plus the cleanup-intent status)
OPEN_RUN_STATUSES = ("provisioning", "queued", "running", "stopping",
                     "cancel-unknown", "finalizing")
#: model-job states that are not terminal (model_jobs.TERMINAL_STATES)
OPEN_MODEL_JOB_STATES = ("queued", "running", "cessation_unknown")


def quiescence_problems(m, *, db_url: str | None = None,
                        allow_fresh_install: bool = False) -> list[str]:
    """Durable facts that mean the range has work in flight.

    EVERY authority is consulted: the broker ledger AND the database.
    A MISSING ledger is not evidence of quiescence — it is missing
    evidence — and only an explicit ``allow_fresh_install`` (operator
    statement that nothing was ever claimed here) may accept it.
    ``cessation_unknown`` rows are the loudest problem of all: work whose
    cessation nobody can confirm is exactly what an upgrade must never
    restart over."""
    problems = []
    ledger_path = pathlib.Path(m.broker_ledger)
    if not ledger_path.is_file():
        if not allow_fresh_install:
            problems.append(
                f"broker ledger {ledger_path} is MISSING: a missing ledger "
                "proves nothing was claimed only on a provably fresh "
                "install — pass --allow-fresh-install when that is the "
                "truth, never by default")
    else:
        from infra.broker.ledger import Ledger
        ledger = Ledger(str(ledger_path))
        try:
            latch = ledger.get_latch()
            if latch.get("latched"):
                problems.append(f"range is LATCHED ({latch.get('reason')})")
            lease = ledger.get_lease()
            if lease.get("armed"):
                problems.append(
                    f"runner lease armed (holder={lease.get('holder')})")
            for name in ("pending_intents", "active_claims",
                         "open_obligations"):
                rows = getattr(ledger, name)()
                if rows:
                    problems.append(f"{len(rows)} {name} outstanding")
        finally:
            ledger.close()
    problems += durable_work_problems(db_url)
    return problems


#: The durable-authority tables and the FIRST schema revision each was
#: introduced by (milestone-21 review round 3, finding 1): on a real old
#: appliance (deployed 52ae355 = migrations through 0019) the newer tables
#: legitimately do not exist yet — their ABSENCE below the introducing
#: revision is truth, not an unreadable unknown. At or above it, a missing
#: table IS a problem.
_DURABLE_TABLE_SINCE: dict[str, str] = {
    "runs": "0001",
    "run_operations": "0008",
    "model_jobs": "0020",
}


def _revision_number(revision: str) -> int:
    digits = "".join(ch for ch in revision if ch.isdigit())
    return int(digits) if digits else -1


def durable_work_problems(db_url: str | None) -> list[str]:
    """Authoritative in-database checks: runs, model jobs (including
    cessation_unknown obligations) and dispatched-command inventory —
    TABLE-AWARE, so the check tells the truth against an old schema
    (0018/0019 deployments) as well as the current one."""
    if not db_url:
        return []  # the caller already refuses an upgrade without a DB URL
    from sqlalchemy import create_engine, text
    engine = create_engine(db_url)
    problems = []
    try:
        with engine.connect() as conn:
            version = conn.execute(text(
                "SELECT max(version_num) FROM alembic_version")).scalar()
            if not version:
                problems.append("alembic_version carries no revision: the "
                                "schema state is unknown, and unknown is "
                                "not quiesced")
                return problems
            present = {row for (row,) in conn.execute(text(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'public'"))}
            for table, since in _DURABLE_TABLE_SINCE.items():
                if table not in present:
                    if _revision_number(version) >= _revision_number(since):
                        problems.append(
                            f"schema at {version} should carry {table} "
                            f"(introduced at {since}) but the table is "
                            "missing: durable work cannot be proven")
                    # else: this authority did not exist at the deployed
                    # revision — nothing durable can live in it
            if "runs" in present:
                for status, count in conn.execute(text(
                        "SELECT status, count(*) FROM runs WHERE status = "
                        "ANY(:s) GROUP BY status"),
                                                  {"s": list(
                                                      OPEN_RUN_STATUSES)}):
                    problems.append(f"{count} run(s) in durable state "
                                    f"{status!r}")
            if "model_jobs" in present:
                for state, count in conn.execute(text(
                        "SELECT state, count(*) FROM model_jobs WHERE state"
                        " = ANY(:s) GROUP BY state"),
                                                  {"s": list(
                                                      OPEN_MODEL_JOB_STATES)}):
                    if state == "cessation_unknown":
                        problems.append(
                            f"{count} model job(s) in cessation_unknown — "
                            "work whose provider-side cessation is "
                            "UNCONFIRMED; an upgrade may never restart over "
                            "it (record a bounded resolution first)")
                    else:
                        problems.append(f"{count} model job(s) {state}")
            if "run_operations" in present:
                n = conn.execute(text(
                    "SELECT count(*) FROM run_operations WHERE state IN "
                    "('active', 'cancel-unknown')")).scalar()
                if n:
                    problems.append(f"{n} dispatched command operation(s) "
                                    "whose cessation is not confirmed")
    except Exception as exc:  # noqa: BLE001 — unknown state is NOT quiesced
        problems.append(f"durable-work database check failed unreadably: "
                        f"{type(exc).__name__}: {str(exc)[:160]}")
    finally:
        engine.dispose()
    return problems


def preflight(m, layout, payload: ReleasePayload, *, db_url: str | None,
              python_exe: str, allow_fresh_install: bool = False) -> dict:
    """Every refusal happens HERE, before a single byte changes.

    The PAYLOAD is qualified first (bytes, contract, inventory): an
    unverified payload must never see enough appliance state to answer a
    convincing no-op or dry-run. Then the appliance, database chain,
    durable work and resources are checked."""
    problems: list[str] = []
    try:
        payload.verify()
    except UpgradeError as exc:
        # verification failures are refusals, not crashes — and they happen
        # before any qualification, quiesce or no-op question is answered
        raise UpgradeError(f"upgrade payload refused before any other check: "
                           f"{exc}") from exc
    # --- credential transport is validated HERE (round-3 finding 5): the
    # --- installer's own driver-qualified SQLAlchemy URLs must parse, and
    # --- an unreadable URL must never first surface mid-backup, after an
    # --- attempt and fence exist. Parsing creates no passfile; close() is
    # --- belt-and-braces for a future constructor side effect.
    if db_url:
        try:
            _OwnerCredential(db_url).close()
        except UpgradeError as exc:
            problems.append(f"owner credential channel refused: {exc}")
    if not layout.receipt.is_file():
        problems.append(f"no installation receipt at {layout.receipt}: "
                        "nothing to upgrade (run apply first)")
    current = installed_version(layout)

    # --- migration chain: forward-only from the LIVE database ------------- #
    payload_revs = migration_revisions(payload.versions_dir())
    payload_heads = {r for r, d in payload_revs.items()
                     if r not in set(payload_revs.values())}
    if len(payload_heads) != 1:
        problems.append(f"payload migration graph has {len(payload_heads)} "
                        f"heads ({sorted(payload_heads)}); refusing")
    payload_head = next(iter(payload_heads)) if len(payload_heads) == 1 else None

    live_heads: set[str] = set()
    if db_url:
        live_heads = db_heads(db_url)
        unknown = sorted(live_heads - set(payload_revs))
        if unknown:
            problems.append(
                "the database has applied revision(s) the payload does not "
                f"contain: {unknown} — unsupported drift; this release will "
                "never reverse or guess a schema")
    else:
        problems.append("no database owner URL (POSTGRES_URL_OWNER or "
                        "--db-url-env NAME): a preserving upgrade must be "
                        "able to verify and back the schema up")

    if payload_head and live_heads == {payload_head} and current.get(
            "revision") == payload.revision:
        return {"no_op": True, "reason": "already at payload revision",
                "revision": payload.revision, "problems": []}

    from deploy.appliance import sandbox_manifest
    problems += [f"not quiesced: {p}" for p in quiescence_problems(
        sandbox_manifest(m, pathlib.Path(layout.root)),
        db_url=db_url, allow_fresh_install=allow_fresh_install)]

    # --- disk headroom: payload staged twice (copy + live) + backup slack -- #
    payload_bytes = sum((payload.dir / rel).stat().st_size
                        for rel in payload.runtime)
    probe = pathlib.Path(layout.state)
    while not probe.is_dir() and probe != probe.parent:
        probe = probe.parent
    free = shutil.disk_usage(str(probe)).free
    need = 2 * payload_bytes + 512 * 1024 * 1024
    if free < need:
        problems.append(f"state filesystem free {free // 1024**2} MiB < "
                        f"{need // 1024**2} MiB needed to stage this payload")

    # --- the interpreter that will run alembic ---------------------------- #
    if not pathlib.Path(python_exe).is_file():
        problems.append(f"python interpreter {python_exe} not found")

    if problems:
        raise UpgradeError("upgrade preflight refused:\n  - "
                           + "\n  - ".join(problems))
    return {"no_op": False, "problems": [],
            "from_revision": current.get("revision", "unknown-install"),
            "to_revision": payload.revision,
            "from_heads": sorted(live_heads), "to_head": payload_head,
            "runtime_files": len(payload.runtime),
            "payload_sha256": payload.sha256,
            "quiesced": True, "staged_bytes_needed": need}


# --------------------------------------------------------------------------- #
# the resumable upgrade                                                       #
# --------------------------------------------------------------------------- #

def forward_migrate(python_exe: str, db_url: str, cwd: str,
                    versions_dir: pathlib.Path, from_heads: set[str],
                    to_head: str, journal=None,
                    attempt: str | None = None) -> tuple[set[str], list[str]]:
    """Walk the chain ONE revision at a time to ``to_head`` (never a blind
    ``upgrade head`` over unknown state). Returns (heads, skipped).

    The ONLY tolerated per-step failure is the F3 SUPPORTED PREREQUISITE
    — documented, recorded, automatic, never a silent pass: applied-0026's
    unique truncation index cannot be created over provable 0025-era
    duplicate markers, and 0026 is immutable. The failed step rolled back
    atomically (heads unchanged, re-proven); skip ONLY that index
    statement by stamping past it and let forward 0027 re-apply 0026's
    other effects idempotently and install the legacy-safe forward
    guard. No row is deleted or modified; any other failure propagates.
    """
    def _alembic(*args: str) -> subprocess.CompletedProcess:
        # Alembic gets the owner URL through ITS explicit channel only:
        # ambient copies of the owner/secret variables (the operator's
        # exported upgrade URL) are stripped from the child env
        # (round-3 finding 5 — no secret travels further than its one
        # authorized channel).
        from deploy import appliance_services as svc
        env = {k: v for k, v in os.environ.items()
               if k not in svc.credential_env_names()}
        # Round 6 (operator-launch audit): alembic loads the PAYLOAD's
        # env.py and version scripts through importlib's source loader,
        # which writes __pycache__/*.pyc NEXT TO those files (probed:
        # alembic.util.pyfiles.load_module_py honors only the interpreter
        # startup flags). Without this guard a real upgrade stamps
        # unlisted bytecode into the sealed release tree and the
        # operator's later `bundle.py verify` fails. The seal is kept by
        # construction, not by loosening verification.
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env["POSTGRES_URL_OWNER"] = db_url
        return subprocess.run(
            [python_exe, "-m", "alembic", *args],
            cwd=cwd, env=env, capture_output=True, text=True, timeout=1800)

    steps = _chain_between(versions_dir, from_heads, to_head)
    if steps is None:  # non-linear graph: one plain forward step
        steps = ["head"]
    skipped: list[str] = []
    while steps:
        rev, steps = steps[0], steps[1:]
        proc = _alembic("upgrade", rev)
        if proc.returncode == 0:
            continue
        if (rev == "0026"
                and db_heads(db_url) == from_heads
                and "uq_operation_outputs_truncated_once"
                in (proc.stdout + proc.stderr)
                and _legacy_duplicate_markers(db_url)):
            stamp = _alembic("stamp", "0026")
            if stamp.returncode != 0:
                raise UpgradeError(
                    "supported 0026 prerequisite could not stamp: "
                    + (stamp.stdout + stamp.stderr)[-400:])
            skipped.append("0026:uq_operation_outputs_truncated_once")
            if journal is not None and attempt is not None:
                journal.mark(attempt, "migrate", "prerequisite",
                             revision="0026",
                             note="0026's unique truncation index is "
                                  "un-creatable over provable 0025-era "
                                  "duplicate markers; stamped past the "
                                  "index statement only; forward 0027 "
                                  "re-applies 0026's other effects and "
                                  "the legacy-safe guard")
            continue
        raise UpgradeError(
            f"forward migration to {rev} failed (exit "
            f"{proc.returncode}): {(proc.stdout + proc.stderr)[-400:]}")
    return db_heads(db_url), skipped


def default_migration_python(layout) -> str:
    """Migrations run with the INSTALLED release's own interpreter, not
    whatever python happened to invoke the CLI: the appliance service
    contract is the venv at the prefix, and an upgrade that migrated with
    the invoking interpreter could certify a schema the services cannot
    reach."""
    venv_python = pathlib.Path(layout.prefix) / ".venv" / "bin" / "python"
    return str(venv_python) if venv_python.is_file() else sys.executable


def provision_release(layout, payload: ReleasePayload, *, run,
                      skip_frontend: bool = False,
                      public_url: str = "") -> dict:
    """The SUPPORTED production provisioning path (milestone 21 review):
    the SAME service helpers a fresh install runs — locked Python
    dependencies, the selected Node runtime, the per-UID runtime
    verification and the frontend build from locked inputs — executed
    against the ACTIVATED payload at the prefix, with that venv's own
    interpreter required to import what every unit execs. Copying new
    source without this leaves old dependencies and a stale frontend
    under a new version stamp; this stage is what makes "the services run
    the verified release" true."""
    from deploy import appliance_services as svc
    source = pathlib.Path(layout.prefix)
    if not (source / "requirements.lock").is_file():
        raise UpgradeError("activated payload has no requirements.lock — "
                           "the appliance refuses to resolve floating "
                           "dependencies")
    receipt: dict = {}
    if layout.sandboxed:
        # a sandbox never mutates host packages or global node: the runtime
        # must already satisfy the floor (the gate installs nothing blind)
        plan = svc.node_runtime_plan("auto")
        if plan.get("action") != "kept":
            raise UpgradeError(
                "sandboxed provisioning cannot fetch a Node runtime; "
                "install Node >= the appliance floor first")
        receipt["node"] = plan
    else:
        receipt["native_packages"] = svc.ensure_native_dependencies(run)
        receipt["node"] = svc.ensure_node_runtime(run)
    venv = svc.ensure_venv(run, prefix=source, source=source,
                           broker_bindings=not layout.sandboxed)
    receipt["venv"] = str(venv)
    # the units exec THIS interpreter on THESE sources — it must import
    # the entrypoints, or activation only moved files
    proc = run(str(venv / "bin" / "python"), "-c",
               "import srplatform.api.app, infra.appliance.brokerd",
               check=False, cwd=str(source))
    if proc.returncode != 0:
        raise UpgradeError(
            "the installed venv cannot import the release entrypoints "
            f"(exit {proc.returncode}): "
            f"{(proc.stdout + proc.stderr)[-400:]}")
    if not layout.sandboxed:
        receipt["runtime_verification"] = svc.verify_service_runtime(
            run, venv, node_binary=receipt["node"].get("binary"))
    if not skip_frontend:
        receipt["web"] = svc.ensure_web_build(
            run, source=source, public_url=public_url,
            node_binary=receipt["node"].get("binary"))
    return receipt


#: The services that ADMIT new durable work (round-3 finding 2). The fence
#: file teaches only NEW code — the barrier that an OLD running API cannot
#: bypass is that the admitting services are STOPPED and verifiably
#: inactive while the authoritative durable re-check happens. Bastion
#: sessions, ingest and the broker are not admission paths and stay up;
#: nothing remote is ever "ceased" by killing a local process — obligations
#: whose cessation is unconfirmed are refused BEFORE this stage runs.
ADMISSION_UNITS = ("sr-worker-supervisor.service", "sr-api.service")


def stop_admission_services(run) -> list[str]:
    """Stop and PROVE-inactive the admission services (checked, like every
    other service command). Raises with everything left exactly as found
    plus the fence UP if a unit cannot be proven stopped."""
    stopped: list[str] = []
    for unit in ADMISSION_UNITS:
        proc = run("systemctl", "stop", unit, check=False)
        if proc.returncode != 0:
            raise UpgradeError(
                f"cannot quiesce for upgrade: systemctl stop {unit} exited "
                f"{proc.returncode}: {(proc.stdout + proc.stderr)[-200:]} — "
                "the upgrade barrier requires the admitting service "
                "stopped; nothing was mutated")
        state = run("systemctl", "is-active", unit, check=False)
        status = (state.stdout or "").strip()
        if status != "inactive":
            raise UpgradeError(
                f"{unit} is not verifiably stopped (is-active reported "
                f"{status!r}): an admitting service in another state may "
                "still hold or create durable work — refusing to upgrade "
                "under it rather than guessing")
        stopped.append(unit)
    return stopped


def checked_service_restart(run, units: list[str], *,
                            timeout_checks: int = 60) -> list[str]:
    """Restart through the real service manager and VERIFY: every unit is
    restarted, every unit then reports active, and any failure raises with
    the unit and exit status named. A restart that was not checked is not
    a restart."""
    for unit in units:
        proc = run("systemctl", "restart", unit, check=False)
        if proc.returncode != 0:
            raise UpgradeError(
                f"service restart failed: systemctl restart {unit} exited "
                f"{proc.returncode}: {(proc.stdout + proc.stderr)[-300:]}")
    for unit in units:
        for _ in range(timeout_checks):
            proc = run("systemctl", "is-active", "--quiet", unit, check=False)
            if proc.returncode == 0:
                break
            time.sleep(1)
        else:
            raise UpgradeError(
                f"service never became active after restart: {unit} — "
                "attempt stays in progress; the admission fence remains "
                "up (no new work is admitted to an unverified release)")
    return list(units)


def bootstrap_secret_store(layout, *, run, db_url: str,
                           secret_role: str | None = None) -> dict:
    """Installer-equivalent, API-only credential-store bootstrap (round-3
    finding 1): a deployed 0019 appliance has neither the ``sr_secret``
    role nor ``secrets/db-secret.env``, and migration 0021 GRANTs to that
    role — an upgrade over that schema would die mid-chain otherwise.

    SAME identity, same minimal boundary, same file contract as a fresh
    install (this mirrors ``ensure_database``'s secret section exactly):
    an existing file or explicit ``SR_PG_SECRET_URL`` is honored (the role
    is created FROM it), a password is generated and ALTERed ONLY when
    this step generated it — an existing file is never re-keyed. Role
    creation goes through the local postgres superuser socket exactly like
    install: no operator SQL, no re-keying of app/owner roles, no other
    file touched, nothing logged."""
    from deploy import appliance_services as svc
    secret_role = secret_role or os.environ.get("DB_SECRET_ROLE",
                                                "sr_secret")
    etc = pathlib.Path(layout.etc)
    secret_env = etc / "secrets" / "db-secret.env"
    owner = _OwnerCredential(db_url)
    try:
        existing = os.environ.get("SR_PG_SECRET_URL") or \
            svc._read_env_file(secret_env).get("SR_PG_SECRET_URL")
        generated = existing is None
        if generated:
            import secrets as _secrets
            url = (f"postgresql+psycopg2://{secret_role}:"
                   f"{_secrets.token_urlsafe(24)}@"
                   f"{owner.host}:{owner.port}/{owner.database}")
        else:
            url = existing
        parsed = svc._parse_url(url)
        if parsed["user"] != secret_role:
            raise UpgradeError(
                f"the provided secret-store URL uses role "
                f"{parsed['user']!r} but migrations grant to "
                f"{secret_role!r} (DB_SECRET_ROLE); refusing to create a "
                "role the release will not use")
        svc._psql_as_postgres(run, [
            f"DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE "
            f"rolname='{parsed['user']}') THEN CREATE ROLE "
            f"{parsed['user']} LOGIN PASSWORD '{parsed['password']}';"
            f"ELSIF '{str(generated).lower()}' = 'true' THEN "
            f"ALTER ROLE {parsed['user']} WITH LOGIN "
            f"PASSWORD '{parsed['password']}'; END IF; END $$;"])
        secret_env.parent.mkdir(parents=True, exist_ok=True)
        wrote = False
        if not secret_env.exists():
            svc._write_secret_file_securely(secret_env, (
                "# API-only identity for the provider-credential table "
                "ONLY\n# (migration 0021 onward). systemd loads it as "
                "root for\n# sr-api.service ONLY — no service USER may "
                "read this file:\n# 0600 root:root, delivered through "
                "the unit environment.\n"
                f"SR_PG_SECRET_URL={url}\n"))
            wrote = True
        svc._verify_secret_file(secret_env, sandboxed=layout.sandboxed)
    finally:
        owner.close()
    return {"secret_role": secret_role, "generated": generated,
            "file_written": wrote}


def _readiness_probe(url: str, *, timeout_s: int,
                     expected_head: str) -> tuple[bool, str]:
    """ONE readiness probe over a REAL socket. Returns (ready, reason).

    This is the round-4 contract: HTTP status alone is NOT readiness —
    the installed /readyz answers 200 with {"ready": false, "issues":
    [...]} when the schema is behind or the controller is lost, and a
    stale old process answers 200/ready:true about a head the release
    never installed. So the parsed JSON must satisfy: ``ready`` is the
    exact boolean True, ``issues`` is an EMPTY list, and
    ``migration_version`` equals the expected schema head. Anything
    malformed — non-JSON, HTML, missing fields, non-bool truthiness, a
    contradictory ready-with-issues — is NOT ready (fail closed)."""
    import json as _json
    import urllib.error
    import urllib.request
    try:
        with urllib.request.urlopen(url, timeout=timeout_s) as resp:
            if resp.status != 200:
                return False, f"HTTP {resp.status}"
            body = resp.read(65536)
    except urllib.error.HTTPError as exc:
        return False, f"HTTP {exc.code}"
    except Exception as exc:  # connection refused, timeout, …
        return False, f"{type(exc).__name__}: {str(exc)[:120]}"
    try:
        doc = _json.loads(body.decode("utf-8"))
    except Exception:
        return False, "readiness body is not JSON (fail closed)"
    if not isinstance(doc, dict):
        return False, "readiness body is not a JSON object (fail closed)"
    if doc.get("ready") is not True:
        return False, (f"ready is {doc.get('ready')!r}, not the exact "
                       "boolean true")
    issues = doc.get("issues")
    if not isinstance(issues, list) or issues:
        return False, f"issues not empty: {str(issues)[:200]}"
    version = doc.get("migration_version")
    if version != expected_head:
        return False, (f"migration_version {version!r} is not the expected "
                       f"{expected_head!r} (stale or migrating process?)")
    return True, "ready"


def wait_for_readiness(m, *, web_url: str, expected_head: str,
                       timeout_s: int = 120, probe_timeout_s: int = 5) -> dict:
    """Bounded REAL-HTTP readiness after restart (round-3 finding 3,
    round-4 finding 1): ``active`` is not ``ready``, and an HTTP 200 is
    not ``ready`` either — the parsed production readiness contract must
    hold (see ``_readiness_probe``). ``GET {internal_url}/readyz`` must
    report ready with no issues and the payload's schema head; the
    frontend must answer 200 at its bound address. A service that is
    restarted but unhealthy (schema behind, controller lost, stale old
    process, malformed reporter) fails HERE, with the fence still up and
    no version stamp, and the attempt stays resumable. Only ever probes
    the manifest's own local endpoints; nothing remote."""
    if not expected_head:
        raise UpgradeError("readiness requires the expected schema head")
    targets = {
        "api": str(m.internal_url).rstrip("/") + "/readyz",
        "web": web_url,
    }
    import urllib.request

    def _web(url: str) -> tuple[bool, str]:
        # the frontend has no JSON contract; a 200 with a body is the
        # documented signal, anything else retries/fails closed
        try:
            with urllib.request.urlopen(url, timeout=probe_timeout_s) as r:
                if r.status != 200 or not r.read(16):
                    return False, f"HTTP {r.status} or empty body"
                return True, "ready"
        except Exception as exc:  # noqa: BLE001
            return False, f"{type(exc).__name__}: {str(exc)[:120]}"

    deadline = time.monotonic() + timeout_s
    last: dict[str, str] = {}
    while True:
        for name, url in targets.items():
            ok, why = (_readiness_probe(url, timeout_s=probe_timeout_s,
                                        expected_head=expected_head)
                       if name == "api" else _web(url))
            last[name] = why
            if not ok:
                break
        else:
            return last  # every endpoint satisfied its contract
        if time.monotonic() >= deadline:
            raise UpgradeError(
                "services never satisfied the readiness CONTRACT within "
                "the bounded wait: "
                + "; ".join(f"{k} {v}" for k, v in sorted(last.items()))
                + " — the fence stays UP and NO version stamp was written; "
                "the attempt remains resumable")
        time.sleep(2)


def _fence_identity(path: pathlib.Path) -> tuple[str, object]:
    """Classify the admission fence WITHOUT touching it.

    kind is one of: "absent" (no file), "unreadable" (present but not a
    JSON object), "anonymous" (JSON object with no usable ``attempt``),
    or "owned" with the owning attempt id. Absence of a journal match is
    NOT authority over an existing fence — round-5 finding 1."""
    if not path.is_file():
        return "absent", None
    try:
        doc = json.loads(path.read_text())
    except Exception:  # noqa: BLE001 — any parse failure is fail closed
        return "unreadable", None
    if not isinstance(doc, dict):
        return "unreadable", None
    owner = doc.get("attempt")
    if isinstance(owner, str) and owner:
        return "owned", owner
    return "anonymous", None


def _require_fence_takeable(kind: str, owner: object) -> None:
    """Refuse to acquire (overwrite/adopt) a fence whose identity is not
    absent — a foreign, anonymous or unreadable fence is kept BYTE-EXACT;
    taking ownership is an explicit operator recovery decision, never a
    side effect of an upgrade starting."""
    if kind == "owned":
        raise UpgradeError(
            f"the admission fence belongs to attempt {owner!r}; an upgrade "
            "never overwrites or adopts another owner's fence. Complete "
            f"that attempt (--resume {owner}) or resolve it explicitly "
            "before starting new upgrade work")
    if kind in ("anonymous", "unreadable"):
        raise UpgradeError(
            "an admission fence exists whose ownership cannot be proven ("
            + ("no owning attempt is recorded" if kind == "anonymous"
               else "the fence file is not readable JSON")
            + "); absence of a matching journal is not authority over it "
            "— verify outstanding obligations, then remove the fence "
            "explicitly or record its owning attempt")


def _write_fence_exclusive(path: pathlib.Path, attempt: str) -> None:
    """Atomically take a fence that was observed ABSENT (round-5 finding
    1): O_CREAT|O_EXCL means a concurrent operator fence can never be
    raced-over between the check and the write."""
    body = json.dumps({
        "reason": "milestone-21 preserving upgrade in progress",
        "started_at": _now(),
        "attempt": attempt,
        "note": "new work refused with 503; terminality callbacks allowed"},
        indent=2, sort_keys=True) + "\n"
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    except FileExistsError:
        kind, owner = _fence_identity(path)
        raise UpgradeError(
            "an admission fence was created concurrently (identity "
            f"{kind} {owner!r}); this attempt stops WITHOUT touching it")
    with os.fdopen(fd, "w") as fh:
        fh.write(body)


def _require_fence_owner(path: pathlib.Path, attempt: str) -> None:
    """Finalization gate (round-5 finding 1): the fence must STILL be
    verifiably ours before the version stamp or any release of admission.
    A fence swapped, stripped or removed during the run keeps its bytes
    and the attempt stays blocked and resumable."""
    kind, owner = _fence_identity(path)
    if kind == "owned" and owner == attempt:
        return
    why = {"absent": "the fence file disappeared during the attempt",
           "unreadable": "the fence file is no longer readable JSON",
           "anonymous": "the fence no longer names an owning attempt"}.get(
               kind, f"the fence now belongs to attempt {owner!r}")
    raise UpgradeError(
        f"admission fence ownership is unresolved: {why} — this process "
        "neither stamps a release nor opens admission; the fence (if any) "
        "is kept byte-exact and the attempt stays in progress")


def run_upgrade(m, layout, payload: ReleasePayload, *, db_url: str,
                resume: str | None = None, dry_run: bool = False,
                python_exe: str | None = None, pg_dump_bin: str | None = None,
                provision_hook=None, restart_hook=None,
                skip_provision: bool = False, skip_frontend: bool = False,
                allow_fresh_install: bool = False,
                maintenance_flag: pathlib.Path | None = None,
                web_url: str = "http://127.0.0.1:3000/",
                credential_env_names: tuple[str, ...] = ()) -> dict:
    """Run (or resume) one preserving upgrade.  Returns the journal.

    Ordering is part of the safety contract (milestone 21 review):
    unfinished attempt beats every no-op answer; the payload is verified
    before anything qualifies; the maintenance/admission fence goes up
    BEFORE the durable-work quiescence is consulted and stays up across
    backup, activation, provisioning, migration and restart; the version
    stamp is written only after the restart and readiness verification
    succeeded; and the fence drops only on a COMPLETED attempt."""
    python_exe = python_exe or default_migration_python(layout)
    if credential_env_names:
        # register the SELECTED credential variable name(s) so EVERY
        # unauthorized child env is scrubbed by name, not pattern
        # (round-4 finding 3); the one authorized migration channel
        # passes its URL explicitly, never by ambient inheritance.
        from deploy import appliance_services as _svc0
        _svc0.note_credential_env_names(credential_env_names)
    journal = Journal(layout.etc)
    fence = (pathlib.Path(maintenance_flag) if maintenance_flag
             else pathlib.Path(layout.state) / "maintenance")
    if not layout.sandboxed and os.geteuid() != 0:
        raise UpgradeError("upgrade on the real appliance requires root "
                           "(or --system-root for a sandbox)")

    other = journal.in_progress(exclude=resume)
    if other:
        raise UpgradeError(
            "upgrade refused: attempt(s) of unknown completion exist: "
            f"{other} — resume one explicitly (--resume) or resolve it; "
            "starting a second upgrade around unknown work is not offered")

    # A RESUMED attempt is an unfinished fact, not an already-upgraded
    # answer: it is loaded and validated BEFORE any no-op question is
    # asked, so an interrupted upgrade can never be "no-op"ed away.
    prior: dict | None = None
    if resume:
        prior = journal.load(resume)
        if prior.get("status") == "done":
            raise UpgradeError(f"attempt {resume} is already done")
        if prior.get("payload_sha256") != payload.sha256:
            raise UpgradeError(
                f"attempt {resume} was started against a different payload "
                f"(digest {prior.get('payload_sha256')!r} != "
                f"{payload.sha256!r}); resuming with substituted bytes is "
                "refused")

    report = preflight(m, layout, payload, db_url=db_url,
                       python_exe=python_exe,
                       allow_fresh_install=allow_fresh_install)
    if prior is not None:
        # the attempt's own recorded chain facts win over any fresh
        # computation: resume continues THAT upgrade
        report = report | {
            "no_op": False,
            "from_revision": prior.get("from_revision", "unknown"),
            "to_revision": prior.get("to_revision", payload.revision),
            "from_heads": prior.get("from_heads", []),
            "to_head": prior.get("to_head"),
        }
    if report.get("no_op"):
        return {"no_op": True, **report}
    if dry_run:
        return {"dry_run": True, "preflight": report}

    # --- attempt + admission fence ---------------------------------------- #
    # NEW work is refused from here until the attempt completes (or the
    # operator resolves it). The fence records WHICH attempt owns it
    # (round-4 finding 2) and is a mutex TOKEN whose ownership is
    # validated on ACQUISITION, atomically (round-5 finding 1): a foreign,
    # anonymous or unreadable fence is refused and kept byte-exact — an
    # upgrade never destructively "takes ownership" — and acquisition of
    # an absent fence uses an exclusive create, so a concurrent operator
    # cannot be raced between the check and the write.
    fence.parent.mkdir(parents=True, exist_ok=True)
    kind0, owner0 = _fence_identity(fence)
    fence_kept = kind0 == "owned" and prior is not None and owner0 == resume
    if not fence_kept:
        # validated BEFORE any mutation and before the journal attempt
        # exists: a refusal here leaves zero side effects
        _require_fence_takeable(kind0, owner0)
    if prior is not None:
        attempt = resume
    else:
        attempt = journal.create(meta={
            "kind": "upgrade", "from_revision": report["from_revision"],
            "to_revision": report["to_revision"],
            "from_heads": report["from_heads"], "to_head": report["to_head"],
            "payload_sha256": payload.sha256,
            "manifest_sha256": hashlib.sha256(
                json.dumps(m.raw, sort_keys=True).encode()).hexdigest(),
        })
    if not fence_kept:
        _write_fence_exclusive(fence, attempt)

    att = journal.path(attempt)
    os.chmod(att, 0o700)
    out: dict = {"attempt": attempt}

    # ---------------- stage: quiesce (the barrier OLD code cannot ignore) -- #
    # The fence file refuses new work in NEW code; the admission services
    # being STOPPED is what an old, fence-unaware running process cannot
    # bypass. The authoritative durable re-check then runs while nothing
    # that admits work is alive — a request that entered before the fence
    # is caught here, before any mutation, instead of being upgraded under.
    if journal.load(attempt)["stages"].get("quiesce", {}).get("status") \
            != "done":
        journal.mark(attempt, "quiesce", "started",
                     units=list(ADMISSION_UNITS))
        from deploy.appliance import Runner as _R
        from deploy.appliance import sandbox_manifest as _sm
        try:
            if shutil.which("systemctl"):
                stop_admission_services(_R(dry_run=False))
                quiesced_note = ("stopped and proven inactive: "
                                 + ", ".join(ADMISSION_UNITS))
            else:
                # sandbox without a service manager (or its double): the
                # durable re-check below is still authoritative, and the
                # scope of this proof is recorded, never inflated.
                quiesced_note = ("no service manager present: sandbox "
                                 "scope, durable re-check only")
            raced = quiescence_problems(_sm(m, pathlib.Path(layout.root)),
                                        db_url=db_url,
                                        allow_fresh_install=allow_fresh_install)
            if raced:
                raise UpgradeError(
                    "upgrade refused after the fence went up and admission "
                    f"services were stopped — work exists at the boundary: "
                    f"{raced}. Attempt {attempt} stays in progress with "
                    "the fence UP and the admission services left STOPPED "
                    "(fail closed, nothing resumes itself); resolve the "
                    f"work and `--resume {attempt}`")
        except UpgradeError as exc:
            journal.mark(attempt, "quiesce", "refused",
                         error=str(exc)[-400:])
            raise
        journal.mark(attempt, "quiesce", "done", note=quiesced_note)
    out["quiesced"] = True

    # ---------------- stage: backup (private, durable manifest) ----------- #
    if journal.load(attempt)["stages"].get("backup", {}).get("status") != "done":
        journal.mark(attempt, "backup", "started")
        config_backup = att / "config-backup"
        # the journal tree is NEVER config: it is mutable attempt state
        # that changes during this very walk (and a restore must never
        # roll back journals — not this attempt's, not another's)
        files = _copy_tree_private(pathlib.Path(layout.etc), config_backup,
                                   exclude_rel="upgrade")
        (att / "config-backup-manifest.json").write_text(json.dumps(
            {"taken_at": _now(), "files": files}, indent=2, sort_keys=True))
        dump = att / "database.dump"
        if not (dump.is_file() and dump.stat().st_size > 0):
            from deploy import appliance_services as _svc
            with _OwnerCredential(db_url) as cred:
                argv = (_resolve_dump_binary(pg_dump_bin)
                        + _dump_endpoint_args(cred)
                        + ["--format=custom", "--file", str(dump) + ".part"])
                # the dump child gets endpoint argv + PGPASSFILE only: the
                # ambient owner URL is scrubbed (round-3 finding 5; the
                # gate's pg_dump wrapper proves nothing else arrives)
                child_env = {k: v for k, v in os.environ.items()
                             if k not in _svc.credential_env_names()}
                child_env.update(cred.env())
                proc = subprocess.run(
                    argv, capture_output=True, text=True, timeout=3600,
                    env=child_env)
            if proc.returncode != 0 or not (dump.with_suffix(".dump.part").is_file()):
                journal.mark(attempt, "backup", "failed",
                             error=f"pg_dump exit {proc.returncode}: "
                                   f"{(proc.stdout + proc.stderr)[-400:]}")
                raise UpgradeError("database backup failed; nothing was "
                                   "mutated: "
                                   + (proc.stdout + proc.stderr)[-400:])
            os.replace(dump.with_suffix(".dump.part"), dump)
        (att / "db-backup-manifest.json").write_text(json.dumps({
            "taken_at": _now(), "file": dump.name, "sha256": _sha256(dump),
            "bytes": dump.stat().st_size, "format": "custom",
            "database": redact_url(db_url),
            "restore_hint": "pg_restore --no-owner -d <url> database.dump "
                            "(operator-gated; the upgrade never restores "
                            "over a live schema automatically)"},
            indent=2, sort_keys=True))
        journal.mark(attempt, "backup", "done",
                     db_sha256=_sha256(dump), config_files=len(files))
    out["backup"] = str(att / "config-backup-manifest.json")

    # ---------------- stage: staged copy + digest verification ------------ #
    if journal.load(attempt)["stages"].get("stage", {}).get("status") != "done":
        journal.mark(attempt, "stage", "started")
        staged = att / "staged"
        for rel, want in sorted(payload.runtime.items()):
            src = payload.dir / rel
            target = staged / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.is_file() and _sha256(target) == want:
                continue
            shutil.copyfile(src, target)
            if _sha256(target) != want:
                journal.mark(attempt, "stage", "failed", file=rel)
                raise UpgradeError(f"staged copy of {rel} does not match "
                                   "the bundle digest")
        (att / "stage-manifest.json").write_text(json.dumps(
            {"payload_sha256": payload.sha256, "files": payload.runtime},
            indent=2, sort_keys=True))
        journal.mark(attempt, "stage", "done", files=len(payload.runtime))
    out["staged"] = str(att / "staged")

    # ---------------- stage: activate (live runtime swap, per-file atomic)  #
    if journal.load(attempt)["stages"].get("activate", {}).get("status") != "done":
        journal.mark(attempt, "activate", "started")
        staged = att / "staged"
        changed = []
        for rel, want in sorted(payload.runtime.items()):
            target = layout.prefix / rel
            source = staged / rel
            if target.is_file() and _sha256(target) == want:
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            tmp = target.with_name(target.name + ".sr-upgrade")
            shutil.copyfile(source, tmp)
            shutil.copymode(source, tmp)
            if _sha256(tmp) != want:
                os.unlink(tmp)
                journal.mark(attempt, "activate", "failed", file=rel)
                raise UpgradeError(
                    f"refusing to activate {rel}: staged bytes drifted after "
                    "staging (post-staging tamper)")
            os.replace(tmp, target)
            changed.append(rel)
        # verify the LIVE tree, not the copy we just wrote from
        drift = [rel for rel, want in sorted(payload.runtime.items())
                 if not (layout.prefix / rel).is_file()
                 or _sha256(layout.prefix / rel) != want]
        if drift:
            journal.mark(attempt, "activate", "failed",
                         files=",".join(drift[:5]), count=len(drift))
            raise UpgradeError(
                f"activation verification failed for {len(drift)} runtime "
                f"file(s) (e.g. {drift[:3]}); attempt stays in progress")
        journal.mark(attempt, "activate", "done", changed=len(changed))
    out["activated"] = True

    # ---------------- stage: provision (the release must RUN, not just
    # ---------------- exist: locked deps, entrypoints, frontend) ---------- #
    if not skip_provision and (
            journal.load(attempt)["stages"].get("provision", {})
            .get("status") != "done"):
        journal.mark(attempt, "provision", "started")
        from deploy.appliance import Runner
        try:
            hook = provision_hook or provision_release
            # LIVE-05: the frontend bakes NEXT_PUBLIC_API_URL at BUILD time.
            # An upgrade that provisions without the manifest's public URL
            # leaves the browser talking to localhost:8000 — a healthy
            # appliance whose login page cannot submit. The install path
            # always passed it; the upgrade path now does too.
            receipt = (hook(layout, payload, run=Runner(dry_run=False),
                            skip_frontend=skip_frontend,
                            public_url=getattr(m, "public_url", ""))
                       if provision_hook is None
                       else hook(layout, payload))
            (att / "provision-receipt.json").write_text(
                json.dumps(receipt, indent=2, sort_keys=True, default=str))
        except Exception as exc:  # noqa: BLE001 — any failure keeps the fence
            journal.mark(attempt, "provision", "failed",
                         error=str(exc)[-400:])
            raise UpgradeError(
                f"provisioning the activated release failed: {exc} — "
                f"services were NOT restarted (the OLD runtime keeps "
                f"serving under the maintenance fence); fix the cause and "
                f"`--resume {attempt}` re-runs only the unfinished stages") \
                from exc
        journal.mark(attempt, "provision", "done",
                     web="skipped" if skip_frontend else "built")
    out["provisioned"] = "skipped" if skip_provision else "done"

    # ---------------- stage: secret-store bootstrap (round-3 finding 1) ---- #
    # 0021 GRANTs to sr_secret; a real 0019 appliance has never seen that
    # role. The installer provisions it at install; an upgrade brings the
    # SAME identity up through the SAME channel BEFORE the chain steps on
    # it — no operator SQL, no manual prereq, idempotent on resume.
    if journal.load(attempt)["stages"].get("secrets", {}).get("status") \
            != "done":
        journal.mark(attempt, "secrets", "started")
        from deploy.appliance import Runner as _Rs
        try:
            secret_receipt = bootstrap_secret_store(
                layout, run=_Rs(dry_run=False), db_url=db_url)
        except (UpgradeError, RuntimeError) as exc:
            journal.mark(attempt, "secrets", "failed",
                         error=str(exc)[-400:])
            raise UpgradeError(
                f"credential-store bootstrap failed before migration: {exc} "
                "— attempt stays in progress with the fence up; the "
                "database was not migrated") from exc
        journal.mark(attempt, "secrets", "done", **secret_receipt)

    # ---------------- stage: forward migrations (proven, never guessed) --- #
    stages = journal.load(attempt)["stages"]
    migrate = stages.get("migrate", {})

    def _chain_to_head() -> set[str]:
        """to_head plus every ancestor revision the payload declares."""
        revs = migration_revisions(payload.versions_dir())
        chain, pending = set(), [report["to_head"]]
        while pending:
            rev = pending.pop()
            if rev in chain or rev not in revs:
                continue
            chain.add(rev)
            down = revs[rev]
            if down:
                pending.append(down)
        return chain

    if migrate.get("status") == "started":
        # interrupted mid-migration: prove where the schema actually is
        now_heads = db_heads(db_url)
        if now_heads == {report["to_head"]}:
            journal.mark(attempt, "migrate", "done",
                         heads=sorted(now_heads),
                         note="proven complete after interruption")
        elif (len(now_heads) == 1
              and now_heads <= _chain_to_head()
              and now_heads != set(report["from_heads"])):
            journal.mark(attempt, "migrate", "requeued",
                         heads=sorted(now_heads),
                         note="stopped at a proven intermediate revision; "
                              "continuing forward only")
        elif now_heads == set(report["from_heads"]):
            journal.mark(attempt, "migrate", "requeued",
                         heads=sorted(now_heads),
                         note="proven still at the old head")
        else:
            raise UpgradeError(
                "migration state UNKNOWN after interruption: database "
                f"reports {sorted(now_heads)}, expected a forward position "
                f"in {sorted(_chain_to_head())} from "
                f"{sorted(set(report['from_heads']))}. "
                f"Attempt {attempt} stays in progress; resolve the schema "
                "before ANY further upgrade (never guessed, never forced)")
        migrate = journal.load(attempt)["stages"]["migrate"]
    if migrate.get("status") != "done":
        journal.mark(attempt, "migrate", "started",
                     from_heads=report["from_heads"],
                     to_head=report["to_head"])
        try:
            after, skipped = forward_migrate(
                python_exe, db_url, str(layout.prefix),
                payload.versions_dir(), set(report["from_heads"]),
                report["to_head"], journal=journal, attempt=attempt)
        except UpgradeError as exc:
            heads_now = db_heads(db_url)
            journal.mark(attempt, "migrate", "failed",
                         error=str(exc)[-400:], heads=sorted(heads_now))
            raise UpgradeError(
                f"{exc} — attempt {attempt} preserved; data and config "
                "were not touched") from exc
        if after != {report["to_head"]}:
            journal.mark(attempt, "migrate", "failed",
                         heads=sorted(after), error="did not reach head")
            raise UpgradeError(
                f"migrations ended at {sorted(after)}, not "
                f"{report['to_head']!r}")
        journal.mark(attempt, "migrate", "done", heads=sorted(after),
                     **({"prerequisite_skips": skipped} if skipped else {}))
    out["migrated_to"] = report["to_head"]

    # ---------------- stage: finalize (config re-render only) -------------- #
    if journal.load(attempt)["stages"].get("finalize", {}).get("status") != "done":
        journal.mark(attempt, "finalize", "started")
        from deploy.appliance import (Runner, render_files, sandbox_manifest,
                                      _write_files)
        lay = layout
        plan = render_files(sandbox_manifest(m, lay.root), layout=lay)
        rewritten = _write_files(plan.files, Runner(dry_run=False), lay)
        journal.mark(attempt, "finalize", "done",
                     config_rewritten=len(rewritten))
        (att / "restart-units.json").write_text(
            json.dumps(sorted(plan.units), indent=2) + "\n")

    # ---------------- stage: restart + readiness (the release must be
    # ---------------- RUNNING before anything claims it is installed) ----- #
    # The version stamp is the LAST durable fact written, only after the
    # restart and readiness verification passed: a stamp means "this
    # revision is live", and writing it before the restart advertised a
    # release that had never executed.
    if journal.load(attempt)["stages"].get("restart", {}).get("status") \
            != "done":
        from deploy.appliance import Runner as _Runner, render_files as _rf, \
            sandbox_manifest as _smf
        intended = sorted(_rf(_smf(m, layout.root),
                              layout=layout).units)
        journal.mark(attempt, "restart", "started", units=intended)
        try:
            if restart_hook is not None:
                restarted = restart_hook(intended) or intended
            elif not shutil.which("systemctl"):
                # sandbox without a service manager (nor a `systemctl`
                # double on PATH): honest operator-pending, never a claim
                restarted = intended
                out["restart_pending_operator"] = intended
            else:
                runner = _Runner(dry_run=False)
                # finalize may have rewritten unit files: the manager must
                # reload its units BEFORE a restart honors them (round-3
                # finding 3) — a stale in-memory unit restarting the old
                # ExecStart looked active while the release never ran.
                reload_proc = runner("systemctl", "daemon-reload",
                                     check=False)
                if reload_proc.returncode != 0:
                    raise UpgradeError(
                        "systemctl daemon-reload exited "
                        f"{reload_proc.returncode}: "
                        f"{(reload_proc.stdout + reload_proc.stderr)[-200:]}"
                        " — rewritten units would not be honored")
                restarted = checked_service_restart(runner, intended)
            if "restart_pending_operator" not in out:
                # active != ready: the bounded REAL HTTP probes must
                # satisfy the parsed readiness contract (ready true, no
                # issues, THIS payload's schema head) before the stamp or
                # the fence-clear.
                wait_for_readiness(m, web_url=web_url,
                                   expected_head=report["to_head"])
            # round-5 finding 1: ownership is re-verified THROUGH
            # finalization — if anything replaced or stripped the fence
            # while this attempt worked (readiness gap included), this
            # process keeps the fence byte-exact and refuses to stamp.
            _require_fence_owner(fence, attempt)
            out["restarted"] = restarted
        except UpgradeError as exc:
            journal.mark(attempt, "restart", "failed", error=str(exc)[-400:])
            raise UpgradeError(
                f"{exc} — the version stamp was NOT written (no false "
                f"success), attempt {attempt} stays in progress with the "
                "fence up; fix and "
                f"`--resume {attempt}` (restart re-runs only)") from exc
        version_file(layout).write_text(json.dumps({
            "revision": payload.revision,
            "payload_sha256": payload.sha256,
            "migration_head": report["to_head"],
            "from_revision": report["from_revision"],
            "upgraded_at": _now(), "attempt": attempt},
            indent=2, sort_keys=True) + "\n")
        journal.mark(attempt, "restart", "done", restarted=len(restarted))

    result = journal.finish(attempt, finished_at=_now(),
                            revision=payload.revision,
                            migration_head=report["to_head"]) | out
    # Only a COMPLETED attempt releases the admission fence — and ONLY
    # when the fence is verifiably OWNED by this attempt, exactly (exact
    # round-5 finding 1): a fence whose identity is absent-in-file,
    # anonymous, unreadable or foreign is NEVER cleared, and its
    # retention is reported truthfully instead.
    kind1, owner1 = _fence_identity(fence)
    if kind1 == "owned" and owner1 == attempt:
        fence.unlink(missing_ok=True)
    else:
        result["maintenance_fence"] = (
            f"RETAINED after completion — ownership is {kind1} "
            f"{owner1!r}, not exactly attempt {attempt}; releasing it is "
            "an explicit, verified recovery decision")
    return result


# --------------------------------------------------------------------------- #
# quiesced restore (config only — never starts or resumes anything)           #
# --------------------------------------------------------------------------- #

def restore_config(m, layout, attempt: str, *, dry_run: bool = False) -> dict:
    """Restore the configuration tree from an attempt's verified backup.

    This function issues NO service command at all — no stop, no start,
    no restart, no resume.  A restored appliance therefore always comes
    back through the operator's own start sequence and can never be
    un-paused into an engagement by a restore.
    """
    journal = Journal(layout.etc)
    data = journal.load(attempt)
    att = journal.path(attempt)
    manifest = json.loads((att / "config-backup-manifest.json").read_text())
    restored = _restore_tree(att / "config-backup", manifest,
                             pathlib.Path(layout.etc), dry_run=dry_run)
    entry = dict(data)
    entry.setdefault("restores", []).append(
        {"at": _now(), "files": len(restored), "dry_run": dry_run,
         "note": "config-only restore; no service was started or resumed"})
    # Round-3 finding 4: a config rollback is NOT admission recovery. A
    # restoring config does not roll back the activated runtime, the
    # forward-only schema, or the admission services this attempt stopped
    # — so for an UNFINISHED attempt the fence stays UP: the box keeps
    # refusing new work until the operator completes it (`--resume`) or
    # resolves it through a verified recovery. Dropping the fence here
    # would un-pause an appliance whose runtime state is, by construction,
    # unknown. Only a restore against an already-DONE attempt (the attempt
    # completed; this is a plain config rollback) clears a fence.
    fence = pathlib.Path(layout.state) / "maintenance"
    unfinished = data.get("status") != "done"
    # Round-4 finding 2: the decision is made against the WHOLE appliance,
    # not just the selected attempt. A config restore may release the
    # admission fence ONLY when (a) this attempt is done, (b) NO other
    # attempt is unresolved, and (c) the fence (if present) is verifiably
    # owned by THIS attempt. An unknown/foreign/unreadable fence identity
    # is kept: releasing it would open admission while an obligation the
    # restore knows nothing about still exists, and the restore can never
    # roll back the runtime or the forward-only schema.
    fence_cleared = False
    other = sorted(set(journal.in_progress()) - {attempt})
    if dry_run:
        fence_state = "unchanged (dry run)"
    elif unfinished:
        fence_state = ("KEPT — attempt unfinished; complete it with "
                       f"--resume {attempt} or resolve it explicitly "
                       "before admission resumes")
    elif other:
        fence_state = (f"KEPT — attempt(s) {other} are still unresolved; "
                       "restoring a completed attempt's config may never "
                       "release an admission fence that protects work "
                       "those attempts own")
    elif not fence.is_file():
        fence_cleared = True
        fence_state = "cleared (attempt done, no other obligation, no fence present)"
    else:
        try:
            fence_owner = json.loads(fence.read_text()).get("attempt")
        except Exception:  # noqa: BLE001 — unknown identity: fail closed
            fence_owner = "unreadable"
        if fence_owner == attempt:
            fence.unlink(missing_ok=True)
            fence_cleared = True
            fence_state = "cleared (attempt done and fence was its own)"
        elif fence_owner in (None, "unreadable"):
            fence_state = ("KEPT — fence identity is missing/unreadable; "
                           "an explicit verified recovery must release it, "
                           "never a config restore")
        else:
            fence_state = (f"KEPT — fence belongs to attempt {fence_owner!r}, "
                           "not the restored one")
    entry["restores"][-1]["maintenance_fence"] = fence_state
    journal._save(attempt, entry)
    return {"restored": len(restored), "dry_run": dry_run,
            "service_actions": [], "attempt": attempt,
            "maintenance_fence": fence_state,
            "maintenance_fence_cleared": fence_cleared,
            "operator_next_step": "review config; for an unfinished attempt"
                                  " the fence REMAINS and admission stays "
                                  "refused — resume the attempt or resolve "
                                  "it; nothing was started or resumed"}
