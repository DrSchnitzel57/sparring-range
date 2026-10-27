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
        self.manifest = json.loads(manifest_path.read_text())
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

    def verify(self) -> None:
        problems = []
        for rel, want in self.runtime.items():
            path = self.dir / rel
            if not path.is_file():
                problems.append(f"missing: {rel}")
            elif _sha256(path) != want:
                problems.append(f"digest mismatch: {rel}")
        if problems:
            raise UpgradeError(
                "upgrade payload failed digest verification: "
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

    ``exclude_rel`` skips the attempt's OWN live journal directory: that
    file changes every stage (and mkstemp-replaces it while the backup
    runs), it is never config to restore, and a config restore must not
    roll back the journal that records the restore.
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
        shutil.copyfile(path, target)
        mode = path.stat().st_mode & 0o777 & ~0o077
        os.chmod(target, mode)
        entries[rel] = {"sha256": src_sha, "mode": f"{mode:04o}",
                        "bytes": target.stat().st_size}
    return entries


def _restore_tree(backup: pathlib.Path, manifest: dict, dst: pathlib.Path,
                  *, dry_run: bool) -> list[str]:
    problems = []
    restored = []
    for rel, meta in sorted((manifest.get("files") or {}).items()):
        src = backup / rel
        if not src.is_file():
            problems.append(f"backup missing {rel}")
            continue
        if _sha256(src) != meta.get("sha256"):
            problems.append(f"backup digest mismatch {rel}")
            continue
        target = dst / rel
        if dry_run:
            restored.append(str(target))
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp = target.with_name(target.name + ".sr-restore")
        shutil.copyfile(src, tmp)
        os.chmod(tmp, int(str(meta.get("mode", "0600")), 8) & ~0o022)
        os.replace(tmp, target)
        restored.append(str(target))
    if problems:
        raise UpgradeError("restore refused — the backup is not intact: "
                           + "; ".join(problems[:5]))
    return restored


def _resolve_dump_binary(override: str | None) -> list[str]:
    """The pg_dump invocation. The override is a path to a binary or
    wrapper that accepts the exact argv ``[bin, '--format=custom',
    '--file', OUT, URL]`` (the upgrade gate uses a wrapper around a real
    pg_dump inside its own fixture container; nothing synthetic is
    dumped either way — the artifact is a restoreable custom-format dump).
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

def quiescence_problems(m) -> list[str]:
    """Durable facts that mean the range has work in flight."""
    ledger_path = pathlib.Path(m.broker_ledger)
    if not ledger_path.is_file():
        return []  # nothing ever claimed: quiesced
    from infra.broker.ledger import Ledger
    ledger = Ledger(str(ledger_path))
    problems = []
    try:
        latch = ledger.get_latch()
        if latch.get("latched"):
            problems.append(f"range is LATCHED ({latch.get('reason')})")
        lease = ledger.get_lease()
        if lease.get("armed"):
            problems.append(f"runner lease armed (holder={lease.get('holder')})")
        for name in ("pending_intents", "active_claims", "open_obligations"):
            rows = getattr(ledger, name)()
            if rows:
                problems.append(f"{len(rows)} {name} outstanding")
    finally:
        ledger.close()
    return problems


def preflight(m, layout, payload: ReleasePayload, *, db_url: str | None,
              python_exe: str) -> dict:
    """Every refusal happens HERE, before a single byte changes."""
    problems: list[str] = []
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
                        "--db-url): a preserving upgrade must be able to "
                        "verify and back the schema up")

    if payload_head and live_heads == {payload_head} and current.get(
            "revision") == payload.revision:
        return {"no_op": True, "reason": "already at payload revision",
                "revision": payload.revision, "problems": []}

    from deploy.appliance import sandbox_manifest
    problems += [f"not quiesced: {p}" for p in quiescence_problems(
        sandbox_manifest(m, pathlib.Path(layout.root)))]

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
        env = {**os.environ, "POSTGRES_URL_OWNER": db_url}
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


def run_upgrade(m, layout, payload: ReleasePayload, *, db_url: str,
                resume: str | None = None, dry_run: bool = False,
                python_exe: str | None = None, pg_dump_bin: str | None = None,
                provision_hook=None, restart_hook=None) -> dict:
    """Run (or resume) one preserving upgrade.  Returns the journal."""
    python_exe = python_exe or sys.executable
    journal = Journal(layout.etc)
    if not layout.sandboxed and os.geteuid() != 0:
        raise UpgradeError("upgrade on the real appliance requires root "
                           "(or --system-root for a sandbox)")

    other = journal.in_progress(exclude=resume)
    if other:
        raise UpgradeError(
            "upgrade refused: attempt(s) of unknown completion exist: "
            f"{other} — resume one explicitly (--resume) or resolve it; "
            "starting a second upgrade around unknown work is not offered")

    report = preflight(m, layout, payload, db_url=db_url,
                       python_exe=python_exe)
    if report.get("no_op"):
        return {"no_op": True, **report}
    if dry_run:
        return {"dry_run": True, "preflight": report}

    if resume:
        data = journal.load(resume)
        if data.get("status") == "done":
            raise UpgradeError(f"attempt {resume} is already done")
        if data.get("payload_sha256") != payload.sha256:
            raise UpgradeError(
                f"attempt {resume} was started against a different payload "
                f"(digest {data.get('payload_sha256')!r} != "
                f"{payload.sha256!r}); resuming with substituted bytes is "
                "refused")
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

    att = journal.path(attempt)
    os.chmod(att, 0o700)
    out: dict = {"attempt": attempt}

    # ---------------- stage: backup (private, durable manifest) ----------- #
    if journal.load(attempt)["stages"].get("backup", {}).get("status") != "done":
        journal.mark(attempt, "backup", "started")
        config_backup = att / "config-backup"
        files = _copy_tree_private(pathlib.Path(layout.etc), config_backup)
        (att / "config-backup-manifest.json").write_text(json.dumps(
            {"taken_at": _now(), "files": files}, indent=2, sort_keys=True))
        dump = att / "database.dump"
        if not (dump.is_file() and dump.stat().st_size > 0):
            argv = _resolve_dump_binary(pg_dump_bin) + [
                "--format=custom", "--file", str(dump) + ".part", db_url]
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=3600)
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
        if provision_hook is not None:
            out["provision"] = provision_hook(layout, payload)
        journal.mark(attempt, "activate", "done", changed=len(changed))
    out["activated"] = True

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

    # ---------------- stage: finalize (config render, version, restart) --- #
    if journal.load(attempt)["stages"].get("finalize", {}).get("status") != "done":
        journal.mark(attempt, "finalize", "started")
        from deploy.appliance import (Runner, render_files, sandbox_manifest,
                                      _write_files)
        lay = layout
        plan = render_files(sandbox_manifest(m, lay.root), layout=lay)
        rewritten = _write_files(plan.files, Runner(dry_run=False), lay)
        version_file(lay).write_text(json.dumps({
            "revision": payload.revision,
            "payload_sha256": payload.sha256,
            "migration_head": report["to_head"],
            "from_revision": report["from_revision"],
            "upgraded_at": _now(), "attempt": attempt},
            indent=2, sort_keys=True) + "\n")
        intended = list(plan.units)
        if restart_hook is not None:
            restart_hook(intended)
            out["restarted"] = intended
        else:
            out["restart_pending_operator"] = intended
        journal.mark(attempt, "finalize", "done",
                     config_rewritten=len(rewritten))
    return journal.finish(attempt, finished_at=_now(),
                          revision=payload.revision,
                          migration_head=report["to_head"]) | out


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
    journal._save(attempt, entry)
    return {"restored": len(restored), "dry_run": dry_run,
            "service_actions": [], "attempt": attempt,
            "operator_next_step": "review config, then start services "
                                  "yourself; nothing was started or resumed"}
