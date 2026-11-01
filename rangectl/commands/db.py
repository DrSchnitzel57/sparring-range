"""rangectl db — the one sanctioned exception to the API-front-door rule:
migrations run Alembic as the schema-OWNER role (the app role lacks DDL and its
append-only revocations would fight the migrator).
"""
from contextlib import contextmanager
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import typer

from srplatform.settings import get_settings

app = typer.Typer(no_args_is_help=True)


def _alembic_root() -> Path:
    """Where the migrations live for THIS installation.

    A development checkout has alembic.ini in the repository root; an
    installed appliance has the package under site-packages and no checkout
    at all.  The lookup therefore follows the installed package first and
    only falls back to the checkout layout, so `rangectl db migrate` works in
    both without a hand-set path.
    """
    env = os.environ.get("SR_ALEMBIC_ROOT")
    if env:
        return Path(env)
    try:
        import srplatform

        migrations = Path(srplatform.__file__).resolve().parent / "db" / "migrations"
        if migrations.is_dir():
            return migrations.parent.parent.parent
    except Exception:  # noqa: BLE001 — the checkout fallback below applies
        pass
    return Path(__file__).resolve().parents[2]


#: Minimal complete ini for the PURE installed case (no tree copy, no ini
#: beside site-packages). Alembic resolves a relative script_location
#: against the process CWD and `migrations/env.py` runs fileConfig(), so
#: the fallback carries absolute paths AND the logging sections. The
#: fast regression in tests/test_plan18_installed_cli.py proves this
#: fallback migrates the same schema as the checked-in ini.
_FALLBACK_INI = """[alembic]
script_location = {root}
prepend_module_path = {pkgroot}
# URL is resolved from POSTGRES_URL_OWNER by env.py (schema owner only).
sqlalchemy.url =

[loggers]
keys = root,sqlalchemy,alembic

[handlers]
keys = console

[formatters]
keys = generic

[logger_root]
level = WARN
handlers = console

[logger_sqlalchemy]
level = WARN
handlers =
qualname = sqlalchemy.engine

[logger_alembic]
level = INFO
handlers =
qualname = alembic

[handler_console]
class = StreamHandler
args = (sys.stderr,)
level = NOTSET
formatter = generic

[formatter_generic]
format = %(levelname)-5.5s [%(name)s] %(message)s
"""


def _migrations_dir(root: Path) -> Path:
    """Where the migration scripts actually live for this installation."""
    candidate = root / "srplatform" / "db" / "migrations"
    if candidate.is_dir():
        return candidate
    import srplatform  # the resolved root must contain the package anyway
    installed = Path(srplatform.__file__).resolve().parent / "db" / "migrations"
    if installed.is_dir():
        return installed
    return candidate


def _alembic_config(root: Path) -> str:
    """An alembic config with ABSOLUTE paths for THIS installation.

    The checked-in alembic.ini spells script_location relative to the
    project root, which Alembic resolves against the process CWD: outside
    the checkout (a non-editable install, or any other working directory
    combined with an ``SR_ALEMBIC_ROOT`` override) the migrations were
    silently invisible and `rangectl db migrate/status` failed with a
    path error that looked like a broken installation.  This materialises
    a deterministic config whose script_location and module path are the
    real, absolute locations, so the CLI works from anywhere.
    """
    migrations = _migrations_dir(root)
    ini = root / "alembic.ini"
    if not ini.is_file():
        ini = Path(__file__).resolve().parents[2] / "alembic.ini"
    if ini.is_file():
        lines = []
        for line in ini.read_text().splitlines():
            stripped = line.strip()
            if stripped.startswith("script_location"):
                lines.append(f"script_location = {migrations}")
            elif stripped.startswith("prepend_module_path"):
                lines.append(f"prepend_module_path = {root}")
            else:
                lines.append(line)
        body = "\n".join(lines) + "\n"
    else:
        body = _FALLBACK_INI.format(root=migrations, pkgroot=root)
    # no cached shared-temp copy (review finding): a predictable
    # /tmp/sr-alembic-<digest>.ini invites another local user to pre-plant
    # content we would then TRUST (the reuse check read whatever was there)
    # or a symlink to aim our writes.  The config is a few hundred bytes:
    # write a fresh 0600 file OWNED by this invocation (mkstemp is O_EXCL,
    # unguessable) and remove it when the caller is done.
    fd, raw = tempfile.mkstemp(prefix="sr-alembic-", suffix=".ini")
    with os.fdopen(fd, "w") as fh:
        fh.write(body)
    return raw


@contextmanager
def _alembic_config_path(root: Path):
    """Context form of _alembic_config: the private config exists exactly
    for the duration of the alembic invocation."""
    path = _alembic_config(root)
    try:
        yield path
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass  # already gone: nothing else may own our mkstemp name


@app.command("migrate")
def migrate():
    """Apply Alembic migrations (schema backbone, Part 4)."""
    s = get_settings()
    env_var = {"POSTGRES_URL_OWNER": s.postgres_url_owner,
               "DB_APP_ROLE": s.db_app_role}
    env = {**os.environ, **env_var}
    root = _alembic_root()
    with _alembic_config_path(root) as cfg:
        result = subprocess.run(
            [sys.executable, "-m", "alembic", "-c", cfg,
             "upgrade", "head"],
            cwd=str(root),
            env=env,
        )
    raise typer.Exit(result.returncode)


@app.command("status")
def status():
    """Show Alembic migration status."""
    s = get_settings()
    env = {**os.environ, "POSTGRES_URL_OWNER": s.postgres_url_owner,
           "DB_APP_ROLE": s.db_app_role}
    root = _alembic_root()
    with _alembic_config_path(root) as cfg:
        result = subprocess.run(
            [sys.executable, "-m", "alembic", "-c", cfg, "current"],
            cwd=str(root), env=env)
    raise typer.Exit(result.returncode)
