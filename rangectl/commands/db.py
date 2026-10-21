"""rangectl db — the one sanctioned exception to the API-front-door rule:
migrations run Alembic as the schema-OWNER role (the app role lacks DDL and its
append-only revocations would fight the migrator).
"""
import os
import subprocess
import sys
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


def _alembic_config(root: Path) -> str:
    """The alembic.ini to use, with script_location pointing at the
    migrations that ship with the installed package."""
    ini = root / "alembic.ini"
    if not ini.is_file():
        ini = Path(__file__).resolve().parents[2] / "alembic.ini"
    return str(ini)


@app.command("migrate")
def migrate():
    """Apply Alembic migrations (schema backbone, Part 4)."""
    s = get_settings()
    env_var = {"POSTGRES_URL_OWNER": s.postgres_url_owner,
               "DB_APP_ROLE": s.db_app_role}
    env = {**os.environ, **env_var}
    root = _alembic_root()
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", _alembic_config(root),
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
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", _alembic_config(root), "current"],
        cwd=str(root), env=env)
    raise typer.Exit(result.returncode)
