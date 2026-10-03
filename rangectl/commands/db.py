"""rangectl db — the one sanctioned exception to the API-front-door rule:
migrations run Alembic as the schema-OWNER role (the app role lacks DDL and its
append-only revocations would fight the migrator).
"""
import subprocess
import sys
from pathlib import Path

import typer

from srplatform.settings import get_settings

REPO_ROOT = Path(__file__).resolve().parents[2]
app = typer.Typer(no_args_is_help=True)


@app.command("migrate")
def migrate():
    """Apply Alembic migrations (schema backbone, Part 4)."""
    s = get_settings()
    env_var = {"POSTGRES_URL_OWNER": s.postgres_url_owner, "DB_APP_ROLE": s.db_app_role}
    import os

    env = {**os.environ, **env_var}
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=REPO_ROOT,
        env=env,
    )
    raise typer.Exit(result.returncode)


@app.command("status")
def status():
    """Show Alembic migration status."""
    s = get_settings()
    import os

    env = {**os.environ, "POSTGRES_URL_OWNER": s.postgres_url_owner, "DB_APP_ROLE": s.db_app_role}
    result = subprocess.run([sys.executable, "-m", "alembic", "current"], cwd=REPO_ROOT, env=env)
    raise typer.Exit(result.returncode)
