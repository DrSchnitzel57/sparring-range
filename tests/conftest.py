"""Shared fixtures. DB tests run against a REAL local Postgres (sparring_range_test),
because append-only enforcement is a database-level guarantee and must not be mocked.
Proxmox/GPU/range-host boundaries use test doubles (Drew owns that reality, Part 7).
"""
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
VENV_PY = str(REPO_ROOT / ".venv" / "bin" / "python")

# Point ALL settings at the test DB before anything imports srplatform.settings
# (get_settings is lru-cached on first call). Tests never touch the dev DB.
os.environ["POSTGRES_URL"] = "postgresql+psycopg2://sr_app:sr_app_dev@localhost:5432/sparring_range_test"
os.environ["POSTGRES_URL_OWNER"] = "postgresql+psycopg2://sr_owner:sr_owner_dev@localhost:5432/sparring_range_test"


def _psql_admin(sql: str) -> str:
    return subprocess.run(
        ["su", "postgres", "-c", f'psql -v ON_ERROR_STOP=1 -t -c "{sql.strip().strip(";")}"'],
        capture_output=True, text=True, check=True,
    ).stdout


@pytest.fixture(scope="session")
def test_db_url_app() -> str:
    return os.environ.get(
        "TEST_POSTGRES_URL_APP",
        "postgresql+psycopg2://sr_app:sr_app_dev@localhost:5432/sparring_range_test",
    )


@pytest.fixture(scope="session")
def test_db_url_owner() -> str:
    return os.environ.get(
        "TEST_POSTGRES_URL_OWNER",
        "postgresql+psycopg2://sr_owner:sr_owner_dev@localhost:5432/sparring_range_test",
    )


@pytest.fixture(scope="session")
def migrated_db(test_db_url_owner, test_db_url_app):
    """Fresh schema: drop/recreate the test DB, then run the REAL migration path."""
    _psql_admin("DROP DATABASE IF EXISTS sparring_range_test")
    # explicit UTF8: the cluster default here is SQL_ASCII, which breaks JSONB
    # unicode escapes; Drew's production DB must also be UTF8.
    _psql_admin("CREATE DATABASE sparring_range_test OWNER sr_owner ENCODING 'UTF8' TEMPLATE template0 "
                "LC_COLLATE 'C' LC_CTYPE 'C'")
    env = {**os.environ, "POSTGRES_URL_OWNER": test_db_url_owner, "DB_APP_ROLE": "sr_app"}
    r = subprocess.run([VENV_PY, "-m", "alembic", "upgrade", "head"], cwd=REPO_ROOT, env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0, f"alembic failed:\n{r.stdout}\n{r.stderr}"
    return test_db_url_owner
