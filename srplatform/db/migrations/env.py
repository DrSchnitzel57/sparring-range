"""Alembic env — resolves the DB URL from POSTGRES_URL_OWNER (schema owner).

The application role is never used for migrations (it lacks DDL and the
append-only revocations would fight the migrator).
"""
from __future__ import annotations

import os
import sys
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine

from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from srplatform.db.models import Base  # noqa: E402

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def _url() -> str:
    url = os.environ.get("POSTGRES_URL_OWNER") or config.get_main_option("sqlalchemy.url")
    if not url:
        raise RuntimeError("POSTGRES_URL_OWNER not set — `rangectl db migrate` runs as the schema owner role")
    return url


def run_migrations_offline() -> None:
    context.configure(url=_url(), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(_url())
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
