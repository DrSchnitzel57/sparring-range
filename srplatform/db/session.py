"""DB access helpers. The API (and only the API) talks to Postgres; the CLI and
web app are HTTP clients (Part 3 front-door rule). Alembic uses the OWNER URL;
everything at runtime uses the app-role URL so the append-only revocations bite.
"""
from __future__ import annotations

from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from srplatform.settings import get_settings


@lru_cache
def owner_engine():
    return create_engine(get_settings().postgres_url_owner, pool_size=5, pool_pre_ping=True)


@lru_cache
def app_engine():
    return create_engine(get_settings().postgres_url, pool_size=5, pool_pre_ping=True)


@contextmanager
def db():
    """Runtime session — app role (append-only enforced against this role)."""
    maker = sessionmaker(app_engine(), expire_on_commit=False)
    s = maker()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


@contextmanager
def owner_db():
    """Owner session — used ONLY by tests/migration verification, not app writes."""
    maker = sessionmaker(owner_engine(), expire_on_commit=False)
    s = maker()
    try:
        yield s
        s.commit()
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()
