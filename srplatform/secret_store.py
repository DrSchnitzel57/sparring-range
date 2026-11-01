"""Provider-credential store behind a SEPARATE minimal DB identity
(review finding 8).

Why this exists: 0020 kept provider keys in ``model_profiles.api_key``,
which the APPLICATION role could SELECT — but the ingestion plane shares
that role, so "only the API can read keys" was false under the deployed
DB identity. Since 0021 the key lives only in ``model_profile_secrets``,
a table with grants to exactly ONE role: the secret identity behind
``postgres_url_secret`` (``SR_PG_SECRET_URL``). That role is granted
nothing else — not events, not sessions, nothing — so stealing the
ingest or worker DB credential cannot read a provider key, and stealing
the secret credential can read nothing but keys.

Honest limits: this is DB-role isolation, not per-process encryption;
the API process holds BOTH connections and is the only code allowed to
use them together. Values never travel over HTTP, into events, logs or
exports; only presence (``api_key_set``) and use are ever observable.
"""
from __future__ import annotations

import threading
import uuid

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

_engines: dict[str, Engine] = {}
_lock = threading.Lock()


def _configured_url() -> str:
    from srplatform.settings import get_settings
    url = get_settings().postgres_url_secret
    if not url:
        raise RuntimeError(
            "postgres_url_secret is not configured: provider credentials "
            "are unreachable. Point SR_PG_SECRET_URL at the dedicated "
            "secret-role connection (see docs/ARCHITECTURE.md); there is "
            "deliberately no fallback to the application role")
    return url


def secret_engine() -> Engine:
    """Own engine, own role, own pool — NEVER the app or owner engine."""
    url = _configured_url()
    with _lock:
        eng = _engines.get(url)
        if eng is None:
            eng = create_engine(url, pool_pre_ping=True, pool_size=2,
                                max_overflow=2)
            _engines[url] = eng
        return eng


def dispose() -> None:
    """Test/settings-swap teardown."""
    with _lock:
        for eng in _engines.values():
            eng.dispose()
        _engines.clear()


def set_key(profile_id, api_key: str) -> None:
    with secret_engine().begin() as conn:
        conn.execute(text(
            "INSERT INTO model_profile_secrets (profile_id, api_key, "
            "updated_at) VALUES (:p, :k, now()) "
            "ON CONFLICT (profile_id) DO UPDATE "
            "SET api_key = EXCLUDED.api_key, updated_at = now()"),
            {"p": str(profile_id), "k": api_key or ""})


def get_key(profile_id) -> str | None:
    with secret_engine().begin() as conn:
        row = conn.execute(text(
            "SELECT api_key FROM model_profile_secrets WHERE profile_id = :p"),
            {"p": str(profile_id)}).first()
    return row[0] if row else None


def delete_key(profile_id) -> None:
    with secret_engine().begin() as conn:
        conn.execute(text(
            "DELETE FROM model_profile_secrets WHERE profile_id = :p"),
            {"p": str(profile_id)})


def keyed_profile_ids() -> set[str]:
    with secret_engine().begin() as conn:
        rows = conn.execute(text(
            "SELECT profile_id FROM model_profile_secrets "
            "WHERE api_key <> ''")).scalars().all()
    return {str(r) for r in rows}


def has_key(profile_id) -> bool:
    with secret_engine().begin() as conn:
        return conn.execute(text(
            "SELECT 1 FROM model_profile_secrets WHERE profile_id = :p "
            "AND api_key <> ''"), {"p": str(profile_id)}).first() is not None
