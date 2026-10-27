"""Plan 19 review ROUND 4, finding 2 (upgrade half): a POPULATED
pre-0023 database — holding the escaped state the old defect produced
(cancelled logical root with queued retry children) — must not survive
the upgrade dispatchable.

These tests drive the REAL Alembic path (0022 first, populate raw rows
in exactly the old schema's columns, then upgrade head), then verify
through the PRODUCTION admission statement that nothing from a
cancelled logical chain can claim, that a failed parent's ordinary
retry chain is untouched, and that running/cessation-unknown
obligations keep their state and the slot.
"""
from __future__ import annotations

import os
import subprocess
import sys
import uuid

import pytest
from sqlalchemy import create_engine, text

from tests.conftest import (PY, REPO_ROOT, _admin_endpoint, _admin_sql)

pytestmark = pytest.mark.db


def _alembic(rev: str, urls: dict, names: dict) -> None:
    env = {**os.environ,
           "POSTGRES_URL_OWNER": urls["owner"],
           "POSTGRES_URL": urls["app"],
           "POSTGRES_URL_SECRET": urls["secret"],
           "DB_APP_ROLE": names["app"], "DB_SECRET_ROLE": names["secret"]}
    r = subprocess.run([PY, "-m", "alembic", "upgrade", rev],
                       cwd=str(REPO_ROOT), env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0, f"alembic {rev} failed:\n{r.stdout}\n{r.stderr}"


@pytest.fixture()
def legacy_db(pg_names, migrated_db):
    """A SECOND disposable database, migrated to 0022 by the real CLI,
    populated by the test, upgraded by the test, dropped exactly."""
    host, port = _admin_endpoint()
    db = f"srtest_r4{uuid.uuid4().hex[:8]}"
    n = pg_names
    _admin_sql(f"CREATE DATABASE {db} OWNER {n['owner']} "
               "ENCODING 'UTF8' TEMPLATE template0 LC_COLLATE 'C' "
               "LC_CTYPE 'C'")
    urls = {
        "owner": (f"postgresql+psycopg2://{n['owner']}:{n['owner_pw']}"
                  f"@{host}:{port}/{db}"),
        "app": (f"postgresql+psycopg2://{n['app']}:{n['app_pw']}"
                f"@{host}:{port}/{db}"),
        "secret": (f"postgresql+psycopg2://{n['secret']}:{n['secret_pw']}"
                   f"@{host}:{port}/{db}"),
    }
    try:
        yield db, urls, n
    finally:
        _admin_sql(f"DROP DATABASE IF EXISTS {db} WITH (FORCE)")


def _populate_0022(url: str, rows: list[tuple]) -> None:
    """Insert rows using ONLY the columns that existed at 0022 (no
    cancel_intent, no chain_root — that is the point)."""
    eng = create_engine(url)
    with eng.begin() as c:
        for jid, kind, state, parent, attempt, err in rows:
            c.execute(text(
                "INSERT INTO model_jobs (job_id, kind, priority, state, "
                " attempt, parent_job, error, payload) "
                "VALUES (:j, :k, 5, :s, :a, :p, :e, '{\"mode\":\"text\"}'::jsonb)"),
                {"j": str(jid), "k": kind, "s": state, "a": attempt,
                 "p": str(parent) if parent else None,
                 "e": err})
    eng.dispose()


def _fetch(url: str) -> dict:
    eng = create_engine(url)
    out = {}
    with eng.connect() as c:
        for row in c.execute(text(
                "SELECT job_id, state, cancel_intent, chain_root "
                "FROM model_jobs")):
            out[str(row[0])] = {"state": row[1], "intent": row[2],
                                "root": str(row[3]) if row[3] else None}
    eng.dispose()
    return out


def _claim_next(url: str):
    """Run the PRODUCTION admission statement against the upgraded
    database — the same SQL the scheduler runs — without persisting the
    claim (rolled back)."""
    from srplatform.model_jobs import _CLAIM_SQL
    eng = create_engine(url)
    try:
        with eng.connect() as c:
            row = c.execute(_CLAIM_SQL).first()
            c.rollback()
        return str(row[0]) if row else None
    finally:
        eng.dispose()


def test_populated_pre0023_escaped_chain_is_fenced_by_upgrade(legacy_db):
    db, urls, names = legacy_db
    _alembic("0022", urls, names)

    escaped_root = uuid.uuid4()
    escaped_child = uuid.uuid4()
    escaped_gchild = uuid.uuid4()
    ordinary_parent = uuid.uuid4()
    ordinary_child = uuid.uuid4()
    obligation = uuid.uuid4()
    _populate_0022(urls["owner"], [
        (escaped_root, "text", "cancelled", None, 1,
         "cancelled by member before execution"),
        (escaped_child, "text", "queued", escaped_root, 2, None),
        (escaped_gchild, "text", "queued", escaped_child, 3, None),
        (ordinary_parent, "text", "failed", None, 1,
         "upstream 500 — retry attempt 2/3 queued"),
        (ordinary_child, "text", "queued", ordinary_parent, 2, None),
        (obligation, "text", "cessation_unknown", None, 1,
         "provider-side cessation cannot be confirmed"),
    ])
    _alembic("head", urls, names)

    rows = _fetch(urls["owner"])
    # escaped logical request: fully fenced, fully cancelled, chain
    # identity backfilled to the root
    for jid in (escaped_root, escaped_child, escaped_gchild):
        r = rows[str(jid)]
        assert r["intent"] is True, f"{jid} survived without the fence"
        assert r["root"] == str(escaped_root)
    assert rows[str(escaped_child)]["state"] == "cancelled"
    assert rows[str(escaped_gchild)]["state"] == "cancelled"
    # ordinary failed parent: retry chain EXACTLY as it was
    assert rows[str(ordinary_parent)]["state"] == "failed"
    assert rows[str(ordinary_parent)]["intent"] is False
    assert rows[str(ordinary_child)]["state"] == "queued"
    assert rows[str(ordinary_child)]["intent"] is False
    # the unknown-cessation obligation keeps its state — the slot
    # stays held; reconciliation never converts an obligation away
    assert rows[str(obligation)]["state"] == "cessation_unknown"

    eng = create_engine(urls["owner"])
    with eng.connect() as c:
        err = c.execute(text(
            "SELECT error FROM model_jobs WHERE job_id = :j"),
            {"j": str(escaped_child)}).scalar_one()
    eng.dispose()
    assert "fence reconciliation" in err

    # and the production admission statement agrees: with the
    # obligation holding the slot nothing claims; release it and ONLY
    # the ordinary retry may ever be admitted.
    assert _claim_next(urls["owner"]) is None
    eng = create_engine(urls["owner"])
    with eng.begin() as c:
        c.execute(text(
            "UPDATE model_jobs SET state='cessation_resolved', "
            "resolved_by='operator', resolution='test release', "
            "resolved_at=now() WHERE job_id = :j"),
            {"j": str(obligation)})
    eng.dispose()
    assert _claim_next(urls["owner"]) == str(ordinary_child)


def test_running_obligation_in_a_cancelled_chain_survives_as_obligation(
        legacy_db):
    """A cancelled logical request whose live child the old defect
    never terminalized: the upgrade keeps the LIVE row's state (an
    obligation is never silently resolved), stamps the fence so the
    chain can never grow or dispatch again, and cancels the queued
    descendant."""
    db, urls, names = legacy_db
    _alembic("0022", urls, names)
    root = uuid.uuid4()
    live = uuid.uuid4()
    queued = uuid.uuid4()
    _populate_0022(urls["owner"], [
        (root, "text", "cancelled", None, 1, "cancelled by member"),
        (live, "text", "running", root, 2, None),
        (queued, "text", "queued", live, 3, None),
    ])
    _alembic("head", urls, names)
    rows = _fetch(urls["owner"])
    assert rows[str(live)]["state"] == "running"     # obligation stands
    assert rows[str(live)]["intent"] is True         # and is fenced
    assert rows[str(queued)]["state"] == "cancelled"
    assert rows[str(queued)]["intent"] is True
    # production reconciliation turns the running row into a
    # cessation_unknown obligation (never a silent success) — and the
    # slot stays held for the operator. reconcile_startup works on any
    # session, so it runs HERE, on this database, directly:
    from sqlalchemy.orm import Session
    from srplatform import model_jobs
    with Session(create_engine(urls["owner"])) as s:
        model_jobs.reconcile_startup(s)
        s.commit()
    rows = _fetch(urls["owner"])
    assert rows[str(live)]["state"] == "cessation_unknown"
    assert rows[str(live)]["intent"] is True
    assert _claim_next(urls["owner"]) is None        # slot held
