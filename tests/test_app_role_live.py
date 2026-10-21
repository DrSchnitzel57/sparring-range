"""Live app-role permission proof (review find 2026-10-15).

Static SQL assertions live in test_app_role_grants.py; this runs the real
grants: fresh disposable schema through 0016+0017, then the app role itself
attempts each operation class. Append-only history must refuse mutation
(trigger and/or grant denial) while mutable workflow tables keep full DML.
Uncommitted: every write rolls back on close.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.db

DENIED = "(?i)denied|not permitted|append-only"


class _savepoint:
    """Each denied statement aborts its transaction; isolate every negative
    probe in a savepoint and assert the denial from the savepoint error."""

    def __init__(self, conn):
        self.conn = conn

    def __enter__(self):
        self.sp = self.conn.begin_nested()
        self.sp.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.sp.__exit__(exc_type, exc, tb)
        if exc_type is None:
            raise AssertionError("expected a permission denial, statement succeeded")
        import re
        assert re.search(DENIED, str(exc)), f"unexpected error (not a denial): {exc!r}"
        return True



def test_app_role_live_boundaries(migrated_db, test_db_url_app):
    import sqlalchemy as sa
    eng = sa.create_engine(test_db_url_app)
    try:
        with eng.connect() as c:
            sid = c.execute(sa.text(
                "INSERT INTO sessions (session_id, scenario_id, status) "
                "VALUES (gen_random_uuid(), 'probe', 'open') "
                "RETURNING session_id")).scalar()
            # mutable workflow tables keep full DML
            c.execute(sa.text("UPDATE sessions SET status='shut' "
                              "WHERE session_id=:s"), {"s": str(sid)})
            # append-only history: insert yes, mutate no
            c.execute(sa.text(
                "INSERT INTO events (session_id, ts, actor, action_type, payload) "
                "VALUES (:s, now(), 'probe', 'probe', '{}')"), {"s": str(sid)})
            with _savepoint(c):
                c.execute(sa.text("UPDATE events SET actor='x' "
                                  "WHERE actor='probe'"))
            with _savepoint(c):
                c.execute(sa.text("DELETE FROM events WHERE actor='probe'"))
            c.execute(sa.text(
                "INSERT INTO uptime_samples "
                "(session_id, deployment_id, host, state) "
                "VALUES (:s, 'd1', 'h1', 'unknown')"), {"s": str(sid)})
            with _savepoint(c):
                c.execute(sa.text("DELETE FROM uptime_samples "
                                  "WHERE session_id=:s"), {"s": str(sid)})
            # migration metadata: read yes, write no
            assert c.execute(
                sa.text("SELECT version_num FROM alembic_version")
            ).scalar() == "0019"
            with _savepoint(c):
                c.execute(sa.text("UPDATE alembic_version "
                                  "SET version_num='0000'"))
    finally:
        eng.dispose()
