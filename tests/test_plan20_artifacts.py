"""Plan 20 durable artifacts: coach conversation + timed operation output.

Both are APPEND-ONLY evidence: the real grants and triggers are probed
with the app role itself (the same savepoint-denial pattern as
test_app_role_live.py), and the operation-output identity contract
(unique run/op/seq) is proven so worker re-delivery cannot duplicate
replay bytes.
"""
from __future__ import annotations

import re

import pytest
from sqlalchemy import text

pytestmark = pytest.mark.db

DENIED = "(?i)denied|not permitted|append-only"
CHECK = "(?i)violates check constraint"
UNIQUE = "(?i)unique|duplicate key"


class _expect:
    """Each failing statement aborts its transaction; isolate the probe in
    a savepoint and assert the EXPECTED error class from it."""

    def __init__(self, conn, pattern=DENIED):
        self.conn = conn
        self.pattern = pattern

    def __enter__(self):
        self.sp = self.conn.begin_nested()
        self.sp.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        self.sp.__exit__(exc_type, exc, tb)
        if exc_type is None:
            raise AssertionError("expected a rejection, statement succeeded")
        assert re.search(self.pattern, str(exc)), \
            f"unexpected error: {exc!r}"
        return True


@pytest.fixture()
def _seed(migrated_db, test_db_url_app):
    import sqlalchemy as sa
    eng = sa.create_engine(test_db_url_app)
    with eng.begin() as c:
        sid = c.execute(sa.text(
            "INSERT INTO sessions (session_id, scenario_id, status) "
            "VALUES (gen_random_uuid(), 'probe', 'open') "
            "RETURNING session_id")).scalar()
        rid = c.execute(sa.text(
            "INSERT INTO runs (run_id, session_id, scenario_id, status) "
            "VALUES (gen_random_uuid(), :s, 'probe', 'running') "
            "RETURNING run_id"),
            {"s": str(sid)}).scalar()
    yield eng, str(sid), str(rid)
    eng.dispose()


def test_coach_messages_append_only_under_app_role(_seed):
    eng, sid, _rid = _seed
    with eng.connect() as c:
        c.execute(text("INSERT INTO coach_messages (session_id, role, body) "
                       "VALUES (:s, 'user', 'how do i start?')"),
                  {"s": sid})
        assert c.execute(text(
            "SELECT count(*) FROM coach_messages WHERE session_id = :s"),
            {"s": sid}).scalar() == 1
        with _expect(c):          # append-only trigger
            c.execute(text("UPDATE coach_messages SET body = 'rewritten'"))
        with _expect(c):
            c.execute(text("DELETE FROM coach_messages"))
        with _expect(c, CHECK):   # role CHECK: only user/coach exist
            c.execute(text("INSERT INTO coach_messages (session_id, role, "
                           "body) VALUES (:s, 'system', 'x')"), {"s": sid})
    c.rollback()


def test_operation_outputs_append_only_and_idempotent_identity(_seed):
    eng, sid, rid = _seed
    with eng.connect() as c:
        c.execute(text(
            "INSERT INTO operation_outputs (run_id, session_id, op_id, seq, "
            "kind, text) VALUES (:r, :s, 'op-1', 0, 'output', 'hello')"),
            {"r": rid, "s": sid})
        with _expect(c, UNIQUE):  # unique (run_id, op_id, seq): re-delivery
            c.execute(text(
                "INSERT INTO operation_outputs (run_id, session_id, op_id, "
                "seq, kind, text) VALUES (:r, :s, 'op-1', 0, 'output', "
                "'duplicate')"), {"r": rid, "s": sid})
        with _expect(c):
            c.execute(text("UPDATE operation_outputs SET text = 'x'"))
        with _expect(c):
            c.execute(text("DELETE FROM operation_outputs"))
        with _expect(c, CHECK):   # honest kinds only
            c.execute(text(
                "INSERT INTO operation_outputs (run_id, session_id, op_id, "
                "seq, kind) VALUES (:r, :s, 'op-1', 1, 'silently-missing')"),
                {"r": rid, "s": sid})
        # gap/truncated markers are first-class honest rows
        c.execute(text(
            "INSERT INTO operation_outputs (run_id, session_id, op_id, seq, "
            "kind, dropped_bytes) VALUES (:r, :s, 'op-1', 1, 'gap', 4096)"),
            {"r": rid, "s": sid})
        assert c.execute(text(
            "SELECT dropped_bytes FROM operation_outputs WHERE seq = 1"
        )).scalar() == 4096
    c.rollback()
