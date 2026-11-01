"""Plan 19 review ROUND 5 — the secret-safe compensation audit.

The remaining blocker at `e07c52a`: ``_record_compensation_failure``
persisted ``str(exc)`` into an append-only admin event. These tests
inject the reviewer's fault with the REAL database — a deliberate
CHECK constraint (a fixture fault, not a production constraint) that
makes the compensation's own secret write fail so PostgreSQL quotes the
failing row, credential included, in ``DETAIL: Failing row contains
(...)`` — and then assert the opposite of a leak: the durable repair
obligation IS present and honest, its error is named by STRUCTURE
(class + SQLSTATE) only, and the secret appears in NO app-role surface:
not the event payload read through the app identity, not session/event
APIs, not a single log record.

Positive behavior stays pinned: with no competing fault a legitimate
rollback restores the credential (round-4 test), and the locked restore
still cannot undo a committed revocation (round-4 TOCTOU test). No
migration edits; migrations 0020..0024 are untouched by this round.
"""
from __future__ import annotations

import json
import logging
import uuid

import pytest
from sqlalchemy import create_engine, select, text

from srplatform import model_admin, secret_store
from srplatform.db.models import Event, ModelProfile

from tests.test_plan19_review_round4 import _create_committed, _raw

pytestmark = pytest.mark.agent

# Short, opaque, pattern-free on purpose: the convention must not
# depend on anything that "looks like a key".
SECRET = "Zk9QrT2vB7xWm4Ld1NhGpR6Y"


def _owner_ddl(owner_url: str, sql: str) -> None:
    eng = create_engine(owner_url)
    try:
        with eng.begin() as c:
            c.execute(text(sql))
    finally:
        eng.dispose()


def _app_read_app_role(app_url: str, sql: str, **params) -> list[str]:
    """Read evidence with the APP identity — the exact role whose
    readability the finding is about."""
    eng = create_engine(app_url)
    try:
        with eng.connect() as c:
            return [str(r[0]) for r in c.execute(text(sql), params)]
    finally:
        eng.dispose()


def _obligations() -> list[dict]:
    with _raw() as s:
        rows = s.execute(select(Event).where(
            Event.action_type
            == "model_admin.profile.secret_compensation_failed")
            .order_by(Event.ts)).scalars().all()
        return [dict(r.payload) for r in rows]


def _arm_poisoned_delete(name: str, poison_sql: str, owner_url: str,
                         s1) -> uuid.UUID:
    """Committed profile + tracked delete + deliberate fault, ready for
    the rollback to trigger a compensation that MUST fail."""
    pid = _create_committed(name, SECRET, session=s1)
    _owner_ddl(owner_url, poison_sql)
    model_admin._delete_secret_tracked(s1, pid)
    assert secret_store.get_key(pid) is None
    s1.execute(select(ModelProfile).where(
        ModelProfile.profile_id == pid))          # open a real transaction
    return pid


def test_compensation_failure_audit_cannot_leak_the_credential(
        client, users, caplog, test_db_url_owner, test_db_url_app):
    """The reviewer's repro, end to end on real PostgreSQL: the restore
    re-inserts the deleted credential, a fixture CHECK refuses that
    value, and PG's IntegrityError DETAIL carries the credential text.
    The obligation must still be durable and honest — with NOTHING
    secret in it."""
    s1 = _raw()
    poison = ("ALTER TABLE model_profile_secrets ADD CONSTRAINT r5_poison "
              f"CHECK (api_key <> '{SECRET}') NOT VALID")
    try:
        pid = _arm_poisoned_delete("r5leak", poison, test_db_url_owner, s1)
        with caplog.at_level(logging.DEBUG, logger="srplatform"):
            s1.rollback()               # fires the guard -> fails -> records

        # 1. the obligation is present, exactly once, and names the op
        notes = [p for p in _obligations() if p["profile_id"] == str(pid)]
        assert len(notes) == 1, \
            "the failed restore vanished — a divergence with no evidence"
        note = notes[0]
        assert note["op"] == "restore-deleted"
        assert "re-align" in note["action_needed"]

        # 2. honest structure: real class, real SQLSTATE (check_violation),
        #    and NO text — the shape cannot contain a value by construction
        assert "IntegrityError" in note["error"] and "23514" in note["error"]
        assert SECRET not in note["error"]

        # 3. the store stays divergent as recorded (the restore did NOT
        #    happen, and nothing claims it did)
        assert secret_store.get_key(pid) is None
        with _raw() as s:
            assert s.get(ModelProfile, pid).status == "active"

        # 4. APP-role readability: raw JSONB (and full row) of every
        #    obligation event, read through the app identity, hold no
        #    credential — and the poisoned row never entered any event.
        raw_rows = _app_read_app_role(
            test_db_url_app,
            "SELECT to_jsonb(e)::text FROM events e "
            "WHERE e.action_type = 'model_admin.profile"
            ".secret_compensation_failed'")
        assert raw_rows, "app role cannot even see the obligation"
        assert all(SECRET not in r for r in raw_rows)
        assert SECRET not in json.dumps([p for p in _obligations()])

        # 5. no log record from the whole sequence carries the credential
        assert SECRET not in caplog.text
    finally:
        _owner_ddl(test_db_url_owner,
                   "ALTER TABLE model_profile_secrets "
                   "DROP CONSTRAINT IF EXISTS r5_poison")
        try:
            secret_store.delete_key(pid)
        except Exception:
            pass
        s1.close()


def test_obligation_write_failure_logs_only_safe_shape(
        client, users, caplog, test_db_url_owner):
    """When even the durable obligation cannot be written (here: a
    deliberate fixture fault refusing that event type), the last-resort
    fallback still records NOTHING secret — class/code structure only —
    states the truth in words (the durable record is missing), and the
    guard never raises out of the rollback and never fakes a success."""
    s1 = _raw()
    poison_secret = ("ALTER TABLE model_profile_secrets ADD CONSTRAINT "
                     f"r5_poison2 CHECK (api_key <> '{SECRET}') NOT VALID")
    poison_events = (
        "ALTER TABLE events ADD CONSTRAINT r5_ev_poison CHECK "
        "(action_type <> 'model_admin.profile.secret_compensation_failed') "
        "NOT VALID")
    pid = None
    try:
        pid = _arm_poisoned_delete("r5leak2", poison_secret,
                                   test_db_url_owner, s1)
        _owner_ddl(test_db_url_owner, poison_events)
        with caplog.at_level(logging.DEBUG):
            s1.rollback()               # compensation fails AND recording fails

        # the failure stayed bounded: the rollback completed, the guard
        # did not explode, and nothing claims the restore succeeded
        assert secret_store.get_key(pid) is None
        assert not [p for p in _obligations() if p["profile_id"] == str(pid)]

        errs = [r for r in caplog.records
                if r.levelno >= logging.ERROR
                and "secret compensation FAILED" in r.getMessage()]
        assert len(errs) == 1, "the un-recordable divergence went silent"
        msg = errs[0].getMessage()
        assert "NOT recorded" in msg and "restore-deleted" in msg
        assert "IntegrityError" in msg and "23514" in msg
        assert SECRET not in msg
        assert SECRET not in caplog.text
    finally:
        _owner_ddl(test_db_url_owner,
                   "ALTER TABLE model_profile_secrets "
                   "DROP CONSTRAINT IF EXISTS r5_poison2")
        _owner_ddl(test_db_url_owner,
                   "ALTER TABLE events DROP CONSTRAINT IF EXISTS r5_ev_poison")
        if pid is not None:
            try:
                secret_store.delete_key(pid)
            except Exception:
                pass
        s1.close()


def test_safe_error_shape_records_structure_never_text():
    """The convention itself, deterministically: a DBAPI-style error
    whose message, params and cause all carry the secret contributes
    NONE of it — only library class names and a 5-character code
    survive. (The two tests above prove the same over the real wire;
    this pins the helper against hand-built adversarial content.)"""
    from sqlalchemy.exc import IntegrityError

    class _Orig(Exception):
        pgcode = "23514"

        def __str__(self):
            return (f"check constraint violates {SECRET}\nDETAIL: Failing "
                    f"row contains (guid,{SECRET},2026-01-01)")

    orig = _Orig()
    exc = IntegrityError(
        f"INSERT INTO model_profile_secrets ... {SECRET}",
        {"k": SECRET}, orig)
    inner = ValueError(f"wrapped {SECRET}")
    inner.__cause__ = exc
    shape = model_admin.safe_error_shape(inner)
    assert SECRET not in shape
    assert "ValueError" in shape and "IntegrityError" in shape
    assert "23514" in shape
    # no infinite chains: cycles terminate
    a, b = RuntimeError("x"), RuntimeError("y")
    a.__cause__, b.__cause__ = b, a
    assert len(model_admin.safe_error_shape(a).split(" <- ")) <= 4
