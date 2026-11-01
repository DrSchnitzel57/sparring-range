"""Milestone-21 pulled release blockers — real proofs.

F1: legacy coach history fails CLOSED across the real upgrade path and
the HTTP boundary; a schema paused at 0026 cannot serve coach threads.
F2: quota admission is always enforced (null-text rows included) and a
second truncation marker is a controlled protocol answer, never a 500.
F3: a POPULATED 0025 database with legacy duplicate truncation markers
upgrades to head through the supported prerequisite — applied 0026
byte-identical, every legacy row still present.
F4: the delivery path is absolutely bounded (dribbling endpoint).
"""
from __future__ import annotations

import hashlib
import http.client
import os
import socket
import subprocess
import sys
import threading
import time
import uuid as U
from urllib.parse import urlsplit, urlunsplit

import pytest
from sqlalchemy import MetaData, Table, create_engine, text

from srplatform.db.session import db as db_ctx

pytestmark = pytest.mark.db

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKDOOR = "PRE0026_SEALED_OPERATOR_BACKDOOR"


def _admin() -> str:
    url = os.environ.get("SR_PG_ADMIN_URL")
    if not url:
        pytest.skip("requires SR_PG_ADMIN_URL (disposable admin)")
    return url


_SUF = U.uuid4().hex[:6]
APP_ROLE = f"sra_p21{_SUF}"
SECRET_ROLE = f"srs_p21{_SUF}"


@pytest.fixture(autouse=True)
def _grant_roles():
    admin = _admin()
    eng = create_engine(admin, isolation_level="AUTOCOMMIT")
    with eng.connect() as c:
        for role in (APP_ROLE, SECRET_ROLE):
            exists = c.execute(text(
                "SELECT 1 FROM pg_roles WHERE rolname=:r"),
                {"r": role}).first()
            if not exists:
                c.execute(text(f'CREATE ROLE "{role}"'))
    eng.dispose()
    yield
    eng = create_engine(admin, isolation_level="AUTOCOMMIT")
    with eng.connect() as c:
        for role in (APP_ROLE, SECRET_ROLE):
            c.execute(text(f'DROP ROLE IF EXISTS "{role}"'))
    eng.dispose()


def _at(url: str, dbname: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, f"/{dbname}", p.query, p.fragment))


def _alembic(url: str, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m", "alembic", *args],
                          cwd=REPO, capture_output=True, text=True,
                          timeout=600,
                          env={**os.environ, "POSTGRES_URL_OWNER": url,
                               "DB_APP_ROLE": APP_ROLE,
                               "DB_SECRET_ROLE": SECRET_ROLE})


def _mkdb(name: str) -> str:
    admin = _admin()
    eng = create_engine(admin, isolation_level="AUTOCOMMIT")
    with eng.connect() as c:
        c.execute(text(f'CREATE DATABASE {name} OWNER '
                       f'"{urlsplit(admin).username}" ENCODING \'UTF8\' '
                       "TEMPLATE template0 LC_COLLATE 'C' LC_CTYPE 'C'"))
    eng.dispose()
    return _at(admin, name)


def _dropdb(name: str) -> None:
    admin = _admin()
    eng = create_engine(admin, isolation_level="AUTOCOMMIT")
    with eng.connect() as c:
        c.execute(text("SELECT pg_terminate_backend(pid) FROM "
                       f"pg_stat_activity WHERE datname='{name}'"))
        c.execute(text(f"DROP DATABASE IF EXISTS {name}"))
    eng.dispose()


def _insert_min(conn, table: str, overrides: dict) -> None:
    """Insert a row satisfying NOT NULLs only, on the CALLER's
    connection (FK triggers are off there: session_replication_role was
    set in the same transaction — synthetic fixture rows in a throwaway
    database; nothing schema- or data-modifying)."""
    md = MetaData()
    tbl = Table(table, md, autoload_with=conn)
    row: dict = {}
    for col in tbl.columns:
        if col.name in overrides:
            row[col.name] = overrides[col.name]
        elif not col.nullable and col.default is None \
                and col.server_default is None and not col.autoincrement:
            n = col.name.lower()
            if n.endswith("_id"):
                row[col.name] = str(U.uuid4())
            elif "at" in n or n.endswith("ts"):
                row[col.name] = "2026-10-27T00:00:00+00:00"
            else:
                t = str(col.type).upper()
                row[col.name] = ("x" if "CHAR" in t or "TEXT" in t
                                 else 0)
    conn.execute(tbl.insert().values(**row))


def _populate_0025(url: str) -> None:
    """Synthetic legacy data: sealed old operator-history row plus TWO
    truncation markers for ONE operation (the pre-fix duplicate the 0025
    schema permitted and 0026's index cannot hold). All parents are
    created by NOT NULL introspection; FK triggers are off for the
    fixture inserts (session_replication_role), nothing is altered."""
    eng = create_engine(url)
    sid, rid = str(U.uuid4()), str(U.uuid4())
    with eng.begin() as c:
        c.execute(text("SET session_replication_role = replica"))
        _insert_min(c, "sessions", {"session_id": sid})
        _insert_min(c, "runs", {"run_id": rid, "session_id": sid})
        _insert_min(c, "coach_messages",
                    {"session_id": sid, "role": "coach",
                     "body": f"sealed operator note {BACKDOOR} keep"})
        for seq in (1, 2):
            _insert_min(c, "operation_outputs",
                        {"run_id": rid, "session_id": sid,
                         "op_id": "op-legacydup", "seq": seq,
                         "kind": "truncated", "text": "legacy marker"})
    eng.dispose()


def test_populated_0025_upgrade_preserves_every_row_and_fails_closed(
        monkeypatch):
    from deploy.upgrade import db_heads, forward_migrate
    import pathlib
    monkeypatch.setenv("DB_APP_ROLE", APP_ROLE)
    monkeypatch.setenv("DB_SECRET_ROLE", SECRET_ROLE)
    name = f"srtest_p21a_{U.uuid4().hex[:8]}"
    url = _mkdb(name)
    try:
        assert _alembic(url, "upgrade", "0025").returncode == 0
        _populate_0025(url)

        # the defect itself, proven: plain forward upgrade of the real
        # chain FAILS on 0026's un-guarded index — 0027 alone cannot
        # help, because 0026 runs first.
        naive = _alembic(url, "upgrade", "head")
        assert naive.returncode != 0
        assert "uq_operation_outputs_truncated_once" in (
            naive.stdout + naive.stderr)
        assert db_heads(url) == {"0025"}

        heads, skipped = forward_migrate(
            sys.executable, url, REPO,
            pathlib.Path(REPO) / "srplatform/db/migrations/versions",
            {"0025"}, "0027")
        assert heads == {"0027"}
        assert skipped == ["0026:uq_operation_outputs_truncated_once"]

        eng = create_engine(url)
        with eng.connect() as c:
            # every legacy row survived, unmodified
            dups = c.execute(text(
                "SELECT count(*) FROM operation_outputs WHERE kind = "
                "'truncated' AND op_id = 'op-legacydup'")).scalar()
            assert dups == 2
            # F1: the unknowable-audience row is FAIL-CLOSED legacy,
            # never silently member
            aud = c.execute(text("SELECT audience FROM coach_messages")
                            ).scalars().all()
            assert aud == ["legacy"]
            # 0027 catch-up applied 0026's other effects (skipped path)
            assert c.execute(text(
                "SELECT 1 FROM information_schema.columns WHERE "
                "table_name='operation_outputs' AND column_name='read_ts'"
            )).first()
            fwd = c.execute(text(
                "SELECT 1 FROM pg_indexes WHERE indexname = "
                "'uq_op_outputs_truncated_once_forward'")).first()
            assert fwd
            glob = c.execute(text(
                "SELECT 1 FROM pg_indexes WHERE indexname = "
                "'uq_operation_outputs_truncated_once'")).first()
            assert glob is None  # the skipped index (legacy duplicates)
            # forward guard is LIVE: a NEW duplicate marker per op is a
            # database impossibility from 0027 on
            ids = c.execute(text("SELECT run_id, session_id FROM "
                                 "operation_outputs LIMIT 1")).first()
        with eng.begin() as c:
            c.execute(text("SET session_replication_role = replica"))
            c.execute(text("INSERT INTO operation_outputs (run_id, "
                           "session_id, op_id, seq, kind, text) VALUES "
                           "(:r,:s,'op-newfwd',10,'truncated','m')"),
                      {"r": ids[0], "s": ids[1]})
        with eng.connect() as c:
            c.execute(text("SET session_replication_role = replica"))
            with pytest.raises(Exception) as exc:
                c.execute(text(
                    "INSERT INTO operation_outputs (run_id, session_id,"
                    " op_id, seq, kind, text) VALUES (:r,:s,:o,11,"
                    "'truncated','dup')"),
                    {"r": ids[0], "s": ids[1], "o": "op-newfwd"})
            assert "uq_op_outputs_truncated_once_forward" in str(exc.value)
        eng.dispose()
    finally:
        _dropdb(name)


def test_fence_refuses_coach_history_while_head_is_0026():
    from fastapi import HTTPException
    from deploy.upgrade import db_heads
    from srplatform.api.coach_routes import _require_audience_safe_schema
    name = f"srtest_p21f_{U.uuid4().hex[:8]}"
    url = _mkdb(name)
    try:
        assert _alembic(url, "upgrade", "0026").returncode == 0
        assert db_heads(url) == {"0026"}
        eng = create_engine(url)
        from sqlalchemy.orm import Session
        with Session(eng) as s:
            with pytest.raises(HTTPException) as exc:
                _require_audience_safe_schema(s)
            assert exc.value.status_code == 503
        eng.dispose()
        assert _alembic(url, "upgrade", "head").returncode == 0
        eng = create_engine(url)
        with Session(eng) as s:
            _require_audience_safe_schema(s)   # must NOT raise
        eng.dispose()
    finally:
        _dropdb(name)


def test_metadata_less_job_outcome_never_lands_in_member_thread(client,
                                                                users):
    import types
    from srplatform.api.coach_routes import _coach_chat_result_handler
    from srplatform.db.models import CoachMessage
    sid = client.post("/sessions",
                      json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    job = types.SimpleNamespace(payload={}, result={},
                                session_id=U.UUID(sid),
                                job_id=U.uuid4())
    with db_ctx() as s:
        _coach_chat_result_handler(s, job, success=False)
        s.commit()
        row = s.query(CoachMessage).filter_by(session_id=U.UUID(sid)
                                              ).one()
        assert row.audience == "legacy"


def test_http_history_legacy_only_privileged(client, users):
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    with db_ctx() as s:
        for aud, body in (("legacy", "LEGACY-SEALED-77"),
                          ("member", "MEMBER-OWN-77"),
                          ("operator", "OPERATOR-OWN-77")):
            s.execute(text("INSERT INTO coach_messages (session_id, role,"
                           " body, audience) VALUES (:s,'coach',:b,:a)"),
                      {"s": sid, "b": body, "a": aud})
        s.commit()
    member = client.get(f"/sessions/{sid}/coach/messages",
                        headers=users["member"]).json()
    bodies_m = [m["body"] for m in member["messages"]]
    assert "MEMBER-OWN-77" in bodies_m
    assert "LEGACY-SEALED-77" not in bodies_m
    assert "OPERATOR-OWN-77" not in bodies_m
    op = client.get(f"/sessions/{sid}/coach/messages",
                    headers=users["op"]).json()
    bodies_o = {m["body"]: m["audience"] for m in op["messages"]}
    assert "OPERATOR-OWN-77" in bodies_o
    assert bodies_o.get("LEGACY-SEALED-77") == "legacy"


# ---------------- F2: always-on admission, controlled marker ---------------

def _token(sid) -> tuple[str, str]:
    from srplatform.db.models import Run
    token = f"wk-{U.uuid4().hex}"
    with db_ctx() as s:
        run = Run(session_id=U.UUID(sid), scenario_id="web-foothold-01",
                  status="running",
                  worker_token=hashlib.sha256(token.encode()).hexdigest())
        s.add(run)
        s.flush()
        return str(run.run_id), token


def _op(client, rid, token, name):
    assert client.post(f"/internal/runs/{rid}/operations",
                       json={"op_id": name, "kind": "local"},
                       headers={"X-Worker-Token": token}).status_code == 201


def test_second_explicit_marker_answers_protocol_never_500(client, users):
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    rid, token = _token(sid)
    _op(client, rid, token, "op-m000000000001")
    r1 = client.post(f"/internal/runs/{rid}/operations/op-m000000000001/output",
                     json={"seq": 0, "kind": "truncated", "text": "m1"},
                     headers={"X-Worker-Token": token})
    assert r1.status_code in (200, 201)
    r2 = client.post(f"/internal/runs/{rid}/operations/op-m000000000001/output",
                     json={"seq": 1, "kind": "truncated", "text": "m2"},
                     headers={"X-Worker-Token": token})
    assert r2.status_code == 200, "a duplicate marker must not 500"
    assert r2.json()["status"] in ("quota", "duplicate")


def test_null_text_rows_cannot_cross_the_row_cap(client, users,
                                                 monkeypatch):
    import srplatform.api.app as app_mod
    from srplatform.settings import get_settings
    small = get_settings().model_copy(update={
        "runner_op_capture_bytes": 100_000,
        "runner_session_capture_bytes": 100_000,
        "runner_op_capture_rows": 3})
    monkeypatch.setattr(app_mod, "get_settings", lambda: small)
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    rid, token = _token(sid)
    _op(client, rid, token, "op-n000000000002")
    statuses = [client.post(
        f"/internal/runs/{rid}/operations/op-n000000000002/output",
        json={"seq": i, "kind": "gap", "text": None, "dropped_bytes": 9},
        headers={"X-Worker-Token": token}).json()["status"]
        for i in range(20)]
    assert statuses.count("stored") <= 3
    assert statuses[-1] == "quota"
    with db_ctx() as s:
        n = s.execute(text("SELECT count(*) FROM operation_outputs WHERE "
                           "run_id = :r AND kind <> 'truncated'"),
                      {"r": rid}).scalar()
        markers = s.execute(text("SELECT count(*) FROM operation_outputs "
                                 "WHERE run_id = :r AND kind = 'truncated'"),
                            {"r": rid}).scalar()
    assert n <= 3 and markers == 1


# ---------------- F4: absolutely bounded delivery ---------------------------

class _Dribble(threading.Thread):
    """Sends response BYTES forever — per-read timeouts never fire, only
    an absolute bound can end the request (review F4 root)."""

    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.stop = False

    def run(self):
        while not self.stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            try:
                conn.recv(65536)
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: "
                             b"application/json\r\nTransfer-Encoding: "
                             b"chunked\r\n\r\n")
                while not self.stop:
                    conn.sendall(b"1\r\n{\r\n")   # dribbles forever
                    time.sleep(0.3)
            except OSError:
                pass

    def stop_now(self):
        self.stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def test_dribbling_endpoint_cannot_pin_a_delivery():
    from srplatform.red_agent.transport import HttpTransport
    srv = _Dribble()
    srv.start()
    try:
        t = HttpTransport(f"http://127.0.0.1:{srv.port}", token="x",
                          run_id="r1")
        start = time.monotonic()
        status = t.append_output("op-1", 0, "output", text="hello",
                                 absolute_timeout_s=2.0)
        elapsed = time.monotonic() - start
        assert status == "error"
        assert elapsed < 5.0, (
            f"dribble pinning: delivery took {elapsed:.1f}s > absolute "
            "budget")
    finally:
        srv.stop_now()


def test_consumer_absolutely_bounded_drops_are_counted():
    from srplatform.red_agent.capture import OutputCapture
    started = threading.Event()

    def slow_emit(*a, **k):
        started.set()
        time.sleep(0.4)          # every attempt "fails" slowly
        return "error"

    cap = OutputCapture(slow_emit, chunk_bytes=16, retries=10,
                        retry_backoff_s=0.05, delivery_budget_s=1.2,
                        idle_exit_s=5.0)
    cap.feed(b"payload bytes for the bounded consumer test")
    start = time.monotonic()
    summary = cap.finish()
    finish_elapsed = time.monotonic() - start
    assert finish_elapsed < 8.0, "finish() unbounded — F4 regression"
    assert summary["chunks"] == 0
    assert summary["chunks_failed"] >= 1   # dropped, COUNTED
    # the consumer thread retires absolutely (idle exit + bounded emits)
    deadline = time.monotonic() + 10
    while any(th.name == "output-capture" and th.is_alive()
              for th in threading.enumerate()):
        if time.monotonic() > deadline:
            pytest.fail("capture consumer thread never retired")
        time.sleep(0.1)
