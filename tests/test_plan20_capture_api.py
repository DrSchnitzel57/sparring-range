"""Plan 20 internal output plane — worker-authenticated, idempotent,
server-enforced quotas. Real API endpoints, real PostgreSQL, real worker
token hashing: forged op ids and bad tokens are refused; chunk
re-delivery is deduplicated on unique (run_id, op_id, seq); the SERVER
independently enforces the per-operation quota and persists exactly one
honest ``truncated`` marker row, whatever the worker sends.
"""
from __future__ import annotations

import hashlib
import uuid as U

import pytest
from sqlalchemy import text

from srplatform.db.models import Run
from srplatform.db.session import db as db_ctx

pytestmark = pytest.mark.db


def _running_session(client, users):
    return client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                       headers=users["member"]).json()["session_id"]


def _run_with_token(sid) -> tuple[str, str]:
    token = f"wk-{uuid4hex()}"
    with db_ctx() as s:
        run = Run(session_id=U.UUID(sid), scenario_id="web-foothold-01",
                  status="running",
                  worker_token=hashlib.sha256(token.encode()).hexdigest())
        s.add(run)
        s.flush()
        rid = str(run.run_id)
    return rid, token


def uuid4hex() -> str:
    import uuid
    return uuid.uuid4().hex


def _register(client, rid, token, op="op-" + "a" * 12):
    r = client.post(f"/internal/runs/{rid}/operations",
                    json={"op_id": op, "kind": "local"},
                    headers={"X-Worker-Token": token})
    assert r.status_code == 201, r.text
    return op


def _append(client, rid, token, op, **body):
    return client.post(f"/internal/runs/{rid}/operations/{op}/output",
                       json=body, headers={"X-Worker-Token": token})


def test_output_append_requires_worker_and_registered_op(client, users):
    sid = _running_session(client, users)
    rid, token = _run_with_token(sid)
    op = _register(client, rid, token)

    r = _append(client, rid, token, op, seq=0, kind="output", text="hello")
    assert r.status_code == 201 and r.json()["stored"] is True
    assert _append(client, rid, "wrong-token", op, seq=1,
                   text="x").status_code == 403
    forged = "op-" + "f" * 12
    assert _append(client, rid, token, forged, seq=0,
                   text="orphan").status_code == 404
    assert _append(client, rid, token, op, seq=1,
                   kind="silently-missing", text=None).status_code == 422

    with db_ctx() as s:
        rows = s.execute(text(
            "SELECT kind, text FROM operation_outputs WHERE run_id = :r"
            " ORDER BY seq"), {"r": rid}).fetchall()
    assert rows == [("output", "hello")]


def test_chunk_redelivery_is_idempotent(client, users):
    sid = _running_session(client, users)
    rid, token = _run_with_token(sid)
    op = _register(client, rid, token)
    assert _append(client, rid, token, op, seq=0,
                   text="first delivery").json()["stored"] is True
    again = _append(client, rid, token, op, seq=0, text="duplicate")
    assert again.status_code == 201 and again.json()["stored"] is False
    assert again.json()["reason"] == "duplicate"
    with db_ctx() as s:
        assert s.execute(text(
            "SELECT count(*) FROM operation_outputs WHERE run_id = :r"),
            {"r": rid}).scalar() == 1


def test_server_enforces_quota_with_one_marker(client, users, monkeypatch):
    import srplatform.api.app as app_mod
    from srplatform.settings import get_settings
    small = get_settings().model_copy(update={"runner_op_capture_bytes": 10})
    monkeypatch.setattr(app_mod, "get_settings", lambda: small)

    sid = _running_session(client, users)
    rid, token = _run_with_token(sid)
    op = _register(client, rid, token)
    assert _append(client, rid, token, op, seq=0,
                   text="1234567890").json()["stored"] is True
    over = _append(client, rid, token, op, seq=1, text="overflow")
    assert over.json()["stored"] is False and over.json()["reason"] == "quota"
    # later chunks also refuse, but the marker exists exactly ONCE
    assert _append(client, rid, token, op, seq=2,
                   text="more").json()["stored"] is False
    with db_ctx() as s:
        kinds = s.execute(text(
            "SELECT kind FROM operation_outputs WHERE run_id = :r"
            " ORDER BY seq"), {"r": rid}).fetchall()
    assert kinds == [("output",), ("truncated",)]


def test_capture_survives_ordinary_completion(client, users):
    """A worker completing its operation does not erase the captured
    chunks — output rows are append-only evidence on their own."""
    sid = _running_session(client, users)
    rid, token = _run_with_token(sid)
    op = _register(client, rid, token)
    _append(client, rid, token, op, seq=0, text="a")
    _append(client, rid, token, op, seq=1, kind="gap", text="capture hiccup",
            dropped_bytes=4096)
    r = client.post(f"/internal/runs/{rid}/operations/{op}/done",
                    json={"state": "completed"},
                    headers={"X-Worker-Token": token})
    assert r.status_code == 200
    with db_ctx() as s:
        rows = s.execute(text(
            "SELECT kind, dropped_bytes FROM operation_outputs "
            "WHERE run_id = :r ORDER BY seq"), {"r": rid}).fetchall()
    assert rows == [("output", None), ("gap", 4096)]


def test_real_loop_captures_timed_output_through_the_api(client, users):
    """FULL worker path, no doubles between loop and DB: the real
    RedAgentLoop dispatches a real command through the LocalDevRunner,
    the chunks travel over the transport to the internal endpoint and
    land in operation_outputs; the action_result event carries the
    capture SUMMARY. Legacy shape is preserved: the event's output is
    still the bounded first-4000-char fact, capture is additive."""
    import json as _json

    from srplatform.red_agent.loop import RedAgentLoop
    from srplatform.red_agent.runner import LocalDevRunner
    from srplatform.red_agent.transport import TestClientTransport
    from srplatform.settings import Settings
    from tests.helpers import FakeLLM

    sid = _running_session(client, users)
    rid, token = _run_with_token(sid)
    tr = TestClientTransport(client, token, run_id=rid)
    runner = LocalDevRunner(Settings(sr_env="dev",
                                     runner_transport="local-dev"))
    llm = FakeLLM([_json.dumps({"thought": "capture probe",
                                "propose_phase": None, "tool": "shell",
                                "args": {"command":
                                         "echo TIMED-CAPTURE-MARKER-42; "
                                         "echo second line"}})])
    RedAgentLoop(sid, "web-foothold-01", tr, llm, runner,
                 max_steps=1, compress_after=50).run()

    events = client.get("/events", params={"session_id": sid, "tail": 200},
                        headers=users["member"]).json()
    ar = [e for e in events if e["action_type"] == "action_result"]
    assert len(ar) == 1
    summary = ar[0]["payload"]["output_capture"]
    assert summary and summary["complete"] is True
    assert summary["chunks"] >= 1
    op_uuid = ar[0]["payload"]["op_uuid"]
    with db_ctx() as s:
        rows = s.execute(text(
            "SELECT seq, kind, text FROM operation_outputs "
            "WHERE run_id = :r AND op_id = :o ORDER BY seq"),
            {"r": rid, "o": op_uuid}).fetchall()
    assert [r[1] for r in rows] == ["output"]
    assert "TIMED-CAPTURE-MARKER-42" in rows[0][2]
    assert "second line" in rows[0][2]
    # the event's own output stayed the honest bounded fact
    assert "TIMED-CAPTURE-MARKER-42" in ar[0]["payload"]["output"]
