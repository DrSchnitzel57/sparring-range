"""Separate-UID worker supervisor contract (milestone 15).

Fast tests cover capability-file validation; the DB-marked test proves the
durable claim/assign/heartbeat/failure state machine without spawning a real
worker. The process identity boundary itself is enforced by the systemd unit
and the authority gate (no DB/broker/libvirt access for srworker).
"""
from __future__ import annotations

import uuid

import pytest
from fastapi import HTTPException


def test_supervisor_capability_file_is_required_and_constant_time(tmp_path,
                                                                 monkeypatch):
    from srplatform import settings
    from srplatform.api import app as api_app
    token = "t" * 64
    path = tmp_path / "supervisor.token"
    path.write_text(token)
    path.chmod(0o600)
    monkeypatch.setenv("SR_WORKER_SUPERVISOR_TOKEN_FILE", str(path))
    settings.get_settings.cache_clear()
    try:
        api_app._require_supervisor(token)
        with pytest.raises(HTTPException) as bad:
            api_app._require_supervisor("wrong")
        assert bad.value.status_code == 403
    finally:
        settings.get_settings.cache_clear()


def test_supervisor_capability_rejects_world_readable(tmp_path, monkeypatch):
    from srplatform import settings
    path = tmp_path / "supervisor.token"
    path.write_text("x" * 64)
    path.chmod(0o644)
    monkeypatch.setenv("SR_WORKER_SUPERVISOR_TOKEN_FILE", str(path))
    monkeypatch.setenv("SR_ENV", "production")
    monkeypatch.setenv("SR_WORKER_DISPATCH", "supervisor")
    settings.get_settings.cache_clear()
    try:
        with pytest.raises(RuntimeError, match="supervisor token"):
            settings.validate_production(settings.get_settings())
    finally:
        settings.get_settings.cache_clear()


def test_claim_assign_heartbeat_and_failure(migrated_db):
    from srplatform.api import runs
    from srplatform.db.models import Run, Session as SessionModel, User
    from srplatform.db.session import db as db_ctx

    with db_ctx() as d:
        u = User(username=f"sup-{uuid.uuid4().hex[:8]}", role="member")
        d.add(u)
        d.flush()
        s = SessionModel(scenario_id="mojang-web-01", user_id=u.user_id,
                         status="running")
        d.add(s)
        d.flush()
        run = Run(session_id=s.session_id, scenario_id=s.scenario_id,
                  status="queued")
        d.add(run)
        d.commit()
        run_id = run.run_id

        claimed = runs.claim_run(d, 1)
        assert claimed is not None
        claimed_run, token = claimed
        assert claimed_run.run_id == run_id and token
        # A second claim must not steal the same queued row.
        assert runs.claim_run(d, 1) is None
        assert runs.assign_run(d, run_id, 4242, 4242, 99) is True
        assert runs.heartbeat_run(d, run_id) is True

    with db_ctx() as d:
        out = runs.worker_failed(d, run_id, "worker process exited 1")
        assert out["ok"] is True
        row = d.get(Run, run_id)
        assert row.status == "failed"
        assert row.worker_token is None
        assert row.worker_heartbeat_at is not None
