"""Separate-UID worker supervisor contract (milestone 15).

Fast tests cover capability-file validation; the DB-marked test proves the
durable claim/assign/heartbeat/failure state machine without spawning a real
worker. The process identity boundary itself is enforced by the systemd unit
and the authority gate (no DB/broker/libvirt access for srworker).
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import update
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
        claimed_run, token, claim_token = claimed
        assert claimed_run.run_id == run_id and token and claim_token
        # A second claim must not steal the same queued row.
        assert runs.claim_run(d, 1) is None
        assert runs.assign_run(d, run_id, 4242, 4242, 99, claim_token) is True
        assert runs.heartbeat_run(d, run_id, claim_token) is True

    with db_ctx() as d:
        out = runs.worker_failed(d, run_id, "worker process exited 1",
                                claim_token)
        assert out["ok"] is True
        row = d.get(Run, run_id)
        assert row.status == "failed"
        assert row.worker_token is None
        assert row.worker_heartbeat_at is not None


def test_supervisor_callbacks_are_fenced_by_the_claim_credential(migrated_db):
    """An OBSOLETE claimant must not be able to act.

    When a claim is reclaimed, the claim credential rotates.  A supervisor
    that still holds the old credential must not be able to assign, heartbeat
    or report a failure for the run.
    """
    from srplatform.api import runs
    from srplatform.db.models import Run, Session as SessionModel, User
    from srplatform.db.session import db as db_ctx

    with db_ctx() as d:
        u = User(username=f"fence-{uuid.uuid4().hex[:8]}", role="member")
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
        _run, _token, claim_token = runs.claim_run(d, 1)
        stale = "s" * 40
        # a different credential cannot assign, heartbeat or report
        assert runs.assign_run(d, run_id, 4242, 4242, 99, stale) is False
        assert runs.heartbeat_run(d, run_id, stale) is False
        out = runs.worker_failed(d, run_id, "stale claimant", stale)
        assert out["ok"] is False
        assert "refused" in out["detail"]
        row = d.get(Run, run_id)
        assert row.status == "queued"       # nothing happened
        # the real credential still works
        assert runs.assign_run(d, run_id, 4242, 4242, 99, claim_token) is True


def test_a_failure_report_cannot_overwrite_a_completed_run(migrated_db):
    """A report that races a confirmed completion must not rewrite it."""
    from srplatform.api import runs
    from srplatform.db.models import Run, Session as SessionModel, User
    from srplatform.db.session import db as db_ctx

    with db_ctx() as d:
        u = User(username=f"done-{uuid.uuid4().hex[:8]}", role="member")
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
        _run, _token, claim_token = runs.claim_run(d, 1)
        assert runs.assign_run(d, run_id, 4242, 4242, 99, claim_token) is True
        d.execute(update(Run).where(Run.run_id == run_id)
                  .values(status="completed", outcome="completed",
                          ended_at=runs._now()))
        d.commit()
        out = runs.worker_failed(d, run_id, "raced the completion", claim_token)
        row = d.get(Run, run_id)
        assert row.status == "completed", (out, row.status)
        assert row.outcome == "completed"


def test_stopping_a_supervisor_run_keeps_the_obligation_until_the_report(
        migrated_db):
    """A worker in another UID cannot be signalled by the API.

    The API marks the run stopping and waits for the supervisor's report; it
    never claims a cessation it cannot confirm, and the report resolves the
    run as cancelled.
    """
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
        _run, _token, claim_token = runs.claim_run(d, 1)
        assert runs.assign_run(d, run_id, 4242, 4242, 99, claim_token) is True

        out = runs.stop_run(d, run_id, supervisor_wait_s=0.2)
        assert out["ok"] is False, out
        assert out["status"] == "stopping"
        row = d.get(Run, run_id)
        assert row.status == "stopping"

        # the supervisor confirms the cessation
        res = runs.worker_failed(d, run_id,
                                 "stopped at the controller's request",
                                 claim_token)
        assert res["ok"] is True, res
        row = d.get(Run, run_id)
        assert row.status == "cancelled", row.status
        assert row.outcome == "canceled"


def test_stopping_an_unstarted_queued_run_resolves_it(migrated_db):
    """A queued run that never started must not stay 'stopping' forever."""
    from srplatform.api import runs
    from srplatform.db.models import Run, Session as SessionModel, User
    from srplatform.db.session import db as db_ctx

    with db_ctx() as d:
        u = User(username=f"queued-{uuid.uuid4().hex[:8]}", role="member")
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
        out = runs.stop_run(d, run_id)
        assert out["ok"] is True, out
        row = d.get(Run, run_id)
        assert row.status == "cancelled", row.status
