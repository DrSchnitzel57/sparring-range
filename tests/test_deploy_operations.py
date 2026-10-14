"""Plan 13 phase 5 — durable deploy-operation records.

DB layer: drives the real routes and asserts persisted operation state —
durable acceptance before effects, duplicate refusal, redacted polling,
and startup reconciliation that marks a dead executor's attempt
`interrupted` without erasing it or clearing a live replacement's claim.
"""
from __future__ import annotations

import pytest
from sqlalchemy import select

pytestmark = pytest.mark.db


def _ops(session_id):
    from srplatform.db.models import DeployOperation
    from srplatform.db.session import db
    with db() as s:
        return list(s.execute(
            select(DeployOperation)
            .where(DeployOperation.session_id == session_id)
            .order_by(DeployOperation.created_at)
        ).scalars().all())


def test_launch_records_durable_operation_and_polling(client, users,
                                                      fake_broker):
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    r = client.post(f"/sessions/{sid}/launch", headers=users["member"])
    assert r.status_code == 200, r.text
    ops = _ops(sid)
    assert len(ops) == 1
    assert ops[0].operation == "launch" and ops[0].state == "succeeded"
    assert ops[0].phase == "readiness" and ops[0].fence
    assert ops[0].deadline_at is not None and ops[0].completed_at is not None

    poll = client.get(f"/sessions/{sid}/operation", headers=users["member"])
    assert poll.status_code == 200
    body = poll.json()
    assert body["state"] == "succeeded" and body["operation_id"] == str(ops[0].operation_id)
    # redacted: no tokens, no provisioning commands
    assert "SR_TELEMETRY_TOKEN" not in poll.text


def test_failed_launch_records_failure_and_second_launch_resumes(
        client, users, fake_broker):
    from infra.proxmox_client import PveHttpError
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    fake_broker.http.fail_requests = {
        "/agent/file-read": PveHttpError(403, "permission check failed")}
    r = client.post(f"/sessions/{sid}/launch", headers=users["member"])
    assert r.status_code >= 500
    ops = _ops(sid)
    assert len(ops) == 1 and ops[0].state == "failed"
    assert ops[0].error and len(ops[0].error) <= 500

    fake_broker.http.fail_requests = {}
    r = client.post(f"/sessions/{sid}/launch", headers=users["member"])
    assert r.status_code == 200, r.text
    ops = _ops(sid)
    assert len(ops) == 2 and ops[1].state == "succeeded"  # attempt history kept


def test_startup_reconcile_marks_dead_executors_interrupted(client, users,
                                                            fake_broker):
    from srplatform.scenario_engine import orchestrator
    from srplatform.db.session import db
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    with db() as s:
        row = orchestrator.begin_deploy_operation(
            s, sid, "launch", fence="dead-executor", deadline_s=60)
        orchestrator.advance_deploy_operation(s, row, "deploying")
        # a LIVE claim by a different fence must survive the reconcile
        orchestrator.claim_operation(s, sid, "launch")
    with db() as s:
        n = orchestrator.reconcile_deploy_operations(s)
        assert n == 1
        ops = _ops(sid)
        assert ops[0].state == "interrupted" and "restart" in ops[0].error
    with db() as s:
        from srplatform.db.models import OperationClaim
        assert s.get(OperationClaim, sid) is not None  # live claim untouched
        orchestrator.release_operation(s, sid)


def test_duplicate_launch_never_creates_second_deployment(client, users,
                                                          fake_broker):
    """The durable claim serializes: while one attempt holds the claim, a
    duplicate is refused 409 and records NO new operation row."""
    from srplatform.scenario_engine import orchestrator
    from srplatform.db.session import db
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    with db() as s:
        orchestrator.claim_operation(s, sid, "launch")
    r = client.post(f"/sessions/{sid}/launch", headers=users["member"])
    assert r.status_code == 409
    assert r.json()["detail"]["error"] == "operation_in_progress"
    assert _ops(sid) == []  # refused BEFORE durable acceptance: no phantom row
    with db() as s:
        orchestrator.release_operation(s, sid)
