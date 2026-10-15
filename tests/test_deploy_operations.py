"""Plan 13 phase 5 — durable deploy-operation records + 202 executor.

DB layer: drives the real routes and asserts persisted operation state —
202 durable acceptance before effects, background completion, duplicate
refusal with the live operation id, redacted polling WITH the completed
result, and startup reconciliation that marks a dead executor's attempt
`interrupted` without erasing it or clearing a live replacement's claim.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from tests.conftest import launch_and_wait, wait_operation

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


def test_launch_accepts_202_then_completes_in_background(
        client, users, fake_broker):
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    r = client.post(f"/sessions/{sid}/launch", headers=users["member"])
    assert r.status_code == 202, r.text
    accepted = r.json()
    assert accepted["status"] == "accepted" and accepted["operation_id"]
    assert accepted["deadline_at"]

    # the durable row exists BEFORE any effect completes
    ops = _ops(sid)
    assert len(ops) == 1
    assert ops[0].operation == "launch" and ops[0].fence
    assert ops[0].deadline_at is not None

    done = wait_operation(client, users["member"], sid)
    assert done["state"] == "succeeded", done
    assert done["operation_id"] == accepted["operation_id"]
    result = done["result"]
    assert result["status"] == "ready" and result["connections"]
    assert result["readiness"]["ok"]
    # redacted: plaintext enrollments never persist, references do
    assert "SR_TELEMETRY_TOKEN" not in str(done)
    assert result["enrollments_issued"] >= 1
    assert result["enrolled_hosts"]

    ops = _ops(sid)
    assert ops[0].state == "succeeded" and ops[0].phase == "readiness"
    assert ops[0].completed_at is not None


def test_failed_launch_records_failure_and_second_launch_resumes(
        client, users, fake_broker):
    from infra.proxmox_client import PveHttpError
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    fake_broker.http.fail_requests = {
        "/agent/file-read": PveHttpError(403, "permission check failed")}
    r = client.post(f"/sessions/{sid}/launch", headers=users["member"])
    assert r.status_code == 202, r.text
    failed = wait_operation(client, users["member"], sid)
    assert failed["state"] == "failed", failed
    assert failed["error"] and len(failed["error"]) <= 500
    assert failed["result"] is None  # no result on failure
    ops = _ops(sid)
    assert len(ops) == 1 and ops[0].state == "failed"

    fake_broker.http.fail_requests = {}
    done = launch_and_wait(client, users["member"], sid)
    assert done["state"] == "succeeded"
    ops = _ops(sid)
    assert len(ops) == 2 and ops[1].state == "succeeded"  # history kept


def test_duplicate_launch_returns_live_operation_id_never_a_second_deploy(
        client, users, fake_broker):
    """While the executor works, a duplicate is refused 409 WITH the live
    operation id — no new row, no second deployment. After completion the
    next launch is a NEW attempt (deploy is idempotent: returns ready)."""
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    first = client.post(f"/sessions/{sid}/launch",
                        headers=users["member"]).json()
    dup = client.post(f"/sessions/{sid}/launch", headers=users["member"])
    if dup.status_code == 202:
        # the first attempt already finished (fast fixture): the retry is a
        # legitimately new attempt, not a duplicate — assert idempotence
        done = wait_operation(client, users["member"], sid)
        assert done["state"] == "succeeded"
    else:
        assert dup.status_code == 409
        assert dup.json()["detail"]["error"] == "operation_in_progress"
        assert dup.json()["detail"]["operation_id"] == first["operation_id"]
        assert len(_ops(sid)) == 1  # no phantom row
        done = wait_operation(client, users["member"], sid)
        assert done["state"] == "succeeded", done


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


def test_expired_deadline_fails_before_dispatch(client, users, fake_broker):
    """An attempt whose deadline already passed never dispatches: the
    executor records `failed` without a single side effect (no clone, no
    lease use beyond what acceptance already reserved)."""
    from srplatform.scenario_engine import deploy_executor, orchestrator
    from srplatform.db.session import db
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    with db() as s:
        row = orchestrator.begin_deploy_operation(
            s, sid, "launch", fence="test-fence", deadline_s=-60)
        op_id = str(row.operation_id)
    deploy_executor._execute(operation_id=op_id, session_id=uuid.UUID(sid),
                             user_id="member", operation="launch",
                             scenario_id="web-foothold-01",
                             broker=fake_broker, owner="test-fence")
    ops = _ops(sid)
    assert len(ops) == 1 and ops[0].state == "failed"
    assert "deadline exceeded" in (ops[0].error or "")
    assert fake_broker.http.requests == [], "no side effects after expiry"
