"""Plan 13 phase 2 — audit A6: resume must COMPLETE a missing host-key pin.

A first-boot host-key read failure (agent channel down, slow boot past the
bounded wait) commits the resource `created` — ownership must survive — but
without `host_key_ref`. Before the fix, every resume skipped both the clone
AND the pin, so the range reached `ready` with no pinned key and SSH clients
(StrictHostKeyChecking, no TOFU) failed forever. Resume must re-pin.

DB layer: drives the real /launch route twice (fail, then resume) and
asserts persisted deployment state, not helper return values.
"""
from __future__ import annotations

import pytest
from sqlalchemy import select

from infra.proxmox_client import PveHttpError
from tests.conftest import launch_and_wait, wait_operation

pytestmark = pytest.mark.db


def _deployment_resources(session_id):
    from srplatform.db.models import Deployment
    from srplatform.db.session import db
    with db() as s:
        dep = s.execute(
            select(Deployment)
            .where(Deployment.session_id == session_id)
            .order_by(Deployment.created_at.desc())
        ).scalars().first()
        return [dict(r) for r in (dep.resources or [])]


def test_resume_repins_host_key_missing_after_failed_launch(client, users,
                                                            fake_broker):
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]

    # Pin fails (403 on the agent channel is immediate, not a not-ready
    # retry): the resource is committed `created` (ownership discipline)
    # but WITHOUT a pin.
    fake_broker.http.fail_requests = {
        "/agent/file-read": PveHttpError(403, "permission check failed")}
    r = client.post(f"/sessions/{sid}/launch", headers=users["member"])
    assert r.status_code == 202, r.text  # accepted; the executor fails loudly
    failed = wait_operation(client, users["member"], sid)
    assert failed["state"] == "failed", failed

    resources = _deployment_resources(sid)
    assert len(resources) == 1
    assert resources[0]["state"] == "created", \
        "ownership must survive the failed pin"
    assert not resources[0].get("host_key_ref"), "precondition: pin missing"

    # Repaired channel: resume must finish the pin (read + publish) and
    # reach ready — never skip it because the state already says created.
    fake_broker.http.fail_requests = {}
    launch_and_wait(client, users["member"], sid)
    resources = _deployment_resources(sid)
    assert resources[0]["state"] == "created"
    assert resources[0].get("host_key_ref"), \
        "resume must complete the missing host-key pin (audit A6)"
