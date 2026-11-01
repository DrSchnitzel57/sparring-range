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

import uuid

import pytest
from sqlalchemy import select

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
    fake_broker.http.fail_reads = {("read_guest_file_when_ready", None): 403}
    r = client.post(f"/sessions/{sid}/launch", headers=users["member"])
    assert r.status_code == 202, r.text  # accepted; the executor fails loudly
    failed = wait_operation(client, users["member"], sid)
    assert failed["state"] == "failed", failed

    resources = _deployment_resources(sid)
    assert len(resources) == 1
    assert resources[0]["state"] == "created", \
        "ownership must survive the failed pin"
    assert not resources[0].get("host_key_ref"), "precondition: pin missing"
    assert not resources[0].get("host_key_pin"), \
        "precondition: no full dial pin either"

    # Repaired channel: resume must finish the pin (read + publish) and
    # reach ready — never skip it because the state already says created.
    fake_broker.http.fail_reads = {}
    launch_and_wait(client, users["member"], sid)
    resources = _deployment_resources(sid)
    assert resources[0]["state"] == "created"
    assert resources[0].get("host_key_ref"), \
        "resume must complete the missing host-key pin (audit A6)"
    assert resources[0].get("host_key_pin"), \
        "resume must store the FULL pin, not only the display ref"
    assert resources[0]["host_key_pin"] != resources[0]["host_key_ref"]


def test_resume_backfills_full_pin_for_legacy_ref_only_row(
        client, users, fake_broker):
    """A row written before the 2026-10-16 fix carries only the truncated
    display ref; the token endpoint then served it as the dial pin and every
    bastion dial failed HostKeyNotVerifiable. Resume must backfill the FULL
    pin from the broker (same generation, no re-clone, no re-pin conflict)."""
    from sqlalchemy.orm.attributes import flag_modified

    from srplatform.db.models import Deployment
    from srplatform.db.session import db as db_ctx
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    launch_and_wait(client, users["member"], sid)
    with db_ctx() as s:
        dep = s.execute(select(Deployment).where(
            Deployment.session_id == uuid.UUID(sid))).scalars().first()
        res = dep.resources[0]
        assert res.get("host_key_pin"), "new rows store the full pin"
        res.pop("host_key_pin")  # simulate the legacy writer's row
        assert res.get("host_key_ref")
        dep.resources = [res] + dep.resources[1:]
        flag_modified(dep, "resources")
        s.commit()
    launch_and_wait(client, users["member"], sid)
    resources = _deployment_resources(sid)
    assert resources[0].get("host_key_pin"), \
        "resume must backfill the full pin for a ref-only row"
    assert resources[0]["host_key_pin"] != resources[0]["host_key_ref"]


def test_unpublished_pin_fails_readiness_and_resume_republicates(
        client, users, fake_broker):
    """A recorded host-key publish failure is a RED readiness check (members
    cannot connect until republication converges), and resume retries the
    publication instead of skipping it on the existing reference."""
    from srplatform import verification_service
    from srplatform.db.models import Deployment
    from srplatform.db.session import db as db_ctx
    from sqlalchemy import select
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    from tests.conftest import launch_and_wait
    launch_and_wait(client, users["member"], sid)
    with db_ctx() as s:
        dep = s.execute(select(Deployment).where(
            Deployment.session_id == uuid.UUID(sid))).scalars().first()
        res = dep.resources[0]
        res["host_key_publish_error"] = "ssh-keygen: known_hosts unwritable"
        dep.resources = [res] + dep.resources[1:]
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(dep, "resources")
        s.commit()
    red = verification_service.readiness_checks
    with db_ctx() as s:
        out = red(s, uuid.UUID(sid))
    assert out["enforced"] and not out["ok"], out
    assert any(i.get("unit") == "host-key-pin" and i["status"] == "failed"
               for i in out["checks"]), out["checks"]
    # resume republicates (fake broker publish succeeds) and clears the error
    launch_and_wait(client, users["member"], sid)
    with db_ctx() as s:
        dep = s.execute(select(Deployment).where(
            Deployment.session_id == uuid.UUID(sid))).scalars().first()
        assert not dep.resources[0].get("host_key_publish_error")
        out = red(s, uuid.UUID(sid))
        assert out["ok"], out
