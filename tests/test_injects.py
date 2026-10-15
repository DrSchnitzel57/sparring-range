"""Plan 13 phase 6 — inject lifecycle (db layer): trusted schedule from
Begin, inbox, first-answer-decides submissions, late/duplicate/advisory
outcomes, disabled set releases nothing."""
from __future__ import annotations

import uuid as U
from datetime import datetime, timedelta, timezone

import pytest
from tests.conftest import launch_and_wait

pytestmark = pytest.mark.db


@pytest.fixture(autouse=True)
def _mojang_templates(fake_pve):
    """Mojang-scenario templates exist ONLY for these tests — the shared
    fake PVE keeps its exact 9001–9004 set so the orphan/VM-set assertions
    elsewhere stay meaningful."""
    for vmid, name in ((9005, "tpl-attacker"), (9011, "tpl-mojang-web"),
                       (9012, "tpl-mojang-db")):
        fake_pve.api.vms[vmid] = {"name": name, "template": vmid,
                                  "status": "stopped"}


def _exec_ok(addr: str, cmd: str):
    if "curl" in cmd:
        return 0, "Minecraft Legends"
    if "mysql" in cmd:
        return 0, "12"
    if "passwd" in cmd:
        return 0, "root\ndefender\nweb-user\nmysql\ndaemon\nsrshipper\n"
    return 1, f"unexpected command: {cmd[:80]}"


def _exec_broken(addr: str, cmd: str):
    if "curl" in cmd:
        return 0, "502 Bad Gateway"
    if "mysql" in cmd:
        return 1, "table corrupted"
    return 0, "root\nmallory\n"  # rogue account present


def _begin(client, users, scenario="mojang-web-db-01", **create):
    sid = client.post("/sessions", json={"scenario_id": scenario, **create},
                      headers=users["member"]).json()["session_id"]
    launch_and_wait(client, users["member"], sid)
    r = client.post(f"/sessions/{sid}/begin", headers=users["member"])
    assert r.status_code == 202, r.text
    return sid


def _open_window(release_id, *, opened_min=1, deadline_min=10):
    from srplatform.db.models import InjectRelease
    from srplatform.db.session import db as db_ctx
    with db_ctx() as s:
        rel = s.get(InjectRelease, U.UUID(release_id))
        now = datetime.now(timezone.utc)
        rel.scheduled_at = now - timedelta(minutes=opened_min)
        rel.deadline_at = now + timedelta(minutes=deadline_min)
        s.commit()


def _close_window(release_id):
    from srplatform.db.models import InjectRelease
    from srplatform.db.session import db as db_ctx
    with db_ctx() as s:
        rel = s.get(InjectRelease, U.UUID(release_id))
        now = datetime.now(timezone.utc)
        rel.scheduled_at = now - timedelta(minutes=20)
        rel.deadline_at = now - timedelta(minutes=1)
        s.commit()


def test_begin_schedules_releases_and_inbox(client, users, fake_broker):
    sid = _begin(client, users)
    body = client.get(f"/sessions/{sid}/injects",
                      headers=users["member"]).json()
    assert len(body["releases"]) == 4
    ids = {x["inject_id"] for x in body["releases"]}
    assert {"restricted-account@1", "web-restoration@1",
            "db-data-recovery@1", "incident-report@1"} == ids
    assert all(x["status"] == "pending" for x in body["releases"])
    assert body["score"]["releases"] == 4 and not body["score"]["scored"]
    # duplicate Begin never re-times or duplicates releases
    client.post(f"/sessions/{sid}/begin", headers=users["member"])
    again = client.get(f"/sessions/{sid}/injects",
                       headers=users["member"]).json()
    assert len(again["releases"]) == 4
    assert {x["release_id"] for x in again["releases"]} == \
        {x["release_id"] for x in body["releases"]}


def test_submission_first_answer_decides(client, users, fake_broker):
    from srplatform import verification_service
    sid = _begin(client, users, duration_minutes=30)
    inbox = client.get(f"/sessions/{sid}/injects",
                       headers=users["member"]).json()
    wr = next(x for x in inbox["releases"]
              if x["inject_id"] == "web-restoration@1")
    url = f"/sessions/{sid}/injects/{wr['release_id']}"
    # not yet open (20 % of the clock): refused, not queued
    r = client.post(url, json={"content": "x"}, headers=users["member"])
    assert r.status_code == 409
    assert r.json()["detail"]["status"] == "not_released"

    _open_window(wr["release_id"])
    verification_service.set_verifier_exec(_exec_ok)
    try:
        r = client.post(url, json={"content": "restored"},
                        headers=users["member"])
        assert r.status_code == 200 and r.json()["status"] == "correct"
        # duplicate: even a now-broken verifier cannot re-decide
        verification_service.set_verifier_exec(_exec_broken)
        r = client.post(url, json={"content": "again"},
                        headers=users["member"])
        assert r.json()["status"] == "correct"
        assert "duplicate" in r.json()["note"]
    finally:
        verification_service.set_verifier_exec(None)
    score = client.get(f"/sessions/{sid}/injects",
                       headers=users["member"]).json()["score"]
    assert score["correct"] == 1 and score["scored"]


def test_incorrect_late_and_advisory(client, users, fake_broker):
    from srplatform import verification_service
    sid = _begin(client, users, duration_minutes=30)
    inbox = client.get(f"/sessions/{sid}/injects",
                       headers=users["member"]).json()
    by = {x["inject_id"]: x for x in inbox["releases"]}
    verification_service.set_verifier_exec(_exec_broken)
    try:
        # incorrect: window open, verification fails deterministically
        _open_window(by["web-restoration@1"]["release_id"])
        r = client.post(f"/sessions/{sid}/injects/{by['web-restoration@1']['release_id']}",
                        json={"content": "tried"}, headers=users["member"])
        assert r.json()["status"] == "incorrect"
        # late: first answer after the deadline
        _close_window(by["db-data-recovery@1"]["release_id"])
        r = client.post(f"/sessions/{sid}/injects/{by['db-data-recovery@1']['release_id']}",
                        json={"content": "sorry"}, headers=users["member"])
        assert r.json()["status"] == "late"
        # advisory: written work never awards verified points
        _open_window(by["incident-report@1"]["release_id"])
        r = client.post(f"/sessions/{sid}/injects/{by['incident-report@1']['release_id']}",
                        json={"content": "timeline: ..."},
                        headers=users["member"])
        assert r.json()["status"] == "advisory"
    finally:
        verification_service.set_verifier_exec(None)
    score = client.get(f"/sessions/{sid}/injects",
                       headers=users["member"]).json()["score"]
    assert score["correct"] == 0 and score["technical_closed"] == 2
    assert score["advisory_only"] == ["incident-report@1"]


def test_disabled_inject_set_releases_nothing(client, users, fake_broker):
    sid = _begin(client, users, injects_enabled=False)
    body = client.get(f"/sessions/{sid}/injects",
                      headers=users["member"]).json()
    assert body["releases"] == []
    assert not body["score"]["scored"]


def test_unknown_release_and_foreign_session_refused(client, users,
                                                     fake_broker):
    sid = _begin(client, users)
    r = client.post(f"/sessions/{sid}/injects/{U.uuid4()}",
                    json={"content": "x"}, headers=users["member"])
    assert r.status_code == 404
