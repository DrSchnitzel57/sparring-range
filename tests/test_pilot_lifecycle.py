"""Pilot step 4: minimal durable match lifecycle (db layer).

Real API + real disposable Postgres + broker/PVE doubles. Proves the
lifecycle contract: creation-time SNAPSHOT (preset/30min/pace), Begin starts
the SERVER clock + attack worker together (duplicate Begin idempotent, never
extends), ready-but-unstarted labs EXPIRE after 15 minutes with safe
cleanup, end/expiry DESTROY owned VMs and release the lease (blocked
teardown keeps the lease), and an API restart INTERRUPTS — never resumes.
"""
import pytest
from sqlalchemy import text

from srplatform import lifecycle

pytestmark = pytest.mark.db


def _db():
    from srplatform.db.session import db
    return db()


def _broker():
    from srplatform.api.deps import get_broker
    return get_broker()


def _launch(client, users, scenario="web-foothold-01", **create):
    sid = client.post("/sessions", json={"scenario_id": scenario, **create},
                      headers=users["member"]).json()["session_id"]
    r = client.post(f"/sessions/{sid}/launch", headers=users["member"])
    assert r.status_code == 200, r.text
    return sid, r.json()


def _backdate(session_id, column, minutes):
    from datetime import datetime, timedelta, timezone
    with _db() as s:
        s.execute(text("UPDATE matches SET " + column
                       + " = now() - make_interval(mins => :m) WHERE session_id = :sid"),
                  {"m": minutes, "sid": str(session_id)})
        s.commit()


def _match_row(session_id):
    with _db() as s:
        row = s.execute(text("SELECT state, expiry_reason, duration_minutes, "
                             "pace_seconds FROM matches WHERE session_id = :sid"),
                        {"sid": str(session_id)}).first()
        return {"state": row[0], "expiry_reason": row[1],
                "duration_minutes": row[2], "pace_seconds": row[3]}


# ------------------------------------------------------------------ snapshot --
def test_match_snapshot_at_creation(client, users):
    sid = client.post("/sessions",
                      json={"scenario_id": "web-foothold-01",
                            "duration_minutes": 45, "pace_seconds": 10},
                      headers=users["member"]).json()["session_id"]
    body = client.get(f"/sessions/{sid}", headers=users["member"]).json()
    m = body["match"]
    assert m["state"] == "provisioning"
    assert m["duration_minutes"] == 45 and m["pace_seconds"] == 10
    # defaults: 30-minute match, 30 s pace; pace 0 is the no-delay option
    sid2 = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                       headers=users["member"]).json()["session_id"]
    m2 = client.get(f"/sessions/{sid2}", headers=users["member"]).json()["match"]
    assert m2["duration_minutes"] == 30 and m2["pace_seconds"] == 30
    sid3 = client.post("/sessions", json={"scenario_id": "web-foothold-01",
                                          "pace_seconds": 0},
                       headers=users["member"]).json()["session_id"]
    m3 = client.get(f"/sessions/{sid3}", headers=users["member"]).json()["match"]
    assert m3["pace_seconds"] == 0
    types = [e["action_type"] for e in
             client.get("/events", params={"session_id": sid, "tail": 50},
                        headers=users["member"]).json()]
    assert "match_snapshot" in types


def test_launch_marks_ready_and_arms_idle_expiry(client, users, fake_pve):
    sid, _ = _launch(client, users)
    m = _match_row(sid)
    assert m["state"] == "ready"
    with _db() as s:
        ready_at = s.execute(text("SELECT ready_at FROM matches WHERE session_id=:sid"),
                             {"sid": str(sid)}).scalar()
    assert ready_at is not None


# --------------------------------------------------------------------- begin --
def test_begin_starts_server_clock_and_worker(client, users, fake_pve):
    sid, _ = _launch(client, users, duration_minutes=30)
    r = client.post(f"/sessions/{sid}/begin", headers=users["member"])
    assert r.status_code == 202, r.text
    body = r.json()
    assert body["started_at"] and body["deadline_at"]
    assert body["duration_minutes"] == 30 and body["pace_seconds"] == 30
    assert body["run_id"]
    m = _match_row(sid)
    assert m["state"] == "running"
    sess = client.get(f"/sessions/{sid}", headers=users["member"]).json()
    assert sess["status"] == "running" and sess["active_run"] == body["run_id"]

    # DUPLICATE BEGIN: idempotent, same deadline — never extends the match
    with _db() as s:
        before = s.execute(text("SELECT started_at, deadline_at FROM matches "
                                "WHERE session_id=:sid"), {"sid": str(sid)}).first()
    r2 = client.post(f"/sessions/{sid}/begin", headers=users["member"])
    assert r2.status_code == 202 and "idempotent" in r2.json()["note"]
    with _db() as s:
        after = s.execute(text("SELECT started_at, deadline_at FROM matches "
                               "WHERE session_id=:sid"), {"sid": str(sid)}).first()
    assert before == after


def test_begin_requires_ready_lab(client, users):
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    r = client.post(f"/sessions/{sid}/begin", headers=users["member"])
    assert r.status_code == 409  # never launched


# ------------------------------------------------------------- idle expiry ---
def test_ready_unstarted_lab_expires_after_15_minutes(client, users, fake_pve):
    sid, out = _launch(client, users)
    tok = out["connections"][0]["login_token"]
    _backdate(sid, "ready_at", 16)
    with _db() as s:
        results = lifecycle.tick(s, broker=_broker())
    assert any(r.get("session_id") == str(sid) for r in results), results

    m = _match_row(sid)
    assert m["state"] == "completed" and m["expiry_reason"] == "idle_expiry"
    sess = client.get(f"/sessions/{sid}", headers=users["member"]).json()
    assert sess["status"] == "complete"
    # safely cleaned up: owned VMs destroyed (only templates remain), lease
    # freed for the next session, login capability revoked
    leftover = [v for v in fake_pve.api.vms if v not in (9001, 9002, 9003, 9004)]
    assert leftover == []
    sid2 = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                       headers=users["op"]).json()["session_id"]
    assert client.post(f"/sessions/{sid2}/launch",
                       headers=users["op"]).status_code == 200
    with _db() as s:
        revoked = s.execute(text("SELECT revoked_at FROM login_tokens WHERE token=:t"),
                            {"t": tok}).scalar()
    assert revoked is not None


def test_idle_expiry_not_applied_before_window_or_while_running(client, users, fake_pve):
    sid, _ = _launch(client, users)
    with _db() as s:
        assert lifecycle.tick(s, broker=_broker()) == []  # inside the window
    assert _match_row(sid)["state"] == "ready"
    # begun labs are deadline-owned, never idle-expired
    client.post(f"/sessions/{sid}/begin", headers=users["member"])
    _backdate(sid, "ready_at", 16)  # stale marker must not matter
    with _db() as s:
        assert lifecycle.tick(s, broker=_broker()) == []
    assert _match_row(sid)["state"] == "running"


# ------------------------------------------------------------------ deadline --
def test_deadline_ends_match_destroys_vms_releases_lease(client, users, fake_pve):
    sid, _ = _launch(client, users, duration_minutes=1)
    client.post(f"/sessions/{sid}/begin", headers=users["member"])
    _backdate(sid, "deadline_at", 2)
    with _db() as s:
        results = lifecycle.tick(s, broker=_broker())
    assert any(r.get("session_id") == str(sid) and r.get("ok")
               for r in results), results
    m = _match_row(sid)
    assert m["state"] == "completed" and m["expiry_reason"] == "deadline"
    sess = client.get(f"/sessions/{sid}", headers=users["member"]).json()
    assert sess["status"] == "complete" and sess["active_run"] is None
    assert [v for v in fake_pve.api.vms if v not in (9001, 9002, 9003, 9004)] == []
    # the range is free again
    sid2 = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                       headers=users["op"]).json()["session_id"]
    assert client.post(f"/sessions/{sid2}/launch",
                       headers=users["op"]).status_code == 200


# ---------------------------------------------------------------- user end ---
def test_end_destroys_owned_vms_and_frees_range(client, users, fake_pve):
    sid, out = _launch(client, users)
    tok = out["connections"][0]["login_token"]
    r = client.post(f"/sessions/{sid}/end", headers=users["member"])
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "complete" and body["lease_released"] is True
    assert [v for v in fake_pve.api.vms if v not in (9001, 9002, 9003, 9004)] == []
    assert _match_row(sid)["state"] == "completed"
    # a second session can launch IMMEDIATELY after end (no separate teardown)
    sid2 = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                       headers=users["op"]).json()["session_id"]
    assert client.post(f"/sessions/{sid2}/launch",
                       headers=users["op"]).status_code == 200
    # capabilities revoked; end is idempotent
    with _db() as s:
        assert s.execute(text("SELECT revoked_at FROM login_tokens WHERE token=:t"),
                         {"t": tok}).scalar() is not None
    r2 = client.post(f"/sessions/{sid}/end", headers=users["member"])
    assert r2.status_code == 200 and "idempotent" in r2.json()["note"]


def test_end_with_failed_destroy_keeps_lease_and_retries(client, users, fake_pve):
    sid, _ = _launch(client, users)
    fake_pve.api.fail_task_fragments = ("/qemu",)
    r = client.post(f"/sessions/{sid}/end", headers=users["member"])
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["lease_released"] is False  # R07: machines exist -> reserved
    assert _match_row(sid)["state"] == "interrupted"
    sid2 = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                       headers=users["op"]).json()["session_id"]
    assert client.post(f"/sessions/{sid2}/launch",
                       headers=users["op"]).status_code == 409
    # retry after the operator fixes the destroy path: cleanup completes
    fake_pve.api.fail_task_fragments = ()
    r2 = client.post(f"/sessions/{sid}/end", headers=users["member"])
    assert r2.status_code == 200 and r2.json()["lease_released"] is True
    assert _match_row(sid)["state"] == "completed"
    assert client.post(f"/sessions/{sid2}/launch",
                       headers=users["op"]).status_code == 200


# ------------------------------------------------------------- api restart ---
def test_api_restart_interrupts_and_never_resumes(client, users, fake_pve):
    sid, _ = _launch(client, users)
    client.post(f"/sessions/{sid}/begin", headers=users["member"])
    assert _match_row(sid)["state"] == "running"
    # simulate the crash: workers die with the API; startup reconcile runs
    from srplatform.api import runs as runs_svc
    runs_svc.reconcile_on_startup()
    with _db() as s:
        results = lifecycle.reconcile_on_startup(s, broker=_broker())
    assert any(r.get("session_id") == str(sid) for r in results), results
    m = _match_row(sid)
    assert m["state"] in ("completed", "interrupted")
    assert m["expiry_reason"] == "api_restart"
    sess = client.get(f"/sessions/{sid}", headers=users["member"]).json()
    assert sess["status"] == "complete"
    assert sess["active_run"] is None  # never silently resumed
    # a fresh session can take over once cleanup completed
    if m["state"] == "completed":
        sid2 = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                           headers=users["op"]).json()["session_id"]
        assert client.post(f"/sessions/{sid2}/launch",
                           headers=users["op"]).status_code == 200


# ------------------------------------------------------------- connections ---
def test_connections_served_from_api(client, users, fake_pve):
    sid, out = _launch(client, users)
    launch_tok = out["connections"][0]["login_token"]
    r = client.get(f"/sessions/{sid}/connections", headers=users["member"])
    assert r.status_code == 200
    conns = r.json()["connections"]
    assert conns and conns[0]["login_token"] == launch_tok
    assert conns[0]["ssh"].startswith("ssh ") and conns[0]["host"]
    # revoked capabilities are never served again
    client.post(f"/sessions/{sid}/end", headers=users["member"])
    r2 = client.get(f"/sessions/{sid}/connections", headers=users["member"])
    assert r2.json()["connections"] == []


# ------------------------------------------------------------- worker env ----
def test_worker_env_carries_snapshot_pace_and_deadline(client, users, fake_pve):
    import uuid as u
    from srplatform.api.runs import _worker_env
    from srplatform.settings import get_settings
    sid, _ = _launch(client, users, duration_minutes=25, pace_seconds=7)
    client.post(f"/sessions/{sid}/begin", headers=users["member"])
    with _db() as s:
        from srplatform.db.models import MatchModel
        m = s.get(MatchModel, u.UUID(str(sid)))
        run = type("R", (), {"run_id": u.uuid4()})()
        env = _worker_env(get_settings(), "tok", u.UUID(str(sid)),
                          "web-foothold-01", run, match=m)
        assert env["SR_ATTACK_PACE_S"] == "7"
        assert "SR_MATCH_DEADLINE_UTC" in env
        # no credential ever rides the worker env
        assert not any(k.startswith(("LLM_", "POSTGRES_", "PROXMOX_")) for k in env)
