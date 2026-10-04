"""M7 acceptance (API side) — the web app is a thin authenticated client of
these endpoints; if they hold, every screen is just a view over the event log:

  * accounts & real credential login (tokens expire; logout revokes)
  * one-click launch = the same backend workflow the CLI uses
  * live dashboard data (phase, detections with real times)
  * replay data (.cast parsed + epoch header + timeline to sync against)
  * progress across MORE THAN ONE session, PER-DOMAIN from trusted score
    snapshots (F20), including partial-score honesty
"""
import uuid
from datetime import datetime, timedelta, timezone

import pytest

pytestmark = pytest.mark.db


def test_m7_login_lifecycle(client, users):
    me = client.get("/users/me", headers=users["member"])
    assert me.status_code == 200 and me.json()["username"] == "blue"
    # bad password never authenticates; unauthenticated is 401 not 200-with-nulls
    assert client.post("/auth/login", json={"username": "blue", "password": "nope"}
                       ).status_code == 401
    assert client.get("/sessions").status_code == 401
    # logout revokes: the same token must stop working
    tok = users["member_token"]
    assert client.post("/auth/logout",
                       headers={"Authorization": f"Bearer {tok}"}).status_code == 200
    assert client.get("/users/me",
                      headers={"Authorization": f"Bearer {tok}"}).status_code == 401


def test_m7_library_filters_and_one_click_launch(client, users):
    rows = client.get("/scenarios", headers=users["member"]).json()
    easy = [r for r in rows if r["difficulty"] == 1 and "web" in (r.get("focus") or [])]
    assert any(r["id"] == "web-foothold-01" for r in easy)
    # one-click = create + launch, and the response carries everything the
    # browser needs to render the "connect" step
    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    out = client.post(f"/sessions/{sid}/launch", headers=users["member"]).json()
    assert out["connections"] and "ssh" in out["connections"][0]


def _mk_events_direct(client, users, sid, rows):
    """Append system-role evidence via the service layer (test stands in for
    runtime events that the endpoints would create over real time)."""
    from srplatform.db.session import db as db_ctx
    from srplatform.db.models import Event
    with db_ctx() as s:
        for r in rows:
            s.add(Event(session_id=uuid.UUID(sid), actor=r.get("actor", "system"),
                        host=r.get("host"), action_type=r["action_type"],
                        phase=r.get("phase"), ts=r["ts"], payload=r["payload"]))
        s.commit()


def test_m7_live_dashboard_reads_state_and_real_times(client, users):
    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    client.put(f"/agent_state/{sid}", json={"current_phase": "recon", "summary": None,
                                            "summary_upto": 0},
               headers=users["member"])
    now = datetime.now(timezone.utc)
    _mk_events_direct(client, users, sid, [
        {"action_type": "verifier", "host": "web01", "ts": now - timedelta(minutes=2),
         "payload": {"objective": "flaggrab", "passed": True}},
    ])
    live = client.get(f"/sessions/{sid}/live", headers=users["member"]).json()
    assert live["red_phase"] == "recon"
    assert live["detections"] and live["detections"][0]["objective"] == "flaggrab"
    assert live["detections"][0]["passed"] is True
    assert live["detections"][0]["ts"].startswith((now - timedelta(minutes=2)).strftime("%Y-%m-%dT"))


def test_m7_progress_is_per_domain_from_snapshots_over_multiple_sessions(client, users):
    import sqlalchemy as sa
    from sqlalchemy import create_engine
    from srplatform import verification_service

    # session 1: quick-win fully healthy hosts -> 15/15
    s1 = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                     headers=users["member"]).json()["session_id"]
    client.post(f"/sessions/{s1}/launch", headers=users["member"])

    def healthy(host, command):
        if "awk" in command:
            return 0, ""
        if "list-unit-files" in command:
            return 0, "sshd.service enabled enabled\n"
        return 1, "no"
    verification_service.set_verifier_exec(healthy)
    c1 = client.post(f"/sessions/{s1}/score", headers=users["member"]).json()
    assert c1["earned"] == 15

    # session 2: web01 up, sshd gone -> partial domain coverage
    s2 = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                     headers=users["member"]).json()["session_id"]
    client.post(f"/sessions/{s2}/launch", headers=users["member"])

    def degraded(host, command):
        if "awk" in command:
            return 0, "hacker\n"          # rogue admin present -> lose identify
        if "list-unit-files" in command:
            return 0, "sshd.service enabled enabled\n"
        return 1, "no"
    verification_service.set_verifier_exec(degraded)
    c2 = client.post(f"/sessions/{s2}/score", headers=users["member"]).json()
    assert c2["earned"] == 5 and c2["status"] == "scored"

    prog = client.get("/users/blue/progress", headers=users["member"]).json()
    assert prog["by_domain"]["identify"]["avg_pct"] == 50      # 10/20 across sessions
    assert prog["by_domain"]["protect"]["avg_pct"] == 100
    assert {s["session_id"] for s in prog["sessions"]} == {s1, s2}
    assert len(prog["sessions"]) == 2                          # deduped per session
    # other members cannot read this progress
    assert client.get("/users/blue/progress", headers=users["op"]).status_code == 200
    assert client.get("/users/drew/progress", headers=users["member"]).status_code == 403


def test_m7_replay_shape_epoch_and_containment(client, users, tmp_path):
    import json as jsonlib
    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    recs_dir = tmp_path / "recordings"
    recs_dir.mkdir(exist_ok=True)
    cast = recs_dir / "rec1.cast"
    hdr = {"version": 2, "width": 120, "height": 32,
           "timestamp": int(datetime.now(timezone.utc).timestamp())}
    cast.write_text(jsonlib.dumps(hdr) + "\n" +
                    jsonlib.dumps([0.1, "o", "$ id\n"]) + "\n" +
                    jsonlib.dumps([0.4, "i", "id\n"]) + "\n")
    # register through the bastion capability (the only writer)
    btok = client.post("/admin/service_tokens", json={"scope": "bastion",
                                                      "session_id": sid},
                       headers=users["op"]).json()["token"]
    r = client.post(f"/sessions/{sid}/recordings",
                    json={"cast_path": str(cast)},
                    headers={"Authorization": f"Bearer {btok}"})
    assert r.status_code == 201
    rid = r.json()["recording_id"]

    rp = client.get(f"/sessions/{sid}/replay", headers=users["member"]).json()
    assert rp["casts"][0]["header"]["timestamp"]              # epoch anchor present
    assert rp["casts"][0]["frames"][1] == [0.4, "i", "id\n"]

    # path containment: a path outside the recordings root is rejected at REGISTRATION
    outside = tmp_path / "evil.cast"
    outside.write_text("x")
    r = client.post(f"/sessions/{sid}/recordings", json={"cast_path": str(outside)},
                    headers={"Authorization": f"Bearer {btok}"})
    assert r.status_code == 422

    # a symlink pointing outside is rejected at READ time (policy in web_routes)
    link = recs_dir / "link.cast"
    link.symlink_to("/etc/passwd")
    from srplatform.db.session import db as db_ctx
    from srplatform.db.models import Recording
    with db_ctx() as s:
        s.add(Recording(session_id=uuid.UUID(sid), cast_path=str(link), status="open"))
        s.commit()
    rp = client.get(f"/sessions/{sid}/replay", headers=users["member"]).json()
    broken = [c for c in rp["casts"] if c.get("error")]
    assert broken and "symlink" in broken[0]["error"]


def test_m7_cursor_pagination_deterministic(client, users):
    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    now = datetime.now(timezone.utc)
    rows = [{"action_type": "note", "ts": now, "payload": {"i": i}} for i in range(25)]
    _mk_events_direct(client, users, sid, rows)
    page1 = client.get("/events", params={"session_id": sid, "limit": 10},
                       headers=users["member"]).json()
    page2 = client.get("/events", params={"session_id": sid, "limit": 10,
                                          "after_event_id": page1[-1]["event_id"]},
                       headers=users["member"]).json()
    ids = [e["event_id"] for e in page1 + page2]
    assert ids == sorted(ids) and len(set(ids)) == 20
    tail = client.get("/events", params={"session_id": sid, "tail": 3},
                      headers=users["member"]).json()
    assert [e["payload"]["i"] for e in tail] == [22, 23, 24]
