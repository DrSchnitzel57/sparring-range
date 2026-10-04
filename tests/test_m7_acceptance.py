"""M7 acceptance (API side) — the web app is a thin client of these endpoints;
if they hold, every screen is just a view over the event log:

  * accounts & login (simple LAN tokens)
  * one-click launch path = same deploy/run code path
  * live dashboard data (phase, detections, clock, hint button)
  * replay data (.cast parsed + timeline to sync against)
  * progress across MORE THAN ONE session, per-domain, derived as a query
"""
import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from srplatform.api.app import app


@pytest.fixture()
def c(migrated_db):
    return TestClient(app)


def test_m7_accounts_and_login_tokens(c):
    assert c.post("/users", json={"username": "teammate1", "display_name": "Teammate One"}).status_code == 201
    assert c.post("/users", json={"username": "teammate1"}).status_code == 409
    r = c.post("/auth/login", json={"username": "teammate1"})
    assert r.status_code == 200 and len(r.json()["token"]) >= 16
    assert c.post("/auth/login", json={"username": "nobody"}).status_code == 404


def test_m7_launch_is_the_same_code_path(c, monkeypatch):
    """Browser launch == deploy + run on the same endpoints rangectl uses."""
    from infra.proxmox_client import FakeProxmox
    from srplatform.api import deps
    deps.set_proxmox(FakeProxmox())
    try:
        assert c.post("/deploy/web-foothold-01").status_code == 200
        sid = c.post("/sessions", json={"scenario_id": "web-foothold-01", "username": "drew"}).json()["session_id"]
        # live view knows the session even before any agent state exists
        live = c.get(f"/sessions/{sid}/live")
        assert live.status_code == 200 and live.json()["status"] == "running"
    finally:
        deps.set_proxmox(None)


def _seed_scored_session(c, username, scenario, earned, total, day):
    c.post("/users", json={"username": username})
    uid = c.get("/sessions").json()  # noop keep-alive
    sid = c.post("/sessions", json={"scenario_id": scenario, "username": username}).json()["session_id"]
    ts = (datetime.now(timezone.utc) - timedelta(days=day)).isoformat()
    r = c.post("/events", json={"session_id": sid, "ts": ts, "actor": "system",
                                "action_type": "verifier", "host": "web01",
                                "payload": {"scorecard": {"earned": earned, "total": total, "items": []}}})
    assert r.status_code == 201
    return sid


def test_m7_progress_reflects_more_than_one_session(c):
    _seed_scored_session(c, "teammate2", "web-foothold-01", 15, 15, day=7)
    _seed_scored_session(c, "teammate2", "web-foothold-01", 10, 15, day=5)
    _seed_scored_session(c, "teammate2", "db-exfil-01", 8, 40, day=2)

    r = c.get("/users/teammate2/progress")
    assert r.status_code == 200
    prog = r.json()
    assert len(prog["sessions"]) == 3, "progress must span multiple sessions"
    # domain labels come from scenario focus metadata
    assert "web" in prog["by_domain"] and "exfiltration" in prog["by_domain"]
    # lagging domains are the worst averages; the web drills (15/15, 10/15) are NOT lagging
    assert prog["lagging_domains"][0] in {"data", "exfiltration", "lateral"}
    assert "web" not in prog["lagging_domains"]
    assert prog["by_domain"]["web"]["avg_pct"] == round((100 + 67) / 2) or \
           prog["by_domain"]["web"]["avg_pct"] in (83, 84)


def test_m7_replay_returns_cast_frames_and_sync_timeline(c, tmp_path, monkeypatch):
    sid = c.post("/sessions", json={"scenario_id": "web-foothold-01"}).json()["session_id"]
    cast_path = tmp_path / "tok_web01-x.cast"
    header = {"version": 2, "width": 120, "height": 32, "timestamp": 1770000000, "session_id": sid}
    cast_path.write_text(json.dumps(header) + "\n" +
                         json.dumps([0.5, "i", "id\n"]) + "\n" +
                         json.dumps([1.2, "o", "uid=0(root)\n"]) + "\n")
    c.post("/events", json={"session_id": sid, "actor": "blue:tok_web01", "host": "bastion",
                            "action_type": "bastion_session_end",
                            "payload": {"cast": str(cast_path)}, "raw_ref": str(cast_path)})
    # one more session's worth of events so the sync timeline has content
    c.post("/events", json={"session_id": sid, "actor": "red", "action_type": "tool_call",
                            "phase": "recon", "payload": {"command": "nmap x"}})

    r = c.get(f"/sessions/{sid}/replay")
    assert r.status_code == 200
    rep = r.json()
    assert rep["casts"] and rep["casts"][0]["header"]["version"] == 2
    dirs = [f[1] for f in rep["casts"][0]["frames"]]
    assert "i" in dirs and "o" in dirs  # scrub-ready frames both directions
    assert len(rep["timeline"]) >= 2
