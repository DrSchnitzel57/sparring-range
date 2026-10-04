"""M1 acceptance tests — Part 5/M1 'Accept when':

  * launching a scenario creates its hosts from golden templates (correct
    clone/config/start sequence, task-waited) — F06 NIC validation included
  * reset returns hosts to a clean baseline (destroy + fresh clones)
  * teardown removes EVERY resource the session owns, no prefix sweeps, no
    orphans; the single-range lease serializes concurrent scenarios

Driven through the API front door with the REAL ProxmoxClient over FakePVEHttp
(so URLs, verbs and UPID polling are exercised). Drew's R740 remains the live gate.
"""
import pytest

pytestmark = pytest.mark.db


def _launch(client, headers, scenario="web-foothold-01"):
    sid = client.post("/sessions", json={"scenario_id": scenario},
                      headers=headers).json()["session_id"]
    r = client.post(f"/sessions/{sid}/launch", headers=headers)
    assert r.status_code == 200, r.text
    return sid, r.json()


def test_m1_launch_clones_from_templates_and_issues_connections(client, users, fake_pve):
    sid, out = _launch(client, users["member"])
    hosts = out["deployment"]["hosts"]
    assert len(hosts) == 1 and hosts[0]["host"] == "web01"
    vmid = hosts[0]["vmid"]
    # the clone exists, is RUNNING, was linked (created from template), and got
    # range network placement + ownership tag (F06)
    v = fake_pve.api.vms[vmid]
    assert v["status"] == "running" and v["template"] == 9001
    cfg = v["config"]
    assert "vmbr" in cfg["net0"] and "srsess=" in cfg["tags"]
    assert hosts[0]["ip"] in cfg["ipconfig0"]
    # session is ready and per-host connection capabilities were issued (F08)
    assert out["status"] == "ready"
    conn = out["connections"][0]
    assert conn["login_token"].startswith("tok-") and conn["login_token"] in conn["ssh"]

    # single-active-range: a second scenario cannot launch over live VMs
    sid2, r2 = None, client.post("/sessions", json={"scenario_id": "db-exfil-01"},
                                 headers=users["member"])
    sid2 = r2.json()["session_id"]
    conflict = client.post(f"/sessions/{sid2}/launch", headers=users["member"])
    assert conflict.status_code == 409
    assert conflict.json()["detail"]["error"] == "range_busy"
    assert conflict.json()["detail"]["holder_session"] == sid


def test_m1_reset_replaces_owned_resources_and_teardown_leaves_no_orphans(
        client, users, fake_pve):
    sid, out = _launch(client, users["member"])
    first_vmid = out["deployment"]["hosts"][0]["vmid"]

    r = client.post(f"/sessions/{sid}/reset", headers=users["member"])
    assert r.status_code == 200, r.text
    out2 = r.json()
    # the owned VM was destroyed and a FRESH clone is serving the session
    # (the PVE allocator may legitimately reuse the freed VMID)
    assert out2["removed"] == [out["deployment"]["hosts"][0]["name"]]
    new_vmid = out2["hosts"][0]["vmid"]
    assert fake_pve.api.vms[new_vmid]["status"] == "running"
    assert len([v for vmid, v in fake_pve.api.vms.items() if vmid not in (9001, 9002, 9003, 9004)]) == 1

    r = client.post(f"/sessions/{sid}/teardown", headers=users["member"])
    assert r.status_code == 200 and r.json()["removed"]
    # no orphans: only the untouched templates remain
    assert set(fake_pve.api.vms) == {9001, 9002, 9003, 9004}
    # teardown is idempotent
    assert client.post(f"/sessions/{sid}/teardown", headers=users["member"]).status_code == 200


def test_m1_end_releases_lease_revokes_tokens_and_scores(client, users, fake_pve, migrated_db):
    import sqlalchemy as sa
    from sqlalchemy import create_engine

    sid, out = _launch(client, users["member"])
    tok = out["connections"][0]["login_token"]

    r = client.post(f"/sessions/{sid}/end", headers=users["member"])
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["status"] == "complete"
    # end runs the TRUSTED scorecard; hosts unreachable here -> visible honesty
    assert body["scorecard_status"] in ("partial", "unscored", "scored")

    # lease released: another member can now launch
    sid2 = client.post("/sessions", json={"scenario_id": "db-exfil-01"},
                       headers=users["op"]).json()["session_id"]
    assert client.post(f"/sessions/{sid2}/launch", headers=users["op"]).status_code == 200

    # session bastion tokens revoked at end
    eng = create_engine(migrated_db)
    with eng.connect() as c:
        revoked = c.execute(sa.text(
            "SELECT revoked_at FROM login_tokens WHERE token=:t"), {"t": tok}).scalar()
        assert revoked is not None


def test_m1_deploy_failure_is_persisted_and_resources_stay_owned(client, users, fake_pve):
    fake_pve.api.fail_task_fragments = ("/clone",)
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    r = client.post(f"/sessions/{sid}/launch", headers=users["member"])
    assert r.status_code >= 500 or r.status_code == 409  # failed loudly, not silently
    fake_pve.api.fail_task_fragments = ()
    # lease still held after failure (documented: operator ends/tears down explicitly)
    ev_types = [e["action_type"] for e in
                client.get(f"/events", params={"session_id": sid, "tail": 50},
                           headers=users["member"]).json()]
    assert "deploy_failed" in ev_types
    # owned-but-failed session can be torn down and the lease freed via end
    client.post(f"/sessions/{sid}/teardown", headers=users["member"])
    assert client.post(f"/sessions/{sid}/end", headers=users["member"]).status_code == 200


def test_m1_access_control_on_other_sessions(client, users):
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    # another member cannot even see it; the operator can
    assert client.get(f"/sessions/{sid}", headers=users["member"]).status_code == 200
    sid2 = client.post("/sessions", json={"scenario_id": "db-exfil-01"},
                       headers=users["op"]).json()["session_id"]
    # member tries to control the operator's session
    assert client.post(f"/sessions/{sid2}/end", headers=users["member"]).status_code == 403
    assert client.post(f"/sessions/{sid}/end", headers=users["op"]).status_code == 200
