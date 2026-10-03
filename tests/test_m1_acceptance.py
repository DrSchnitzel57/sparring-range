"""M1 acceptance tests — Part 5/M1 'Accept when':

  * `rangectl deploy web-foothold-01` creates the scenario hosts from templates
  * `rangectl reset` returns them to a clean baseline
  * `rangectl teardown` removes every clone with no orphans left behind

Driven through the API front door (Part 3) with FakeProxmox (Drew's R740 is the
real gate — the linked-clone + cloud-init + start call sequence is what we pin).
"""
import pytest
from fastapi.testclient import TestClient

from infra.proxmox_client import FakeProxmox
from srplatform.api import deps
from srplatform.api.app import app


@pytest.fixture()
def client(migrated_db):
    fake = FakeProxmox()
    deps.set_proxmox(fake)
    yield TestClient(app), fake
    deps.set_proxmox(None)


def test_m1_deploy_creates_hosts_from_templates(client):
    c, fake = client
    r = c.post("/deploy/web-foothold-01")
    assert r.status_code == 200, r.text
    hosts = r.json()["hosts"]
    assert len(hosts) == 1 and hosts[0]["host"] == "web01"
    # linked clone from the golden template (full=False), then cloud-init IP pinned, then start
    clone = [call for call in fake.calls if call[0] == "CLONE"]
    assert clone and clone[0][1] == 9001 and clone[0][4] is False, "deploy must use LINKED clones"
    assert any(call[0] == "POST" and "config" in call[1] and "ip=10.66.0.10" in call[2].get("ipconfig0", "") for call in fake.calls)
    assert any(call[0] == "START" for call in fake.calls)
    # deployment is recorded in the append-only log
    events = c.get("/events").json()
    dep = [e for e in events if e["action_type"] == "deploy"]
    assert dep and dep[-1]["payload"]["linked"] is True and dep[-1]["payload"]["template_vmid"] == 9001


def test_m1_reset_returns_hosts_to_clean_baseline(client):
    c, fake = client
    deploy = c.post("/deploy/web-foothold-01").json()
    vmid = deploy["hosts"][0]["vmid"]

    r = c.post("/deploy/web-foothold-01/reset")
    assert r.status_code == 200, r.text
    assert r.json()["removed"], "reset must destroy the dirty clone"
    # the dirty clone was destroyed (the freed VMID may be reused for the fresh clone)
    assert any(call[0] == "DESTROY" and call[2] == vmid for call in fake.calls)
    new_hosts = r.json()["redeployed"]
    assert new_hosts and new_hosts[0]["host"] == "web01"
    clones = [call for call in fake.calls if call[0] == "CLONE"]
    assert len(clones) == 2, "reset = destroy + fresh clone from golden template"
    # a fresh login token target still resolves to the new vm (topology name stable)
    assert new_hosts[0]["ip"] == "10.66.0.10"


def test_m1_teardown_removes_every_clone_no_orphans(client):
    c, fake = client
    c.post("/deploy/web-foothold-01")
    r = c.post("/deploy/web-foothold-01/teardown")
    assert r.status_code == 200, r.text
    assert r.json()["removed"], "teardown must remove the clone"
    assert r.json()["orphans"] == [], "no orphans left behind"
    assert fake.vms == {}
