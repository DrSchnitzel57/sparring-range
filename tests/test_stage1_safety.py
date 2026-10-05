"""Stage 1 regressions (audit N01–N03, second follow-up review).

Covers the negative paths the review reproduced with narrow AST substitutes,
now exercised through the REAL adapter, orchestrator and API routes:

  * uncertain management reads never authorize deletion or complete teardown;
  * confirmed absence is idempotent (no unnecessary delete);
  * a foreign VM at a pending VMID receives ZERO mutation calls;
  * durable operation claims serialize lifecycle operations across commits;
  * database-enforced single active run + start/engage race containment.
"""
from __future__ import annotations

import subprocess
import threading
import uuid

import pytest

_REAL_POPEN = subprocess.Popen


def _launch(client, users, scenario="quick-win-01", headers=None):
    sid = client.post("/sessions", json={"scenario_id": scenario},
                      headers=headers or users["member"]).json()["session_id"]
    r = client.post(f"/sessions/{sid}/launch", headers=headers or users["member"])
    assert r.status_code == 200, r.text
    return sid, r.json()


# --------------------------------------------------------------------------- #
# N01 — uncertain reads never authorize deletion                              #
# --------------------------------------------------------------------------- #

@pytest.mark.db
def test_config_read_timeout_retains_resource_and_lease(client, users, fake_pve):
    """Probe `ownership_on_read_timeout`: a config-read outage must NOT be
    read as 'gone' -> no delete may proceed; teardown reports incomplete and
    the lease stays reserved."""
    sid, out = _launch(client, users)
    vmid = out["deployment"]["hosts"][0]["vmid"]

    fake_pve.api.fail_requests = {"/config": TimeoutError("management outage")}
    t = client.post(f"/sessions/{sid}/teardown", headers=users["member"])
    assert t.status_code == 200, t.text
    body = t.json()
    assert body.get("complete") is False, body
    assert vmid in fake_pve.api.vms, "resource deleted on an UNCERTAIN identity read!"
    # no DELETE was ever issued for the VM whose identity could not be read
    dels = [r for r in fake_pve.api.requests
            if r[0] == "DELETE" and f"/qemu/{vmid}" in r[1]]
    assert dels == [], f"delete issued without ownership: {dels}"

    # lease retained -> next launch conflicts
    sid2 = client.post("/sessions", json={"scenario_id": "db-exfil-01"},
                       headers=users["op"]).json()["session_id"]
    assert client.post(f"/sessions/{sid2}/launch",
                       headers=users["op"]).status_code == 409

    # recovery: teardown completes once the API answers again
    fake_pve.api.fail_requests = {}
    t = client.post(f"/sessions/{sid}/teardown", headers=users["member"])
    assert t.json().get("complete") is True, t.json()
    assert vmid not in fake_pve.api.vms


@pytest.mark.db
@pytest.mark.parametrize("failure", [500, 403, 503])
def test_status_read_failure_during_teardown_retains_everything(client, users, fake_pve,
                                                                failure):
    """Probe `destroy_on_status_timeout`: 5xx/403 on the status endpoint is
    uncertain — resource retained, complete=false, lease retained."""
    sid, out = _launch(client, users)
    vmid = out["deployment"]["hosts"][0]["vmid"]

    fake_pve.api.fail_requests = {"/status/current": failure}
    t = client.post(f"/sessions/{sid}/teardown", headers=users["member"])
    body = t.json()
    assert body.get("complete") is False, body
    assert vmid in fake_pve.api.vms, "teardown 'completed' through a failing status read"

    sid2 = client.post("/sessions", json={"scenario_id": "db-exfil-01"},
                       headers=users["op"]).json()["session_id"]
    assert client.post(f"/sessions/{sid2}/launch",
                       headers=users["op"]).status_code == 409
    fake_pve.api.fail_requests = {}


@pytest.mark.db
def test_confirmed_absent_is_idempotent_without_delete(client, users, fake_pve):
    """A VM PVE CONFIRMS missing is booked as removed with NO delete call."""
    sid, out = _launch(client, users)
    vmid = out["deployment"]["hosts"][0]["vmid"]
    # the machine vanishes out-of-band (operator removed it, host failure...)
    del fake_pve.api.vms[vmid]

    t = client.post(f"/sessions/{sid}/teardown", headers=users["member"])
    body = t.json()
    assert body.get("complete") is True, body
    dels = [r for r in fake_pve.api.requests
            if r[0] == "DELETE" and f"/qemu/{vmid}" in r[1]]
    assert dels == [], "unnecessary delete issued for a confirmed-absent VM"


@pytest.mark.db
def test_pending_vmid_now_foreign_receives_zero_mutation(client, users, fake_pve):
    """Probe N01-resume: crash leaves a pending VMID; the number is then
    reused by a FOREIGN machine. Resume must refuse and must not send ANY
    set-config/start/delete for that VMID."""
    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    # crash between clone-completion and config (config endpoint down)
    fake_pve.api.fail_request_fragments = ("/config",)
    r = client.post(f"/sessions/{sid}/launch", headers=users["member"])
    assert r.status_code >= 500 or r.status_code == 409
    fake_pve.api.fail_request_fragments = ()

    from sqlalchemy import select
    from srplatform.db.session import db as db_ctx
    from srplatform.db.models import Deployment
    with db_ctx() as s:
        dep = s.execute(select(Deployment).where(Deployment.session_id == uuid.UUID(sid))
                        .order_by(Deployment.created_at.desc())).scalars().first()
        vmid = dep.resources[0]["vmid"]

    # VMID recycled by a foreign tenant BEFORE our resume
    v = fake_pve.api.vms[vmid]
    v["name"] = "tenant-x-db"
    v["config"] = {"name": "tenant-x-db", "tags": "tenant-x",
                   "net0": "virtio,bridge=vmbr0"}

    requests_before = len(fake_pve.api.requests)
    r = client.post(f"/sessions/{sid}/launch", headers=users["member"])
    assert r.status_code == 409, r.text
    assert r.json()["detail"]["error"] == "foreign_resource"

    mutations = [q for q in fake_pve.api.requests[requests_before:]
                 if q[0] in ("POST", "DELETE") and f"/qemu/{vmid}" in q[1]]
    assert mutations == [], f"foreign VM was mutated: {mutations}"
    assert vmid in fake_pve.api.vms and fake_pve.api.vms[vmid]["name"] == "tenant-x-db"


# --------------------------------------------------------------------------- #
# N02 — durable claims + DB-enforced run uniqueness                           #
# --------------------------------------------------------------------------- #

@pytest.mark.db
def test_operation_claim_serializes_across_commits(migrated_db, test_db_url_app):
    """The claim survives the commits that release row locks: with two
    INDEPENDENT sessions, exactly one holder wins until it releases."""
    from srplatform.db.session import db as db_ctx
    from srplatform.scenario_engine import orchestrator

    session_id = uuid.uuid4()
    with db_ctx() as s:
        from srplatform.db.models import Session as SM
        s.add(SM(session_id=session_id, scenario_id="quick-win-01", status="preparing"))
        s.commit()

    results = {}
    barrier = threading.Barrier(2)

    def worker(name):
        with db_ctx() as s:
            barrier.wait()
            try:
                orchestrator.claim_operation(s, session_id, name)
                results[name] = "claimed"
                import time
                time.sleep(0.3)
                orchestrator.release_operation(s, session_id)
            except orchestrator.OperationInProgress:
                results[name] = "conflict"

    ts = [threading.Thread(target=worker, args=(n,)) for n in ("a", "b")]
    [t.start() for t in ts]
    [t.join(timeout=10) for t in ts]
    assert sorted(results.values()) == ["claimed", "conflict"], results


@pytest.mark.db
def test_concurrent_launch_cannot_double_deploy(client, users, fake_pve):
    """Barrier-synchronized launch/launch: clone side effects happen exactly
    once regardless of which request wins the claim."""
    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    outs, barrier = {}, threading.Barrier(2)

    def fire(name):
        barrier.wait()
        outs[name] = client.post(f"/sessions/{sid}/launch", headers=users["member"])

    ts = [threading.Thread(target=fire, args=(n,)) for n in ("a", "b")]
    [t.start() for t in ts]
    [t.join(timeout=30) for t in ts]
    codes = sorted(r.status_code for r in outs.values())
    assert codes == [200, 200] or codes == [200, 409], codes
    clones = [q for q in fake_pve.api.requests if q[0] == "POST" and "/clone" in q[1]]
    assert len(clones) == 1, f"duplicate deployment side effects: {clones}"


class _DummyWorker:
    """Stand-in for the red worker subprocess (real spawn is covered in the
    M3/R01 tests; here we test SUPERVISION invariants)."""

    procs: list = []

    def __init__(self, *a, **k):
        self._p = _REAL_POPEN(["sleep", "30"], start_new_session=True,
                              stdout=subprocess.DEVNULL)
        self.pid = self._p.pid
        _DummyWorker.procs.append(self._p)

    def wait(self, timeout=None):
        return self._p.wait(timeout=timeout)

    def poll(self):
        return self._p.poll()


def _dummy_popen(*a, **k):
    return _DummyWorker()


@pytest.mark.db
def test_concurrent_run_spawns_exactly_one_worker(client, users, monkeypatch):
    """Probe N02 (run/run): the partial unique index + atomic transition mean
    concurrent /run requests produce ONE active run and ONE spawn."""
    _DummyWorker.procs = []
    import srplatform.api.runs as runs_svc
    monkeypatch.setattr(runs_svc.subprocess, "Popen", _dummy_popen)

    sid, _ = _launch(client, users)
    outs, barrier = {}, threading.Barrier(2)

    def fire(name):
        barrier.wait()
        outs[name] = client.post(f"/run/quick-win-01", json={"session_id": sid},
                                 headers=users["member"])

    ts = [threading.Thread(target=fire, args=(n,)) for n in ("a", "b")]
    [t.start() for t in ts]
    [t.join(timeout=30) for t in ts]
    assert all(r.status_code in (202, 409) for r in outs.values()), \
        {k: (r.status_code, r.text[:200]) for k, r in outs.items()}
    run_ids = {r.json().get("run_id") for r in outs.values() if r.status_code == 202}
    assert len(run_ids) == 1, "two workers for one session"
    assert len(_DummyWorker.procs) == 1, "duplicate worker spawn"

    from sqlalchemy import func as sa_func
    from sqlalchemy import select
    from srplatform.db.session import db as db_ctx
    from srplatform.db.models import Run
    with db_ctx() as s:
        n = s.execute(select(sa_func.count()).select_from(Run)
                      .where(Run.session_id == sid,
                             Run.status.in_(("queued", "running")))).scalar()
    assert n == 1
    # cleanup
    for rid in run_ids:
        client.post(f"/runs/{rid}/stop", headers=users["member"])


@pytest.mark.db
def test_start_racing_engage_never_escapes_supervision(client, users, monkeypatch):
    """Probe N02 (start/engage): if the latch engages between the gate check
    and registration, the just-spawned worker is killed and the start is
    refused — it never escapes supervision."""
    _DummyWorker.procs = []
    import srplatform.api.runs as runs_svc
    from srplatform.safety import get_supervisor

    def popen_and_engage(*a, **k):
        proc = _DummyWorker()
        # the killswitch lands while this worker is being registered
        get_supervisor().engage(reason="race test")
        return proc

    monkeypatch.setattr(runs_svc.subprocess, "Popen", popen_and_engage)
    sid, _ = _launch(client, users)
    r = client.post("/run/quick-win-01", json={"session_id": sid},
                    headers=users["member"])
    assert r.status_code == 423, r.text  # GateRefused: latched during start

    proc = _DummyWorker.procs[0]
    import time
    for _ in range(50):
        # poll() reaps the (possibly zombie) child — killpg on a zombie group
        # leader would misleadingly "succeed"
        if proc.poll() is not None:
            break
        time.sleep(0.1)
    else:
        pytest.fail("worker spawned during engage survived termination")

    from sqlalchemy import select
    from srplatform.db.session import db as db_ctx
    from srplatform.db.models import Run
    with db_ctx() as s:
        run = s.execute(select(Run).where(Run.session_id == sid)).scalars().one()
        assert run.status == "cancelled" and run.worker_token is None


# --------------------------------------------------------------------------- #
# N03 — one lifecycle policy                                                  #
# --------------------------------------------------------------------------- #

@pytest.mark.db
def test_teardown_then_run_is_refused(client, users, fake_pve):
    """A torn-down session cannot start a run against addresses it no longer
    owns; a fresh launch is required."""
    sid, _ = _launch(client, users)
    t = client.post(f"/sessions/{sid}/teardown", headers=users["member"])
    assert t.json().get("complete") is True
    r = client.post("/run/quick-win-01", json={"session_id": sid},
                    headers=users["member"])
    assert r.status_code == 409
    detail = r.json()["detail"]
    if isinstance(detail, dict):
        assert detail["error"] in ("no_current_reservation", "no_ready_deployment")
    else:
        # torn-down sessions are refused by the lifecycle status itself
        assert "torn_down" in str(detail)


@pytest.mark.db
def test_legacy_deploy_enforces_scenario_and_terminal_state(client, users, fake_pve):
    """The legacy /deploy side door enforces the same invariants as /launch."""
    sid, _ = _launch(client, users)
    # mismatched scenario -> refused BEFORE any side effect
    r = client.post("/deploy/db-exfil-01", json={"session_id": sid},
                    headers=users["member"])
    assert r.status_code == 422, r.text
    # terminal session -> refused
    client.post(f"/sessions/{sid}/end", headers=users["member"])
    r = client.post("/deploy/quick-win-01", json={"session_id": sid},
                    headers=users["member"])
    assert r.status_code == 409, r.text


@pytest.mark.db
def test_teardown_stops_active_worker_before_release(client, users, fake_pve, monkeypatch):
    """Teardown with an active run must stop and CONFIRM the worker first;
    a failed stop is a conflict and releases nothing."""
    _DummyWorker.procs = []
    import srplatform.api.runs as runs_svc
    monkeypatch.setattr(runs_svc.subprocess, "Popen", _dummy_popen)
    sid, _ = _launch(client, users)
    r = client.post("/run/quick-win-01", json={"session_id": sid},
                    headers=users["member"])
    assert r.status_code == 202, r.text
    run_id = r.json()["run_id"]

    # make termination fail -> teardown must conflict and retain everything
    def bad_terminate(pgid, expected_pstart=None):
        return {"ok": False, "detail": "injected termination failure"}
    monkeypatch.setattr(runs_svc.run_registry, "terminate_group", bad_terminate)
    t = client.post(f"/sessions/{sid}/teardown", headers=users["member"])
    assert t.status_code == 409, t.text
    assert t.json()["detail"]["error"] == "worker_stop_failed"
    assert len(fake_pve.api.vms) > 4, "machines released despite failed worker stop"

    # working termination -> teardown proceeds
    monkeypatch.undo()
    t = client.post(f"/sessions/{sid}/teardown", headers=users["member"])
    assert t.status_code == 200 and t.json().get("complete") is True
    assert len([v for v in fake_pve.api.vms if v < 9000]) == 0
