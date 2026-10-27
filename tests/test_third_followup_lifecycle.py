"""Third-follow-up regressions — Stage 1: authoritative cancellation and
lifecycle coordination (audit T01/T02/T07).

Every test drives the ACTUAL lifecycle/recovery functions
(`runs.stop_run`, `runs.reconcile_on_startup`, `runs.complete_run`,
`orchestrator.claim_operation`, the real `runner_supervise.sh`, the real
`_bounded_reader`). Remote containment uses a DISPOSABLE LOCAL runner
fixture: the real supervisor script with `RUNNER_SUPERVISOR_STATE` in a
tmp dir and the SSH transport seam (`_base_cmd`) replaced by `/bin/sh -c`
— the containment protocol itself is production code end to end.

No test kills the descendant in its assertion path and calls it recovery;
cleanup only removes leftovers AFTER the assertions recorded the truth.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import threading
import time
import uuid

import pytest
from tests.conftest import launch_and_wait


REPO = pathlib.Path(__file__).resolve().parents[1]
SUPERVISOR = REPO / "infra" / "runner" / "runner_supervise.sh"
PY = __import__("sys").executable


# --------------------------------------------------------------------------- #
# Disposable local runner fixture: the REAL supervisor script                  #
# --------------------------------------------------------------------------- #

@pytest.fixture()
def local_supervisor(tmp_path, monkeypatch):
    """SshRunner whose control/start channels execute the REAL
    runner_supervise.sh locally (SSH seam only). Returns
    (runner, state_dir, script). Containment is the production contract:
    a delegated cgroup v2 root is required (skips with an explicit reason
    when the host does not delegate one — the supervisor refuses uncontained
    starts, audit T-04)."""
    from tests.helpers import cgroup_containment_root
    monkeypatch.setenv("RUNNER_SUPERVISOR_STATE", str(tmp_path / "jobs"))
    monkeypatch.setenv("RUNNER_CGROUP_ROOT", cgroup_containment_root())
    kh = tmp_path / "known_hosts"
    kh.write_text("runner.invalid ssh-ed25519 AAAAfake\n")
    key = tmp_path / "id_ed25519"
    key.write_text("fake\n")
    from srplatform.settings import Settings
    from srplatform.red_agent.runner import SshRunner
    s = Settings(sr_env="dev", runner_transport="ssh",
                 runner_ssh_target="runner.invalid",
                 runner_ssh_key_path=str(key),
                 runner_ssh_known_hosts=str(kh),
                 runner_supervisor_bin=str(SUPERVISOR),
                 runner_command_timeout_s=15, runner_max_output_bytes=65536)
    r = SshRunner(s)
    r._base_cmd = lambda: ["/bin/sh", "-c"]     # SSH seam only
    return r, tmp_path / "jobs", SUPERVISOR


def _sup(script, op, verb, state_dir, timeout=20):
    env = {**os.environ, "RUNNER_SUPERVISOR_STATE": str(state_dir)}
    return subprocess.run(["/bin/sh", "-c", f"{script} {verb}"],
                          capture_output=True, text=True, env=env, timeout=timeout)


def _pids_carrying(op: str) -> list[int]:
    out = []
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            with open(f"/proc/{d}/environ", "rb") as f:
                if f"SR_OP_ID={op}".encode() in f.read().split(b"\0"):
                    out.append(int(d))
        except OSError:
            continue
    return out


# --------------------------------------------------------------------------- #
# T01 — supervisor containment: descendants, tombstones, transport loss       #
# --------------------------------------------------------------------------- #

def test_t01_descendant_survives_leader_exit_status_still_sees_it(local_supervisor):
    """The review's core reproduction was: a background descendant outliving
    the leader while leader-PID-only containment reported 'gone'. Under the
    namespace boundary the kernel clears the WHOLE PID namespace when its
    init exits, so a descendant CANNOT outlive the leader — the regression
    is that this is actually true (host-identity verified, containment tree
    empty) and that status then confirms cessation truthfully. The
    anti-blind-'gone' half is preserved in the same test: while a
    descendant IS alive, status must report running and cancel must kill
    the observed host identity."""
    from tests.helpers import (alive as _alive, cgroup_tree_members,
                               find_tree_member, wait_value)
    _, state, script = local_supervisor
    from tests.helpers import cgroup_containment_root
    cg = cgroup_containment_root()
    op = f"desc{uuid.uuid4().hex[:8]}"
    started = pathlib.Path(state).parent / "started.marker"
    # start a job whose leader exits immediately, backgrounding a descendant
    conn = subprocess.Popen(
        ["/bin/sh", "-c",
         f"{script} start {op} -- bash -c 'sleep 30 & touch {started}; exit 0'"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={**os.environ, "RUNNER_SUPERVISOR_STATE": str(state)})
    try:
        conn.wait(timeout=30)
        assert started.exists(), "descendant never started"
        deadline = time.time() + 10
        while ((_pids_carrying(op) or cgroup_tree_members(cg, op))
               and time.time() < deadline):
            time.sleep(0.1)
        assert not _pids_carrying(op), \
            "work survived the leader exit (marker-carrying identity)"
        assert not cgroup_tree_members(cg, op), \
            "a HOST process survived the leader exit — cessation is a lie"
        st = _sup(script, op, f"status {op}", state)
        # 'gone' or 'not-found': the start connection's confirmed-gone
        # cleanup may already have removed the records — both are truthful
        # cessation confirmations (the runner folds both into 'confirmed').
        assert st.returncode == 0 and st.stdout.strip() in ("gone", "not-found"), \
            f"confirmed-empty tree did not report cessation: {st.stdout!r}"

        # the anti-blind-'gone' half: while a descendant IS alive
        op2 = f"alive{uuid.uuid4().hex[:8]}"
        conn2 = subprocess.Popen(
            ["/bin/sh", "-c",
             f"{script} start {op2} -- bash -c 'sleep 30 & wait'"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            env={**os.environ, "RUNNER_SUPERVISOR_STATE": str(state)})
        try:
            child = wait_value(lambda: find_tree_member(cg, op2, ("sleep", "30")))
            assert child, "descendant never started"
            st = _sup(script, op2, f"status {op2}", state)
            assert st.returncode == 0 and st.stdout.strip() == "running", \
                f"live descendant invisible to status: {st.stdout!r}"
            c = _sup(script, op2, f"cancel {op2}", state)
            assert c.returncode == 0 and c.stdout.strip() == "gone", \
                c.stdout + c.stderr
            assert wait_value(lambda: None if _alive(child) else True, 5), \
                "cancel confirmed while the descendant lived"
        finally:
            for pid in cgroup_tree_members(cg, op2):
                try:
                    os.kill(pid, 9)
                except OSError:
                    pass
            if conn2.poll() is None:
                conn2.kill()
    finally:
        for pid in cgroup_tree_members(cg, op):
            try:
                os.kill(pid, 9)
            except OSError:
                pass
        if conn.poll() is None:
            conn.kill()


def test_t01_cancel_before_start_tombstone_blocks_late_start(local_supervisor):
    """Cancel arrives before remote start registration: the acknowledgement
    must leave a tombstone so the delayed start can NEVER execute."""
    _, state, script = local_supervisor
    op = f"tomb{uuid.uuid4().hex[:8]}"
    marker = state.parent / "executed.marker"
    c = _sup(script, op, f"cancel {op}", state)
    assert c.returncode == 0 and c.stdout.strip() == "gone"
    s = _sup(script, op, f"start {op} -- touch {marker}", state)
    assert s.returncode == 3, f"late start must be refused, got {s.returncode}: {s.stdout}{s.stderr}"
    assert not marker.exists(), "cancelled operation EXECUTED after cancellation was acknowledged"


def test_t01_ssh_transport_loss_invokes_remote_cancellation(local_supervisor):
    """Ordinary SSH connection loss (client exit 255) must go through the
    supervisor — disconnect is never treated as remote cessation."""
    runner, state, script = local_supervisor
    op = f"loss{uuid.uuid4().hex[:8]}"
    result = _run_client_255(runner, op, state, script)
    assert result.exit_code == 255
    assert result.cancel_state == "confirmed", \
        f"transport loss did not confirm remote cessation: {result}"
    assert result.cancelled is True
    deadline = time.time() + 5
    while _pids_carrying(op) and time.time() < deadline:
        time.sleep(0.1)
    assert not _pids_carrying(op), "transport loss left the remote job running"


def _run_client_255(runner, op, state, script):
    """Drive SshRunner.run with a client seam that starts the real supervisor
    job and then exits 255 (transport loss) — the production 255 branch must
    cancel through the control channel."""
    import srplatform.red_agent.runner as R

    real_popen = subprocess.Popen

    class LossyPopen:
        def __init__(self, *a, **k):
            self.pid = os.getpid()   # _attach_proc identity probe only
            self.stdout = None
            self.returncode = None
            p = real_popen(
                ["/bin/sh", "-c",
                 f"{script} start {op} -- bash -c 'sleep 30' >/dev/null 2>&1 & exit 255"],
                env={**os.environ, "RUNNER_SUPERVISOR_STATE": str(state)})
            p.communicate()
            self.returncode = 255

        def wait(self, timeout=None):
            return 255

        def poll(self):
            return 255

    real_reader = R._bounded_reader
    state_flag = {"spawned": False}

    def fake_popen(*a, **k):
        # ONLY the command spawn is lossy; control-channel Popen calls go
        # through to the real subprocess (the control channel is production
        # code under test, not a seam).
        if not state_flag["spawned"]:
            state_flag["spawned"] = True
            return LossyPopen()
        return real_popen(*a, **k)

    R.subprocess.Popen = fake_popen
    R._bounded_reader = lambda proc, max_bytes, deadline=None, sink=None: (b"", False)
    try:
        return runner.run("true", timeout=8, op_id=op)
    finally:
        R.subprocess.Popen, R._bounded_reader = real_popen, real_reader


# --------------------------------------------------------------------------- #
# T01 — durable operation identity + API stop/recovery                         #
# --------------------------------------------------------------------------- #

@pytest.mark.db
def test_t01_operation_identity_persisted_before_dispatch_with_deployment(
        client, users, fake_pve):
    """The API persists the operation BEFORE dispatch, associated with the
    run AND the deployment generation (no test-created pidfile, nothing
    supplied manually by the test)."""
    from srplatform.db.models import Deployment, RunOperation
    from srplatform.db.session import db as db_ctx
    from tests.helpers import make_runner_token

    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    launch_and_wait(client, users["member"], sid)
    with db_ctx() as s:
        dep = s.query(Deployment).filter_by(session_id=sid, status="ready").first()
        dep_id = str(dep.deployment_id)
    op_id = uuid.uuid4().hex
    tok = make_runner_token(sid)
    run_id = _run_id_for(client, sid)
    r = client.post(f"/internal/runs/{run_id}/operations",
                    json={"op_id": op_id, "kind": "remote"},
                    headers={"X-Worker-Token": tok})
    assert r.status_code == 201, r.text
    with db_ctx() as s:
        row = s.query(RunOperation).filter_by(op_id=op_id).first()
        assert row is not None and row.state == "active"
        assert str(row.deployment_id) == dep_id, "operation not bound to the deployment generation"


def _run_id_for(client, sid):
    from srplatform.db.models import Run
    from srplatform.db.session import db as db_ctx
    with db_ctx() as s:
        return str(s.query(Run).filter_by(session_id=sid).order_by(Run.started_at.desc()).first().run_id)


@pytest.mark.db
def test_t01_api_stop_confirms_remote_cessation_via_production_recovery(
        client, users, local_supervisor, monkeypatch):
    """Acceptance #1 at the API boundary: a remote command is ACTUALLY
    RUNNING (host identity observed in the containment tree); stop_run must
    remove it through the control channel BEFORE reporting success — and
    only then mark the run cancelled. (The pre-namespace premise "leader
    exited, descendant lives on" is now kernel-impossible; the regression
    here is that stop confirms real cessation, never blind success.)"""
    from srplatform.db.models import Run, RunOperation
    from srplatform.db.session import db as db_ctx
    from srplatform.api import runs as runs_svc
    from tests.helpers import (cgroup_containment_root, cgroup_tree_members,
                               make_runner_token)

    runner, state, script = local_supervisor
    cg = cgroup_containment_root()
    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    tok = make_runner_token(sid)
    run_id = _run_id_for(client, sid)
    op = f"stop{uuid.uuid4().hex[:8]}"
    assert client.post(f"/internal/runs/{run_id}/operations",
                       json={"op_id": op, "kind": "remote"},
                       headers={"X-Worker-Token": tok}).status_code == 201
    # start an ACTUALLY RUNNING remote job (foreground sleep, host-visible)
    subprocess.Popen(["/bin/sh", "-c",
                      f"{script} start {op} -- sleep 30"],
                     env={**os.environ, "RUNNER_SUPERVISOR_STATE": str(state)})
    deadline = time.time() + 15
    while not cgroup_tree_members(cg, op) and time.time() < deadline:
        time.sleep(0.1)
    assert cgroup_tree_members(cg, op), "the remote job never started"

    monkeypatch.setattr(runs_svc, "_control_runner", lambda: runner)
    with db_ctx() as s:
        out = runs_svc.stop_run(s, run_id)
    assert out["ok"] is True, f"stop claimed success without confirmation: {out}"
    assert out["status"] == "cancelled"
    assert not cgroup_tree_members(cg, op), \
        "run cancelled while the remote command still lived"
    with db_ctx() as s:
        assert s.get(Run, uuid.UUID(run_id)).status == "cancelled"
        assert s.query(RunOperation).filter_by(op_id=op).first().state == "completed"


@pytest.mark.db
def test_t01_worker_sigkill_and_restart_recovers_persisted_operation(
        client, users, local_supervisor, monkeypatch):
    """Acceptance #2: worker SIGKILL + API restart must recover the PERSISTED
    operation through production code (reconcile_on_startup), confirm the
    REAL running remote job's cessation, and only then finish the run."""
    from srplatform.db.models import Run, RunOperation
    from srplatform.db.session import db as db_ctx
    from srplatform.api import runs as runs_svc
    from srplatform.safety.runregistry import pgid_start_time
    from tests.helpers import (cgroup_containment_root, cgroup_tree_members,
                               make_runner_token)

    runner, state, script = local_supervisor
    cg = cgroup_containment_root()
    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    tok = make_runner_token(sid)
    run_id = _run_id_for(client, sid)
    # a real worker process, then SIGKILL (no handler runs)
    worker = subprocess.Popen(["sleep", "300"], start_new_session=True)
    with db_ctx() as s:
        r = s.get(Run, uuid.UUID(run_id))
        r.pid, r.pgid, r.pgid_pstart = worker.pid, os.getpgid(worker.pid), pgid_start_time(worker.pid)
        s.commit()
    op = f"kill{uuid.uuid4().hex[:8]}"
    assert client.post(f"/internal/runs/{run_id}/operations",
                       json={"op_id": op, "kind": "remote"},
                       headers={"X-Worker-Token": tok}).status_code == 201
    subprocess.Popen(["/bin/sh", "-c",
                      f"{script} start {op} -- sleep 30"],
                     env={**os.environ, "RUNNER_SUPERVISOR_STATE": str(state)})
    deadline = time.time() + 15
    while not cgroup_tree_members(cg, op) and time.time() < deadline:
        time.sleep(0.1)
    assert cgroup_tree_members(cg, op), "the remote job never started"
    worker.kill()
    worker.wait(timeout=10)

    monkeypatch.setattr(runs_svc, "_control_runner", lambda: runner)
    runs_svc.reconcile_on_startup()

    assert not cgroup_tree_members(cg, op), \
        "startup recovery did not cancel the persisted operation"
    with db_ctx() as s:
        assert s.get(Run, uuid.UUID(run_id)).status == "failed"  # worker gone, remote confirmed
        assert s.query(RunOperation).filter_by(op_id=op).first().state == "completed"


@pytest.mark.db
def test_t01_failed_control_connection_keeps_stop_partial(client, users, monkeypatch):
    """Acceptance #3: a failed control connection/ack keeps stop PARTIAL,
    the reservation retained, and further execution blocked."""
    from srplatform.db.models import Run, RunOperation
    from srplatform.db.session import db as db_ctx
    from srplatform.api import runs as runs_svc
    from tests.helpers import make_runner_token

    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    launch_and_wait(client, users["member"], sid)
    tok = make_runner_token(sid)
    run_id = _run_id_for(client, sid)
    op = f"fail{uuid.uuid4().hex[:8]}"
    client.post(f"/internal/runs/{run_id}/operations",
                json={"op_id": op, "kind": "remote"},
                headers={"X-Worker-Token": tok})

    def broken():
        raise RuntimeError("control channel down")
    monkeypatch.setattr(runs_svc, "_control_runner", broken)

    out = client.post(f"/runs/{run_id}/stop", headers=users["member"]).json()
    assert out["ok"] is False and out["status"] == "cancel-unknown", out
    with db_ctx() as s:
        assert s.get(Run, uuid.UUID(run_id)).status == "cancel-unknown"
        assert s.query(RunOperation).filter_by(op_id=op).first().state == "cancel-unknown"
    # reservation retained + further execution blocked
    t = client.post(f"/sessions/{sid}/teardown", headers=users["member"])
    assert t.status_code == 409 and t.json()["detail"]["error"] == "worker_stop_failed"
    r = client.post("/run/quick-win-01", json={"session_id": sid},
                    headers=users["member"])
    assert r.status_code == 202 and r.json()["run_id"] == run_id, \
        "a new worker must not spawn while remote work is unknown"


@pytest.mark.db
def test_t02_run_participates_in_lifecycle_claim(client, users, fake_pve, monkeypatch):
    """Acceptance #5 (deterministic half): while a lifecycle operation holds
    the claim, /run is rejected — the bypass the review found was /run
    checking lease/deployment without ever taking the claim."""
    from srplatform.scenario_engine import orchestrator
    from srplatform.db.session import db as db_ctx

    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    launch_and_wait(client, users["member"], sid)
    with db_ctx() as s:
        orchestrator.claim_operation(s, uuid.UUID(sid), "teardown")
    r = client.post("/run/quick-win-01", json={"session_id": sid},
                    headers=users["member"])
    assert r.status_code == 409 and r.json()["detail"]["error"] == "operation_in_progress"
    with db_ctx() as s:
        orchestrator.clear_operation_claims(s)


@pytest.mark.db
def test_t02_barrier_run_versus_teardown_never_dispatches_after_release(
        client, users, fake_pve):
    """Acceptance #5 (racing half): barrier-controlled /run vs /teardown.
    The invariant: a run is never ACTIVE while the lease is released — no
    dispatch against released machines."""
    from srplatform.db.models import RangeLease
    from srplatform.db.session import db as db_ctx

    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    launch_and_wait(client, users["member"], sid)

    outs = {}
    barrier = threading.Barrier(2)

    def fire(name, fn):
        barrier.wait()
        outs[name] = fn()

    ts = [
        threading.Thread(target=fire, args=("run", lambda: client.post(
            "/run/quick-win-01", json={"session_id": sid}, headers=users["member"]).status_code)),
        threading.Thread(target=fire, args=("td", lambda: client.post(
            f"/sessions/{sid}/teardown", headers=users["member"]).status_code)),
    ]
    [t.start() for t in ts]
    [t.join(timeout=60) for t in ts]

    with db_ctx() as s:
        from srplatform.api import runs as runs_svc
        from srplatform.db.models import Run
        active = s.query(Run).filter(Run.session_id == sid,
                                     Run.status.in_(runs_svc.ACTIVE)).first()
        lease = s.get(RangeLease, 1)
        lease_held = lease is not None and lease.released_at is None
    assert not (active is not None and not lease_held), \
        f"active run {active.status if active else None} with released lease: {outs}"


@pytest.mark.db
def test_t02_queued_stop_spawn_race_persists_terminal_state(client, users, monkeypatch):
    """Acceptance #6: queued-stop racing process registration must not leave
    a permanent 'stopping' row, an unknown worker, or a false completion —
    the spawner persists the correct terminal state with identity retained."""
    from srplatform.api import runs as runs_svc
    from srplatform.db.models import Run
    from srplatform.db.session import db as db_ctx

    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    launch_and_wait(client, users["member"], sid)

    gate = threading.Event()
    real_env = runs_svc._worker_env

    def slow_env(*a, **k):
        gate.wait(timeout=15)
        return real_env(*a, **k)
    monkeypatch.setattr(runs_svc, "_worker_env", slow_env)

    result = {}

    def do_run():
        result["run"] = client.post("/run/quick-win-01", json={"session_id": sid},
                                    headers=users["member"])
    t = threading.Thread(target=do_run)
    t.start()
    # wait until the queued row exists (spawner is paused before Popen)
    run_id = None
    deadline = time.time() + 10
    while time.time() < deadline:
        with db_ctx() as s:
            row = (s.query(Run).filter(Run.session_id == sid)
                   .order_by(Run.started_at.desc()).first())
            if row is not None:
                run_id = str(row.run_id)
                break
        time.sleep(0.05)
    assert run_id, "queued row never persisted"

    stop_out = client.post(f"/runs/{run_id}/stop", headers=users["member"]).json()
    assert stop_out["ok"] is False, f"unconfirmed queued stop reported success: {stop_out}"
    gate.set()
    t.join(timeout=30)

    # the spawner must eventually persist a correct terminal state
    deadline = time.time() + 15
    while time.time() < deadline:
        with db_ctx() as s:
            st = s.get(Run, uuid.UUID(run_id)).status
            if st in runs_svc.TERMINAL or st == "cancel-unknown":
                break
        time.sleep(0.1)
    with db_ctx() as s:
        row = s.get(Run, uuid.UUID(run_id))
        assert row.status in runs_svc.TERMINAL + ("cancel-unknown",), \
            f"permanent intermediate state: {row.status}"
        if row.status == "cancelled":
            assert row.pgid is not None, "terminal cancelled without retained process identity"


@pytest.mark.db
def test_t02_callback_cannot_overwrite_terminal_cancellation(client, users):
    """Acceptance #7: a callback racing stop cannot overwrite a terminal
    cancellation — and cannot touch a 'stopping' row either."""
    from srplatform.api import runs as runs_svc
    from srplatform.db.models import Run
    from srplatform.db.session import db as db_ctx
    from tests.helpers import make_runner_token

    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    tok = make_runner_token(sid)
    run_id = _run_id_for(client, sid)

    out = client.post(f"/runs/{run_id}/stop", headers=users["member"]).json()
    assert out["ok"] and out["status"] == "cancelled"
    with pytest.raises(PermissionError):
        with db_ctx() as s:
            runs_svc.complete_run(s, run_id, tok, {"outcome": "complete"})
    with db_ctx() as s:
        assert s.get(Run, uuid.UUID(run_id)).status == "cancelled"

    # stopping is not terminal but also NOT callback-writable
    import hashlib
    with db_ctx() as s:
        r = Run(session_id=uuid.UUID(sid), scenario_id="quick-win-01",
                status="stopping",
                worker_token=hashlib.sha256(("x" * 10).encode()).hexdigest())
        s.add(r)
        s.commit()
        stopping_id = str(r.run_id)
    with pytest.raises(runs_svc.RunStateError):
        with db_ctx() as s:
            runs_svc.complete_run(s, stopping_id, "x" * 10, {"outcome": "complete"})
    with db_ctx() as s:
        assert s.get(Run, uuid.UUID(stopping_id)).status == "stopping"


@pytest.mark.db
def test_t02_failed_kill_never_sets_cancelled(client, users, monkeypatch):
    """A failed local kill must never set cancelled (T02) — the row becomes
    cancel-unknown and stays visible."""
    from srplatform.api import runs as runs_svc
    from srplatform.db.models import Run
    from srplatform.db.session import db as db_ctx
    from tests.helpers import make_runner_token

    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    make_runner_token(sid)
    run_id = _run_id_for(client, sid)
    # point the run at a group we CANNOT signal (identity mismatch = refuse)
    proc = subprocess.Popen(["sleep", "60"], start_new_session=True)
    try:
        from srplatform.safety.runregistry import pgid_start_time
        with db_ctx() as s:
            r = s.get(Run, uuid.UUID(run_id))
            r.pgid, r.pgid_pstart = os.getpgid(proc.pid), 99  # wrong start time
            s.commit()
        out = client.post(f"/runs/{run_id}/stop", headers=users["member"]).json()
        assert out["ok"] is False and out["status"] == "cancel-unknown", out
        with db_ctx() as s:
            assert s.get(Run, uuid.UUID(run_id)).status == "cancel-unknown"
    finally:
        proc.kill()
        proc.wait()


@pytest.mark.db
def test_t02_claim_owner_fencing(client, users):
    """Stale takeover + release cannot erase another request's ownership."""
    from srplatform.db.models import OperationClaim
    from srplatform.db.session import db as db_ctx
    from srplatform.scenario_engine import orchestrator
    from datetime import timedelta

    sid = uuid.UUID(client.post("/sessions", json={"scenario_id": "quick-win-01"},
                                headers=users["member"]).json()["session_id"])
    with db_ctx() as s:
        owner_a = orchestrator.claim_operation(s, sid, "launch")
        # release with the WRONG owner is a no-op
        assert orchestrator.release_operation(s, sid, "not-the-owner") is False
        assert s.get(OperationClaim, sid) is not None
        # stale takeover mints a NEW owner; the old owner's release erases nothing
        row = s.get(OperationClaim, sid)
        row.claimed_at = orchestrator._now() - timedelta(minutes=31)
        s.commit()
        owner_b = orchestrator.claim_operation(s, sid, "teardown")
        assert owner_b != owner_a
        assert orchestrator.release_operation(s, sid, owner_a) is False
        assert s.get(OperationClaim, sid) is not None, "stale owner erased the live claim"
        assert orchestrator.release_operation(s, sid, owner_b) is True
        assert s.get(OperationClaim, sid) is None


# --------------------------------------------------------------------------- #
# T07 — bounded byte-oriented reads with an independent deadline               #
# --------------------------------------------------------------------------- #

def test_t07_sparse_output_respects_deadline_and_keeps_partial_buffer():
    """One byte then a long silence: the deadline must be respected (the old
    buffered read blocked ~10x past it) and the PARTIAL buffer preserved."""
    from srplatform.red_agent.runner import _bounded_reader
    proc = subprocess.Popen(
        ["/bin/bash", "-c", "printf x; sleep 3"],
        stdout=subprocess.PIPE)
    try:
        t0 = time.monotonic()
        raw, timed_out = _bounded_reader(proc, 4096,
                                         deadline=time.monotonic() + 0.05)
        elapsed = time.monotonic() - t0
        assert timed_out is True
        assert raw == b"x", f"partial buffer lost: {raw!r}"
        assert elapsed < 0.5, f"deadline overran: {elapsed:.2f}s for a 0.05s deadline"
    finally:
        proc.kill()
        proc.wait()


def test_t07_multibyte_output_respects_BYTE_bounds():
    """The bound counts ENCODED BYTES, not text characters."""
    from srplatform.red_agent.runner import _bounded_reader
    payload = "é" * 1000          # 2 bytes each
    proc = subprocess.Popen(["/bin/bash", "-c", f"printf %s {payload!r}; true"],
                            stdout=subprocess.PIPE)
    try:
        raw, timed_out = _bounded_reader(proc, 10)
        assert timed_out is False
        assert len(raw) == 10, f"byte bound violated: {len(raw)} bytes kept"
        assert raw == payload.encode()[:10]
    finally:
        proc.kill()
        proc.wait()


def test_t07_local_runner_timeout_retains_partial_output():
    from srplatform.settings import Settings
    from srplatform.red_agent.runner import LocalDevRunner
    s = Settings(sr_env="dev", runner_transport="local-dev",
                 runner_command_timeout_s=1, runner_max_output_bytes=4096)
    r = LocalDevRunner(s)
    res = r.run("printf partial-so-far; sleep 5", timeout=1)
    assert res.timed_out is True
    assert res.output.startswith("partial-so-far"), \
        f"timeout discarded the partial buffer: {res.output!r}"


# --------------------------------------------------------------------------- #
# T01 — the worker's own stop path must not discard the verdict                #
# --------------------------------------------------------------------------- #

def test_t01_worker_signal_handler_reports_unconfirmed_cancellation(tmp_path):
    script = tmp_path / "w.py"
    script.write_text(
        "import sys, os, signal\n"
        f"sys.path.insert(0, {str(REPO)!r})\n"
        "from srplatform.red_agent import runner\n"
        "class FailingRemote:\n"
        "    def cancel_remote(self, op_id, timeout_s=10.0):\n"
        "        return False\n"
        "runner._register('opx', {'kind': 'remote', 'state': 'active',\n"
        "                         'remote': True, 'runner': FailingRemote()})\n"
        "runner.install_cancellation_handlers()\n"
        "print('ready', flush=True)\n"
        "os.kill(os.getpid(), signal.SIGTERM)\n"
        "import time; time.sleep(5)\n")
    env = {**os.environ, "SR_ENV": "dev", "RUNNER_TRANSPORT": "local-dev", "ALLOW_LOCAL_DEV_FIXTURE": "1"}
    p = subprocess.Popen([PY, str(script)], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, env=env, text=True)
    out, err = p.communicate(timeout=20)
    assert p.returncode == 144, f"exit {p.returncode}: {out}{err}"
    assert "UNCONFIRMED" in err, f"unconfirmed stop was discarded silently: {err!r}"
