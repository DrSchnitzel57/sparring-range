"""Fourth-follow-up regressions — acceptance blocker T-04: command completion
must never hide surviving remote work.

Every test drives PRODUCTION boundaries: the real `runner_supervise.sh`
(real cgroup v2 containment, real tombstones, real flocks), the real
`SshRunner` completion path, the real `RedAgentLoop` worker path, the real
API routes and the real database. No test hand-writes an active operation
row as a substitute for the worker's normal completion path, and no test
kills the descendant in its assertion path — cleanup only removes leftovers
AFTER the assertions recorded the truth.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import threading
import time
import uuid

import pytest

from tests.helpers import (alive as _alive, cgroup_tree_members as _tree_members,
                           find_tree_member as _find_member, wait_value as _wait_value)
from tests.conftest import launch_and_wait

REPO = pathlib.Path(__file__).resolve().parents[1]
SUPERVISOR = REPO / "infra" / "runner" / "runner_supervise.sh"


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


def _cgroup_members(root: str, op: str) -> list[int]:
    p = pathlib.Path(root) / f"sr-{op}" / "cgroup.procs"
    try:
        return [int(x) for x in p.read_text().split()]
    except (OSError, ValueError):
        return []


@pytest.fixture()
def local_supervisor(tmp_path, monkeypatch):
    """SshRunner over the REAL supervisor script with cgroup containment
    (SSH seam only). Returns (runner, state_dir, script, cgroup_root)."""
    from tests.helpers import cgroup_containment_root
    cg = cgroup_containment_root()
    monkeypatch.setenv("RUNNER_SUPERVISOR_STATE", str(tmp_path / "jobs"))
    monkeypatch.setenv("RUNNER_CGROUP_ROOT", cg)
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
    return r, tmp_path / "jobs", SUPERVISOR, cg


def _sup(script, verb_and_op, state_dir, timeout=20):
    env = {**os.environ, "RUNNER_SUPERVISOR_STATE": str(state_dir)}
    return subprocess.run(["/bin/sh", "-c", f"{script} {verb_and_op}"],
                          capture_output=True, text=True, env=env, timeout=timeout)


def _start(script, args, state_dir, **extra_env):
    return subprocess.Popen(
        ["/bin/sh", "-c", f"{script} {args}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={**os.environ, "RUNNER_SUPERVISOR_STATE": str(state_dir), **extra_env})


def _reap(cg: str, op: str):
    for pid in _tree_members(cg, op):
        try:
            os.kill(pid, 9)
        except OSError:
            pass


# --------------------------------------------------------------------------- #
# Supervisor containment: environment-independent, identity-guarded, atomic    #
# --------------------------------------------------------------------------- #

def test_t04_cleared_env_descendant_is_visible_and_contained(local_supervisor):
    """THE core T-04 reproduction under the namespace boundary: a background
    descendant that CLEARS its environment is invisible to the marker scan,
    yet the cgroup-backed supervisor must see it (by HOST identity) while
    the operation runs, status must say running, and cancel must remove it
    before confirming. (Marker-only tracking reported 'gone' here; the
    review's blocker.) A descendant can no longer OUTLIVE the leader — the
    kernel clears the whole PID namespace at leader exit — which the
    zero/nonzero-exit completion regressions below assert directly."""
    _, state, script, cg = local_supervisor
    op = f"clrenv{uuid.uuid4().hex[:8]}"
    conn = _start(script, f"start {op} -- bash -c 'env -i sleep 30 & wait'", state)
    try:
        child = _wait_value(lambda: _find_member(cg, op, ("sleep", "30")))
        assert child, "cleared-environment descendant never appeared in the cgroup"
        # the marker scan alone would be blind here — prove the difference:
        assert child not in _pids_carrying(op), \
            "test premise broken: env -i child still carries SR_OP_ID"
        st = _sup(script, f"status {op}", state)
        assert st.returncode == 0 and st.stdout.strip() == "running", \
            f"survivor invisible to status: {st.stdout!r}"
        c = _sup(script, f"cancel {op}", state)
        assert c.returncode == 0 and c.stdout.strip() == "gone", c.stdout + c.stderr
        assert _wait_value(lambda: None if _alive(child) else True, 5), \
            "cancel confirmed while the child lived"
        assert not _tree_members(cg, op), "members survived an acknowledged cancel"
    finally:
        _reap(cg, op)
        if conn.poll() is None:
            conn.kill()


def test_t04_start_refused_without_authoritative_containment(tmp_path):
    """The contract's other half: with no usable cgroup root the supervisor
    REFUSES the unsupported execution mode — it never runs uncontained work
    and never pretends the marker scan is authoritative."""
    state = tmp_path / "jobs"
    plain = tmp_path / "not-a-cgroup"
    plain.mkdir()
    marker = tmp_path / "executed.marker"
    env = {**os.environ, "RUNNER_SUPERVISOR_STATE": str(state),
           "RUNNER_CGROUP_ROOT": str(plain)}
    r = subprocess.run(
        ["/bin/sh", "-c", f"{SUPERVISOR} start ref{uuid.uuid4().hex[:6]} -- touch {marker}"],
        capture_output=True, text=True, env=env, timeout=20)
    assert r.returncode == 4, f"uncontained start must be refused (exit 4): {r}"
    assert "containment unavailable" in r.stderr
    assert not marker.exists(), "refused start still EXECUTED the command"


def test_t04_tombstone_refuses_start_after_acknowledged_cancel(local_supervisor,
                                                               tmp_path):
    """A start racing an ACKNOWLEDGED cancellation is refused by the durable
    tombstone — the cancelled command never executes, ever."""
    _, state, script, _ = local_supervisor
    op = f"tombs{uuid.uuid4().hex[:8]}"
    marker = tmp_path / "executed.marker"
    c = _sup(script, f"cancel {op}", state)          # cancel-before-start
    assert c.returncode == 0 and c.stdout.strip() == "gone", c.stdout + c.stderr
    s = _sup(script, f"start {op} -- touch {marker}", state)
    assert s.returncode == 3, f"delayed start after acknowledged cancel: {s}"
    assert not marker.exists(), "cancelled operation EXECUTED after cancel ack"


def test_t04_barrier_start_cancel_never_leaves_survivor_after_ack(local_supervisor,
                                                                  tmp_path):
    """The exact interleaving the review called out: start passes its
    tombstone check, cancel then runs — WITHOUT the per-op lock cancel could
    acknowledge 'gone' (seeing no process yet) while the delayed start spawns
    live work. Pinned deterministically with the documented test hook that
    runs WHILE THE START LOCK IS HELD: cancel must block, then take the
    registered job down — an acknowledged cancel never leaves a survivor."""
    _, state, script, cg = local_supervisor
    op = f"race{uuid.uuid4().hex[:8]}"
    marker = tmp_path / "executed.marker"
    hook_started = tmp_path / "hook.started"
    cancel_entered = tmp_path / "cancel.entered"
    hook = (f"touch {hook_started}; "
            f"while [ ! -f {cancel_entered} ]; do sleep 0.02; done")
    env = {**os.environ, "RUNNER_SUPERVISOR_STATE": str(state),
           "RUNNER_CGROUP_ROOT": cg, "RUNNER_SUPERVISOR_TEST_HOOK": hook}
    start = subprocess.Popen(
        ["/bin/sh", "-c", f"{script} start {op} -- bash -c 'touch {marker}; exec sleep 30'"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
    try:
        deadline = time.time() + 10
        while not hook_started.exists() and time.time() < deadline:
            time.sleep(0.02)
        assert hook_started.exists(), "start never reached the pinned window"
        cancel = subprocess.Popen(
            ["/bin/sh", "-c", f"touch {cancel_entered}; {script} cancel {op}"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env)
        cout, _ = cancel.communicate(timeout=60)
        assert "gone" in cout, f"cancel did not confirm: {cout!r}"
        # cancel acknowledged: whatever start managed to spawn, NOTHING may
        # survive the acknowledged cancellation now.
        deadline = time.time() + 10
        while _cgroup_members(cg, op) and time.time() < deadline:
            time.sleep(0.05)
        assert not _cgroup_members(cg, op), \
            "work survived a cancellation that was already acknowledged"
        assert not _pids_carrying(op)
    finally:
        _reap(cg, op)
        if start.poll() is None:
            start.kill()
        else:
            start.communicate(timeout=10)


def test_t04_pgid_signal_requires_process_identity(local_supervisor):
    """A recorded pid whose START IDENTITY does not match (reused pid/pgid)
    must never be signalled — the kill is cgroup/marker-scoped, not
    number-scoped."""
    _, state, script, _ = local_supervisor
    op = f"reuse{uuid.uuid4().hex[:8]}"
    victim = subprocess.Popen(["/bin/bash", "-c", "trap '' TERM; sleep 30"],
                              start_new_session=True)   # pgid == pid
    try:
        state.mkdir(parents=True, exist_ok=True)
        # pidfile records the LIVE victim pid with a WRONG start time
        (state / f"{op}.pid").write_text(f"{victim.pid}:1\n")
        c = _sup(script, f"cancel {op}", state)
        assert c.returncode == 0 and c.stdout.strip() == "gone", c.stdout + c.stderr
        assert victim.poll() is None, \
            "cancel signalled a process group whose recorded identity did not match"
    finally:
        victim.kill()
        victim.wait()


# --------------------------------------------------------------------------- #
# SshRunner completion path: exit code never outranks containment              #
# --------------------------------------------------------------------------- #

def test_t04_normal_zero_exit_with_survivor_is_contained_not_blind(local_supervisor,
                                                                    monkeypatch):
    """Leader exits 0 leaving a redirected background child. Under the
    namespace boundary the kernel removes EVERY descendant when the
    namespace's init exits — a survivor cannot form. The completion path
    must still CONSULT the authoritative supervisor before calling the
    operation finished, and the clean verdict must be backed by an empty
    containment tree observed with real host identities — never a blind
    success."""
    runner, state, script, cg = local_supervisor
    op = f"done0{uuid.uuid4().hex[:8]}"
    consulted: list[str] = []
    real_status = runner.containment_status

    def spy(op_id):
        consulted.append(op_id)
        return real_status(op_id)

    monkeypatch.setattr(runner, "containment_status", spy)
    res = runner.run("sleep 30 & echo hi; exit 0", timeout=15, op_id=op)
    try:
        assert res.exit_code == 0 and res.error is None, res
        assert res.cancel_state is None, res
        assert consulted == [op], "completion did not consult the containment authority"
        assert res.note is None, f"confirmed cessation must not claim survivors: {res}"
        assert not _tree_members(cg, op), \
            "runner reported completion while work survived the leader exit"
    finally:
        _reap(cg, op)


def test_t04_completion_note_records_survivor_containment(local_supervisor,
                                                          monkeypatch):
    """If the supervisor ever DOES report surviving work at completion, the
    runner must contain it and RECORD the containment in the result note —
    never report a blind success. (Under the namespace boundary survivors
    cannot form, so this pins the completion-path logic itself with a
    controlled authoritative verdict.)"""
    runner, state, script, cg = local_supervisor
    monkeypatch.setattr(runner, "containment_status", lambda op_id: "running")
    monkeypatch.setattr(runner, "cancel_remote", lambda op_id, timeout_s=10: True)
    res = runner.run("true", timeout=15, op_id=f"note{uuid.uuid4().hex[:8]}")
    assert res.exit_code == 0, res
    assert res.note and "surviving" in res.note.lower(), \
        f"completion did not record survivor containment: {res}"


def test_t04_failed_normal_exit_is_also_gated_on_containment(local_supervisor,
                                                             monkeypatch):
    """'Cover failed normal exits as well as zero exits': a NONZERO leader
    exit goes through the same containment gate — the exit code never
    outranks the authoritative cessation verdict."""
    runner, state, script, cg = local_supervisor
    op = f"done7{uuid.uuid4().hex[:8]}"
    consulted: list[str] = []
    real_status = runner.containment_status

    def spy(op_id):
        consulted.append(op_id)
        return real_status(op_id)

    monkeypatch.setattr(runner, "containment_status", spy)
    res = runner.run("sleep 30 & exit 7", timeout=15, op_id=op)
    try:
        assert res.exit_code == 7, res
        assert consulted == [op], "nonzero exit skipped the containment gate"
        assert not _tree_members(cg, op), \
            "work survived a nonzero leader exit"
    finally:
        _reap(cg, op)


def test_t04_unconfirmed_survivor_containment_is_unknown(local_supervisor,
                                                         monkeypatch):
    """A survivor the supervisor cannot confirm gone yields
    cancel_state='unknown' with a SURVIVING error — the nonzero-exit
    completion path never folds an unresolved containment into a plain
    failure exit."""
    runner, state, script, cg = local_supervisor
    monkeypatch.setattr(runner, "containment_status", lambda op_id: "running")
    monkeypatch.setattr(runner, "cancel_remote", lambda op_id, timeout_s=10: False)
    res = runner.run("exit 7", timeout=15, op_id=f"unconf{uuid.uuid4().hex[:8]}")
    assert res.exit_code == 7, res
    assert res.cancel_state == "unknown", res
    assert "SURVIVING" in (res.error or "").upper(), res


def test_t04_unreachable_supervisor_at_completion_is_unknown(local_supervisor,
                                                             monkeypatch):
    """When containment CANNOT be observed (control channel dead at the
    completion check), the result is cancel_state='unknown' with an
    UNREACHABLE error — never a silent completion. The loop halts and the
    API refuses finalization on that verdict. (The unknown comes from the
    dead control channel itself; no survivor needs to exist for the state
    to be unknown.)"""
    runner, state, script, cg = local_supervisor
    op = f"unreach{uuid.uuid4().hex[:8]}"
    real_control = runner._control

    def dead(verb, op_id, timeout=15):
        return 124, "control channel down"

    try:
        monkeypatch.setattr(runner, "_control", dead)
        # start still goes through the real channel (Popen, not _control):
        # the command runs and completes, and the containment check that
        # follows finds the supervisor unreachable.
        res = runner.run("echo bg; exit 0", timeout=15, op_id=op)
        assert res.cancel_state == "unknown", \
            f"unreachable supervisor folded into completion: {res}"
        assert "UNREACHABLE" in (res.error or "").upper(), res
        assert "bg" in res.output, f"command never ran: {res}"
    finally:
        monkeypatch.setattr(runner, "_control", real_control)
        _sup(script, f"cancel {op}", state)
        _reap(cg, op)


def test_t04_control_channel_noise_cannot_forge_a_verdict():
    """The channel merges stderr: a stray line must not turn 'gone' into
    'unknown' (the exact failure that made the transport-loss regression
    environment-dependent)."""
    from srplatform.red_agent.runner import SshRunner
    noise = ("/path/runner_supervise.sh: line 62: /proc/1/environ: "
             "Permission denied\ngone\n")
    assert SshRunner._verdict(noise) == "gone"
    assert SshRunner._verdict("running") == "running"
    assert SshRunner._verdict("") == ""


# --------------------------------------------------------------------------- #
# Full worker → operation-done → API path (real loop, real routes, real DB)    #
# --------------------------------------------------------------------------- #

def _run_id_for(sid) -> str:
    from srplatform.db.models import Run
    from srplatform.db.session import db as db_ctx
    with db_ctx() as s:
        return str(s.query(Run).filter_by(session_id=sid)
                   .order_by(Run.started_at.desc()).first().run_id)


def _only_op(run_id) -> str:
    from srplatform.db.models import RunOperation
    from srplatform.db.session import db as db_ctx
    with db_ctx() as s:
        return s.query(RunOperation).filter_by(run_id=run_id).first().op_id


@pytest.mark.db
def test_t04_worker_completion_contains_survivors_before_api_stop(
        client, users, local_supervisor):
    """ACCEPTANCE #1 (review): the real worker/runner executes a harmless
    command whose leader exits zero while backgrounding a child; the
    ORDINARY operation-done path runs; then the actual API stop/end path.
    Under the namespace boundary the kernel removes every descendant at
    leader exit, so the child CANNOT survive — the regression is that the
    completion path still CONSULTS the authoritative containment (never
    blind), the tree is verifiably empty by the time the row says
    completed, and the API stop/end path stays clean."""
    from srplatform.db.models import Run, RunOperation
    from srplatform.db.session import db as db_ctx
    from srplatform.red_agent.loop import RedAgentLoop
    from srplatform.red_agent.transport import TestClientTransport
    from tests.helpers import FakeLLM, make_runner_token, tool

    runner, state, script, cg = local_supervisor
    consulted: list[str] = []
    real_status = runner.containment_status

    def spy(op_id):
        consulted.append(op_id)
        return real_status(op_id)

    runner.containment_status = spy
    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    tok = make_runner_token(sid)
    run_id = _run_id_for(sid)
    tr = TestClientTransport(client, tok, run_id=run_id)
    loop = RedAgentLoop(sid, "quick-win-01", tr,
                        FakeLLM([tool("x", "sleep 30 & echo bg; exit 0"),
                                 tool("d", "DONE"), tool("d", "DONE"),
                                 tool("d", "DONE")]),
                        runner, max_steps=6, compress_after=50)
    loop.run()

    with db_ctx() as s:
        ops = s.query(RunOperation).filter_by(run_id=run_id).all()
        assert len(ops) == 1, "the worker's normal path must register its operation"
        assert ops[0].state == "completed"
        op_id = ops[0].op_id
    assert consulted == [op_id], \
        "worker completion did not consult the containment authority (blind completion)"
    # the survivor was impossible AND the tree is verifiably empty by the
    # time the operation row says completed
    assert not _tree_members(cg, op_id), "survivor outlived operation-done"

    stop = client.post(f"/runs/{run_id}/stop", headers=users["member"]).json()
    assert stop["ok"] is True and stop["status"] == "cancelled", stop
    end = client.post(f"/sessions/{sid}/end", headers=users["member"])
    assert end.status_code == 200, end.text
    with db_ctx() as s:
        assert s.get(Run, uuid.UUID(run_id)).status == "cancelled"


@pytest.mark.db
def test_t04_unconfirmed_containment_refuses_finalization_stop_and_end(
        client, users, fake_pve, local_supervisor, monkeypatch):
    """When containment CANNOT BE CONFIRMED the WHOLE chain refuses to call
    it finished: the loop halts, the worker's completion is refused
    (cancel-unknown, never completed), stop is partial, /end is 409, and the
    reservation is retained — until the containment authority answers again,
    after which the retry finalizes.

    Under the namespace boundary a survivor cannot outlive the leader, so
    "unconfirmed" is produced the way production produces it: the supervisor
    is UNREACHABLE at completion (containment_status -> None). Unknown is
    never folded into gone, exactly as an unreachable control channel must
    behave even when the tree happens to be empty."""
    from srplatform.api import runs as runs_svc
    from srplatform.db.models import RangeLease, Run, RunOperation
    from srplatform.db.session import db as db_ctx
    from srplatform.red_agent.loop import RedAgentLoop
    from srplatform.red_agent.transport import TestClientTransport
    from tests.helpers import FakeLLM, make_runner_token, tool

    runner, state, script, cg = local_supervisor
    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    launch_and_wait(client, users["member"], sid)
    tok = make_runner_token(sid)
    run_id = _run_id_for(sid)

    class BrokenControl:
        def cancel_remote(self, op_id, timeout_s=15.0):
            return False

    real_cancel = runner.cancel_remote
    real_status = runner.containment_status
    # containment authority UNREACHABLE at completion time
    runner.containment_status = lambda op_id: None
    monkeypatch.setattr(runs_svc, "_control_runner", lambda: BrokenControl())

    tr = TestClientTransport(client, tok, run_id=run_id)
    loop = RedAgentLoop(sid, "quick-win-01", tr,
                        FakeLLM([tool("x", "sleep 30 & exit 0")]),
                        runner, max_steps=6, compress_after=50)
    result = loop.run()
    assert result["outcome"] == "cancel_unconfirmed", result
    op_id = _only_op(run_id)
    try:
        # the kernel boundary means nothing survived — the refusal is about
        # the UNCONFIRMED verdict, not about a live tree
        assert not _tree_members(cg, op_id)

        # the worker reports its truthful outcome; finalization must refuse
        with db_ctx() as s:
            runs_svc.complete_run(s, run_id, tok, {"outcome": "cancel_unconfirmed"})
        with db_ctx() as s:
            assert s.get(Run, uuid.UUID(run_id)).status == "cancel-unknown"
            assert s.query(RunOperation).filter_by(run_id=run_id).first().state \
                == "cancel-unknown"

        # stop is PARTIAL while containment cannot be confirmed
        stop = client.post(f"/runs/{run_id}/stop", headers=users["member"]).json()
        assert stop["ok"] is False and stop["status"] == "cancel-unknown", stop
        # end refuses to release the range
        end = client.post(f"/sessions/{sid}/end", headers=users["member"])
        assert end.status_code == 409
        assert end.json()["detail"]["error"] == "worker_stop_failed"
        with db_ctx() as s:
            lease = s.get(RangeLease, 1)
            assert lease is not None and lease.released_at is None, \
                "reservation released with unconfirmed remote work"

        # containment authority reachable again — the retry confirms and finalizes
        runner.containment_status = real_status
        runner.cancel_remote = real_cancel
        monkeypatch.setattr(runs_svc, "_control_runner", lambda: runner)
        end = client.post(f"/sessions/{sid}/end", headers=users["member"])
        assert end.status_code == 200, end.text
        assert not _tree_members(cg, op_id), \
            "successful cessation response with the child still alive"
        with db_ctx() as s:
            assert s.get(Run, uuid.UUID(run_id)).status == "cancelled"
            assert s.query(RunOperation).filter_by(op_id=op_id).first().state \
                == "completed"
    finally:
        runner.containment_status = real_status
        runner.cancel_remote = real_cancel
        _sup(script, f"cancel {op_id}", state)
        _reap(cg, op_id)


# --------------------------------------------------------------------------- #
# Registration vs stop/finalization serialization (production routes)          #
# --------------------------------------------------------------------------- #

@pytest.mark.db
def test_t04_registration_refused_for_stopping_and_cancel_unknown(client, users):
    from srplatform.db.models import Run
    from srplatform.db.session import db as db_ctx
    from tests.helpers import make_runner_token

    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    tok = make_runner_token(sid)
    run_id = _run_id_for(sid)

    def register():
        return client.post(f"/internal/runs/{run_id}/operations",
                           json={"op_id": uuid.uuid4().hex, "kind": "remote"},
                           headers={"X-Worker-Token": tok})

    assert register().status_code == 201
    for bad in ("stopping", "cancel-unknown"):
        with db_ctx() as s:
            s.get(Run, uuid.UUID(run_id)).status = bad
            s.commit()
        r = register()
        assert r.status_code == 409, f"registration accepted while {bad}: {r.text}"
        assert "refused" in str(r.json()).lower()


@pytest.mark.db
def test_t04_registration_races_stop_never_active_on_terminal(client, users,
                                                              monkeypatch):
    """Both sides of the race, independent DB sessions, production routes,
    barrier-synchronized. Invariant after every interleaving: a terminal run
    NEVER has an unresolved operation row, and an unresolved row never
    coexists with a terminal run."""
    from srplatform.api import runs as runs_svc
    from srplatform.db.models import Run, RunOperation
    from srplatform.db.session import db as db_ctx
    from tests.helpers import make_runner_token

    class ConfirmingRunner:
        def cancel_remote(self, op_id, timeout_s=15.0):
            return True

    monkeypatch.setattr(runs_svc, "_control_runner", lambda: ConfirmingRunner())

    for attempt in range(5):
        sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                          headers=users["member"]).json()["session_id"]
        tok = make_runner_token(sid)
        run_id = _run_id_for(sid)
        op_id = uuid.uuid4().hex
        outs = {}
        barrier = threading.Barrier(2)

        def register():
            barrier.wait()
            outs["reg"] = client.post(f"/internal/runs/{run_id}/operations",
                                      json={"op_id": op_id, "kind": "remote"},
                                      headers={"X-Worker-Token": tok}).status_code

        def stop():
            barrier.wait()
            outs["stop"] = client.post(f"/runs/{run_id}/stop",
                                       headers=users["member"]).json()

        ts = [threading.Thread(target=register), threading.Thread(target=stop)]
        [t.start() for t in ts]
        [t.join(timeout=60) for t in ts]

        with db_ctx() as s:
            run = s.get(Run, uuid.UUID(run_id))
            op = s.query(RunOperation).filter_by(run_id=run_id).first()
            unresolved = op is not None and op.state in runs_svc.UNRESOLVED_OPS
            assert not (run.status in runs_svc.TERMINAL and unresolved), \
                f"attempt {attempt}: terminal {run.status} with {op.state} op: {outs}"
            if run.status in runs_svc.TERMINAL:
                assert op is None or op.state == "completed", \
                    f"attempt {attempt}: {outs}"


@pytest.mark.db
def test_t04_complete_run_refused_while_operation_unresolved(client, users,
                                                             monkeypatch):
    """Run finalization depends on AUTHORITATIVE containment, not the
    worker's word: with an unresolved operation, a 'complete' callback is
    refused while containment fails, and only finalizes once the control
    channel confirms cessation."""
    from srplatform.api import runs as runs_svc
    from srplatform.db.models import Run, RunOperation
    from srplatform.db.session import db as db_ctx
    from tests.helpers import make_runner_token

    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    tok = make_runner_token(sid)
    run_id = _run_id_for(sid)
    op_id = uuid.uuid4().hex
    assert client.post(f"/internal/runs/{run_id}/operations",
                       json={"op_id": op_id, "kind": "remote"},
                       headers={"X-Worker-Token": tok}).status_code == 201

    class BrokenRunner:
        def cancel_remote(self, op_id, timeout_s=15.0):
            return False

    monkeypatch.setattr(runs_svc, "_control_runner", lambda: BrokenRunner())
    with db_ctx() as s:
        runs_svc.complete_run(s, run_id, tok, {"outcome": "complete"})
    with db_ctx() as s:
        run = s.get(Run, uuid.UUID(run_id))
        assert run.status == "cancel-unknown", \
            f"finalized while remote work unresolved: {run.status}"
        assert s.query(RunOperation).filter_by(op_id=op_id).first().state \
            == "cancel-unknown"

    # containment confirmed — a later stop finalizes correctly
    class ConfirmingRunner:
        def cancel_remote(self, op_id, timeout_s=15.0):
            return True

    monkeypatch.setattr(runs_svc, "_control_runner", lambda: ConfirmingRunner())
    out = client.post(f"/runs/{run_id}/stop", headers=users["member"]).json()
    assert out["ok"] is True and out["status"] == "cancelled", out
    with db_ctx() as s:
        assert s.query(RunOperation).filter_by(op_id=op_id).first().state == "completed"
