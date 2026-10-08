"""Fifth-follow-up acceptance regressions (findings F1-F5, F7, F8).

Every test drives PRODUCTION boundaries: the real `runner_supervise.sh`
(real cgroup v2 containment + real namespace boundary), the real `SshRunner`
completion path, the real `LocalDevRunner`, the real API routes and the real
database. Assertions require the DESIRED invariant (audit F1-F8 plan, step 1)
— they never assert that the current bug occurs. Child liveness is checked on
the ACTUAL process identity (/proc kill-0 on recorded pids), never only via
the same cgroup query production uses. Cleanup happens after the assertions
and only touches this fixture's own processes/cgroups.
"""
from __future__ import annotations

import os
import pathlib
import subprocess
import sys
import threading
import time
import uuid

import pytest

# Host-identity observation across the PID namespace: the pids a command
# prints are namespace-local; only the host cgroup tree is authoritative.
from tests.helpers import find_tree_member as _find_member, wait_value as _wait_value

REPO = pathlib.Path(__file__).resolve().parents[1]
SUPERVISOR = REPO / "infra" / "runner" / "runner_supervise.sh"
PY = sys.executable


# --------------------------------------------------------------------- probes
def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _cgroup_members(root: str, op: str) -> list[int]:
    """DIRECT membership only — the exact query the (faulty) production code
    used; tests assert against it to prove nesting actually happened."""
    p = pathlib.Path(root) / f"sr-{op}" / "cgroup.procs"
    try:
        return [int(x) for x in p.read_text().split()]
    except (OSError, ValueError):
        return []


def _cgroup_tree_members(root: str, op: str) -> list[int]:
    """RECURSIVE membership: every process inside the operation tree,
    including nested descendants."""
    base = pathlib.Path(root) / f"sr-{op}"
    out: list[int] = []
    if not base.is_dir():
        return out
    for procs in base.rglob("cgroup.procs"):
        try:
            out.extend(int(x) for x in procs.read_text().split())
        except (OSError, ValueError):
            continue
    return out


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


def _wait_until(fn, timeout=10.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if fn():
            return True
        time.sleep(0.05)
    return False



def _reap(root: str, op: str):
    for pid in _cgroup_tree_members(root, op):
        try:
            os.kill(pid, 9)
        except OSError:
            pass


# ------------------------------------------------------------------- fixtures
@pytest.fixture()
def local_supervisor(tmp_path, monkeypatch):
    """SshRunner over the REAL supervisor script with cgroup containment
    (SSH executable seam only). Returns (runner, state_dir, script, cg_root)."""
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


def _sup(script, verb_and_op, state_dir, timeout=30):
    env = {**os.environ, "RUNNER_SUPERVISOR_STATE": str(state_dir)}
    return subprocess.run(["/bin/sh", "-c", f"{script} {verb_and_op}"],
                          capture_output=True, text=True, env=env, timeout=timeout)


def _start(script, args, state_dir, **extra_env):
    return subprocess.Popen(
        ["/bin/sh", "-c", f"{script} {args}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={**os.environ, "RUNNER_SUPERVISOR_STATE": str(state_dir), **extra_env})


def _run_id_for(sid) -> str:
    from srplatform.db.models import Run
    from srplatform.db.session import db as db_ctx
    with db_ctx() as s:
        return str(s.query(Run).filter_by(session_id=sid)
                   .order_by(Run.started_at.desc()).first().run_id)


@pytest.fixture()
def enrollment_channel(monkeypatch):
    from srplatform.scenario_engine import orchestrator
    orchestrator.set_enrollment_exec(None)
    yield orchestrator
    orchestrator.set_enrollment_exec(None)


# =========================================================================== #
# F1 — the containment boundary must be trusted and fail CLOSED                #
# =========================================================================== #

def test_f1_same_uid_escape_to_parent_cgroup_is_impossible(local_supervisor, tmp_path):
    """THE F1 escape probe under the namespace boundary: a redirected
    background child attempts to move itself into the delegated PARENT
    cgroup (the same-UID escape that made cessation a lie). Inside the
    trusted boundary the real hierarchy above the operation is INVISIBLE
    (cgroup namespace + rooted cgroupfs), so the attempt must FAIL; the
    child must remain inside the operation tree — observed by its real HOST
    identity, never the namespace-local number the command prints — status
    must say running, and cancel must actually kill it. No false 'gone'."""
    _, state, script, cg = local_supervisor
    op = f"esc{uuid.uuid4().hex[:8]}"
    started = tmp_path / "started"
    marker = tmp_path / "escape.outcome"
    # `wait` keeps the leader alive so the child is observable while the
    # operation runs; a survivor can no longer outlive the leader (the
    # kernel clears the whole PID namespace at leader exit — regression
    # test_t01_leader_exit_cannot_leave_survivors...).
    cmd = (f"sleep 300 & echo x > {started}; "
           f'if echo $! > "$RUNNER_CGROUP_ROOT/cgroup.procs" 2>/dev/null; then '
           f'echo ESCAPED > {marker}; else echo BLOCKED > {marker}; fi; wait')
    conn = _start(script, f"start {op} -- bash -c {chr(39)}{cmd}{chr(39)}", state)
    try:
        assert _wait_until(started.exists), "command never started"
        assert _wait_until(lambda: marker.exists()), "escape attempt never ran"
        outcome = marker.read_text().strip()
        assert outcome == "BLOCKED", (
            "the command MIGRATED OUT of its operation cgroup — the boundary "
            "does not contain same-UID escape (F1)")
        child = _wait_value(lambda: _find_member(cg, op, ("sleep", "300")))
        assert child, ("the background child is not inside the operation tree "
                       "on the HOST view — containment lost track of it (F1)")
        assert _alive(child), "test premise: the background child must be alive"
        st = _sup(script, f"status {op}", state)
        assert st.returncode == 0 and st.stdout.strip() == "running", \
            f"contained survivor invisible to status: {st.stdout!r}"
        c = _sup(script, f"cancel {op}", state)
        assert c.returncode == 0 and c.stdout.strip() == "gone", c.stdout + c.stderr
        assert _wait_until(lambda: not _alive(child)), \
            "cancel acknowledged while the recorded child identity was alive"
    finally:
        _reap(cg, op)
        if conn.poll() is None:
            conn.kill()


def test_f1_nested_membership_is_running_not_gone(local_supervisor, tmp_path):
    """F1 nested probe under the boundary: a child moves into a NESTED
    cgroup under the operation (the namespace-rooted view — the only one
    the command can reach) and clears its environment. The child is NOT in
    the operation's DIRECT cgroup.procs, yet the tree is populated: status
    must report running (recursive liveness, not the direct list), and
    cancel must reach the nested child (kernel subtree-scoped kill)."""
    _, state, script, cg = local_supervisor
    op = f"nest{uuid.uuid4().hex[:8]}"
    started = tmp_path / "started"
    # Prefer the real op-cgroup path (pre-boundary); fall back to the
    # namespace-rooted view (post-boundary) — both nest UNDER the operation.
    cmd = (
        'cg=""; for p in "$RUNNER_CGROUP_ROOT/sr-$SR_OP_ID" /sys/fs/cgroup; do '
        '[ -w "$p" ] && cg="$p" && break; done; '
        'mkdir -p "$cg/nested" 2>/dev/null; '
        'env -i sleep 300 & CP=$!; '
        f'echo x > {started}; '
        'echo $CP > "$cg/nested/cgroup.procs" 2>/dev/null; wait')
    conn = _start(script, f"start {op} -- bash -c {chr(39)}{cmd}{chr(39)}", state)
    try:
        assert _wait_until(started.exists), "command never started"

        def _nested():
            pid = _find_member(cg, op, ("sleep", "300"))
            return pid if pid and pid not in _cgroup_members(cg, op) else None

        child = _wait_value(_nested)
        assert child, ("test premise: child never entered a nested cgroup of "
                       "the operation (host view)")
        assert _alive(child)
        st = _sup(script, f"status {op}", state)
        assert st.returncode == 0 and st.stdout.strip() == "running", (
            f"nested membership reported {st.stdout.strip()!r} while the child "
            "was alive (F1 false-gone)")
        c = _sup(script, f"cancel {op}", state)
        assert c.returncode == 0 and c.stdout.strip() == "gone", c.stdout + c.stderr
        assert _wait_until(lambda: not _alive(child)), \
            "cancel confirmed while the nested child lived"
        assert not _cgroup_tree_members(cg, op), \
            "members survived an acknowledged cancellation"
    finally:
        _reap(cg, op)
        if conn.poll() is None:
            conn.kill()


def test_f1_unreadable_membership_is_unknown_not_gone(local_supervisor):
    """F1 unreadable probe: with a live member inside the operation cgroup,
    removing read permission from the authoritative state must NOT produce
    'gone'. The verdict must be a visible unknown, the bookkeeping must
    survive the failed read, and restoring permission must show the same
    live process. (The leader stays alive so the member genuinely lives —
    under the namespace boundary a background child cannot outlive its
    leader, so 'live member' requires a running operation.)"""
    _, state, script, cg = local_supervisor
    op = f"unread{uuid.uuid4().hex[:8]}"
    conn = _start(script,
                  f"start {op} -- bash -c {chr(39)}env -i sleep 300 & wait{chr(39)}",
                  state)
    opcg = pathlib.Path(cg) / f"sr-{op}"
    try:
        # wait for the operation to reach its IDLE shape (the sleep child is
        # present) before snapshotting — a mid-startup snapshot would race
        # with the boundary's own setup processes (mount helpers)
        assert _wait_value(lambda: _find_member(cg, op, ("sleep", "300"))), \
            "test premise: no member inside the operation cgroup"
        members = _cgroup_tree_members(cg, op)
        for f in ("cgroup.procs", "cgroup.events"):
            try:
                os.chmod(opcg / f, 0o000)
            except OSError:
                pass
        st = _sup(script, f"status {op}", state)
        assert st.returncode == 0, st.stdout + st.stderr
        assert st.stdout.strip() == "unknown", (
            f"failed state read reported {st.stdout.strip()!r} — a failed read "
            "is indistinguishable from empty membership (F1)")
        assert (state / f"{op}.pid").exists(), \
            "records were cleaned up merely because a read failed"
        for f in ("cgroup.procs", "cgroup.events"):
            try:
                os.chmod(opcg / f, 0o644)
            except OSError:
                pass
        st = _sup(script, f"status {op}", state)
        assert st.stdout.strip() == "running", \
            "the same live PID must still be reported after restoring permission"
        assert set(_cgroup_tree_members(cg, op)) == set(members)
        c = _sup(script, f"cancel {op}", state)
        assert c.returncode == 0 and c.stdout.strip() == "gone"
    finally:
        for f in ("cgroup.procs", "cgroup.events"):
            try:
                os.chmod(opcg / f, 0o644)
            except OSError:
                pass
        _reap(cg, op)
        if conn.poll() is None:
            conn.kill()


def test_f1_bookkeeping_is_not_command_writable(local_supervisor, tmp_path):
    """F1: 'commands also share access to supervisor bookkeeping; that is not
    a trusted boundary.' The command must NOT be able to forge tombstones or
    erase pidfiles of the real state directory — verified from OUTSIDE the
    command's view: the real files must be unchanged."""
    _, state, script, cg = local_supervisor
    op = f"bkpp{uuid.uuid4().hex[:8]}"
    other = f"victim{uuid.uuid4().hex[:6]}"
    (state).mkdir(parents=True, exist_ok=True)
    tomb = state / f"{other}.cancelled"
    tomb.write_text("")                                    # real tombstone
    cmd = (f'echo forged > "$RUNNER_SUPERVISOR_STATE/{other}.cancelled" 2>/dev/null; '
           f'rm -f "$RUNNER_SUPERVISOR_STATE/{other}.cancelled" 2>/dev/null; exit 0')
    r = subprocess.run(["/bin/sh", "-c", f"{script} start {op} -- bash -c {chr(39)}{cmd}{chr(39)}"],
                       capture_output=True, text=True, timeout=30,
                       env={**os.environ, "RUNNER_SUPERVISOR_STATE": str(state),
                            "RUNNER_CGROUP_ROOT": cg})
    assert r.returncode == 0, r.stdout + r.stderr
    assert tomb.exists() and tomb.read_text() == "", \
        "the command rewrote/erased the supervisor's trusted bookkeeping (F1)"


@pytest.mark.containment  # probes cgroup_containment_root() directly (no fixture)
def test_f1_unsupported_boundary_refuses_before_any_side_effect(tmp_path):
    """An unsupported isolation setup refuses the harmless command BEFORE
    executing it: with no unshare available, start exits 4 and the command
    never runs."""
    state = tmp_path / "jobs"
    bindir = tmp_path / "bin"
    bindir.mkdir()
    for b in ("bash", "cat", "awk", "setsid", "flock", "mkdir", "rmdir", "rm",
              "touch", "stat", "date", "seq", "sleep", "find", "sh", "ls",
              "basename", "grep", "tr", "kill", "cut"):
        src = pathlib.Path(f"/usr/bin/{b}")
        if not src.exists():
            src = pathlib.Path(f"/bin/{b}")
        if src.exists():
            os.symlink(src, bindir / b)
    marker = tmp_path / "executed.marker"
    env = {**os.environ, "PATH": f"{bindir}:/usr/bin:/bin",
           "RUNNER_SUPERVISOR_STATE": str(state),
           "RUNNER_CGROUP_ROOT": str(tmp_path / "not-a-cgroup")}
    # First: a NON-cgroup root still refuses (existing contract)
    r = subprocess.run(["/bin/sh", "-c", f"{SUPERVISOR} start bnd{uuid.uuid4().hex[:6]} -- touch {marker}"],
                       capture_output=True, text=True, env=env, timeout=20)
    assert r.returncode == 4 and not marker.exists()
    # Then: a usable cgroup root but NO unshare on PATH must also refuse
    from tests.helpers import cgroup_containment_root
    cg = cgroup_containment_root()
    (bindir / "unshare").unlink(missing_ok=True)
    env["RUNNER_CGROUP_ROOT"] = cg
    marker2 = tmp_path / "executed2.marker"
    # PATH without /usr/bin (where unshare lives) but with the coreutils links
    env["PATH"] = str(bindir)
    r = subprocess.run(["/bin/sh", "-c", f"/bin/sh {SUPERVISOR} start bnd2{uuid.uuid4().hex[:6]} -- touch {marker2}"],
                       capture_output=True, text=True, env=env, timeout=20)
    assert r.returncode == 4, \
        f"start without the namespace boundary must refuse (exit 4): {r}"
    assert "boundary" in r.stderr.lower() or "refus" in r.stderr.lower(), r.stderr
    assert not marker2.exists(), "refused start EXECUTED the command anyway"


def test_f5_signals_are_identity_or_kernel_scoped_never_bare_markers(local_supervisor):
    """F5: environment markers are diagnostic, never authority. A process
    OUTSIDE the containment tree that carries SR_OP_ID must never be
    signalled by cancellation; inside the tree, the kernel-scoped cgroup.kill
    reaches even a TERM-ignoring member without any scan-to-signal PID race."""
    _, state, script, cg = local_supervisor
    op = f"sig{uuid.uuid4().hex[:8]}"
    victim = subprocess.Popen(["/bin/bash", "-c", "trap '' TERM; exec sleep 30"],
                              env={**os.environ, "SR_OP_ID": op},
                              start_new_session=True)
    _start(script, f"start {op} -- bash -c {chr(39)}trap '' TERM; exec sleep 300{chr(39)}",
           state)
    try:
        assert _wait_until(lambda: _cgroup_tree_members(cg, op)), "job never started"
        assert victim.pid not in _cgroup_tree_members(cg, op)  # outside the tree
        c = _sup(script, f"cancel {op}", state)
        assert c.returncode == 0 and c.stdout.strip() == "gone", c.stdout + c.stderr
        assert _wait_until(lambda: not _cgroup_tree_members(cg, op)), \
            "TERM-ignoring member survived the kernel-scoped kill"
        time.sleep(0.5)
        assert victim.poll() is None, (
            "cancel signalled a bare environment-marker pid outside the "
            "containment tree (F5)")
    finally:
        victim.kill()
        victim.wait()
        _reap(cg, op)


def test_f1_missing_control_state_with_live_leader_is_not_gone(local_supervisor):
    """A missing control file is never proof of cessation for previously
    dispatched work: with a recorded leader whose identity MATCHES a live
    process and no cgroup directory, status must not answer gone/not-found."""
    _, state, script, _ = local_supervisor
    op = f"lost{uuid.uuid4().hex[:8]}"
    leader = subprocess.Popen(["/bin/bash", "-c", "exec sleep 30"],
                              start_new_session=True)
    try:
        state.mkdir(parents=True, exist_ok=True)
        st_ticks = None
        with open(f"/proc/{leader.pid}/stat") as f:
            st_ticks = f.read().rsplit(")", 1)[1].split()[19]
        (state / f"{op}.pid").write_text(f"{leader.pid}:{st_ticks}\n")
        s = _sup(script, f"status {op}", state)
        assert s.returncode == 0 and s.stdout.strip() == "running", (
            f"live recorded leader with missing cgroup reported {s.stdout.strip()!r} "
            "— missing control state accepted as proof (F1)")
    finally:
        leader.kill()
        leader.wait()


def test_f1_runner_health_rejects_unknown_cessation(local_supervisor, monkeypatch):
    """F7/health: an exit-zero result whose cessation verdict is unknown
    must make health() unhealthy — 'reachable' never means 'contained'."""
    runner, state, script, cg = local_supervisor

    def dead(verb, op_id, timeout=15):
        return 124, "control channel down"

    monkeypatch.setattr(runner, "_control", dead)
    ok, detail = runner.health()
    assert ok is False, "health reported healthy over an UNKNOWN cessation"
    assert "unknown" in detail.lower() or "unreachable" in detail.lower(), detail


# =========================================================================== #
# F2 — lifecycle obligations are serialized, everywhere                        #
# =========================================================================== #

@pytest.mark.db
def test_f2_completion_racing_registration_is_pinned_and_safe(client, users, monkeypatch,
                                                              tmp_path):
    """THE F2 probe: registration pauses AFTER acquiring the run-row lock and
    BEFORE its INSERT; completion then runs against an independent DB
    session. Completion must actually block on the lock (observed in
    pg_stat_activity), and after the release the invariant must hold: a
    terminal run NEVER has an unresolved operation."""
    import threading as th

    from srplatform.api import runs as runs_svc
    from srplatform.db.models import Run, RunOperation
    from srplatform.db.session import db as db_ctx
    from tests.helpers import make_runner_token

    class ConfirmingRunner:
        def cancel_remote(self, op_id, timeout_s=15.0):
            return True

    monkeypatch.setattr(runs_svc, "_control_runner", lambda: ConfirmingRunner())

    hook_started = tmp_path / "hook.register.started"
    release = tmp_path / "hook.register.release"
    for f in (hook_started, release):
        f.unlink(missing_ok=True)
    monkeypatch.setenv("SR_TEST_REGISTER_HOOK",
                       f"touch {hook_started}; while [ ! -f {release} ]; do sleep 0.05; done")

    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    tok = make_runner_token(sid)
    run_id = _run_id_for(sid)
    op_id = uuid.uuid4().hex
    outs = {}

    def register():
        r = client.post(f"/internal/runs/{run_id}/operations",
                        json={"op_id": op_id, "kind": "remote"},
                        headers={"X-Worker-Token": tok})
        outs["reg"] = r.status_code

    def complete():
        with db_ctx() as s:
            run = runs_svc.complete_run(s, run_id, tok, {"outcome": "complete"})
            outs["status"] = run.status

    t_reg = th.Thread(target=register)
    t_reg.start()
    assert _wait_until(hook_started.exists, 15), \
        "registration never reached the pinned pre-INSERT window (test seam missing?)"
    t_cmp = th.Thread(target=complete)
    t_cmp.start()
    try:
        time.sleep(1.5)
        assert t_cmp.is_alive(), \
            "completion did not block on the registration lock — the " \
            "finalization snapshot is not serialized with registration (F2)"
        # observe the wait on the real DB: a blocked statement must be there
        from sqlalchemy import text
        with db_ctx() as s:
            waiting = s.execute(text(
                "SELECT wait_event_type, state FROM pg_stat_activity "
                "WHERE pid <> pg_backend_pid() AND wait_event_type = 'Lock'")).fetchall()
        assert waiting, "expected a lock-blocked statement while registration holds the row"
    finally:
        release.touch()
    t_reg.join(timeout=60)
    t_cmp.join(timeout=60)
    hook_started.unlink(missing_ok=True)
    release.unlink(missing_ok=True)

    assert outs.get("reg") == 201, outs
    with db_ctx() as s:
        run = s.get(Run, uuid.UUID(run_id))
        op = s.query(RunOperation).filter_by(run_id=run_id).first()
        assert not (run.status in runs_svc.TERMINAL
                    and op.state in runs_svc.UNRESOLVED_OPS), (
            f"terminal {run.status} with {op.state} operation — the pinned "
            f"completion/registration race is not closed: {outs}")
        if run.status in runs_svc.TERMINAL:
            assert op.state == "completed", \
                f"terminal run left {op.state}: {outs}"


@pytest.mark.db
def test_f2_registration_vs_completion_both_orders(client, users, monkeypatch):
    """Barrier-driven registration vs COMPLETION (the fourth suite only pinned
    stop): independent sessions, both interleavings, invariant after every
    attempt."""
    import threading as th

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
        barrier = th.Barrier(2)

        def register():
            barrier.wait()
            outs["reg"] = client.post(f"/internal/runs/{run_id}/operations",
                                      json={"op_id": op_id, "kind": "remote"},
                                      headers={"X-Worker-Token": tok}).status_code

        def complete():
            barrier.wait()
            try:
                with db_ctx() as s:
                    outs["cmp"] = runs_svc.complete_run(
                        s, run_id, tok, {"outcome": "complete"}).status
            except Exception as e:  # RunStateError etc. are legal outcomes
                outs["cmp"] = f"refused:{type(e).__name__}"

        ts = [th.Thread(target=register), th.Thread(target=complete)]
        [t.start() for t in ts]
        [t.join(timeout=60) for t in ts]

        with db_ctx() as s:
            run = s.get(Run, uuid.UUID(run_id))
            op = s.query(RunOperation).filter_by(run_id=run_id).first()
            unresolved = op is not None and op.state in runs_svc.UNRESOLVED_OPS
            assert not (run.status in runs_svc.TERMINAL and unresolved), \
                f"attempt {attempt}: terminal {run.status} with {op.state}: {outs}"


@pytest.mark.db
def test_f2_terminal_row_with_unresolved_op_blocks_end_until_repaired(
        client, users, monkeypatch):
    """A PRE-EXISTING inconsistent terminal row (terminal run + active
    operation) must block end/reset/teardown release until cessation is
    genuinely resolved — the active-run-only lookup must not hide it, and
    resolution must never fabricate cessation."""
    from srplatform.api import runs as runs_svc
    from srplatform.db.models import RangeLease, Run, RunOperation
    from srplatform.db.session import db as db_ctx
    from tests.helpers import make_runner_token

    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    assert client.post(f"/sessions/{sid}/launch",
                       headers=users["member"]).status_code == 200
    tok = make_runner_token(sid)
    run_id = _run_id_for(sid)
    op_id = uuid.uuid4().hex
    assert client.post(f"/internal/runs/{run_id}/operations",
                       json={"op_id": op_id, "kind": "remote"},
                       headers={"X-Worker-Token": tok}).status_code == 201
    # simulate the corrupt pre-existing state: terminal row, active operation
    with db_ctx() as s:
        s.get(Run, uuid.UUID(run_id)).status = "completed"
        s.commit()

    # a BROKEN control channel: resolution cannot confirm — end must block
    class BrokenRunner:
        def cancel_remote(self, op_id, timeout_s=15.0):
            return False

    monkeypatch.setattr(runs_svc, "_control_runner", lambda: BrokenRunner())
    end = client.post(f"/sessions/{sid}/end", headers=users["member"])
    assert end.status_code == 409, \
        f"end released the session with an unresolved operation on a terminal row: {end.text}"
    assert "unresolved" in str(end.json()).lower(), end.text
    with db_ctx() as s:
        assert s.get(RangeLease, 1).released_at is None, \
            "reservation released while an unresolved operation existed"
        assert s.query(RunOperation).filter_by(op_id=op_id).first().state \
            in runs_svc.UNRESOLVED_OPS, "unconfirmed resolution must retain the row"

    # genuine resolution (control channel repaired) unblocks end
    class ConfirmingRunner:
        def cancel_remote(self, op_id, timeout_s=15.0):
            return True

    monkeypatch.setattr(runs_svc, "_control_runner", lambda: ConfirmingRunner())
    stop = client.post(f"/runs/{run_id}/stop", headers=users["member"]).json()
    assert stop["ok"] is True, f"stop must resolve the lingering obligation: {stop}"
    end = client.post(f"/sessions/{sid}/end", headers=users["member"])
    assert end.status_code == 200, end.text
    with db_ctx() as s:
        assert s.query(RunOperation).filter_by(op_id=op_id).first().state == "completed"


@pytest.mark.db
def test_f2_startup_recovery_never_hides_registered_operations(client, users, monkeypatch):
    """Watchdog/startup transitions are terminal writers too: a dead worker
    with a registered operation must NOT become 'failed' while cessation is
    unconfirmed; after confirmed resolution the retry finalizes."""
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
    runs_svc.reconcile_on_startup()
    with db_ctx() as s:
        run = s.get(Run, uuid.UUID(run_id))
        assert run.status == "cancel-unknown", \
            f"startup recovery finalized with unresolved work: {run.status}"
        assert s.query(RunOperation).filter_by(op_id=op_id).first().state \
            == "cancel-unknown"

    class ConfirmingRunner:
        def cancel_remote(self, op_id, timeout_s=15.0):
            return True

    monkeypatch.setattr(runs_svc, "_control_runner", lambda: ConfirmingRunner())
    runs_svc.reconcile_on_startup()
    with db_ctx() as s:
        assert s.get(Run, uuid.UUID(run_id)).status in runs_svc.TERMINAL
        assert s.query(RunOperation).filter_by(op_id=op_id).first().state == "completed"


@pytest.mark.db
def test_f2_guarded_terminal_update_refuses_with_unresolved_op(client, users):
    """The shared terminal-transition guard used by EVERY writer (spawn/latch
    included): with an unresolved operation present, a guarded terminal write
    changes nothing."""
    from srplatform.api import runs as runs_svc
    from srplatform.db.models import Run, RunOperation
    from srplatform.db.session import db as db_ctx
    from tests.helpers import make_runner_token

    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    tok = make_runner_token(sid)
    run_id = _run_id_for(sid)
    assert client.post(f"/internal/runs/{run_id}/operations",
                       json={"op_id": uuid.uuid4().hex, "kind": "remote"},
                       headers={"X-Worker-Token": tok}).status_code == 201
    with db_ctx() as s:
        wrote = runs_svc.guarded_terminal_update(
            s, run_id, {"status": "cancelled", "outcome": "canceled"})
        assert wrote == 0, "a terminal writer bypassed the unresolved-operation guard"
        assert s.get(Run, uuid.UUID(run_id)).status == "running"


# =========================================================================== #
# F7 — local-dev cannot silently outlive completed state                       #
# =========================================================================== #

def test_f7_local_dev_background_child_cannot_outlive_completion(tmp_path, monkeypatch):
    """LocalDevRunner gives every command an INDEPENDENT process group: a
    redirected background child survives the leader's exit-0. The SSH-only
    stream assumption must not mark that operation done — the local runner
    must contain the group and confirm, or report unknown."""
    from srplatform.settings import Settings
    from srplatform.red_agent.runner import LocalDevRunner
    monkeypatch.setenv("RUNNER_LOCAL_OP_DIR", str(tmp_path / "localops"))
    s = Settings(sr_env="dev", runner_transport="local-dev",
                 runner_command_timeout_s=15, runner_max_output_bytes=65536)
    r = LocalDevRunner(s)
    child = tmp_path / "child.pid"
    res = r.run(f"sleep 300 & echo $! > {child}; echo hi; exit 0", timeout=15)
    try:
        assert res.exit_code == 0, res
        pid = int(child.read_text().strip())
        assert res.cancel_state != "unknown" or not _alive(pid), \
            "local completion left live work unconfirmed"
        assert _wait_until(lambda: not _alive(pid), 10), \
            "local-dev background child silently outlived completed operation state"
        assert res.note and "surviv" in res.note.lower(), \
            f"completion did not record the local containment: {res}"
    finally:
        try:
            os.kill(int(child.read_text().strip()), 9)
        except (OSError, ValueError):
            pass


@pytest.mark.db
def test_f7_local_rows_resolve_truthfully_and_stay_retryable(client, users, tmp_path,
                                                             monkeypatch):
    """The terminal guard counts LOCAL rows too, so the resolution pass must
    handle them: with no recorded local identity the row becomes a VISIBLE
    cancel-unknown (never silently active); once real local cessation
    evidence exists (recorded group confirmed dead), a later pass resolves
    it — unconfirmed work stays retryable with the reservation retained."""
    from srplatform.api import runs as runs_svc
    from srplatform.db.models import RangeLease, Run, RunOperation
    from srplatform.db.session import db as db_ctx
    from tests.helpers import make_runner_token

    opdir = tmp_path / "localops"
    monkeypatch.setenv("RUNNER_LOCAL_OP_DIR", str(opdir))
    from srplatform import settings as st
    st.get_settings.cache_clear()

    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    assert client.post(f"/sessions/{sid}/launch",
                       headers=users["member"]).status_code == 200
    tok = make_runner_token(sid)
    run_id = _run_id_for(sid)
    op_id = uuid.uuid4().hex
    assert client.post(f"/internal/runs/{run_id}/operations",
                       json={"op_id": op_id, "kind": "local"},
                       headers={"X-Worker-Token": tok}).status_code == 201

    stop = client.post(f"/runs/{run_id}/stop", headers=users["member"]).json()
    assert stop["ok"] is False, f"stop claimed success over an unresolvable local row: {stop}"
    with db_ctx() as s:
        row = s.query(RunOperation).filter_by(op_id=op_id).first()
        assert row.state == "cancel-unknown", \
            f"local row must become VISIBLE cancel-unknown, not stay {row.state}"
        assert s.get(RangeLease, 1).released_at is None
        assert s.get(Run, uuid.UUID(run_id)).status == "cancel-unknown"

    # real local cessation evidence: the recorded command group is gone
    opdir.mkdir(parents=True, exist_ok=True)
    (opdir / f"{op_id}.pgid").write_text("999999:1\n")   # dead pid identity
    stop = client.post(f"/runs/{run_id}/stop", headers=users["member"]).json()
    assert stop["ok"] is True, f"retry after real cessation evidence must resolve: {stop}"
    with db_ctx() as s:
        assert s.query(RunOperation).filter_by(op_id=op_id).first().state == "completed"
        assert s.get(Run, uuid.UUID(run_id)).status == "cancelled"
    st.get_settings.cache_clear()


# =========================================================================== #
# F3/F4 — enrollment evidence: current generation, exact capability            #
# =========================================================================== #

def _issue_for(sid, host, deployment_id=None):
    from srplatform.db.session import db
    from srplatform.scenario_engine import orchestrator
    with db() as s:
        tok, nonce = orchestrator._enroll_telemetry(s, sid, host, deployment_id)
        s.commit()
    return tok, nonce


def _token_evidence(token):
    from srplatform.db.models import ServiceToken
    from srplatform.db.session import db
    with db() as s:
        row = s.get(ServiceToken, token)
        return (row.enroll_confirmed_at if row else None,
                row.enroll_capture_at if row else None)


@pytest.mark.db
def test_f4_evidence_is_bound_to_the_exact_capability(client, users):
    """F4 probe: two same-session/same-host enrollments with DIFFERENT
    deployment generations. The older capability + the newer nonce must be
    rejected; an audit batch authenticated by the older capability must not
    set the newer token's capture timestamp; only the exact pair updates its
    own row."""
    from srplatform.db.models import Deployment
    from srplatform.db.session import db
    from srplatform.scenario_engine.orchestrator import capture_marker

    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    with db() as s:
        d1 = Deployment(session_id=sid, scenario_id="quick-win-01", status="torn_down")
        d2 = Deployment(session_id=sid, scenario_id="quick-win-01", status="ready")
        s.add_all([d1, d2])
        s.commit()
        old_dep, new_dep = str(d1.deployment_id), str(d2.deployment_id)

    tok_old, nonce_old = _issue_for(sid, "web01", old_dep)
    tok_new, nonce_new = _issue_for(sid, "web01", new_dep)

    # older capability + NEWER nonce: rejected, and NOTHING gains evidence
    r = client.post("/enroll/confirm", json={"nonce": nonce_new},
                    headers={"Authorization": f"Bearer {tok_old}"})
    assert r.status_code == 403, \
        f"older capability confirmed with the newer nonce: {r.text}"
    assert _token_evidence(tok_new)[0] is None, "wrong-capability confirm moved newer evidence"
    assert _token_evidence(tok_old)[0] is None

    # capture via the OLDER capability carrying the NEWER marker: no effect
    r = client.post("/ingest/auditd", json={"events": [
        {"kind": "command", "argv": f"/bin/true {capture_marker(nonce_new)}",
         "source_id": uuid.uuid4().hex, "boot_id": "b1"}]},
        headers={"Authorization": f"Bearer {tok_old}"})
    assert r.status_code == 201
    assert _token_evidence(tok_new)[1] is None, \
        "older capability set the newer enrollment's capture timestamp (F4)"
    assert _token_evidence(tok_old)[1] is None

    # the exact pair works
    r = client.post("/enroll/confirm", json={"nonce": nonce_new},
                    headers={"Authorization": f"Bearer {tok_new}"})
    assert r.status_code == 201, r.text
    assert _token_evidence(tok_new)[0] is not None

    # obsolete generation (torn_down deployment) is refused
    r = client.post("/enroll/confirm", json={"nonce": nonce_old},
                    headers={"Authorization": f"Bearer {tok_old}"})
    assert r.status_code == 403, "confirmation accepted for an obsolete generation"

    # revoked capability is refused outright
    with db() as s:
        from srplatform.db.models import ServiceToken
        s.get(ServiceToken, tok_new).revoked_at = \
            __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
        s.commit()
    r = client.post("/enroll/confirm", json={"nonce": nonce_new},
                    headers={"Authorization": f"Bearer {tok_new}"})
    assert r.status_code in (401, 403)


@pytest.mark.db
def test_f4_concurrent_duplicate_confirmations_are_idempotent(client, users):
    """Concurrent repeats of the authenticated callback produce exactly ONE
    evidence timestamp and ONE event (the sequential case already passes;
    the race must too)."""
    import threading as th

    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    tok, nonce = _issue_for(sid, "web01")
    codes, first = [], None
    barrier = th.Barrier(5)

    def confirm():
        barrier.wait()
        r = client.post("/enroll/confirm", json={"nonce": nonce},
                        headers={"Authorization": f"Bearer {tok}"})
        codes.append(r.status_code)

    ts = [th.Thread(target=confirm) for _ in range(5)]
    [t.start() for t in ts]
    [t.join(timeout=60) for t in ts]
    assert all(c == 201 for c in codes), codes
    assert _token_evidence(tok)[0] is not None
    from srplatform.db.models import Event
    from srplatform.db.session import db
    with db() as s:
        n = s.query(Event).filter_by(session_id=sid,
                                     action_type="telemetry_enroll_confirmed").count()
    assert n == 1, f"{n} confirmation events from concurrent duplicates"


@pytest.mark.db
def test_f3_legacy_phase_only_confirmed_is_not_ready_and_reenrolls(
        client, users, fake_pve, enrollment_channel, monkeypatch):
    """F3 probe: a deployment whose resource says phase=confirmed but whose
    capability carries NO evidence (the pre-0009 shape) must NOT pass
    enforced readiness, must NOT satisfy /run, and must be safely
    RE-ENROLLED (same capability resumed, not re-cloned)."""
    from srplatform import verification_service
    from srplatform.db.models import Deployment, ServiceToken
    from srplatform.db.session import db
    from tests.test_fourth_followup_enrollment import HostChannel

    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    chan = HostChannel(host_client=client)
    enrollment_channel.set_enrollment_exec(chan)
    verification_service.set_verifier_exec(chan)
    assert client.post(f"/sessions/{sid}/launch",
                       headers=users["member"]).status_code == 200

    # simulate the pre-upgrade shape: phase-only confirmation, no evidence
    with db() as s:
        s.query(ServiceToken).filter_by(session_id=sid, scope="telemetry") \
            .update({"enroll_confirmed_at": None, "enroll_capture_at": None})
        s.commit()

    with db() as s:
        rd = verification_service.readiness_checks(s, sid)
    assert rd["enforced"] and rd["ok"] is False, \
        f"phase-only confirmation satisfied readiness (F3): {rd}"
    assert any(not e["ok"] for e in rd["enrollments"]), rd

    # /run cannot bypass the new requirement on an already-ready session
    r = client.post("/run/quick-win-01", json={"session_id": sid},
                    headers=users["member"])
    assert r.status_code == 409, \
        f"/run started work despite missing current enrollment evidence: {r.text}"
    assert "enrollment" in str(r.json()).lower()

    # relaunch RESUMES the same enrollment (safe re-enroll, no re-clone)
    chan2 = HostChannel(host_client=client)
    enrollment_channel.set_enrollment_exec(chan2)
    verification_service.set_verifier_exec(chan2)
    r = client.post(f"/sessions/{sid}/launch", headers=users["member"])
    assert r.status_code == 200, r.text
    assert any("shipper.env" in c for _, c in chan2.commands), \
        "stale phase-only enrollment was skipped — zero provisioning commands (F3)"
    with db() as s:
        toks = s.query(ServiceToken).filter_by(session_id=sid, scope="telemetry").all()
        assert len(toks) == 1, "re-enrollment gratuitously issued a second capability"
        assert toks[0].enroll_confirmed_at is not None


@pytest.mark.db
def test_f3_migration_downgrades_phase_only_and_binds_evidence(client, users):
    """The upgrade itself: migration 0010's data step downgrades phase-only
    confirmations and leaves genuinely evidence-backed ones alone."""
    import importlib.util

    from srplatform.db.models import Deployment
    from srplatform.db.session import db

    spec = importlib.util.spec_from_file_location(
        "m0010", REPO / "srplatform" / "db" / "migrations" / "versions"
        / "0010_fifth_followup_enrollment.py")
    m0010 = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m0010)

    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    with db() as s:
        legacy = Deployment(session_id=sid, scenario_id="quick-win-01", status="ready",
                            resources=[{"host": "web01", "state": "created",
                                        "telemetry_enroll": {"phase": "confirmed"}}])
        s.add(legacy)
        s.commit()
        # token WITHOUT evidence (pre-0009 shape), unbound deployment
        tok, _ = _issue_for(sid, "web01", None)
        m0010.downgrade_stale_confirmed(s.bind)
        s.expire_all()
        res = s.get(Deployment, legacy.deployment_id).resources
        assert res[0]["telemetry_enroll"]["phase"] != "confirmed", \
            "phase-only confirmation survived the upgrade (F3)"
        from srplatform.db.models import ServiceToken
        assert str(s.get(ServiceToken, tok).enrollment_deployment_id) == \
            str(legacy.deployment_id), "enrollment token not bound to its generation"

        # an evidence-backed enrollment is untouched
        s.query(ServiceToken).filter_by(token=tok).update({
            "enroll_confirmed_at": __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc),
            "enroll_capture_at": __import__("datetime").datetime.now(
                __import__("datetime").timezone.utc)})
        s.get(Deployment, legacy.deployment_id).resources = [
            {"host": "web01", "state": "created",
             "telemetry_enroll": {"phase": "confirmed"}}]
        from sqlalchemy.orm.attributes import flag_modified
        flag_modified(s.get(Deployment, legacy.deployment_id), "resources")
        s.commit()
        m0010.downgrade_stale_confirmed(s.bind)
        s.expire_all()
        res = s.get(Deployment, legacy.deployment_id).resources
        assert res[0]["telemetry_enroll"]["phase"] == "confirmed", \
            "evidence-backed confirmation must not be downgraded"


# =========================================================================== #
# F8 — required gates fail instead of silently skipping                        #
# =========================================================================== #

def test_f8_required_containment_fails_instead_of_skipping(tmp_path):
    """With SR_REQUIRE_CONTAINMENT=1 an unusable containment root is a
    FAILURE; without it the same host SKIPs (developer compatibility)."""
    helper = (
        "import pytest, sys; sys.path.insert(0, {repo!r});\n"
        "from tests.helpers import cgroup_containment_root\n"
        "def test_marker():\n"
        "    assert cgroup_containment_root()\n")
    t = tmp_path / "test_gate_probe.py"
    t.write_text(helper.format(repo=str(REPO)))
    base_env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
                "RUNNER_CGROUP_ROOT": str(tmp_path / "definitely-not-a-cgroup")}
    # the probe itself must control the flag — never inherit it from a
    # required-mode outer run, or the "optional host SKIPs" half breaks
    base_env.pop("SR_REQUIRE_CONTAINMENT", None)

    r = subprocess.run([PY, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(t)],
                       capture_output=True, text=True, env=base_env, timeout=120)
    assert r.returncode == 0 and "1 skipped" in r.stdout, \
        f"optional host must SKIP with a reason: {r.stdout[-500:]}"

    r = subprocess.run([PY, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(t)],
                       capture_output=True, text=True,
                       env={**base_env, "SR_REQUIRE_CONTAINMENT": "1"}, timeout=120)
    assert r.returncode != 0 and "1 failed" in r.stdout, \
        f"SR_REQUIRE_CONTAINMENT=1 must FAIL on missing containment: {r.stdout[-500:]}"


def test_f8_ci_probe_marker_runs_under_real_containment(local_supervisor):
    """Marker test used by CI as the real prerequisite probe: it only passes
    when a REAL delegated cgroup accepted a process move (the fixture probes
    that) — and under SR_REQUIRE_CONTAINMENT=1 it fails rather than skips."""
    _, _, _, cg = local_supervisor
    assert pathlib.Path(cg).is_dir()
