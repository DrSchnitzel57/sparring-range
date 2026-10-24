"""Plan 18 — adversarial containment negatives (containment layer).

The follow-up suites (third/fourth/fifth) already prove the positive
controls: the boundary is created, cessation is authoritative, survivors
are contained, bookkeeping is not command-writable. This file instead
ATTACKS the boundary FROM INSIDE a running model command — the software
share of the scoped-profile adversarial qualification (installed-profile
qualification stays the operator's manual gate):

1. DISCOVERY: a running operation must not be able to enumerate or match
   another operation's processes (fresh PID namespace + fresh /proc).
2. SIGNALLING: a cross-operation signal is denied even when the attacker
   is TOLD the victim's real host PID (the boundary process lives in a
   child user namespace — the kernel refuses signals outward), and a
   namespace-wide broadcast kill cannot reach the victim, the supervisor
   or any other operation.
3. VISIBILITY: the supervisor's real state directory and the cgroup
   hierarchy above the operation must be invisible from inside; writes
   the attacker makes to the masked state path must not touch the real
   records.

Nothing here weakens containment: every test drives the REAL supervisor
script through the REAL unshare/cgroup boundary.
"""
from __future__ import annotations

import os
import pathlib
import shlex
import subprocess
import time
import uuid

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
SUPERVISOR = REPO / "infra" / "runner" / "runner_supervise.sh"

pytestmark = pytest.mark.containment


@pytest.fixture()
def runner(tmp_path, monkeypatch):
    from tests.helpers import cgroup_containment_root
    cg = cgroup_containment_root()
    state = tmp_path / "jobs"
    state.mkdir(parents=True)
    env = {**os.environ, "RUNNER_SUPERVISOR_STATE": str(state),
           "RUNNER_CGROUP_ROOT": cg}
    monkeypatch.setenv("RUNNER_SUPERVISOR_STATE", str(state))
    monkeypatch.setenv("RUNNER_CGROUP_ROOT", cg)
    return {"env": env, "state": state, "cg": cg, "tmp": tmp_path}


def _op(name: str) -> str:
    return f"{name}{uuid.uuid4().hex[:8]}"


def _start_bg(runner, op: str, command: str) -> subprocess.Popen:
    return subprocess.Popen(
        ["/bin/sh", "-c",
         f"{SUPERVISOR} start {op} -- bash -c {shlex.quote(command)}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env=runner["env"])


def _run_fg(runner, op: str, command: str, timeout: int = 40):
    return subprocess.run(
        ["/bin/sh", "-c",
         f"{SUPERVISOR} start {op} -- bash -c {shlex.quote(command)}"],
        capture_output=True, text=True, timeout=timeout, env=runner["env"])


def _status(runner, op: str) -> str:
    r = subprocess.run(["/bin/sh", "-c", f"{SUPERVISOR} status {op}"],
                       capture_output=True, text=True, timeout=60,
                       env=runner["env"])
    return r.stdout.strip()


def _wait_status(runner, op: str, want: str, timeout: float = 25) -> bool:
    """Accept the settled end states: 'gone' until the start connection
    cleans the records, 'not-found' once they are cleaned — both mean the
    operation is finished and no longer tracked."""
    wants = {want} | ({"not-found"} if want == "gone" else set())
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _status(runner, op) in wants:
            return True
        time.sleep(0.15)
    return False


def _cancel(runner, op: str) -> str:
    r = subprocess.run(["/bin/sh", "-c", f"{SUPERVISOR} cancel {op}"],
                       capture_output=True, text=True, timeout=60,
                       env=runner["env"])
    assert r.returncode == 0, f"cancel must confirm: {r.stdout}{r.stderr}"
    return r.stdout.strip()


# --------------------------------------------------------------------------- #
# 1. cross-operation discovery is denied                                        #
# --------------------------------------------------------------------------- #

def test_operation_cannot_discover_other_operations(runner):
    """A model command enumerating every visible /proc entry must never see
    another operation's processes: the fresh PID namespace hides them."""
    victim, attacker = _op("vic"), _op("atk")
    # the victim's own bash command line carries the marker; the attacker
    # assembles the search pattern at runtime (printf split) so its OWN
    # argv can never match and produce a false positive
    _start_bg(runner, victim,
              "SR-CROSS-VICTIM-MARKER=1; while :; do sleep 1; done")
    assert _wait_status(runner, victim, "running"), "victim never registered"
    try:
        probe = (
            "t=$(printf 'SR-CROSS-%s' VICTIM-MARKER); "
            "for p in /proc/[0-9]*; do "
            "if tr '\\0' ' ' < \"$p/cmdline\" 2>/dev/null | grep -q \"$t\""
            "; then echo FOUND; fi; done; "
            "echo VISIBLE=$(ls -d /proc/[0-9]* | wc -l)")
        r = _run_fg(runner, attacker, probe)
        assert r.returncode == 0, r.stderr
        assert "FOUND" not in r.stdout, \
            "a running operation could discover another operation's process"
        # sanity: the probe itself ran inside a tiny namespace (its own few
        # processes), i.e. the enumeration really was namespace-scoped
        assert int(r.stdout.split("VISIBLE=")[1].split()[0]) < 15
        assert _status(runner, victim) == "running", "victim disturbed"
    finally:
        _cancel(runner, victim)


# --------------------------------------------------------------------------- #
# 2. cross-operation signalling is denied (even with the real PID)             #
# --------------------------------------------------------------------------- #

def test_kill_by_known_host_pid_cannot_reach_other_operation(runner):
    """The attacker is TOLD the victim's real host leader PID (taken from
    the supervisor's own pidfile by this test, standing for a leak) and
    tries to kill it, plus a namespace-wide broadcast. Both must fail to
    touch the victim: signals outward from a child user namespace are
    denied, and the fresh PID namespace has no outward signal authority."""
    victim, attacker = _op("vic"), _op("atk")
    started, finished = runner["tmp"] / "v.started", runner["tmp"] / "v.done"
    _start_bg(runner, victim,
              f"touch {started}; sleep 4; touch {finished}")
    assert _wait_status(runner, victim, "running")
    assert started.is_file()
    pid = (runner["state"] / f"{victim}.pid").read_text().split(":")[0]

    r = _run_fg(runner, attacker,
                f"kill -9 {pid} 2>&1; kill -KILL {pid} 2>&1; "
                "kill -9 -1 2>/dev/null; true", timeout=40)
    # the attacker's own namespace-wide kill may end the attacker itself —
    # what must never happen is any effect on the victim
    _ = r
    assert _status(runner, victim) == "running", \
        "a cross-boundary signal reached another operation"
    assert not finished.is_file(), "victim was killed early"
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline and not finished.is_file():
        time.sleep(0.2)
    assert finished.is_file(), "victim did not complete despite the attack"
    assert _wait_status(runner, victim, "gone", timeout=15)


def test_broadcast_kill_cannot_reach_the_supervisor(runner):
    """`kill -9 -1` inside the boundary must not kill the supervisor's
    control path either: after the attacker self-destructs, status and
    cancel for the attacker, and start for a new operation, still work."""
    attacker = _op("atk")
    r = _run_fg(runner, attacker, "kill -9 -1 2>/dev/null; true", timeout=40)
    assert r.returncode != 127  # the command itself ran inside the boundary
    # the supervisor still answers authoritatively for the dead attacker
    assert _wait_status(runner, attacker, "gone", timeout=15)
    fresh = _op("post")
    assert _run_fg(runner, fresh, "true").returncode == 0


# --------------------------------------------------------------------------- #
# 3. masked bookkeeping and re-rooted cgroups are invisible                    #
# --------------------------------------------------------------------------- #

def test_state_mask_hides_real_records_from_inside(runner):
    """Inside the boundary the state directory is an empty tmpfs: the
    attacker can neither enumerate another operation's records nor forge
    into the real ones — verified from the host side afterwards."""
    victim, attacker = _op("vic"), _op("atk")
    _start_bg(runner, victim, "exec sleep 8")
    assert _wait_status(runner, victim, "running")
    real_pidfile = runner["state"] / f"{victim}.pid"
    real_before = real_pidfile.read_text()

    probe = (
        f'ls "$RUNNER_SUPERVISOR_STATE" 2>/dev/null | grep -c "{victim}" ; '
        f'echo forged > "$RUNNER_SUPERVISOR_STATE/{victim}.pid" 2>/dev/null; '
        "true")
    r = _run_fg(runner, attacker, probe)
    assert r.returncode == 0, r.stderr
    assert r.stdout.strip().splitlines()[0] == "0", \
        "the attacker could see the real state directory through the mask"
    assert real_pidfile.read_text() == real_before, \
        "a write through the mask reached the supervisor's real records"

    _cancel(runner, victim)


def test_parent_cgroup_hierarchy_is_unreachable_from_inside(runner):
    """The operation sees /sys/fs/cgroup as a bind of its OWN containment
    directory; the hierarchy above (where the supervisor and every other
    operation live, and where an escape would migrate) must be unreadable
    and unwritable from inside."""
    attacker = _op("atk")
    probe = (
        "cat /sys/fs/cgroup/cgroup.procs >/dev/null 2>&1 && echo SELF-OK; "
        "cat /sys/fs/cgroup/../cgroup.procs >/dev/null 2>&1 && "
        "  echo PARENT-READABLE; "
        "echo x > /sys/fs/cgroup/../cgroup.procs 2>/dev/null && "
        "  echo PARENT-WRITABLE; "
        "cat /sys/fs/cgroup/../../cgroup.procs >/dev/null 2>&1 && "
        "  echo ROOT-READABLE; true")
    r = _run_fg(runner, attacker, probe)
    assert "SELF-OK" in r.stdout, "own containment tree should be visible"
    assert "PARENT-READABLE" not in r.stdout
    assert "PARENT-WRITABLE" not in r.stdout
    assert "ROOT-READABLE" not in r.stdout
