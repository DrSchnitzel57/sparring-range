"""Run registry (F02): supervised run handles with process identity.

Replaces arbitrary-PID registration. Workers are spawned through the API's run
manager, which records the Popen handle here (pid + its OWN process group).
Engagement terminates process groups — the API's own group is refused by
identity check, and no client can ever name a PID to kill.

PGID REUSE GUARD (audit R03): a stored numeric PGID says nothing about WHICH
process once time has passed. Every handle records the group leader's start
time (proc-start clock ticks from /proc/<pid>/stat); termination refuses to
signal a group whose leader identity does not match.
"""
from __future__ import annotations

import os
import signal
import threading
import time
from dataclasses import dataclass, field


def pgid_start_time(pid: int) -> int | None:
    """Start time (clock ticks) of the process — stable identity across PID
    reuse. None when /proc is unavailable or the process is gone."""
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            raw = f.read().decode("utf-8", "replace")
        # comm may contain spaces/parens — fields after the LAST ')' are stable
        rest = raw[raw.rfind(")") + 2:].split()
        return int(rest[19])  # field 22 overall == index 19 after pid,comm,state
    except (OSError, ValueError, IndexError):
        return None


def pgid_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, not ours — still alive


def pgid_matches_identity(pgid: int, expected_pstart: int | None) -> bool:
    """True when the group leader still has the recorded start time, or when
    no identity was ever recorded (legacy rows: fall back to liveness only —
    logged by the caller's own policy)."""
    if expected_pstart is None:
        return True
    return pgid_start_time(pgid) == expected_pstart


@dataclass
class RunHandle:
    run_id: str
    pid: int
    pgid: int
    process: object = None  # subprocess.Popen when in-process; None when recovered
    meta: dict = field(default_factory=dict)
    pgid_pstart: int | None = None  # group-leader start time (identity guard)


class RunRegistry:
    def __init__(self):
        self._lock = threading.Lock()
        self._handles: dict[str, RunHandle] = {}

    def add(self, handle: RunHandle) -> None:
        with self._lock:
            self._handles[handle.run_id] = handle

    def remove(self, run_id: str) -> None:
        with self._lock:
            self._handles.pop(run_id, None)

    def active(self) -> list[RunHandle]:
        with self._lock:
            return list(self._handles.values())

    @staticmethod
    def terminate_group(pgid: int, grace_s: float = 5.0,
                        expected_pstart: int | None = None) -> dict:
        """Kill a process GROUP (worker + its command descendants), never the
        caller's own group. Returns a truthful result."""
        my_pgid = os.getpgid(0)
        if pgid == my_pgid or pgid <= 1:
            return {"ok": False, "detail": f"refusing to signal process group {pgid} (identity guard)"}
        if not pgid_matches_identity(pgid, expected_pstart):
            return {"ok": False, "detail": f"refusing to signal group {pgid}: leader start-time "
                                           "does not match the recorded run (PGID reused?)"}
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return {"ok": True, "detail": f"group {pgid} already exited"}
        except PermissionError:
            return {"ok": False, "detail": f"group {pgid} exists but is not ours to signal"}
        try:
            os.killpg(pgid, signal.SIGTERM)
        except ProcessLookupError:
            return {"ok": True, "detail": f"group {pgid} exited during TERM"}
        deadline = time.time() + grace_s
        while time.time() < deadline:
            try:
                os.killpg(pgid, 0)
            except ProcessLookupError:
                return {"ok": True, "detail": f"group {pgid} terminated (SIGTERM)"}
            time.sleep(0.1)
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            return {"ok": True, "detail": f"group {pgid} exited before KILL"}
        return {"ok": True, "detail": f"group {pgid} killed (SIGKILL after grace)"}


run_registry = RunRegistry()
