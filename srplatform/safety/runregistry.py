"""Run registry (F02): supervised run handles with process identity.

Replaces arbitrary-PID registration. Workers are spawned through the API's run
manager, which records the Popen handle here (pid + its OWN process group).
Engagement terminates process groups — the API's own group is refused by
identity check, and no client can ever name a PID to kill.
"""
from __future__ import annotations

import os
import signal
import threading
import time
from dataclasses import dataclass, field


@dataclass
class RunHandle:
    run_id: str
    pid: int
    pgid: int
    process: object = None  # subprocess.Popen when in-process
    meta: dict = field(default_factory=dict)


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
    def terminate_group(pgid: int, grace_s: float = 5.0) -> dict:
        """Kill a process GROUP (worker + its command descendants), never the
        caller's own group. Returns a truthful result."""
        my_pgid = os.getpgid(0)
        if pgid == my_pgid or pgid <= 1:
            return {"ok": False, "detail": f"refusing to signal process group {pgid} (identity guard)"}
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return {"ok": True, "detail": f"group {pgid} already exited"}
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
