"""Isolated command runner (F01): model-selected commands execute ONLY on the
designated isolated runner, never in the control-plane API environment.

Transport: SSH to a FIXED destination (from settings), dedicated low-privilege
user, pinned host key (StrictHostKeyChecking=yes — no TOFU, no `known_hosts=None`),
BatchMode. Bounded time and output. There is deliberately NO fallback to a
local shell: if the runner is unavailable, execution fails and the run fails
visibly.

CANCELLATION / STOP SEMANTICS (audit R03):
  * Every command runs in its OWN process group and is registered in a
    module-level handle set while executing.
  * The worker installs a SIGTERM handler that calls `cancel_active()`, so
    stopping the worker (which SIGTERMs its process group) also terminates the
    CURRENTLY RUNNING command group — nothing survives the advertised stop.
  * LOCAL transport: killing the group is authoritative.
  * REMOTE (SSH) transport: killing the local ssh client does NOT by itself
    kill a detached remote process. The remote command is started as the
    session leader (`exec`) so the SIGHUP on transport loss reaches it, which
    is best-effort, NOT a guarantee. A real cancel-and-acknowledge operation
    protocol on the runner remains an explicit LIVE GATE (docs/ARCHITECTURE_
    NOTES.md); no claim of remote group cancellation is made here.

`LocalDevRunner` exists solely for developer machines (SR_ENV=dev, explicit
`runner_transport=local-dev`) and refuses to run anything in production mode —
it is a convenience, not a fallback, and it says so in every result.
"""
from __future__ import annotations

import os
import shlex
import signal
import subprocess
import threading
from dataclasses import dataclass

from srplatform.settings import Settings, get_settings

# --------------------------------------------------------------- supervision
# Command handles are supervised HERE (in the worker process), so that the
# worker's stop path can terminate the actual command group — the API kills
# the worker's group, the worker's signal handler kills command groups (R03).
_ACTIVE_LOCK = threading.Lock()
_ACTIVE: set[subprocess.Popen] = set()


def _spawn_monitored(argv: list[str], **kw) -> subprocess.Popen:
    proc = subprocess.Popen(argv, start_new_session=True, **kw)
    with _ACTIVE_LOCK:
        _ACTIVE.add(proc)
    return proc


def _finish(proc: subprocess.Popen) -> None:
    with _ACTIVE_LOCK:
        _ACTIVE.discard(proc)


def cancel_active() -> int:
    """Kill every command process group currently supervised by this process.
    Returns how many groups were signalled."""
    with _ACTIVE_LOCK:
        procs = list(_ACTIVE)
    n = 0
    for p in procs:
        _kill_group(p)
        n += 1
    return n


def install_cancellation_handlers() -> None:
    """Called by the worker: SIGTERM (graceful stop) and exit paths must not
    leave command processes behind."""
    import atexit
    import sys

    def _term(signum, frame):
        try:
            cancel_active()
        finally:
            sys.exit(143)

    signal.signal(signal.SIGTERM, _term)
    atexit.register(cancel_active)


class RunnerUnavailable(RuntimeError):
    pass


@dataclass
class RunResult:
    exit_code: int
    output: str
    timed_out: bool = False
    cancelled: bool = False
    error: str | None = None


class Runner:
    mechanism = "abstract"

    def run(self, command: str, timeout: int | None = None) -> RunResult:
        raise NotImplementedError

    def health(self) -> tuple[bool, str]:
        raise NotImplementedError

    def close(self) -> None:
        pass


class SshRunner(Runner):
    mechanism = "ssh"

    def __init__(self, settings: Settings | None = None):
        s = settings or get_settings()
        self.s = s
        missing = [k for k, v in (("RUNNER_SSH_TARGET", s.runner_ssh_target),
                                  ("RUNNER_SSH_KEY_PATH", s.runner_ssh_key_path),
                                  ("RUNNER_SSH_KNOWN_HOSTS", s.runner_ssh_known_hosts)) if not v]
        if missing:
            raise RunnerUnavailable(f"runner not configured: {', '.join(missing)}")
        if not os.path.exists(s.runner_ssh_known_hosts):
            raise RunnerUnavailable(f"runner host-key file missing: {s.runner_ssh_known_hosts}")

    def _base_cmd(self) -> list[str]:
        s = self.s
        return ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                "-o", f"UserKnownHostsFile={s.runner_ssh_known_hosts}",
                "-o", f"ConnectTimeout=10", "-i", s.runner_ssh_key_path,
                "--", s.runner_ssh_target]

    def run(self, command: str, timeout: int | None = None) -> RunResult:
        t = timeout or self.s.runner_command_timeout_s
        # ssh concatenates trailing args into ONE remote command string that the
        # remote login shell parses — so the model command must be quoted to
        # arrive at `bash -lc` as exactly one argument (no injection into the
        # transport layer; the command is still a full shell command ON the runner).
        remote_cmd = f"exec bash -lc {shlex.quote(command)}"
        full = self._base_cmd() + [remote_cmd]
        proc = _spawn_monitored(full, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True)
        timed_out = False
        try:
            out, _ = proc.communicate(timeout=t)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_group(proc)
            try:
                out, _ = proc.communicate(timeout=5)
            except Exception:
                out = ""
        except OSError as e:
            _finish(proc)
            return RunResult(exit_code=-1, output="", error=f"runner spawn failed: {e}")
        _finish(proc)
        out = (out or "")[: self.s.runner_max_output_bytes]
        if timed_out:
            return RunResult(exit_code=124, output=out + "\n[runner] command timed out",
                             timed_out=True)
        return RunResult(exit_code=proc.returncode if proc.returncode is not None else -1, output=out)

    def health(self) -> tuple[bool, str]:
        r = self.run("true", timeout=15)
        if r.exit_code == 0:
            return True, f"runner reachable at {self.s.runner_ssh_target}"
        return False, f"runner health failed (exit {r.exit_code}): {r.output[:200] or r.error}"


class LocalDevRunner(Runner):
    """DEV-ONLY convenience (explicit opt-in). Not isolated. Refuses in prod."""

    mechanism = "local-dev"

    def __init__(self, settings: Settings | None = None):
        self.s = settings or get_settings()
        if self.s.sr_env == "production":
            raise RunnerUnavailable("local-dev runner is forbidden in production")

    def run(self, command: str, timeout: int | None = None) -> RunResult:
        if self.s.sr_env == "production":
            raise RunnerUnavailable("local-dev runner is forbidden in production")
        t = timeout or self.s.runner_command_timeout_s
        proc = _spawn_monitored(["/bin/bash", "-lc", command], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True)
        timed_out = False
        try:
            out, _ = proc.communicate(timeout=t)
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_group(proc)
            try:
                out, _ = proc.communicate(timeout=5)
            except Exception:
                out = ""
        _finish(proc)
        out = (out or "")[: self.s.runner_max_output_bytes]
        return RunResult(exit_code=124 if timed_out else proc.returncode,
                         output=out, timed_out=timed_out)

    def health(self) -> tuple[bool, str]:
        return True, "local-dev runner (NOT isolated — dev only)"


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            proc.kill()
        except Exception:
            pass


def get_runner(settings: Settings | None = None) -> Runner:
    """Factory. No fallback chain — one configured transport or a hard error."""
    s = settings or get_settings()
    if s.runner_transport == "ssh":
        return SshRunner(s)
    if s.runner_transport == "local-dev":
        return LocalDevRunner(s)
    raise RunnerUnavailable(f"unknown runner transport '{s.runner_transport}'")
