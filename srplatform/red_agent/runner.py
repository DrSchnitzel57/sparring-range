"""Isolated command runner (F01): model-selected commands execute ONLY on the
designated isolated runner, never in the control-plane API environment.

Transport: SSH to a FIXED destination (from settings), dedicated low-privilege
user, pinned host key (StrictHostKeyChecking=yes — no TOFU, no `known_hosts=None`),
BatchMode. Bounded time and output. There is deliberately NO fallback to a
local shell: if the runner is unavailable, execution fails and the run fails
visibly.
CANCELLATION / STOP SEMANTICS (audit R03/N05):
  * Every command runs in its OWN process group and is registered in a
    module-level SUPERVISORY TABLE with a stable operation identity
    (op_id) before it can execute. The table is the single source of truth
    for what is running — including commands spawned but not yet fully
    registered (spawn/register race closed by registering the PENDING
    intent under the same lock that guards the table).
  * The worker installs a SIGTERM handler that calls `cancel_active()`, so
    stopping the worker (which SIGTERMs its process group) also terminates
    the CURRENTLY RUNNING command group — nothing survives the advertised
    stop. A crash/SIGKILL of the worker leaves the command group's parent
    (the worker) dead: the group is reparented and the API-side run
    reconciliation terminates it via the recorded pgid.
  * LOCAL transport: killing the group is authoritative.
  * REMOTE (SSH) transport: cancellation is AUTHORITATIVE VIA THE RUNNER
    CHANNEL, not via the command connection: a separate short SSH control
    connection runs the runner-side supervisor script
    (runner_supervise.sh), which starts each operation as a tracked,
    killable job (stable op_id, pidfile, process group) and answers
    status/cancel/ack. `stop(op_id)` polls until the supervisor CONFIRMS
    the job group is gone; an unconfirmed cancel stays 'unknown' and the
    worker reports the stop as PARTIAL — never silently 'cancelled'.
    SSH disconnect alone is never treated as remote cancellation.
  * Output is captured with a BOUNDED streaming reader (never unbounded
    buffering followed by truncation).

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
# Audit N05: entries carry a STABLE OPERATION IDENTITY and are registered
# BEFORE the process can execute (the spawn/register window is closed by
# registering under the supervision lock).
_ACTIVE_LOCK = threading.Lock()
_ACTIVE: dict[str, dict] = {}   # op_id -> {kind, proc?, pgid?, remote?, state}
# set by the atexit handler when a cancellation could NOT be confirmed
stop_unconfirmed: dict | None = None


def _new_op_id() -> str:
    import uuid
    return uuid.uuid4().hex


def _register(op_id: str, entry: dict) -> None:
    with _ACTIVE_LOCK:
        _ACTIVE[op_id] = entry


def _attach_proc(op_id: str, proc: subprocess.Popen) -> None:
    """Attach the spawned process to its PENDING registration atomically —
    cancel_active() between spawn and attach still finds and kills it."""
    with _ACTIVE_LOCK:
        entry = _ACTIVE.get(op_id)
        if entry is None:      # cancelled before attach — kill now
            pid = proc.pid
        else:
            entry["proc"] = proc
            entry["pgid"] = os.getpgid(proc.pid)
            pid = None
    if pid is not None:
        try:
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            try:
                proc.kill()
            except Exception:
                pass


def _finish_op(op_id: str) -> None:
    with _ACTIVE_LOCK:
        _ACTIVE.pop(op_id, None)


def active_ops() -> list[dict]:
    with _ACTIVE_LOCK:
        return [{"op_id": k, **{f: v.get(f) for f in ("kind", "state", "remote")}}
                for k, v in _ACTIVE.items()]


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        try:
            proc.kill()
        except Exception:
            pass


def cancel_active(timeout_s: float = 10.0) -> dict:
    """Terminate every supervised operation. LOCAL groups are killed and
    CONFIRMED dead. REMOTE groups go through the runner control channel; an
    unconfirmed remote cancel is reported, never assumed. Returns a truthful
    per-op summary — the worker's stop path must not claim 'cancelled' for
    anything reported here as unknown/failed."""
    with _ACTIVE_LOCK:
        items = list(_ACTIVE.items())
    results = []
    for op_id, entry in items:
        if entry.get("kind") == "remote":
            runner = entry.get("runner")
            try:
                ok = runner.cancel_remote(op_id, timeout_s=timeout_s) if runner else False
            except Exception as e:  # noqa: BLE001
                ok = False
                entry["error"] = str(e)[:200]
            entry["state"] = "cancelling" if ok else "cancel-unknown"
            # the local ssh client is ALSO killed (transport must not linger)
            proc = entry.get("proc")
            if proc is not None:
                _kill_group(proc)
            results.append({"op_id": op_id, "kind": "remote",
                            "cancelled": bool(ok),
                            "detail": entry.get("error") or
                            ("runner confirmed cessation" if ok else
                             "remote cessation UNCONFIRMED — report partial")})
        else:
            proc = entry.get("proc")
            if proc is not None:
                _kill_group(proc)
                try:
                    proc.wait(timeout=timeout_s)
                    confirmed = True
                except Exception:
                    confirmed = proc.poll() is not None
                entry["state"] = "cancelled" if confirmed else "cancel-unknown"
                results.append({"op_id": op_id, "kind": "local",
                                "cancelled": confirmed,
                                "detail": "group killed and reaped" if confirmed
                                else "group survived SIGKILL wait"})
            else:
                # pending spawn: mark cancelled so _attach_proc kills on attach
                entry["state"] = "cancelled-before-attach"
                results.append({"op_id": op_id, "kind": "local", "cancelled": True,
                                "detail": "cancelled before spawn/attach"})
    with _ACTIVE_LOCK:
        for r in results:
            if r["cancelled"]:
                _ACTIVE.pop(r["op_id"], None)
    return {"ok": all(r["cancelled"] for r in results) if results else True,
            "ops": results,
            "detail": f"{sum(1 for r in results if not r['cancelled'])} of "
                      f"{len(results)} operations unconfirmed"}


def install_cancellation_handlers() -> None:
    """Called by the worker: SIGTERM (graceful stop) and exit paths must not
    leave command processes behind.

    AUDIT T01: `cancel_active()` returning an unconfirmed summary must NOT be
    discarded. An unconfirmed cancellation is printed to stderr (the API
    captures worker output) and the worker exits 144 — a distinct code so
    "stopped cleanly" and "stop UNCONFIRMED" are distinguishable. The API
    still treats remote cessation authoritatively through the durable
    operation inventory; this handler is the LOCAL containment layer."""
    import atexit
    import sys

    def _report(summary: dict) -> int:
        if summary.get("ok"):
            return 0
        print(f"[worker] cancellation UNCONFIRMED: {summary.get('detail')} "
              f"ops={summary.get('ops')}", file=sys.stderr, flush=True)
        return 1

    def _term(signum, frame):
        code = 143
        try:
            if _report(cancel_active()):
                code = 144
        finally:
            sys.exit(code)

    signal.signal(signal.SIGTERM, _term)

    def _atexit():
        summary = cancel_active()
        _report(summary)
        global stop_unconfirmed
        if not summary.get("ok"):
            stop_unconfirmed = summary
    atexit.register(_atexit)


class RunnerUnavailable(RuntimeError):
    pass


@dataclass
class RunResult:
    exit_code: int
    output: str
    timed_out: bool = False
    cancelled: bool = False
    error: str | None = None
    op_id: str | None = None
    cancel_state: str | None = None   # confirmed | unknown | failed (N05)


def _bounded_reader(proc: subprocess.Popen, max_bytes: int,
                    deadline: float | None = None) -> tuple[bytes, bool]:
    """Streaming capture with a HARD BYTE bound and an INDEPENDENT DEADLINE
    (audit N05/T07).

    T07 fixes: reads are BYTE-ORIENTED via os.read on the raw descriptor —
    select() guarantees data is ready, and os.read returns whatever is
    available instead of blocking for a full buffer (the old buffered
    `stream.read(4096)` could wait indefinitely for more characters after a
    small write from a long-silent child). The deadline is checked on every
    loop iteration, so a one-byte-then-silence child is cut off at the
    deadline, and the PARTIAL output captured so far is RETURNED, never
    discarded. Returns (bytes, timed_out)."""
    import os as _os
    import select
    import time
    fd = proc.stdout.fileno()
    buf = bytearray()
    while True:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return bytes(buf), True
            wait = min(remaining, 0.5)
        else:
            wait = 0.5
        ready, _, _ = select.select([fd], [], [], wait)
        if not ready:
            continue
        try:
            chunk = _os.read(fd, 65536)
        except (BlockingIOError, InterruptedError):
            continue
        except OSError:
            break
        if not chunk:
            break  # EOF
        if len(buf) < max_bytes:
            buf.extend(chunk[: max_bytes - len(buf)])
        # past the bound: keep draining (prevents pipe deadlock) without keeping
    return bytes(buf), False


class Runner:
    mechanism = "abstract"

    def run(self, command: str, timeout: int | None = None) -> RunResult:
        raise NotImplementedError

    def health(self) -> tuple[bool, str]:
        raise NotImplementedError

    def close(self) -> None:
        pass


class SshRunner(Runner):
    """SSH transport with a runner-side SUPERVISED containment protocol.

    Each operation gets a stable op_id and is executed through the
    runner-side supervisor (runner_supervise.sh, installed on the isolated
    runner — see infra/runner/runner_supervise.sh and OPERATOR_RUNBOOK):
    the job runs in its own process group under a pidfile the supervisor
    tracks. Cancellation goes over an INDEPENDENT short SSH control
    connection (the command connection may be wedged), and is only reported
    confirmed when the supervisor answers that the group is gone. An
    unconfirmed cancel is surfaced as cancel_state='unknown' — the worker's
    stop path must report PARTIAL, never 'cancelled' (audit N05)."""

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
                "-o", "ConnectTimeout=10", "-i", s.runner_ssh_key_path,
                "--", s.runner_ssh_target]

    # --- runner-side supervisor control channel -------------------------------
    def _supervisor_bin(self) -> str:
        return getattr(self.s, "runner_supervisor_bin", "") or "runner-supervisor"

    def _control(self, verb: str, op_id: str, timeout: int = 15) -> tuple[int, str]:
        proc = subprocess.Popen(self._base_cmd() +
                                [f"{shlex.quote(self._supervisor_bin())} {verb} "
                                 f"{shlex.quote(op_id)}"],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, start_new_session=True)
        try:
            out, _ = proc.communicate(timeout=timeout)
            return proc.returncode, (out or "")
        except subprocess.TimeoutExpired:
            _kill_group(proc)
            return 124, "control channel timeout"

    def cancel_remote(self, op_id: str, timeout_s: float = 10.0) -> bool:
        """Cancel via the control channel and WAIT for confirmed cessation."""
        import time
        code, out = self._control("cancel", op_id, timeout=int(max(5, timeout_s / 2)))
        if code != 0:
            return False
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            code, out = self._control("status", op_id, timeout=5)
            if code == 0 and out.strip() in ("gone", "not-found"):
                return True
            time.sleep(0.5)
        return False

    def run(self, command: str, timeout: int | None = None,
            op_id: str | None = None) -> RunResult:
        t = timeout or self.s.runner_command_timeout_s
        op_id = op_id or _new_op_id()
        _register(op_id, {"kind": "remote", "state": "pending", "remote": True,
                          "runner": self})
        # The supervisor starts the job (own process group, tracked pidfile)
        # and streams its output on THIS connection; the control channel
        # cancels it by op_id regardless of this connection's fate.
        remote_cmd = (f"{shlex.quote(self._supervisor_bin())} start {shlex.quote(op_id)} "
                      f"-- bash -lc {shlex.quote(command)}")
        full = self._base_cmd() + [remote_cmd]
        try:
            proc = subprocess.Popen(full, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT,
                                    start_new_session=True)
        except OSError as e:
            _finish_op(op_id)
            return RunResult(exit_code=-1, output="", error=f"runner spawn failed: {e}",
                             op_id=op_id)
        _attach_proc(op_id, proc)
        with _ACTIVE_LOCK:
            cancelled_early = (_ACTIVE.get(op_id) or {}).get("state") == "cancelled-before-attach"
        timed_out = False
        raw = b""
        if cancelled_early:
            raw = b""
        else:
            import time as _time
            raw, timed_out = _bounded_reader(proc, self.s.runner_max_output_bytes,
                                             deadline=_time.monotonic() + t)
        # bounded wait for exit (the reader already drained; guard stragglers)
        if not timed_out:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                timed_out = True
                _kill_group(proc)
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
        else:
            _kill_group(proc)
            try:
                proc.wait(timeout=5)
            except Exception:
                pass
        with _ACTIVE_LOCK:
            entry = _ACTIVE.pop(op_id, None)
        cancel_state = (entry or {}).get("state")
        out = raw.decode("utf-8", "replace")[: self.s.runner_max_output_bytes]
        if timed_out:
            # the LOCAL ssh client died — the REMOTE job needs the supervisor
            confirmed = self.cancel_remote(op_id, timeout_s=10)
            return RunResult(exit_code=124, output=out + "\n[runner] command timed out",
                             timed_out=True, op_id=op_id,
                             cancel_state="confirmed" if confirmed else "unknown")
        code = proc.returncode if proc.returncode is not None else -1
        if cancel_state in ("cancelling", "cancelled", "cancelled-before-attach"):
            return RunResult(exit_code=code, output=out, cancelled=True, op_id=op_id,
                             cancel_state="confirmed")
        if cancel_state == "cancel-unknown":
            return RunResult(exit_code=code, output=out, cancelled=False, op_id=op_id,
                             cancel_state="unknown",
                             error="remote cessation UNCONFIRMED — report partial stop")
        if code == 255:
            # SSH TRANSPORT LOSS (audit T01): the command connection died for
            # a reason we cannot distinguish from the remote job's own exit —
            # the remote job may still be running. Cancellation must go
            # through the supervisor; ordinary disconnect is never treated as
            # remote cessation.
            confirmed = self.cancel_remote(op_id, timeout_s=10)
            return RunResult(exit_code=code, output=out, op_id=op_id,
                             cancelled=confirmed,
                             cancel_state="confirmed" if confirmed else "unknown",
                             error=None if confirmed else
                             ("ssh transport lost and remote cessation UNCONFIRMED "
                              "— report partial stop"))
        return RunResult(exit_code=code, output=out, op_id=op_id)

    def health(self) -> tuple[bool, str]:
        r = self.run("true", timeout=15)
        if r.exit_code == 0:
            return True, f"runner reachable at {self.s.runner_ssh_target} (supervised)"
        return False, f"runner health failed (exit {r.exit_code}): {r.output[:200] or r.error}"


class LocalDevRunner(Runner):
    """DEV-ONLY convenience (explicit opt-in). Not isolated. Refuses in prod."""

    mechanism = "local-dev"

    def __init__(self, settings: Settings | None = None):
        self.s = settings or get_settings()
        if self.s.sr_env == "production":
            raise RunnerUnavailable("local-dev runner is forbidden in production")

    def run(self, command: str, timeout: int | None = None,
            op_id: str | None = None) -> RunResult:
        if self.s.sr_env == "production":
            raise RunnerUnavailable("local-dev runner is forbidden in production")
        t = timeout or self.s.runner_command_timeout_s
        op_id = op_id or _new_op_id()
        _register(op_id, {"kind": "local", "state": "pending", "remote": False})
        try:
            proc = subprocess.Popen(["/bin/bash", "-lc", command], stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT,
                                    start_new_session=True)
        except OSError as e:
            _finish_op(op_id)
            return RunResult(exit_code=-1, output="", error=f"spawn failed: {e}", op_id=op_id)
        _attach_proc(op_id, proc)
        timed_out = False
        import time as _time
        raw, timed_out = _bounded_reader(proc, self.s.runner_max_output_bytes,
                                         deadline=_time.monotonic() + t)
        if not timed_out:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                timed_out = True
        if timed_out:
            _kill_group(proc)
            try:
                proc.wait(timeout=5)
            except Exception:
                pass
        with _ACTIVE_LOCK:
            entry = _ACTIVE.pop(op_id, None)
        cancelled = (entry or {}).get("state") in ("cancelled", "cancelled-before-attach")
        out = raw.decode("utf-8", "replace")[: self.s.runner_max_output_bytes]
        return RunResult(exit_code=124 if timed_out else proc.returncode,
                         output=out, timed_out=timed_out, cancelled=cancelled,
                         op_id=op_id,
                         cancel_state="confirmed" if cancelled else None)

    def health(self) -> tuple[bool, str]:
        return True, "local-dev runner (NOT isolated — dev only)"


def get_runner(settings: Settings | None = None) -> Runner:
    """Factory. No fallback chain — one configured transport or a hard error."""
    s = settings or get_settings()
    if s.runner_transport == "ssh":
        return SshRunner(s)
    if s.runner_transport == "local-dev":
        return LocalDevRunner(s)
    raise RunnerUnavailable(f"unknown runner transport '{s.runner_transport}'")
