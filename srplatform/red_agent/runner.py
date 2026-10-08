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
  * ORDINARY COMPLETION IS GATED ON CONTAINMENT (audit T-04): before a
    remote command's exit is reported as finished, the runner queries the
    supervisor's authoritative (cgroup-backed) containment status. Surviving
    descendants are contained via the control channel and the containment is
    CONFIRMED; an unconfirmed or unreachable verdict is reported as
    cancel_state='unknown' — the loop halts and the API refuses to finalize
    the run. The SSH leader's exit code alone never marks work complete.

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


# ------------------------------------------------- local process-group plane
# AUDIT F7: LocalDevRunner gives every command an INDEPENDENT process group
# (start_new_session), so a redirected background child survives the leader —
# and after a WORKER death the API must still be able to resolve the local
# operation with REAL cessation evidence. The runner therefore records the
# command group's identity (pgid + leader start-time) in a sidecar the API's
# resolution pass can verify, and confirms/removes it on cessation.
def local_op_dir() -> "os.PathLike | None":
    from srplatform.settings import get_settings
    d = getattr(get_settings(), "runner_local_op_dir", "") or ""
    if not d:
        home = os.environ.get("HOME") or os.path.expanduser("~")
        d = os.path.join(home, ".sparring_range", "local_ops")
    return d


def _local_op_file(op_id: str):
    import pathlib
    return pathlib.Path(local_op_dir()) / f"{op_id}.pgid"


def _proc_start_ticks(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/stat") as f:
            return int(f.read().rsplit(")", 1)[1].split()[19])
    except (OSError, IndexError, ValueError):
        return 0


def local_group_members(pgid: int) -> list[int]:
    """PIDs whose process group is PGID (a group exists while any member
    lives, even after its leader exited)."""
    out = []
    for d in os.listdir("/proc"):
        if not d.isdigit():
            continue
        try:
            with open(f"/proc/{d}/stat") as f:
                fields = f.read().rsplit(")", 1)[1].split()
            if int(fields[2]) == pgid:
                out.append(int(d))
        except (OSError, IndexError, ValueError):
            continue
    return out


def _record_local_op(op_id: str, pgid: int, pstart: int) -> None:
    try:
        import pathlib
        p = _local_op_file(op_id)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(f"{pgid}:{pstart}\n")
    except OSError:
        pass    # dev-mode best effort; resolution then stays UNKNOWN-visible


def _clear_local_op(op_id: str) -> None:
    try:
        _local_op_file(op_id).unlink(missing_ok=True)
    except OSError:
        pass


def local_op_cessation(op_id: str) -> dict:
    """REAL local cessation evidence for a recorded command group (audit F7):
    the recorded identity must be verifiably gone. A group whose leader pid
    was RECYCLED (identity mismatch) is never signalled — the row stays
    unconfirmed instead. When the group is alive it is killed (same identity,
    dev transport) and re-verified."""
    f = _local_op_file(op_id)
    try:
        rec = f.read_text().strip()
        pid_s, _, st_s = rec.partition(":")
        pgid, pstart = int(pid_s), int(st_s)
    except (OSError, ValueError):
        return {"confirmed": False,
                "detail": "local command identity not recorded — cessation "
                          "UNCONFIRMED (never assumed gone)"}
    leader_ticks = _proc_start_ticks(pgid)
    if leader_ticks and leader_ticks != pstart:
        # the recorded leader pid was recycled — the group number now belongs
        # to someone else; those processes are NOT ours and are never killed
        return {"confirmed": False,
                "detail": f"recorded local group leader pid {pgid} was recycled — "
                          "cessation of the recorded work UNCONFIRMED"}
    members = local_group_members(pgid)
    if not members:
        _clear_local_op(op_id)
        return {"confirmed": True,
                "detail": f"local command group {pgid} confirmed gone (no members)"}
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    import time as _t
    deadline = _t.monotonic() + 5.0
    while _t.monotonic() < deadline:
        if not local_group_members(pgid):
            _clear_local_op(op_id)
            return {"confirmed": True,
                    "detail": f"local command group {pgid} killed and confirmed gone"}
        _t.sleep(0.1)
    return {"confirmed": False,
            "detail": f"local command group {pgid} survived SIGKILL — cessation UNCONFIRMED"}


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
    note: str | None = None           # truthful completion detail (audit T-04)


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
    discarded. Returns (bytes, timed_out).

    AUDIT T-04: a SUPERVISED start connection ends when the job LEADER exits,
    but a backgrounded survivor inherits the pipe's write end — waiting for
    EOF would block until the survivor exits and fold ordinary completion
    into a timeout. Once the start process has exited, one more quiet select
    window is the end of the stream; the survivor is then handled by the
    containment check, not by waiting on it. LOCAL transports get their own
    cessation handling (audit F7) — this early-end behavior must never be an
    SSH-only assumption silently applied to a runner without a check.
    """
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
            if proc.poll() is not None:
                break     # leader gone; stream held open only by survivors
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

    @staticmethod
    def _verdict(out: str) -> str:
        """The supervisor answers with exactly ONE token on stdout; take the
        LAST non-empty line so stray noise on the merged channel can never
        turn a clean 'gone' into 'unknown' (audit T-04)."""
        for line in reversed((out or "").splitlines()):
            if line.strip():
                return line.strip()
        return ""

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
            if code == 0 and self._verdict(out) in ("gone", "not-found"):
                return True
            time.sleep(0.5)
        return False

    def containment_status(self, op_id: str) -> str | None:
        """AUTHORITATIVE containment verdict for an operation (audit T-04):
        'running' (work survives), 'gone'/'not-found' (confirmed finished),
        or None — the supervisor is unreachable and the state is UNKNOWN.
        Unknown is never folded into 'gone'."""
        code, out = self._control("status", op_id, timeout=15)
        if code != 0:
            return None
        verdict = self._verdict(out)
        if verdict in ("running", "gone", "not-found"):
            return verdict
        return None   # unparseable answer is unknown, not gone

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
        # ORDINARY COMPLETION (audit T-04): a successful shell can exit while
        # a redirected background child KEEPS RUNNING — the leader's exit
        # code says nothing about the operation's containment. Ask the
        # supervisor (authoritative, cgroup-backed) before calling this
        # operation finished; unknown is treated as unknown.
        verdict = self.containment_status(op_id)
        if verdict == "running":
            confirmed = self.cancel_remote(op_id, timeout_s=10)
            if confirmed:
                return RunResult(exit_code=code, output=out, op_id=op_id,
                                 note="command exited with surviving remote descendants "
                                      "— contained and confirmed gone via supervisor")
            return RunResult(exit_code=code, output=out, op_id=op_id,
                             cancel_state="unknown",
                             error="command exited with SURVIVING REMOTE DESCENDANTS "
                                   "and containment is UNCONFIRMED — report partial stop")
        if verdict is None:
            return RunResult(exit_code=code, output=out, op_id=op_id,
                             cancel_state="unknown",
                             error="command exited but supervisor containment status is "
                                   "UNREACHABLE — remote cessation UNKNOWN, not gone")
        return RunResult(exit_code=code, output=out, op_id=op_id)

    def health(self) -> tuple[bool, str]:
        r = self.run("true", timeout=15)
        # AUDIT F7: an exit-zero result whose CESSATION verdict is unknown is
        # not a healthy runner — "reachable" must never fold into "contained".
        if r.exit_code == 0 and r.cancel_state != "unknown":
            return True, f"runner reachable at {self.s.runner_ssh_target} (supervised)"
        if r.cancel_state == "unknown":
            return False, ("runner health FAILED: cessation verdict UNKNOWN — "
                           f"{(r.error or r.output or '')[:200]}")
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
        # RECORD the independent command-group identity (audit F7): the API's
        # resolution pass needs real cessation evidence after a worker death.
        pgid, pstart = proc.pid, _proc_start_ticks(proc.pid)
        _record_local_op(op_id, pgid, pstart)
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
        note, cancel_state, error = None, None, None
        # ORDINARY COMPLETION IS GATED ON LOCAL CESSATION (audit F7): this
        # runner gives every command its OWN process group, so the leader's
        # exit says NOTHING about a redirected background child. Consult the
        # group before calling the operation finished — contain and confirm,
        # or report unknown. (The SSH runner asks its supervisor; local-dev
        # asks the kernel.)
        survivors = local_group_members(pgid)
        if survivors:
            try:
                os.killpg(pgid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass
            import time as _t
            deadline = _t.monotonic() + 5.0
            while _t.monotonic() < deadline and local_group_members(pgid):
                _t.sleep(0.1)
            if local_group_members(pgid):
                cancel_state = "unknown"
                error = ("command exited with SURVIVING local descendants and "
                         "local cessation is UNCONFIRMED — report partial stop")
            else:
                note = ("command exited with surviving local descendants — "
                        "contained (process group killed and confirmed gone)")
        if cancel_state != "unknown":
            _clear_local_op(op_id)   # cessation confirmed — obligation resolved
            if cancelled:
                cancel_state = "confirmed"
        return RunResult(exit_code=124 if timed_out else proc.returncode,
                         output=out, timed_out=timed_out, cancelled=cancelled,
                         op_id=op_id, error=error, note=note,
                         cancel_state=cancel_state)

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
