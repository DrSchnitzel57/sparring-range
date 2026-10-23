"""Separate-UID worker supervisor (milestone 15).

Runs as ``srworker`` under systemd. It claims a durable queued run through the
API with a dedicated supervisor capability, spawns the red worker in a NEW
process group, records that group identity with the API, renews heartbeats,
and reports a truthful failure if the child exits without completing.

The supervisor holds no database, broker, libvirt, model or controller secret.
The assignment response contains only the worker's serialized environment:
API base URL, one-shot run capability, runner channel, pace/deadline. The API
cannot spawn or signal this UID; this process owns its child group.

Every callback carries the CLAIM credential the controller handed out with the
assignment. It fences the callback: once the controller has reclaimed the run
the credential is rotated and this supervisor's authority is gone.

The state of ONE assignment is immutable and is never shared with the next
one: a heartbeat that is still waiting for its reply when the worker exits
must not clear the run id of the assignment that follows it.
"""
from __future__ import annotations

import os
import pathlib
import signal
import subprocess
import sys
import threading

import httpx


def _pstart(pid: int) -> int | None:
    try:
        fields = pathlib.Path(f"/proc/{pid}/stat").read_text().split()
        return int(fields[21])
    except (OSError, ValueError, IndexError):
        return None


def _token_file() -> str:
    path = os.environ.get("SR_WORKER_SUPERVISOR_TOKEN_FILE", "")
    if not path:
        raise SystemExit("SR_WORKER_SUPERVISOR_TOKEN_FILE is required")
    try:
        token = pathlib.Path(path).read_text().strip()
    except OSError as exc:
        raise SystemExit(f"supervisor token unreadable: {exc}") from exc
    if len(token) < 32:
        raise SystemExit("supervisor token is too short")
    return token


def _post(client: httpx.Client, url: str, headers: dict,
          body: dict | None = None):
    """POST and raise on an error status.

    The error is an ``httpx.HTTPStatusError`` so the callers can look at the
    status code (a 409 means "the controller no longer recognises this
    claim"), not a bare RuntimeError.
    """
    r = client.post(url, headers=headers, json=body or {}, timeout=30)
    if r.status_code >= 400:
        raise httpx.HTTPStatusError(
            f"{url} -> {r.status_code}: {r.text[:300]}",
            request=r.request, response=r)
    return r.json() if r.content else {}


class Assignment:
    """The immutable state of ONE claimed run.

    The heartbeat thread works on its own assignment: it must never touch the
    supervisor's current assignment, because a late heartbeat (the join
    timed out) would otherwise clear the run id and the claim credential of
    the NEXT assignment.
    """

    __slots__ = ("run_id", "claim_token", "_child")

    def __init__(self, run_id: str, claim_token: str | None,
                 child: subprocess.Popen | None = None):
        object.__setattr__(self, "run_id", run_id)
        object.__setattr__(self, "claim_token", claim_token)
        object.__setattr__(self, "_child", child)

    @property
    def child(self) -> subprocess.Popen | None:
        return self._child

    def attach_child(self, child: subprocess.Popen) -> None:
        """The spawned child belongs to THIS assignment and to no other."""
        object.__setattr__(self, "_child", child)

    def __setattr__(self, name, value):
        raise AttributeError("an assignment is immutable once it is claimed")


class Supervisor:
    def __init__(self, api: str, token: str, poll_s: float,
                 heartbeat_s: float):
        self.api = api.rstrip("/")
        self.headers = {"X-Worker-Supervisor-Token": token}
        self.poll_s = max(0.25, float(poll_s))
        self.heartbeat_s = max(1.0, float(heartbeat_s))
        self.stop = threading.Event()
        # The assignment this supervisor currently owns (never mutated in
        # place: a new assignment replaces it).
        self.current: Assignment | None = None

    # ---------------------------------------------------------------- child --
    def _terminate_child(self, child: subprocess.Popen | None,
                         grace_s: float = 8.0) -> str:
        if child is None:
            return "no child"
        if child.poll() is not None:
            return f"child already exited {child.returncode}"
        try:
            os.killpg(os.getpgid(child.pid), signal.SIGTERM)
        except OSError as exc:
            return f"killpg failed: {exc}"
        try:
            child.wait(timeout=grace_s)
            return "child group terminated"
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(child.pid), signal.SIGKILL)
            except OSError:
                pass
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                return "child group termination UNCONFIRMED"
            return "child group killed"

    # --------------------------------------------------------------- report --
    def _report(self, client, assignment: Assignment | None,
                reason: str) -> bool:
        """Tell the controller that the child is gone.

        True means acknowledged or definitively fenced, NOT confirmed remote
        cessation. The API retains any unresolved cancellation obligation.
        The CLAIM credential is always presented — the endpoint refuses a
        report without it.
        """
        if assignment is None:
            return True
        try:
            reply = _post(client,
                  f"{self.api}/internal/worker/{assignment.run_id}/failed",
                  self.headers,
                  {"reason": reason[:1000],
                   "claim_token": assignment.claim_token or ""})
            # This endpoint uses 200 even for a fenced claim and for a
            # recorded cancel-unknown. Do not mistake either for cessation.
            return (isinstance(reply, dict) and
                    (reply.get("ok") is True or reply.get("detail") in {
                        "unknown run",
                        "claim credential does not match — refused (obsolete claimant)",
                        "worker exit recorded; remote cessation UNCONFIRMED",
                    }))
        except httpx.HTTPStatusError as exc:
            # A generic conflict is not proof this claim was superseded. Only
            # the endpoint's explicit, authenticated fenced reply above is.
            print(f"[supervisor] failure report refused: {exc}",
                  file=sys.stderr, flush=True)
        except Exception as exc:  # noqa: BLE001
            print(f"[supervisor] failure report refused: {exc}",
                  file=sys.stderr, flush=True)
        return False

    def _resolve_assignment(self, client, assignment: Assignment, reason: str) -> bool:
        """Retry with bounded backoff, never claim/restart while unresolved.

        Shutdown may interrupt retries, but keeps ``current`` intact; the API's
        durable run/operation obligations remain outstanding for recovery.
        """
        delay = self.poll_s
        while True:
            if self._report(client, assignment, reason):
                if self.current is assignment:
                    self.current = None
                return True
            if self.stop.wait(min(delay, 30.0)):
                return False
            delay = min(delay * 2, 30.0)

    # ------------------------------------------------------------ heartbeat --
    def _beat(self, done: threading.Event, assignment: Assignment) -> None:
        with httpx.Client() as client:
            while not done.wait(self.heartbeat_s):
                try:
                    reply = _post(client,
                                  f"{self.api}/internal/worker/"
                                  f"{assignment.run_id}/heartbeat",
                                  self.headers,
                                  {"claim_token": assignment.claim_token or ""})
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code == 409:
                        # The controller no longer recognises this claim: the
                        # run was stopped, reclaimed or completed by someone
                        # else. This supervisor has NO authority over the
                        # child any more, so it must not keep it running.
                        print("[supervisor] claim refused — terminating the "
                              "child (the authority is gone)",
                              file=sys.stderr, flush=True)
                        self._terminate_child(assignment.child)
                        self._report(client, assignment,
                                     "the controller no longer recognises "
                                     "this claim")
                        return
                    print(f"[supervisor] heartbeat failed: {exc}",
                          file=sys.stderr, flush=True)
                    # A missing heartbeat is not a stop signal; the API and
                    # operator can see staleness. Keep trying while the child
                    # is alive so a transient API restart does not orphan it.
                    continue
                except Exception as exc:  # noqa: BLE001
                    print(f"[supervisor] heartbeat failed: {exc}",
                          file=sys.stderr, flush=True)
                    # A missing heartbeat is not a stop signal; the API and
                    # operator can see staleness. Keep trying while the child
                    # is alive so a transient API restart does not orphan it.
                    continue
                if isinstance(reply, dict) and reply.get("stop"):
                    # The controller asked for this worker to stop.  The
                    # supervisor is the ONLY party that may signal a
                    # foreign-UID child, so the request comes back here.
                    print("[supervisor] stop requested by the controller",
                          file=sys.stderr, flush=True)
                    self._terminate_child(assignment.child)
                    self._report(client, assignment,
                                 "stopped at the controller's request")
                    return

    # ------------------------------------------------------------------ run --
    def run(self) -> int:
        with httpx.Client() as client:
            while not self.stop.is_set():
                try:
                    body = _post(client, f"{self.api}/internal/worker/claim",
                                 self.headers)
                except Exception as exc:  # noqa: BLE001
                    print(f"[supervisor] claim failed: {exc}",
                          file=sys.stderr, flush=True)
                    self.stop.wait(self.poll_s)
                    continue
                payload = body.get("assignment") if body else None
                if not payload:
                    self.stop.wait(self.poll_s)
                    continue
                assignment = Assignment(payload["run_id"],
                                        payload.get("claim_token"))
                self.current = assignment
                env = dict(payload.get("env") or {})
                # The child gets ONLY this serialized environment. Never
                # inherit the supervisor's own token or controller secrets.
                for key in ("PATH", "HOME", "LANG", "LC_ALL", "TZ"):
                    if key not in env and os.environ.get(key):
                        env[key] = os.environ.get(key)
                env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
                try:
                    assignment.attach_child(subprocess.Popen(
                        [sys.executable, "-m", "srplatform.red_agent.worker"],
                        env=env, start_new_session=True))
                except OSError as exc:
                    if not self._resolve_assignment(client, assignment,
                                                    f"worker spawn failed: {exc}"):
                        return 1
                    continue
                pgid = os.getpgid(assignment.child.pid)
                try:
                    _post(client,
                          f"{self.api}/internal/worker/{assignment.run_id}/assign",
                          self.headers,
                          {"pid": assignment.child.pid, "pgid": pgid,
                           "pgid_pstart": _pstart(assignment.child.pid),
                           "claim_token": assignment.claim_token or ""})
                except Exception as exc:  # noqa: BLE001
                    print(f"[supervisor] assign refused: {exc}",
                          file=sys.stderr, flush=True)
                    self._terminate_child(assignment.child)
                    # The assignment may already have been stopped while it
                    # was being registered: the report resolves it.
                    if not self._resolve_assignment(client, assignment, f"assign refused: {exc}"):
                        return 1
                    continue
                done = threading.Event()
                beat = threading.Thread(target=self._beat,
                                        args=(done, assignment), daemon=True)
                beat.start()
                rc = assignment.child.wait()
                done.set()
                beat.join(timeout=5)
                # The worker normally posts /internal/runs/{id}/complete before
                # exit. This report is a no-op if that already made the run
                # terminal; otherwise it records a truthful failure. It names
                # THIS assignment, never the next one.
                if not self._resolve_assignment(
                        client, assignment, f"worker process exited with status {rc} "
                                            "without a confirmed completion"):
                    return 1
                if self.stop.is_set():
                    break
        return 0

    def terminate(self) -> None:
        self.stop.set()
        assignment = self.current
        if assignment is not None and assignment.child is not None:
            detail = self._terminate_child(assignment.child)
            try:
                with httpx.Client() as client:
                    self._report(client, assignment, f"supervisor stopping: {detail}")
            except Exception:  # noqa: BLE001
                pass


def main() -> int:
    api = os.environ.get("SR_API_BASE", "http://127.0.0.1:8000")
    token = _token_file()
    poll = float(os.environ.get("SR_WORKER_POLL_S", "2"))
    heartbeat = float(os.environ.get("SR_WORKER_HEARTBEAT_S", "5"))
    sup = Supervisor(api, token, poll, heartbeat)

    def _stop(_signum, _frame):
        sup.terminate()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    print(f"[supervisor] polling {api} as separate worker UID", flush=True)
    return sup.run()


if __name__ == "__main__":
    sys.exit(main())
