"""Separate-UID worker supervisor (milestone 15).

Runs as ``srworker`` under systemd. It claims a durable queued run through the
API with a dedicated supervisor capability, spawns the red worker in a NEW
process group, records that group identity with the API, renews heartbeats,
and reports a truthful failure if the child exits without completing.

The supervisor holds no database, broker, libvirt, model or controller secret.
The assignment response contains only the worker's serialized environment:
API base URL, one-shot run capability, runner channel, pace/deadline. The API
cannot spawn or signal this UID; this process owns its child group.
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
    r = client.post(url, headers=headers, json=body or {}, timeout=30)
    if r.status_code >= 400:
        raise RuntimeError(f"{url} -> {r.status_code}: {r.text[:300]}")
    return r.json() if r.content else {}


class Supervisor:
    def __init__(self, api: str, token: str, poll_s: float,
                 heartbeat_s: float):
        self.api = api.rstrip("/")
        self.headers = {"X-Worker-Supervisor-Token": token}
        self.poll_s = max(0.25, float(poll_s))
        self.heartbeat_s = max(1.0, float(heartbeat_s))
        self.stop = threading.Event()
        self.child: subprocess.Popen | None = None
        self.run_id: str | None = None

    def _terminate_child(self, grace_s: float = 8.0) -> str:
        proc = self.child
        if proc is None:
            return "no child"
        if proc.poll() is not None:
            return f"child already exited {proc.returncode}"
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except OSError as exc:
            return f"killpg failed: {exc}"
        try:
            proc.wait(timeout=grace_s)
            return "child group terminated"
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except OSError:
                pass
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                return "child group termination UNCONFIRMED"
            return "child group killed"

    def _beat(self, done: threading.Event) -> None:
        with httpx.Client() as client:
            while not done.wait(self.heartbeat_s):
                if not self.run_id:
                    continue
                try:
                    _post(client,
                          f"{self.api}/internal/worker/{self.run_id}/heartbeat",
                          self.headers)
                except Exception as exc:  # noqa: BLE001
                    print(f"[supervisor] heartbeat failed: {exc}",
                          file=sys.stderr, flush=True)
                    # A missing heartbeat is not a stop signal; the API and
                    # operator can see staleness. Keep trying while the child
                    # is alive so a transient API restart does not orphan it.

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
                assignment = body.get("assignment") if body else None
                if not assignment:
                    self.stop.wait(self.poll_s)
                    continue
                self.run_id = assignment["run_id"]
                env = dict(assignment.get("env") or {})
                # The child gets ONLY this serialized environment. Never
                # inherit the supervisor's own token or controller secrets.
                for key in ("PATH", "HOME", "LANG", "LC_ALL", "TZ"):
                    if key not in env and os.environ.get(key):
                        env[key] = os.environ[key]
                env.setdefault("PATH", "/usr/local/bin:/usr/bin:/bin")
                try:
                    self.child = subprocess.Popen(
                        [sys.executable, "-m", "srplatform.red_agent.worker"],
                        env=env, start_new_session=True)
                except OSError as exc:
                    _post(client,
                          f"{self.api}/internal/worker/{self.run_id}/failed",
                          self.headers,
                          {"reason": f"worker spawn failed: {exc}"})
                    self.run_id = None
                    continue
                pgid = os.getpgid(self.child.pid)
                try:
                    _post(client,
                          f"{self.api}/internal/worker/{self.run_id}/assign",
                          self.headers,
                          {"pid": self.child.pid, "pgid": pgid,
                           "pgid_pstart": _pstart(self.child.pid)})
                except Exception as exc:  # noqa: BLE001
                    print(f"[supervisor] assign refused: {exc}",
                          file=sys.stderr, flush=True)
                    self._terminate_child()
                    try:
                        _post(client,
                              f"{self.api}/internal/worker/{self.run_id}/failed",
                              self.headers,
                              {"reason": f"assign refused: {exc}"})
                    except Exception:  # noqa: BLE001
                        pass
                    self.run_id = None
                    self.child = None
                    continue
                done = threading.Event()
                beat = threading.Thread(target=self._beat, args=(done,),
                                        daemon=True)
                beat.start()
                rc = self.child.wait()
                done.set()
                beat.join(timeout=5)
                # The worker normally posts /internal/runs/{id}/complete before
                # exit. This report is a no-op if that already made the run
                # terminal; otherwise it records a truthful failure.
                try:
                    _post(client,
                          f"{self.api}/internal/worker/{self.run_id}/failed",
                          self.headers,
                          {"reason": f"worker process exited with status {rc} "
                                     "without a confirmed completion"})
                except Exception as exc:  # noqa: BLE001
                    print(f"[supervisor] failure report failed: {exc}",
                          file=sys.stderr, flush=True)
                self.child = None
                self.run_id = None
                if self.stop.is_set():
                    break
        return 0

    def terminate(self) -> None:
        self.stop.set()
        if self.run_id and self.child is not None:
            detail = self._terminate_child()
            try:
                with httpx.Client() as client:
                    _post(client,
                          f"{self.api}/internal/worker/{self.run_id}/failed",
                          self.headers,
                          {"reason": f"supervisor stopping: {detail}"})
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
