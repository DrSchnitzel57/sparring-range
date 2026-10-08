"""Disposable PostgreSQL 16 fixture (milestone 01, audit F22/F23).

Starts a run-OWNED `postgres:16` container with unique names/storage, a
configurable LOOPBACK port and synthetic credentials, waits for real
readiness, and removes exactly the resources this fixture created.

It never infers permission on an existing cluster: absent Docker or the
image, `start()` raises PrerequisiteMissing with the exact gap. Partial
setup (container created but not ready, volume created but container gone)
is cleaned on any failure path, and cleanup failures are SURFACED, never
swallowed.
"""
from __future__ import annotations

import os
import secrets
import socket
import subprocess
import sys
import time
import uuid

IMAGE = "postgres:16"


class PrerequisiteMissing(Exception):
    pass


class CleanupError(Exception):
    pass


def _docker(args, timeout=120, check=False):
    r = subprocess.run(["docker", *args], capture_output=True, text=True,
                       timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args)} -> {r.returncode}: "
                           f"{(r.stderr or r.stdout).strip()[:400]}")
    return r


def free_loopback_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class PgFixture:
    """One disposable cluster: unique container + volume, loopback-only port,
    synthetic superuser password. `cleanup()` is idempotent and reports every
    resource it could not remove."""

    def __init__(self, port: int | None = None, run_id: str | None = None):
        tag = run_id or uuid.uuid4().hex[:8]
        self.run_id = tag
        self.container = f"sr-acc-pg-{tag}"
        self.volume = f"sr-acc-pgdata-{tag}"
        self.port = int(port) if port else free_loopback_port()
        self.password = secrets.token_urlsafe(18)
        self._owned_container = False
        self._owned_volume = False

    # -- lifecycle ----------------------------------------------------------
    def start(self) -> "PgFixture":
        if _docker(["version"]).returncode != 0:
            raise PrerequisiteMissing("docker daemon not reachable "
                                      "(required for the disposable DB)")
        if _docker(["image", "inspect", IMAGE]).returncode != 0:
            pull = _docker(["pull", IMAGE], timeout=600)
            if pull.returncode != 0:
                raise PrerequisiteMissing(
                    f"cannot pull {IMAGE}: {(pull.stderr or pull.stdout).strip()[:200]}")
        # names are unique per run, so cleanup may always attempt removal —
        # ownership is claimed BEFORE each create/start so a PARTIAL startup
        # (volume made, container created but failed to start, died during
        # readiness) can never strand a resource (review P2)
        self._owned_volume = True
        r = _docker(["volume", "create", self.volume])
        if r.returncode != 0:
            problems = self.cleanup()
            raise RuntimeError(f"volume create failed: "
                               f"{(r.stderr or r.stdout).strip()[:300]}"
                               + (f"; cleanup problems: {problems}" if problems else ""))
        self._owned_container = True
        r = _docker([
            "run", "-d", "--name", self.container,
            "--label", f"sr-range-run={self.run_id}",
            "-e", f"POSTGRES_PASSWORD={self.password}",
            "-e", "POSTGRES_DB=postgres",
            "-p", f"127.0.0.1:{self.port}:5432",
            "-v", f"{self.volume}:/var/lib/postgresql/data",
            IMAGE,
        ])
        if r.returncode != 0:
            # docker may have CREATED the container before failing (e.g. an
            # occupied port) — cleanup removes whatever exists under our
            # unique names and SURFACES any residue
            problems = self.cleanup()
            raise RuntimeError(
                f"postgres container start failed: "
                f"{(r.stderr or r.stdout).strip()[:400]}"
                + (f"; cleanup problems: {problems}" if problems else ""))
        try:
            self._wait_ready(timeout=90)
        except Exception as e:
            problems = self.cleanup()
            raise RuntimeError(f"{e}"
                               + (f"; cleanup problems: {problems}" if problems else ""))
        return self

    def _wait_ready(self, timeout: float) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            r = _docker(["exec", self.container, "pg_isready", "-U", "postgres",
                         "-d", "postgres"], timeout=20)
            if r.returncode == 0:
                return
            # a container that already died will never answer
            if _docker(["inspect", "-f", "{{.State.Running}}",
                        self.container]).stdout.strip() != "true":
                logs = _docker(["logs", "--tail", "20", self.container])
                raise RuntimeError("postgres container died during readiness "
                                   f"wait: {(logs.stdout + logs.stderr)[-400:]}")
            time.sleep(0.4)
        self._dump_logs()
        raise RuntimeError(f"postgres not ready within {timeout}s on port {self.port}")

    def _dump_logs(self) -> None:
        logs = _docker(["logs", "--tail", "30", self.container])
        print(f"[pg-fixture] container logs:\n{logs.stdout}{logs.stderr}",
              file=sys.stderr)

    def cleanup(self) -> list[str]:
        """Remove exactly the resources THIS fixture names (unique per run).
        Always attempts both removals and tolerates 'not found' (idempotent);
        returns every other failure — callers must treat non-empty as fatal."""
        problems: list[str] = []
        r = _docker(["rm", "-f", self.container], timeout=60)
        err = (r.stderr or "").lower()
        if r.returncode != 0 and "no such container" not in err:
            problems.append(f"container {self.container}: "
                            f"{(r.stderr or r.stdout).strip()[:200]}")
        self._owned_container = False
        r = _docker(["volume", "rm", self.volume], timeout=60)
        err = (r.stderr or "").lower()
        if r.returncode != 0 and "not found" not in err and "no such volume" not in err:
            problems.append(f"volume {self.volume}: "
                            f"{(r.stderr or r.stdout).strip()[:200]}")
        self._owned_volume = False
        return problems

    # -- access -------------------------------------------------------------
    def admin_url(self) -> str:
        """Superuser URL for the fixture cluster ONLY. Test fixtures derive
        every per-test DB URL from this endpoint (never a hardcoded host)."""
        return (f"postgresql+psycopg2://postgres:{self.password}"
                f"@127.0.0.1:{self.port}/postgres")

    def psql(self, sql: str) -> tuple[int, str]:
        r = _docker(["exec", self.container, "psql", "-X", "-U", "postgres",
                     "-d", "postgres", "-tAc", sql], timeout=60)
        return r.returncode, (r.stdout or "") + (r.stderr or "")

    def leftover_test_databases(self) -> list[str]:
        """srtest_* databases/roles surviving the suite = cleanup failure."""
        rc, out = self.psql("SELECT datname FROM pg_database WHERE datname LIKE 'srtest_%'")
        dbs = [d.strip() for d in out.splitlines() if d.strip()] if rc == 0 else ["<unreadable>"]
        rc, out = self.psql("SELECT rolname FROM pg_roles WHERE rolname LIKE 'sr\\_%'")
        roles = [d.strip() for d in out.splitlines() if d.strip()] if rc == 0 else ["<unreadable>"]
        return dbs + roles
