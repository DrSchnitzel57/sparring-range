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

    # -- identity ------------------------------------------------------------
    def _inspect_state(self, kind: str, name: str) -> str:
        """'exists' or 'absent'. A failed inspection is treated as absence
        ONLY when docker reports the resource does not exist — daemon errors
        are raised, never silently read as a free name (review P2)."""
        args = (["inspect", name] if kind == "container"
                else ["volume", "inspect", name])
        r = _docker(args)
        if r.returncode == 0:
            return "exists"
        err = (r.stderr or "").lower()
        if "no such" in err or "not found" in err:
            return "absent"
        raise RuntimeError(
            f"cannot verify whether {kind} {name} is free: rc {r.returncode}: "
            f"{(r.stderr or r.stdout).strip()[:200]}")

    def _owner_nonce(self, kind: str, name: str) -> str | None:
        """The sr-range-run label of an existing resource ('' when it has
        none), or None when it does not exist. Raises on inspection error —
        ownership must be CONFIRMED before any deletion, never assumed."""
        if kind == "container":
            args = ["inspect", "-f",
                    '{{ index .Config.Labels "sr-range-run" }}', name]
        else:
            args = ["volume", "inspect", "-f",
                    '{{ index .Labels "sr-range-run" }}', name]
        r = _docker(args)
        if r.returncode == 0:
            return r.stdout.strip()
        err = (r.stderr or "").lower()
        if "no such" in err or "not found" in err:
            return None
        raise RuntimeError(
            f"cannot confirm ownership of {kind} {name}: rc {r.returncode}: "
            f"{(r.stderr or r.stdout).strip()[:200]}")

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
        # EVERY partial-startup path — nonzero exits AND timeouts/crashes in
        # any docker call (review P2) — runs cleanup and surfaces its
        # problems; nothing under our unique names can be stranded.
        try:
            self._start_inner()
        except Exception as e:
            problems = self.cleanup()
            raise RuntimeError(
                f"{type(e).__name__}: {e}"
                + (f"; cleanup problems: {problems}" if problems else "")) from e
        return self

    def _start_inner(self) -> None:
        # REFUSE pre-existing resources (review P2): a name collision means
        # the resource is NOT ours, and cleanup must never remove it. Names
        # are claimed only after the name is VERIFIED free (errors abort);
        # every resource is created with a run-unique ownership label, and
        # cleanup re-verifies that label before deleting — so a race that
        # plants a foreign resource between check and create can still never
        # be deleted by us.
        if self._inspect_state("volume", self.volume) == "exists":
            raise RuntimeError(
                f"volume {self.volume} already exists — refusing to adopt a "
                "resource this run did not create")
        self._owned_volume = True
        r = _docker(["volume", "create", "--label",
                     f"sr-range-run={self.run_id}", self.volume])
        if r.returncode != 0:
            raise RuntimeError(
                f"volume create failed: {(r.stderr or r.stdout).strip()[:300]}")
        if self._inspect_state("container", self.container) == "exists":
            raise RuntimeError(
                f"container {self.container} already exists — refusing to "
                "adopt a resource this run did not create")
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
            # occupied port) — cleanup removes whatever carries OUR ownership
            # label and SURFACES anything else it must not touch
            raise RuntimeError(
                f"postgres container start failed: "
                f"{(r.stderr or r.stdout).strip()[:400]}")
        self._wait_ready(timeout=90)

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
        """Remove ONLY resources carrying this run's ownership label, and
        only after that label is CONFIRMED. Absence is success (idempotent);
        a foreign resource under our names is left in place and reported;
        an unconfirmable identity is never deleted. Every other failure is
        returned for the caller to treat as fatal.
        """
        problems: list[str] = []
        for kind, name, claimed in (
                ("container", self.container, self._owned_container),
                ("volume", self.volume, self._owned_volume)):
            if not claimed:
                continue
            try:
                nonce = self._owner_nonce(kind, name)
            except RuntimeError as e:
                problems.append(f"{kind} {name}: {e} — NOT removed")
                continue
            if nonce is None:
                continue  # gone: never created, or already removed
            if nonce != self.run_id:
                problems.append(
                    f"{kind} {name} exists WITHOUT this run's ownership label "
                    f"(found {nonce!r}) — left in place, NOT removed")
                continue
            rm = (["rm", "-f", name] if kind == "container"
                  else ["volume", "rm", name])
            r = _docker(rm, timeout=60)
            err = (r.stderr or "").lower()
            if (r.returncode != 0 and "no such" not in err
                    and "not found" not in err):
                problems.append(f"{kind} {name}: "
                                f"{(r.stderr or r.stdout).strip()[:200]}")
        self._owned_container = False
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
