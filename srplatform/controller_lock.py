"""The controller singleton: exactly one API process acts as the controller.

The API process that serves requests also runs the controller duties:
reconciling interrupted runs, clearing dead operation claims and heartbeating
the control lease.  Two processes doing that at once is not a slower version
of one process - it is two controllers racing over the same durable state.

The lock is a PostgreSQL advisory lock, which is exactly the right primitive
here:

* it is held by the DATABASE, so it survives a crash of this process (the
  session ends, the lock is released) and cannot leak;
* it is scoped to the database, so a second deployment against the same
  database sees it;
* it is a session-level lock, so the connection that holds it must stay open
  for as long as this process is the controller.

A process that cannot take the lock is NOT the controller: it must not
reconcile, must not clear claims and must not heartbeat - and it must say so
in its readiness report instead of pretending to be healthy.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

# A fixed, namespaced key. The value is arbitrary but must never collide with
# another advisory lock in the same database.
CONTROLLER_LOCK_KEY = 0x5352_4331  # "SRC1" — the sparring-range controller


@dataclass
class ControllerLock:
    """Holds the controller advisory lock for the lifetime of the process."""

    key: int = CONTROLLER_LOCK_KEY
    connection: object | None = None
    acquired: bool = False
    detail: str = ""
    _stop: threading.Event = field(default_factory=threading.Event)

    def acquire(self, dsn: str, *, timeout_s: float = 5.0) -> bool:
        """Try to become the controller.

        Returns True when this process holds the lock.  A database that
        cannot be reached is NOT a silent success: the caller reports it.
        """
        try:
            import psycopg2
        except ImportError:  # pragma: no cover - psycopg2 is a dependency
            self.detail = "psycopg2 is not installed"
            return False
        deadline = time.monotonic() + max(0.0, timeout_s)
        conn = None
        last = ""
        while time.monotonic() < deadline:
            try:
                conn = psycopg2.connect(dsn)
                break
            except Exception as exc:  # noqa: BLE001 - reported, never hidden
                last = f"{type(exc).__name__}: {exc}"
                conn = None
                time.sleep(0.5)
        if conn is None:
            self.detail = last or "the database could not be reached"
            return False
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT pg_try_advisory_lock(%s)", (self.key,))
                got = bool(cur.fetchone()[0])
            if not got:
                self.detail = ("another controller holds the lock for this "
                               "database")
                conn.close()
                conn = None
                return False
            self.connection = conn
            self.acquired = True
            self.detail = "controller lock held"
            return True
        except Exception as exc:  # noqa: BLE001 - reported, never hidden
            self.detail = f"{type(exc).__name__}: {exc}"
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
            return False

    def release(self) -> None:
        if self.connection is not None:
            try:
                with self.connection.cursor() as cur:
                    cur.execute("SELECT pg_advisory_unlock(%s)", (self.key,))
                    self.connection.commit()
            except Exception:  # noqa: BLE001 - the lock dies with the session
                pass
            try:
                self.connection.close()
            except Exception:  # noqa: BLE001
                pass
            self.connection = None
        self.acquired = False
