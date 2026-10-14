"""Control-plane lease heartbeat (milestone 02; bounded by plan 13 phase 2).

While the DB-backed control plane holds the range lease (a session owns the
range), this thread renews the broker's control lease every 5 seconds. If the
control plane dies, renewals stop; after 30 seconds the BROKER itself latches
and hard-stops every owned VM — cessation does not depend on the dead
component noticing its own death. Renewal can never resume a stopped range:
the broker refuses renew_lease while latched.

Plan 13 phase 2 (DB/control failure must not indefinitely renew a supposedly
healthy lease): a DB read is either CONFIRMED (active / provably idle) or
UNVERIFIED (error). While unverified, renewals continue only within a bounded
grace window (`max_unverified_s`, default 60 s = 2x the broker lease TTL):
a transient DB blip must not kill a live range, but a persistent control-
plane/DB failure must not keep asserting health forever either. Past the
window this heartbeat goes silent and the broker's own watchdog latches and
stops the range — fail-closed cessation, proven by tests.
"""
from __future__ import annotations

import threading
import time


def control_is_active() -> bool | None:
    """DB-backed truth: does some session currently hold the range lease?

    Returns True (lease held), False (provably idle) or None (UNVERIFIED —
    the read itself failed). None is never silently treated as either."""
    try:
        from srplatform.db.session import db
        from srplatform.scenario_engine.orchestrator import current_lease
        with db() as s:
            return current_lease(s) is not None
    except Exception:
        return None


class ControlHeartbeat:
    def __init__(self, broker, *, interval_s: float = 5.0,
                 active_check=control_is_active, holder: str = "api-control",
                 max_unverified_s: float = 60.0,
                 monotonic=time.monotonic):
        self.broker = broker
        self.interval_s = interval_s
        self.active_check = active_check
        self.holder = holder
        self.max_unverified_s = max_unverified_s
        self._monotonic = monotonic
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_error: str | None = None
        self._disarmed = False
        self._unverified_since: float | None = None

    def tick(self) -> bool:
        """One renewal cycle. Returns True when a renewal was sent."""
        try:
            active = self.active_check()
        except Exception as e:  # noqa: BLE001 — an exploding check is unverified
            self.last_error = f"active check raised: {e}"
            active = None
        if active is None:
            now = self._monotonic()
            if self._unverified_since is None:
                self._unverified_since = now
            elapsed = now - self._unverified_since
            if elapsed > self.max_unverified_s:
                # Bounded policy exhausted: go SILENT. The broker's lease
                # watchdog (30 s) latches and hard-stops the range. A control
                # plane that cannot verify its own DB for this long has lost
                # control — renewing would be an unverifiable health claim.
                self.last_error = (
                    f"control state unverified for {elapsed:.0f}s > "
                    f"{self.max_unverified_s:.0f}s — renewals withheld "
                    "(fail-closed; broker watchdog will stop the range)")
                return False
            # Inside the grace window: keep a LIVE range alive; renewal can
            # never resume a latched one (the broker refuses that).
            self.last_error = (f"control state unverified ({elapsed:.0f}s/"
                               f"{self.max_unverified_s:.0f}s): renewing under "
                               "bounded grace")
        else:
            self._unverified_since = None

        if active is False:
            # Range provably idle (DB says no lease holder): disarm the
            # broker's watchdog lease so an inactive control plane is not
            # mistaken for a dead one. A latched broker refuses nothing here
            # — disarming can never resume a stopped range.
            if not self._disarmed:
                try:
                    self.broker.disarm_lease()
                    self._disarmed = True
                    self.last_error = None
                except Exception as e:  # noqa: BLE001 — retry next tick
                    self.last_error = f"disarm failed: {e}"
            return False
        self._disarmed = False
        try:
            self.broker.renew_lease(self.holder)
            self.last_error = None
            return True
        except Exception as e:  # noqa: BLE001 — broker down: keep trying until
            self.last_error = str(e)  # its own watchdog takes over
            return False

    def start(self) -> None:
        if self._thread is not None:
            return

        def loop() -> None:
            while not self._stop.wait(self.interval_s):
                self.tick()
        self._thread = threading.Thread(target=loop, name="control-lease-heartbeat",
                                        daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=self.interval_s + 1)
            self._thread = None
