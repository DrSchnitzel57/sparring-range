"""Control-plane lease heartbeat (milestone 02).

While the DB-backed control plane holds the range lease (a session owns the
range), this thread renews the broker's control lease every 5 seconds. If
the control plane dies, renewals stop; after 30 seconds the BROKER itself
latches and hard-stops every owned VM — cessation does not depend on the
dead component noticing its own death. Renewal can never resume a stopped
range: the broker refuses renew_lease while latched.
"""
from __future__ import annotations

import threading
import time


def control_is_active() -> bool:
    """DB-backed truth: does some session currently hold the range lease?"""
    try:
        from srplatform.db.session import db
        from srplatform.scenario_engine.orchestrator import current_lease
        with db() as s:
            return current_lease(s) is not None
    except Exception:
        # A DB outage does NOT stop renewals: the range may still be live
        # and the broker's expiry is the safety net either way. Renewing on
        # transient DB errors can only keep a LIVE range running; it can
        # never resume a latched one (the broker refuses that).
        return True


class ControlHeartbeat:
    def __init__(self, broker, *, interval_s: float = 5.0,
                 active_check=control_is_active, holder: str = "api-control"):
        self.broker = broker
        self.interval_s = interval_s
        self.active_check = active_check
        self.holder = holder
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.last_error: str | None = None

    def tick(self) -> bool:
        """One renewal cycle. Returns True when a renewal was sent."""
        try:
            active = self.active_check()
        except Exception as e:  # noqa: BLE001 — fail toward renewing (see above)
            self.last_error = f"active check failed: {e}"
            active = True
        if not active:
            return False
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
