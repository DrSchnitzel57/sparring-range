"""Control-heartbeat lifecycle (live-deploy find, 2026-10-14).

renew_lease ARMS the broker's watchdog lease, and nothing used to DISARM it:
after every session ended, the armed-forever lease expired and the broker's
watchdog latched the range ~TTL later. The heartbeat must disarm when the
DB provably shows the range idle, keep the dead-man switch intact while a
range is live, and never let disarming resume a latched broker (the broker
enforces that itself; the heartbeat simply never calls release_latch).
"""
from srplatform.safety.lease import ControlHeartbeat


class FakeBroker:
    def __init__(self):
        self.renews = 0
        self.disarms = 0

    def renew_lease(self, holder):
        self.renews += 1
        return {"armed": True}

    def disarm_lease(self):
        self.disarms += 1


def test_idle_disarms_once_and_renews_resume_on_activity():
    broker = FakeBroker()
    active = {"yes": True}
    hb = ControlHeartbeat(broker, active_check=lambda: active["yes"])

    assert hb.tick() is True
    assert (broker.renews, broker.disarms) == (1, 0)

    active["yes"] = False
    assert hb.tick() is False
    assert (broker.renews, broker.disarms) == (1, 1)
    assert hb.tick() is False  # idle stays quiet, no per-tick spam
    assert broker.disarms == 1

    active["yes"] = True
    assert hb.tick() is True
    assert broker.renews == 2
    active["yes"] = False
    assert hb.tick() is False  # a NEW idle period disarms again
    assert broker.disarms == 2


def test_disarm_failure_is_reported_and_retried():
    class Flaky(FakeBroker):
        def __init__(self):
            super().__init__()
            self.fail_once = True

        def disarm_lease(self):
            if self.fail_once:
                self.fail_once = False
                raise RuntimeError("broker down")
            self.disarms += 1

    broker = Flaky()
    hb = ControlHeartbeat(broker, active_check=lambda: False)
    assert hb.tick() is False
    assert broker.disarms == 0 and "disarm failed" in (hb.last_error or "")
    assert hb.tick() is False
    assert broker.disarms == 1 and hb.last_error is None


def test_db_outage_keeps_renewing_and_never_disarms():
    broker = FakeBroker()

    def boom():
        raise RuntimeError("db down")

    hb = ControlHeartbeat(broker, active_check=boom)
    assert hb.tick() is True  # fail toward renewing: a live range must survive
    assert broker.renews == 1 and broker.disarms == 0


def test_persistent_db_outage_stops_renewing_after_bounded_window():
    """Plan 13 phase 2: a DB/control failure must NOT indefinitely renew a
    supposedly healthy lease. Within the grace window renewals continue (a
    live range survives a blip); past the window the heartbeat goes silent
    and the broker's own watchdog latches and stops the range."""
    broker = FakeBroker()
    clock = {"t": 1000.0}

    def boom():
        raise RuntimeError("db down")

    hb = ControlHeartbeat(broker, active_check=boom, max_unverified_s=60.0,
                          monotonic=lambda: clock["t"])
    assert hb.tick() is True            # t+0: inside the window
    clock["t"] += 30
    assert hb.tick() is True            # t+30: still bounded grace
    clock["t"] += 45
    assert hb.tick() is False           # t+75 > 60: withheld
    assert "withheld" in (hb.last_error or "")
    assert broker.renews == 2 and broker.disarms == 0  # silent, never disarms


def test_unverified_read_is_tri_state_and_recovers_reset_window():
    broker = FakeBroker()
    clock = {"t": 0.0}
    state = {"mode": "down"}

    def check():
        if state["mode"] == "down":
            return None            # explicit UNVERIFIED (not True, not False)
        return state["mode"] == "active"

    hb = ControlHeartbeat(broker, active_check=check, max_unverified_s=60.0,
                          monotonic=lambda: clock["t"])
    clock["t"] = 50
    assert hb.tick() is True            # grace renewal
    clock["t"] = 100                    # 50s of downtime survived, then DB back
    state["mode"] = "active"
    assert hb.tick() is True
    assert hb._unverified_since is None  # verified read resets the window
    clock["t"] = 150
    state["mode"] = "down"
    assert hb.tick() is True            # a FULL fresh window, not the old one
    clock["t"] = 205
    assert hb.tick() is True            # 55s into the NEW window
    clock["t"] = 215
    assert hb.tick() is False           # 65s > 60s: withheld again
    assert broker.disarms == 0


def test_provably_idle_disarms_even_after_outage_window():
    broker = FakeBroker()
    clock = {"t": 0.0}
    state = {"mode": "down"}

    def check():
        return None if state["mode"] == "down" else False

    hb = ControlHeartbeat(broker, active_check=check, max_unverified_s=10.0,
                          monotonic=lambda: clock["t"])
    assert hb.tick() is True            # first unverified tick: grace renewal
    clock["t"] = 999                    # far past the window, still unverified
    assert hb.tick() is False           # silent — withheld
    assert broker.disarms == 0          # unverified is NOT provably idle
    state["mode"] = "idle-confirmed"    # DB answers: no lease holder
    assert hb.tick() is False
    assert broker.disarms == 1          # confirmed idle disarms immediately
