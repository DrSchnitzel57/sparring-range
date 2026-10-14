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
