"""First-boot management-channel race (live-deploy find, 2026-10-14).

The readiness gate and telemetry enrollment SSH into freshly started clones;
for 10–30s after "running", ssh exits 255 ("session never established")
because sshd is still booting. The first live deploy failed enrollment
exactly there (provision_failed on both clones one second after boot).
_provision_with_boot_wait rides out ONLY that dialect: 255 means the
command never ran, so retrying the idempotent provisioning is safe and is
bounded; every other rc is a real answer and must fail fast and visibly.
"""
import pytest

from srplatform.scenario_engine import orchestrator


@pytest.fixture(autouse=True)
def _fast_poll(monkeypatch):
    monkeypatch.setattr(orchestrator, "_MANAGEMENT_READY_POLL_S", 0.01)


def _chan(script):
    calls = []

    def chan(ip, cmd):
        calls.append((ip, cmd))
        return script[min(len(calls) - 1, len(script) - 1)]
    chan.calls = calls
    return chan


def test_255_boot_race_is_retried_until_the_channel_answers():
    chan = _chan([(255, "connect refused"), (255, "connect refused"),
                  (0, "provisioned")])
    code, tail = orchestrator._provision_with_boot_wait(
        chan, "10.66.0.9", "provision", wait_s=5)
    assert (code, tail) == (0, "provisioned")
    assert len(chan.calls) == 3  # the SAME command retried


def test_other_rc_is_never_retried():
    for rc in (1, 127, 254):
        chan = _chan([(rc, "real answer")])
        code, tail = orchestrator._provision_with_boot_wait(
            chan, "10.66.0.9", "provision", wait_s=5)
        assert code == rc and tail == "real answer"
        assert len(chan.calls) == 1  # broken channels fail FAST


def test_persistent_255_gives_up_at_the_deadline():
    chan = _chan([(255, "still booting")])
    code, _ = orchestrator._provision_with_boot_wait(
        chan, "10.66.0.9", "provision", wait_s=0.1)
    assert code == 255
    assert len(chan.calls) > 1  # it did wait...
    assert len(chan.calls) < 50  # ...but the window is bounded


def test_zero_wait_disables_retry_entirely():
    chan = _chan([(255, "nope")])
    code, _ = orchestrator._provision_with_boot_wait(
        chan, "10.66.0.9", "provision", wait_s=0)
    assert code == 255 and len(chan.calls) == 1
