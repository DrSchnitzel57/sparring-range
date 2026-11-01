"""Agent-read wait windows: silent guest vs hard failure (live 2026-10-19).

First live boot: the guest agent answers ~30 s late, and the SSH host key
materializes only once cloud-init finishes. The contract under test (the
broker-side read loop, exercised through the fake's scripted agent hook):

  * a SILENT agent (no content yet, file not materialized) keeps the read
    polling until its bounded window expires — never a premature "absent";
  * a HARD failure (guest agent answers an error) raises UNCERTAIN
    immediately — never swallowed into an empty read or a false absence;
  * an absent guest raises, it never silently reads nothing;
  * only the fixed host-key path is readable at all.

A virtual clock drives the waits, so the tests are instant.
"""
from __future__ import annotations

import pytest

from infra.appliance.errors import BackendUnavailable
from infra.broker.testing import FakeBackend

NODE = "r740"
VM = 210
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakefakefakefakefakefakefakefake"


class Clock:
    def __init__(self):
        self.t = 0.0
        self.slept = []

    def monotonic(self):
        return self.t

    def sleep(self, s):
        self.t += max(0.0, s)
        self.slept.append(s)


@pytest.fixture()
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr("infra.broker.testing.time", c)
    return c


def _backend(**overrides):
    be = FakeBackend()
    be.vms[9001] = {"name": "tpl-web", "template": 9001, "status": "stopped"}
    be.vms[VM] = {"name": "sr-run-x", "template": None, "status": "running",
                  "guest_host_key": KEY, "boot_completed": True, **overrides}
    return be


def test_marker_present_reads_true_without_wait(clock):
    be = _backend()
    assert be.read_boot_marker(NODE, VM, timeout_s=600) is True
    assert clock.slept == []  # already there: never waits


def test_missing_marker_waits_out_its_whole_window(clock):
    be = _backend(boot_completed=False)
    assert be.read_boot_marker(NODE, VM, timeout_s=60, poll_s=2.0) is False
    # gave up only after the FULL window, polling (bounded), never before
    assert sum(clock.slept) >= 59.0


def test_silent_agent_waits_until_ready(clock):
    be = _backend()
    be.agent_not_ready_polls = 3  # first three reads answer "nothing yet"
    assert be.read_boot_marker(NODE, VM, timeout_s=600, poll_s=2.0) is True
    assert len(clock.slept) == 3


def test_key_read_waits_out_silence_then_reads(clock):
    be = _backend()
    be.agent_not_ready_polls = 2
    assert be.read_guest_file_when_ready(
        NODE, VM, be.GUEST_HOST_KEY_PATH, timeout_s=600, poll_s=2.0) == KEY
    assert len(clock.slept) == 2


def test_empty_key_polls_stay_silent_not_uncertain(clock):
    be = _backend()
    be.empty_key_polls = 2
    assert be.read_guest_file_when_ready(
        NODE, VM, be.GUEST_HOST_KEY_PATH, timeout_s=600, poll_s=2.0) == KEY
    assert len(clock.slept) == 2


def test_key_window_exhaustion_returns_none_only_after_the_window(clock):
    be = _backend()
    be.agent_not_ready_polls = 10_000  # agent never answers
    got = be.read_guest_file_when_ready(
        NODE, VM, be.GUEST_HOST_KEY_PATH, timeout_s=60, poll_s=2.0)
    assert got is None
    assert sum(clock.slept) >= 59.0


def test_absent_guest_raises_never_reads_nothing(clock):
    be = _backend()
    with pytest.raises(BackendUnavailable, match="VMID 9999"):
        be.read_guest_file_when_ready(NODE, 9999, be.GUEST_HOST_KEY_PATH,
                                      timeout_s=60, poll_s=2.0)
    with pytest.raises(BackendUnavailable, match="VMID 9999"):
        be.read_boot_marker(NODE, 9999, timeout_s=60, poll_s=2.0)
    assert clock.slept == []  # absence raised at once: never waited on


def test_hard_agent_failure_propagates_as_uncertain(clock):
    be = _backend()

    def broken(node, vmid, path):
        raise BackendUnavailable("QEMU guest agent said no")
    be.agent_file_read = broken
    with pytest.raises(BackendUnavailable, match="said no"):
        be.read_guest_file_when_ready(NODE, VM, be.GUEST_HOST_KEY_PATH,
                                      timeout_s=600, poll_s=2.0)
    with pytest.raises(BackendUnavailable, match="said no"):
        be.read_boot_marker(NODE, VM, timeout_s=600, poll_s=2.0)
    assert clock.slept == []  # uncertainty is immediate, never polled away


def test_only_the_fixed_host_key_path_is_readable(clock):
    be = _backend()
    with pytest.raises(BackendUnavailable, match="fixed host-key path"):
        be.read_guest_file_when_ready(NODE, VM, "etc/passwd", timeout_s=1)
