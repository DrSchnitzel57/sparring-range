"""Host-key pinning under denial and slow first boots.

Live find 2026-10-15 (kept from the direct-PVE era): a teardown that deletes
the guest silently eats the grants/keys its clones used, and the next scan
or pin must fail as a NAMED uncertain — never a mystery 500 chain or a
silent skip. The pin-sequence deadline tests (review finds 2026-10-16)
verify on a virtual clock that the stability re-reads share ONE
`agent_ready_timeout_s` window and that no probe starts once it is spent,
so the documented server bound really covers the operation.
"""
from __future__ import annotations

import pytest

from infra.appliance.errors import BackendUnavailable
from infra.broker.errors import BrokerUnavailable
from infra.broker.testing import make_fake_broker, make_test_policy

NODE = "r740"


def test_next_vmid_denied_candidate_read_is_uncertain_not_free(tmp_path):
    policy = make_test_policy()
    client, service, backend = make_fake_broker(
        policy=policy, ledger_path=tmp_path / "l.sqlite3")

    def denied(node, vmid):
        raise BackendUnavailable(
            f"permission check failed for domain {vmid} — grant was lost "
            "when the last clone was destroyed")

    service.backend.lookup_vm = denied
    with pytest.raises(BrokerUnavailable, match="cannot read candidate 210"):
        client.next_vmid(NODE, 210, session_id="s")
    # refusing to allocate OVER a machine it could not rule out: no claim
    assert service.ledger.get_claim(210) is None


def _reserved_client(tmp_path, reads):
    policy = make_test_policy()
    client, service, backend = make_fake_broker(
        policy=policy, ledger_path=tmp_path / "l4.sqlite3")
    service.agent_ready_poll_s = 0
    it = iter(reads)

    def scripted(node, vmid, path, timeout_s=None, poll_s=None):
        try:
            return next(it)
        except StopIteration:
            return reads[-1]

    backend.read_guest_file_when_ready = scripted
    vmid = client.next_vmid(NODE, 210, session_id="s")
    name = f"sr-pin-{vmid}"
    service.ledger.upsert_claim(vmid, node=NODE, state="reserved", name=name,
                                session_id="s")
    backend.vms[vmid] = {"status": "stopped", "name": name}
    return client, service, vmid


def test_pin_waits_out_first_boot_regen(tmp_path):
    client, service, vmid = _reserved_client(
        tmp_path, ["ssh-ed25519 AAAA", "ssh-ed25519 BBBB", "ssh-ed25519 BBBB"])
    key = service.read_host_key(NODE, vmid, session_id="s")
    assert key == "ssh-ed25519 BBBB"


def test_pin_skips_empty_reads(tmp_path):
    client, service, vmid = _reserved_client(
        tmp_path, ["", "ssh-ed25519 CCCC", "ssh-ed25519 CCCC"])
    assert service.read_host_key(NODE, vmid, session_id="s") == "ssh-ed25519 CCCC"


def test_ever_rotating_key_is_refused_loudly(tmp_path):
    client, service, vmid = _reserved_client(
        tmp_path, ["ssh-ed25519 A", "ssh-ed25519 B", "ssh-ed25519 C",
                   "ssh-ed25519 D", "ssh-ed25519 E"])
    with pytest.raises(BrokerUnavailable, match="never stabilized"):
        service.read_host_key(NODE, vmid, session_id="s")
    kinds = {o["kind"] for o in service.ledger.open_obligations()}
    assert "host-key-unstable" in kinds


# --------------------------------------------------------------------------- #
# pin-sequence deadline (review find 2026-10-16): the re-read phase shares
# ONE agent_ready_timeout_s window, so the documented server bound
# (boot-marker wait + one stability window) really covers the op.
# --------------------------------------------------------------------------- #

class _VClock:
    """Virtual monotonic clock: sleeps advance it and nothing waits in real
    time, so multi-minute server sequences are exercised deterministically."""

    def __init__(self):
        self.t = 0.0

    def monotonic(self):
        return self.t

    def sleep(self, s):
        self.t += max(0.0, s)


def _virtual_broker(tmp_path, monkeypatch, ledger_name):
    clock = _VClock()
    monkeypatch.setattr("infra.broker.service.time", clock)
    monkeypatch.setattr("infra.broker.testing.time", clock)
    client, service, backend = make_fake_broker(
        ledger_path=tmp_path / ledger_name)
    service.agent_ready_timeout_s = 120.0
    service.agent_ready_poll_s = 2.0
    vmid = client.next_vmid(NODE, 220, session_id="s")
    name = f"sr-pin-{vmid}"
    service.ledger.upsert_claim(vmid, node=NODE, state="reserved", name=name,
                                session_id="s")
    backend.vms[vmid] = {"status": "stopped", "name": name,
                         "guest_host_key": "ssh-ed25519 " + "K" * 40}
    return clock, service, backend, vmid


def _script_marker(backend, clock):
    """Boot-marker reads follow the entry's boot_completed flag, polling on
    the virtual clock within the caller's window (production shape)."""

    def scripted(node, vmid, timeout_s=120.0, poll_s=2.0):
        deadline = clock.t + max(0.0, float(timeout_s))
        while True:
            if backend.vms.get(int(vmid), {}).get("boot_completed", True):
                return True
            if clock.t >= deadline:
                return False
            clock.sleep(max(0.0, min(float(poll_s), deadline - clock.t)))
    backend.read_boot_marker = scripted


def _marker_completes_at(backend, clock, t_ready):
    """Complete the boot marker only once the virtual clock reaches
    `t_ready` (slow first boot)."""
    def scripted(node, vmid, timeout_s=120.0, poll_s=2.0):
        deadline = clock.t + max(0.0, float(timeout_s))
        while True:
            if clock.t >= t_ready:
                return True
            if clock.t >= deadline:
                return False
            clock.sleep(max(0.0, min(float(poll_s), deadline - clock.t)))
    backend.read_boot_marker = scripted


def _script_key_polls(backend, clock, not_ready, latency_s=0.0, key_seq=None):
    """Host-key reads answer 'silent' per the predicate, then succeed with
    the backend's deterministic per-VM key (or a rotating `key_seq`). Each
    scripted read behaves like the production wrapper: it polls within the
    window it was given (advancing the virtual clock by `latency_s` per
    request) and returns None only after that window is spent. Returns the
    counter state so tests can assert how many requests were issued."""
    state = {"n": 0, "ok": 0}
    keys = list(key_seq or [])

    def scripted(node, vmid, path, timeout_s=120.0, poll_s=2.0):
        deadline = clock.t + max(0.0, float(timeout_s or 0.0))
        while True:
            n = state["n"]
            state["n"] = n + 1
            if latency_s:
                clock.t += latency_s
            if not_ready(n):
                if clock.t >= deadline:
                    return None  # silent window exhausted, not uncertain
                clock.sleep(max(0.0, min(float(poll_s), deadline - clock.t)))
                continue
            if keys:
                key = keys[min(state["ok"], len(keys) - 1)]
                state["ok"] += 1
                return key
            return backend.vms[int(vmid)].get("guest_host_key")

    backend.read_guest_file_when_ready = scripted
    return state


def test_rereads_share_one_window_and_never_outlast_the_client(
        tmp_path, monkeypatch):
    """Review blocker 2026-10-16: each stability re-read used to get a FRESH
    120 s window. The reviewer's virtual-clock sequence — 118 s to boot
    completion, 110 s first read, 2 s pause, 110 s confirmation — completed
    at ~340 s server-side while the 300 s client bound had already failed
    the deployment (broker kept pinning). With one SHARED window the same
    sequence must fail BOUNDED, with the obligation retained."""
    clock, service, backend, vmid = _virtual_broker(tmp_path, monkeypatch,
                                                    "l6.sqlite3")
    _marker_completes_at(backend, clock, 118.0)
    _script_key_polls(backend, clock, not_ready=lambda n: n % 56 != 55)
    # n=0..54 silent (110 s) then the key at t=228; the confirmation
    # only gets the 8 s left of the shared window (deadline t=238).

    with pytest.raises(BrokerUnavailable, match="never stabilized"):
        service.read_host_key(NODE, vmid, session_id="s")
    # 120 s boot-marker window + 120 s shared stability window; a fresh
    # per-read window leaking back in would land near the reviewer's 340 s.
    assert clock.t <= 241.0, f"pin sequence ran {clock.t:.0f}s past its bound"
    kinds = {o["kind"] for o in service.ledger.open_obligations()}
    assert "host-key-unstable" in kinds


def test_slow_but_in_window_boot_still_pins(tmp_path, monkeypatch):
    """The shared window must not tighten a legitimate slow first boot away:
    a 118 s boot marker plus a 10 s first read and an immediate stable
    confirmation still pins within the bound."""
    clock, service, backend, vmid = _virtual_broker(tmp_path, monkeypatch,
                                                    "l7.sqlite3")
    _marker_completes_at(backend, clock, 118.0)
    _script_key_polls(backend, clock, not_ready=lambda n: n < 5)  # 10 s first

    key = service.read_host_key(NODE, vmid, session_id="s")
    assert key.startswith("ssh-ed25519 ")
    assert clock.t <= 241.0


def test_request_latency_never_outlasts_the_client_bound(
        tmp_path, monkeypatch):
    """Review find 2026-10-16 round 2: `timeout_s=0` bounds polling SLEEPS,
    not the request itself — each exhausted-window probe still costs up to
    the adapter request timeout, and a success response bypasses the
    deadline check. The reviewer's virtual clock (29 s requests): boot
    marker at 118 s, then successful key reads at 240+ s stabilised
    server-side while the 300 s client bound had already failed. The loop
    must issue NO probe once the shared window is spent; a bounded failure
    with the obligation retained is the fix."""
    clock, service, backend, vmid = _virtual_broker(tmp_path, monkeypatch,
                                                    "l8.sqlite3")
    _marker_completes_at(backend, clock, 118.0)
    keys = [f"ssh-ed25519 {c * 40}" for c in "ABCC"]
    state = _script_key_polls(backend, clock, not_ready=lambda n: n < 3,
                              latency_s=29.0, key_seq=keys)
    # Shared deadline is t=238: three silent requests (n=0..2, 29 s each,
    # 2 s poll pauses) end at t=209, 211 starts the successful read; it
    # succeeds at t=240 — 2 s past the window, inside the one-in-flight-
    # request allowance. The old code kept probing; now it must stop.

    with pytest.raises(BrokerUnavailable, match="never stabilized"):
        service.read_host_key(NODE, vmid, session_id="s")
    assert state["n"] == 4, \
        f"post-exhaustion probes issued: {state['n']} key requests"
    # (120 s window + one request) per phase = 298 s worst case.
    assert clock.t <= 298.0, f"pin sequence ran {clock.t:.0f}s past its bound"
    kinds = {o["kind"] for o in service.ledger.open_obligations()}
    assert "host-key-unstable" in kinds


def test_request_latency_inside_the_window_still_pins(tmp_path, monkeypatch):
    """29 s requests are slow but legitimate: two equal reads inside the
    shared window still pin, and the confirmation request that starts just
    before the deadline may complete after it (one in-flight request per
    window is accounted for in the documented bound)."""
    clock, service, backend, vmid = _virtual_broker(tmp_path, monkeypatch,
                                                    "l9.sqlite3")
    _marker_completes_at(backend, clock, 118.0)
    state = _script_key_polls(backend, clock, not_ready=lambda n: n < 2,
                              latency_s=29.0)

    key = service.read_host_key(NODE, vmid, session_id="s")
    assert key.startswith("ssh-ed25519 ")
    assert state["n"] == 4
    assert clock.t <= 298.0


def test_pin_waits_for_boot_completion(tmp_path, monkeypatch):
    """Keys readable before first boot completes must not pin: the marker
    gate precedes even the stability reads. (Virtual clock with a real
    window: since the review find 2026-10-16 round 2 an exhausted — or
    zero-sized — window issues NO probe, so a zero-window fixture could
    never read twice to confirm.)"""
    clock, service, backend, vmid = _virtual_broker(tmp_path, monkeypatch,
                                                    "l5.sqlite3")
    _script_marker(backend, clock)
    backend.vms[vmid]["boot_completed"] = False
    with pytest.raises(BrokerUnavailable, match="never finished"):
        service.read_host_key(NODE, vmid, session_id="s")
    backend.vms[vmid]["boot_completed"] = True
    key = service.read_host_key(NODE, vmid, session_id="s")
    assert key.startswith("ssh-ed25519 ")
