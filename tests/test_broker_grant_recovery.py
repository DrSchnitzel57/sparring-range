"""Live find 2026-10-15: PVE deletes per-VMID ACL entries when it destroys
the VM, so each teardown silently eats the window grants its clones used
and the next scan dies on a 403 that used to surface as a raw 500 chain.
The scan must fail with the re-apply named, not a mystery."""
from __future__ import annotations

import pytest

from infra.broker.errors import BrokerUnavailable
from infra.broker.testing import make_fake_broker, make_test_policy
from infra.proxmox_client import PveHttpError, PveUnavailable, ProxmoxClient

NODE = "r740"


def test_next_vmid_denial_names_the_acl_reapply(tmp_path):
    policy = make_test_policy()
    client, service, http = make_fake_broker(
        policy=policy, ledger_path=tmp_path / "l.sqlite3")

    def denied(node, vmid):
        raise PveUnavailable(
            "PVE status 403: 403 Forbidden: Permission check failed "
            f"(/vms/{vmid}, VM.Audit)")

    service.pve.lookup_vm = denied
    with pytest.raises(BrokerUnavailable, match=r"pve_broker_acl\.sh --apply"):
        client.next_vmid(NODE, 210, session_id="s")


def _reserved_client(tmp_path, reads):
    from infra.broker.testing import make_fake_broker, make_test_policy
    policy = make_test_policy()
    client, service, http = make_fake_broker(
        policy=policy, ledger_path=tmp_path / "l4.sqlite3")
    service.agent_ready_poll_s = 0
    it = iter(reads)

    def scripted(node, vmid, path, timeout_s=None, poll_s=None):
        try:
            return next(it)
        except StopIteration:
            return reads[-1]

    service.pve.read_guest_file_when_ready = scripted
    vmid = client.next_vmid("r740", 210, session_id="s")
    http.vms.setdefault(vmid, {"status": "stopped", "name": None})
    return client, service, vmid


def test_pin_waits_out_first_boot_regen(tmp_path):
    client, service, vmid = _reserved_client(
        tmp_path, ["ssh-ed25519 AAAA", "ssh-ed25519 BBBB", "ssh-ed25519 BBBB"])
    key = service.read_host_key("r740", vmid, session_id="s")
    assert key == "ssh-ed25519 BBBB"


def test_pin_skips_empty_reads(tmp_path):
    client, service, vmid = _reserved_client(
        tmp_path, ["", "ssh-ed25519 CCCC", "ssh-ed25519 CCCC"])
    assert service.read_host_key("r740", vmid, session_id="s") == "ssh-ed25519 CCCC"


def test_ever_rotating_key_is_refused_loudly(tmp_path):
    from infra.broker.errors import BrokerUnavailable
    client, service, vmid = _reserved_client(
        tmp_path, ["ssh-ed25519 A", "ssh-ed25519 B", "ssh-ed25519 C",
                   "ssh-ed25519 D", "ssh-ed25519 E"])
    import pytest
    with pytest.raises(BrokerUnavailable, match="never stabilized"):
        service.read_host_key("r740", vmid, session_id="s")


def test_pin_waits_for_boot_completion(tmp_path):
    """Keys readable before first boot completes must not pin: the marker
    gate precedes even the stability reads."""
    from infra.broker.errors import BrokerUnavailable
    from infra.broker.testing import make_fake_broker, make_test_policy
    import pytest
    policy = make_test_policy()
    client, service, http = make_fake_broker(
        policy=policy, ledger_path=tmp_path / "l5.sqlite3")
    service.agent_ready_poll_s = 0
    service.agent_ready_timeout_s = 0
    vmid = client.next_vmid("r740", 210, session_id="s")
    http.vms.setdefault(vmid, {"status": "stopped", "name": None})
    http.vms[vmid]["boot_completed"] = False
    with pytest.raises(BrokerUnavailable, match="never finished"):
        service.read_host_key("r740", vmid, session_id="s")
    http.vms[vmid]["boot_completed"] = True
    key = service.read_host_key("r740", vmid, session_id="s")
    assert key.startswith("ssh-ed25519 ")


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
    monkeypatch.setattr("infra.proxmox_client.time", clock)
    client, service, http = make_fake_broker(
        ledger_path=tmp_path / ledger_name)
    service.agent_ready_timeout_s = 120.0
    service.agent_ready_poll_s = 2.0
    vmid = client.next_vmid(NODE, 220, session_id="s")
    http.vms.setdefault(vmid, {"status": "stopped", "name": None})
    http.vms[vmid]["boot_completed"] = True
    return clock, service, http, vmid


def _script_key_polls(http, not_ready):
    """Host-key reads answer 'not ready' per the predicate, then succeed
    with the fake's deterministic per-VM key (real polling code above the
    fake HTTP boundary; only the response schedule is scripted). The file
    parameter arrives URL-encoded, so decode before matching."""
    import urllib.parse
    state = {"n": 0}
    orig_get = http.get

    def is_key_read(path):
        query = urllib.parse.urlparse(path).query
        return urllib.parse.parse_qs(query).get("file", [""])[0] == \
            ProxmoxClient.GUEST_HOST_KEY_PATH

    def scripted_get(path, **kw):
        if "/agent/file-read" in path and is_key_read(path):
            n = state["n"]
            state["n"] = n + 1
            if not_ready(n):
                raise PveHttpError(500, "QEMU guest agent is not running")
        return orig_get(path, **kw)

    http.get = scripted_get


def test_rereads_share_one_window_and_never_outlast_the_client(
        tmp_path, monkeypatch):
    """Review blocker 2026-10-16: each stability re-read used to get a FRESH
    120 s window. The reviewer's virtual-clock sequence — 118 s to boot
    completion, 110 s first read, 2 s pause, 110 s confirmation — completed
    at ~340 s server-side while the 300 s client bound had already failed
    the deployment (broker kept pinning). With one SHARED window the same
    sequence must fail BOUNDED, with the obligation retained."""
    clock, service, http, vmid = _virtual_broker(tmp_path, monkeypatch,
                                                 "l6.sqlite3")
    http.agent_not_ready_polls = 59              # marker completes at t=118
    _script_key_polls(http, not_ready=lambda n: n % 56 != 55)
    # n=0..54 not-ready (110 s) then the key at t=228; the confirmation
    # would need 110 s more — past the shared window (deadline t=238).

    with pytest.raises(BrokerUnavailable,
                       match="read uncertain|never stabilized"):
        service.read_host_key(NODE, vmid, session_id="s")
    # 120 s boot-marker window + 120 s shared stability window; a fresh
    # per-read window leaking back in would land near the reviewer's 340 s.
    assert clock.t <= 241.0, f"pin sequence ran {clock.t:.0f}s past its bound"
    kinds = {o["kind"] for o in service.ledger.open_obligations()}
    assert "host-key-read-uncertain" in kinds


def test_slow_but_in_window_boot_still_pins(tmp_path, monkeypatch):
    """The shared window must not tighten a legitimate slow first boot away:
    a 118 s boot marker plus a 10 s first read and an immediate stable
    confirmation still pins within the bound."""
    clock, service, http, vmid = _virtual_broker(tmp_path, monkeypatch,
                                                 "l7.sqlite3")
    http.agent_not_ready_polls = 59              # marker completes at t=118
    _script_key_polls(http, not_ready=lambda n: n < 5)   # 10 s first read

    key = service.read_host_key(NODE, vmid, session_id="s")
    assert key.startswith("ssh-ed25519 ")
    assert clock.t <= 241.0
