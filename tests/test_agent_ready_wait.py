"""Guest-agent readiness wait (live-deploy find, 2026-10-14).

Right after a clone starts, real PVE answers every guest-agent call with
500 "QEMU guest agent is not running" until the agent daemon inside the
guest connects its channel — the first live deploy failed exactly there
("host-key read uncertain ... guest agent is not running"). The broker
now waits, bounded, before the single honest host-key read; only that
exact signature retries, and a timeout stays uncertain (never success).
"""
import pytest

from infra.broker.testing import make_fake_broker
from infra.proxmox_client import PveNotFound, PveUnavailable, ProxmoxClient


def _setup(**kw):
    client, service, http = make_fake_broker(**kw)
    return client, service, http


def test_wait_agent_ready_returns_when_agent_answers():
    _, _, http = _setup()
    http.vms[9100] = {"name": "sr-x", "status": "running"}
    ProxmoxClient(api=http).wait_agent_ready("r740", 9100, timeout_s=1)
    assert any("/agent/status" in p for _, p, _ in http.requests)


def test_wait_agent_ready_retries_only_not_running():
    _, _, http = _setup()
    http.vms[9100] = {"name": "sr-x", "status": "running"}
    http.agent_not_ready_polls = 2  # two live-style 500s, then ready
    ProxmoxClient(api=http).wait_agent_ready("r740", 9100, timeout_s=5,
                                             poll_s=0.01)
    probes = [p for _, p, _ in http.requests if "/agent/status" in p]
    assert len(probes) == 3


def test_wait_agent_ready_timeout_stays_uncertain():
    _, _, http = _setup()
    http.vms[9100] = {"name": "sr-x", "status": "running"}
    http.agent_not_ready_polls = 10 ** 6
    with pytest.raises(PveUnavailable) as e:
        ProxmoxClient(api=http).wait_agent_ready("r740", 9100, timeout_s=0.05,
                                                 poll_s=0.01)
    assert "not ready within" in str(e.value)


def test_wait_agent_ready_absent_vm_raises_immediately():
    _, _, http = _setup()  # 9999 was never created
    with pytest.raises(PveNotFound):
        ProxmoxClient(api=http).wait_agent_ready("r740", 9999, timeout_s=5,
                                                 poll_s=0.01)


def test_wait_agent_ready_other_error_raises_immediately():
    _, _, http = _setup()
    http.vms[9100] = {"name": "sr-x", "status": "running"}
    http.fail_requests = {"/agent/status": 403}  # e.g. missing privilege
    from infra.proxmox_client import ProxmoxError
    with pytest.raises(ProxmoxError) as e:
        ProxmoxClient(api=http).wait_agent_ready("r740", 9100, timeout_s=5,
                                                 poll_s=0.01)
    assert "403" in str(e.value)
    # NOT retried: exactly one probe, then straight out.
    assert sum(1 for _, p, _ in http.requests if "/agent/status" in p) == 1


def test_host_key_read_waits_for_agent_before_reading():
    """The broker's read_host_key probes readiness (retrying the live 500)
    and only then performs its single allowlisted file-read."""
    client, service, http = _setup(templates=(9005,))
    service.agent_ready_poll_s = 0.01
    vmid = service.next_vmid("r740", 200, session_id="s1")
    service.clone_and_wait("r740", 9005, vmid, "sr-attacker-s1", full=False,
                           session_id="s1", generation="g1")
    http.agent_not_ready_polls = 2
    key = client.read_host_key("r740", vmid, session_id="s1", generation="g1")
    assert key.startswith("ssh-ed25519 ")
    paths = [p for _, p, _ in http.requests]
    probes = [i for i, p in enumerate(paths) if "/agent/status" in p]
    reads = [i for i, p in enumerate(paths) if "/agent/file-read" in p]
    assert len(probes) == 3 and len(reads) == 1
    assert max(probes) < reads[0]  # readiness confirmed BEFORE the read
