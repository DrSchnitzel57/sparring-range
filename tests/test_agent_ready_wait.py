"""Guest-agent first-boot readiness (live-deploy finds, 2026-10-14).

Right after a clone starts, real PVE answers guest-agent calls with 500
"QEMU guest agent is not running" until the in-guest agent connects its
channel — the first live deploy failed exactly there. There is NO
separate status endpoint (second live find: GET .../agent/status answers
501 "Not Implemented"), so readiness is probed by retrying the real
allowlisted host-key read itself. Only that exact signature retries;
absence and any other error raise immediately, and a timeout stays
uncertain — never a silent success.
"""
import pytest

from infra.broker.testing import make_fake_broker
from infra.proxmox_client import (PveNotFound, PveUnavailable, ProxmoxClient,
                                  ProxmoxError)

HOSTKEY = ProxmoxClient.GUEST_HOST_KEY_PATH


def _client_with_vm():
    _, _, http = make_fake_broker()
    http.vms[9100] = {"name": "sr-x", "status": "running"}
    return ProxmoxClient(api=http), http


def test_read_when_ready_returns_key_when_agent_answers():
    c, http = _client_with_vm()
    key = c.read_guest_file_when_ready("r740", 9100, HOSTKEY, timeout_s=1)
    assert key.startswith("ssh-ed25519 ")


def test_read_when_ready_retries_only_not_running():
    c, http = _client_with_vm()
    http.agent_not_ready_polls = 2  # two live-style 500s, then the key
    key = c.read_guest_file_when_ready("r740", 9100, HOSTKEY, timeout_s=5,
                                       poll_s=0.01)
    assert key.startswith("ssh-ed25519 ")
    assert sum(1 for _, p, _ in http.requests
               if "/agent/file-read" in p) == 3


def test_read_when_ready_timeout_stays_uncertain():
    c, http = _client_with_vm()
    http.agent_not_ready_polls = 10 ** 6
    with pytest.raises(PveUnavailable) as e:
        c.read_guest_file_when_ready("r740", 9100, HOSTKEY, timeout_s=0.05,
                                     poll_s=0.01)
    assert "not ready within" in str(e.value)


def test_read_when_ready_absent_vm_raises_immediately():
    c, http = _client_with_vm()  # 9999 was never created
    with pytest.raises(PveNotFound):
        c.read_guest_file_when_ready("r740", 9999, HOSTKEY, timeout_s=5,
                                     poll_s=0.01)


def test_read_when_ready_other_error_raises_immediately():
    c, http = _client_with_vm()
    http.fail_requests = {"/agent/file-read": 403}  # e.g. missing privilege
    with pytest.raises(ProxmoxError) as e:
        c.read_guest_file_when_ready("r740", 9100, HOSTKEY, timeout_s=5,
                                     poll_s=0.01)
    assert "403" in str(e.value)
    # NOT retried: exactly one probe, then straight out.
    assert sum(1 for _, p, _ in http.requests
               if "/agent/file-read" in p) == 1


def test_read_when_ready_retries_empty_key_until_cloud_init_regenerates():
    # Live find 2026-10-14: the agent answers BEFORE cloud-init's ssh
    # module has regenerated the template-scrubbed host key — empty
    # content. That is "not materialized yet", retried in the same window.
    c, http = _client_with_vm()
    http.empty_key_polls = 2
    key = c.read_guest_file_when_ready("r740", 9100, HOSTKEY, timeout_s=5,
                                       poll_s=0.01)
    assert key.startswith("ssh-ed25519 ")
    assert sum(1 for _, p, _ in http.requests
               if "/agent/file-read" in p) == 3


def test_read_guest_file_accepts_and_strips_hostname_comment():
    # Live find 2026-10-14: cloud-init writes `ssh-ed25519 <b64>
    # root@hostname` — valid, but the pin/known_hosts format carries no
    # comment, so the comment must be stripped from the returned key.
    c, http = _client_with_vm()
    http.vms[9100]["guest_host_key"] = (
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF5/Yr9SC+IM2Q04FRm7jVdxbaK0"
        "9b+3DPZ+wEARcfzI root@sr-mojang-web-01-attacker-9233821e")
    key = c.read_guest_file("r740", 9100, HOSTKEY)
    assert key.startswith("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIF5")
    assert len(key.split()) == 2 and "root@" not in key


def test_read_guest_file_rejects_four_field_garbage():
    c, http = _client_with_vm()
    http.vms[9100]["guest_host_key"] = "ssh-ed25519 " + "A" * 40 + " a b"
    with pytest.raises(PveUnavailable):
        c.read_guest_file("r740", 9100, HOSTKEY)


def test_host_key_read_survives_first_boot_window():
    """The broker's read_host_key rides out the live 500 dialect and pins
    the key; the fake never saw a separate status endpoint (501 lesson)."""
    client, service, http = make_fake_broker(templates=(9005,))
    service.agent_ready_poll_s = 0.01
    vmid = service.next_vmid("r740", 200, session_id="s1")
    service.clone_and_wait("r740", 9005, vmid, "sr-attacker-s1", full=False,
                           session_id="s1", generation="g1")
    http.agent_not_ready_polls = 2
    key = client.read_host_key("r740", vmid, session_id="s1", generation="g1")
    assert key.startswith("ssh-ed25519 ")
    paths = [p for _, p, _ in http.requests]
    assert not any("/agent/status" in p for p in paths)  # endpoint does not exist
    assert sum(1 for p in paths if "/agent/file-read" in p) == 3
