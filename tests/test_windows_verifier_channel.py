"""Windows verifier evidence: through the guest agent, never guessed.

Half the blue checks name Windows hosts (`ad-dns` flags, mssql, win11). Those
goldens carry no sshd, so before this lane every such check was `unknown`;
now the agent runs the command. The dispatch must be decided from the
deployment's own artifact and FAIL CLOSED: an untranslated command or a
missing channel is `unknown`, never the guest's state.
"""
from __future__ import annotations

import pytest

from srplatform import verification_service as V
from srplatform.verification_service import _NOT_OWNED, _resolve, \
    resource_platform, windows_argv


# ------------------------------------------------------------- translation ---
def test_cat_translates_to_the_windows_type_command():
    argv = windows_argv("cat C:/Users/Public/.sr-practice-ad.txt")
    assert argv[:3] == [V.WINDOWS_CMD, "/c", "type"]
    assert argv[3] == "C:/Users/Public/.sr-practice-ad.txt"


def test_an_untranslatable_command_is_None_never_a_guess():
    """`systemctl is-active nginx` means nothing in cmd.exe; running it and
    reading the error as the guest's state would score fiction."""
    assert windows_argv("systemctl is-active nginx") is None
    assert windows_argv("cat") is None
    assert windows_argv("cat a b") is None
    assert windows_argv("") is None


def test_the_platform_comes_from_the_cloned_artifact_not_the_hostname():
    assert resource_platform({"image_profile": "ws2022-dc"}) == "windows"
    assert resource_platform({"image_profile": "win11-wkst"}) == "windows"
    assert resource_platform({"image_profile": "ubuntu-desktop"}) == "linux"
    assert resource_platform({"image_profile": "opnsense"}) == "linux"
    assert resource_platform({}) == "linux"     # unknown profile: ssh path


# ------------------------------------------------------------- dispatch -----
def test_resolve_sends_a_windows_host_to_its_own_channel():
    seen = []

    def ssh(addr, command):
        seen.append(("ssh", addr, command))
        return 0, "ssh-out"

    def win(host, command):
        seen.append(("win", host, command))
        return 0, "agent-out"

    resolved = _resolve(ssh, {"ad-dns": "172.20.240.100",
                              "ecomm": "172.20.240.10"},
                        platforms={"ad-dns": "windows", "ecomm": "linux"},
                        windows=win)
    assert resolved("ad-dns", "cat C:/x.txt") == (0, "agent-out")
    assert resolved("ecomm", "cat /tmp/x") == (0, "ssh-out")
    assert seen == [("win", "ad-dns", "cat C:/x.txt"),
                    ("ssh", "172.20.240.10", "cat /tmp/x")]


def test_a_windows_host_without_a_channel_is_unknown_not_attempted():
    def ssh(addr, command):
        raise AssertionError("a Windows host must not be sent to ssh")

    resolved = _resolve(ssh, {"ad-dns": "172.20.240.100"},
                        platforms={"ad-dns": "windows"}, windows=None)
    rc, out = resolved("ad-dns", "cat C:/x.txt")
    assert rc == 126 and "unknown, not attempted" in out


def test_an_unowned_host_is_refused_before_any_channel():
    def boom(*a):
        raise AssertionError("no channel may be tried for an unowned host")

    resolved = _resolve(boom, {}, platforms={}, windows=boom)
    rc, out = resolved("ghost", "cat /x")
    assert rc == 254 and out == _NOT_OWNED


# ------------------------------------------------------------- the channel ---
class _FakeOut(dict):
    pass


def test_the_channel_runs_the_translated_command_on_the_owned_vmid(monkeypatch):
    from srplatform.db.models import Deployment

    calls = []

    def fake_guest_exec(node, vmid, argv, **kw):
        calls.append((node, vmid, list(argv), kw))
        return {"returncode": 0, "stdout": "SRUP{ad-dns}\n", "stderr": ""}

    dep = Deployment(session_id=None, status="ready", resources=[{
        "host": "ad-dns", "ip": "172.20.240.100", "state": "created",
        "vmid": 200, "node": "n1", "image_profile": "ws2022-dc",
        "generation_attempt": 1}])
    monkeypatch.setattr(V, "active_deployment", lambda db, sid: dep)
    V.set_guest_exec(fake_guest_exec)
    try:
        chan = V.windows_channel(None, "sess")
        rc, out = chan("ad-dns", "cat C:/Users/Public/.sr-practice-ad.txt")
    finally:
        V.set_guest_exec(None)
    assert rc == 0 and out.startswith("SRUP")
    node, vmid, argv, kw = calls[0]
    assert (node, vmid) == ("n1", 200)
    assert argv[:4] == [V.WINDOWS_CMD, "/c", "type",
                        "C:/Users/Public/.sr-practice-ad.txt"]
    # the generation is the deployment's INCLUDING the rebuild attempt
    assert kw["generation"].endswith(":a1")


def test_the_channel_reports_an_agent_failure_as_unknown(monkeypatch):
    """An agent that cannot run the command is a CHANNEL failure: reading it
    as the target's state would score fiction either way."""
    from srplatform.db.models import Deployment

    def broken(*a, **kw):
        from infra.broker.errors import BrokerUnavailable
        raise BrokerUnavailable("agent not running")

    dep = Deployment(session_id=None, status="ready", resources=[{
        "host": "mssql", "ip": "172.20.240.120", "state": "created",
        "vmid": 204, "node": "n1", "image_profile": "ws2022-dc"}])
    monkeypatch.setattr(V, "active_deployment", lambda db, sid: dep)
    V.set_guest_exec(broken)
    try:
        chan = V.windows_channel(None, "sess")
        rc, out = chan("mssql", "cat C:/x.txt")
    finally:
        V.set_guest_exec(None)
    assert rc == 125 and "agent channel unavailable" in out
