"""Plan 22 review (item 1): the runner admission check must be REAL protocol
evidence, not configured strings.

Every test here drives the actual ``SshRunner`` transport — real OpenSSH
client process, real asyncssh SSH server, real host-key pinning, real
public-key authentication, real runner-supervisor control-channel
semantics — through the very probe the Supervisor's ``runner`` admission
check runs. Positive: reachable + pinned + identity accepted + supervisor
answers. Negatives: closed port, foreign host pin, wrong identity, EMPTY
trust file, missing key file, and a runner whose containment (cessation)
authority is missing — each must refuse, with an honest reason, and none
may look like "inapplicable".
"""
from __future__ import annotations

import asyncio
import pathlib
import subprocess

import asyncssh
import pytest

import srplatform.safety as safety_mod
from srplatform.settings import Settings

pytestmark = pytest.mark.practice


# ------------------------------------------------------------- the fixture --- #
class _RunnerServer:
    """A real SSH server emulating the isolated runner.

    ``supervisor`` toggles whether the runner-supervisor binary answers;
    the exec contract is exactly what SSHRunner sends:
    ``runner-supervisor start <op> -- bash -lc '<cmd>'`` on the job
    connection and ``runner-supervisor status <op>`` on the control
    channel.
    """

    def __init__(self, *, supervisor=True):
        self.supervisor = supervisor
        self.host_key = asyncssh.generate_private_key("ssh-ed25519")
        self.accepted_pub: str | None = None
        self._srv = None

    async def start(self, *, accept_pub: str):
        """accept_pub: public-key TEXT the one identity may authenticate."""
        self.accepted_pub = accept_pub
        outer = self

        class _Server(asyncssh.SSHServer):
            def begin_auth(self, username):
                return True

            def public_key_auth_supported(self):
                return True

            async def validate_public_key(self, username, key):
                return key.export_public_key().decode().strip() == \
                    outer.accepted_pub

        def _session(process):
            cmd = process.command or ""
            if "runner-supervisor" in cmd:
                if not outer.supervisor:
                    process.stdout.write(
                        "bash: runner-supervisor: command not found\n")
                    process.exit(127)
                    return
                if " status " in cmd:
                    process.stdout.write("not-found\n")
                process.exit(0)
                return
            process.stdout.write("ok\n")
            process.exit(0)

        self._srv = await asyncssh.create_server(
            _Server, "127.0.0.1", 0,
            server_host_keys=[self.host_key],
            process_factory=_session)
        return self._srv.sockets[0].getsockname()[1]

    async def stop(self):
        if self._srv is not None:
            self._srv.close()
            await self._srv.wait_closed()
            self._srv = None


def _throwaway_pub() -> str:
    return asyncssh.generate_private_key(
        "ssh-ed25519").export_public_key().decode().strip()


def _gen_key(tmp_path, name):
    p = tmp_path / name
    subprocess.run(["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(p),
                    "-q"], check=True)
    return p


def _keys(tmp_path):
    """Real OpenSSH key material (ed25519, no passphrase) via ssh-keygen."""
    return (_gen_key(tmp_path, "client_key"),
            _gen_key(tmp_path, "client_key_other"),
            _gen_key(tmp_path, "host_key"))


def _pub_of(priv_path) -> str:
    """Public key line WITHOUT the comment field — what asyncssh's
    export_public_key() produces and compares against."""
    return " ".join(pathlib.Path(f"{priv_path}.pub").read_text().split()[:2])


def _pin(port, srv) -> str:
    """known_hosts line pinning the RUNNING server's real host key under
    the bracketed [host]:port form the OpenSSH client uses for
    non-default ports."""
    pub = " ".join(srv.host_key.export_public_key().decode().split()[:2])
    return f"[127.0.0.1]:{port} {pub}\n"


def _settings(tmp_path, *, key, known_hosts, port, sr_env="dev"):
    return Settings(sr_env=sr_env,
                    runner_transport="ssh",
                    runner_ssh_target=f"runner@[127.0.0.1]:{port}",
                    runner_ssh_key_path=str(key),
                    runner_ssh_known_hosts=str(known_hosts),
                    runner_supervisor_bin="runner-supervisor",
                    safety_state_file=str(tmp_path / "safety.json"))


@pytest.fixture
def _isolate_home(tmp_path, monkeypatch):
    """The probe spawns the real ssh client: no user ~/.ssh/config or
    ssh-agent may influence the outcome of a test."""
    (tmp_path / "home").mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)


# ------------------------------------------------------------- the positive --- #
async def test_reachable_runner_passes_with_real_protocol(tmp_path,
                                                          _isolate_home):
    """Positive control: reachable host, matching pin, accepted identity,
    supervisor answering — the probe says healthy, through the transport
    itself (no intermediate dicts)."""
    client_key, _other, host_key = _keys(tmp_path)
    srv = _RunnerServer()
    port = await srv.start(accept_pub=_pub_of(client_key))
    try:
        kh = tmp_path / "known_hosts"
        kh.write_text(_pin(port, srv))
        s = _settings(tmp_path, key=client_key, known_hosts=kh, port=port)
        ok, why = await asyncio.to_thread(safety_mod._runner_health_probe, s)
        assert ok is True, why
        assert "reachable" in why.lower() and "supervised" in why.lower()
    finally:
        await srv.stop()


# ------------------------------------------------------------- the negatives --- #
async def test_closed_port_refuses_unreachable(tmp_path, _isolate_home):
    """The review's core counterexample: an UNREACHABLE destination must
    refuse — never inherit a 'configured therefore fine' verdict."""
    client_key, _other, host_key = _keys(tmp_path)
    srv = _RunnerServer()
    port = await srv.start(accept_pub=_throwaway_pub())
    await srv.stop()          # port now closed — connections are refused
    kh = tmp_path / "known_hosts"
    kh.write_text(_pin(port, srv))
    s = _settings(tmp_path, key=client_key, known_hosts=kh, port=port)
    ok, why = await asyncio.to_thread(safety_mod._runner_health_probe, s)
    assert ok is False
    low = why.lower()
    assert "refused" in low or "transport" in low or "unreachable" in low, why


async def test_foreign_host_pin_refuses(tmp_path, _isolate_home):
    """A runner presenting a DIFFERENT host key than the pin must be
    refused by StrictHostKeyChecking — not silently trusted."""
    client_key, _other, _host_key = _keys(tmp_path)
    wrong_pin = _gen_key(tmp_path, "wrong_pin")
    srv = _RunnerServer()
    port = await srv.start(accept_pub=_pub_of(client_key))
    try:
        kh = tmp_path / "known_hosts"
        kh.write_text(f"[127.0.0.1]:{port} {_pub_of(wrong_pin)}\n")
        s = _settings(tmp_path, key=client_key, known_hosts=kh, port=port)
        ok, why = await asyncio.to_thread(safety_mod._runner_health_probe, s)
        assert ok is False
        low = why.lower()
        assert ("host key" in low or "identification has changed" in low
                or "man-in-the-middle" in low), why
    finally:
        await srv.stop()


async def test_wrong_identity_refused(tmp_path, _isolate_home):
    """The server accepts only key A; offering key B must refuse."""
    client_key, other_key, host_key = _keys(tmp_path)
    srv = _RunnerServer()
    port = await srv.start(accept_pub=_pub_of(client_key))
    try:
        kh = tmp_path / "known_hosts"
        kh.write_text(_pin(port, srv))
        s = _settings(tmp_path, key=other_key, known_hosts=kh, port=port)
        ok, why = await asyncio.to_thread(safety_mod._runner_health_probe, s)
        assert ok is False
        low = why.lower()
        assert "permission denied" in low or "identity" in low \
            or "auth" in low, why
    finally:
        await srv.stop()


async def test_missing_key_file_and_empty_trust_file_refuse(tmp_path,
                                                            _isolate_home):
    """The reviewer's exact production scenario pieces: a missing private
    key and an EMPTY known_hosts each refuse through the probe — file
    existence is not trust."""
    client_key, _other, host_key = _keys(tmp_path)
    srv = _RunnerServer()
    port = await srv.start(accept_pub=_pub_of(client_key))
    try:
        kh = tmp_path / "known_hosts"
        kh.write_text(_pin(port, srv))
        s = _settings(tmp_path, key=tmp_path / "absent_key",
                      known_hosts=kh, port=port)
        ok, why = await asyncio.to_thread(safety_mod._runner_health_probe, s)
        assert ok is False, why
        # EMPTY (but existing) trust file: nothing is pinned
        empty = tmp_path / "empty_trust"
        empty.write_text("")
        s2 = _settings(tmp_path, key=client_key, known_hosts=empty, port=port)
        ok2, why2 = await asyncio.to_thread(safety_mod._runner_health_probe, s2)
        assert ok2 is False, why2
        assert "host key" in why2.lower(), why2
    finally:
        await srv.stop()


async def test_runner_without_supervisor_is_not_healthy(tmp_path,
                                                        _isolate_home):
    """Audit F7 boundary kept honest by the probe: a runner that answers
    SSH but has NO containment authority (runner-supervisor missing) is
    NOT healthy — 'reachable' must never fold into 'contained'."""
    client_key, _other, host_key = _keys(tmp_path)
    srv = _RunnerServer(supervisor=False)
    port = await srv.start(accept_pub=_pub_of(client_key))
    try:
        kh = tmp_path / "known_hosts"
        kh.write_text(_pin(port, srv))
        s = _settings(tmp_path, key=client_key, known_hosts=kh, port=port)
        ok, why = await asyncio.to_thread(safety_mod._runner_health_probe, s)
        assert ok is False
        assert "unknown" in why.lower(), why
    finally:
        await srv.stop()


# ------------------------------------------------- Supervisor integration --- #
async def test_supervisor_runner_check_probes_once_per_ttl(tmp_path, monkeypatch,
                                                           _isolate_home):
    """The admission check itself (not just the helper): one REAL probe per
    TTL window; a runner that died after a cached success is caught by the
    NEXT probe after the TTL (no success is cached forever)."""
    import time as _t

    from srplatform.safety import Supervisor
    from tests.helpers import FakeDatapath

    client_key, _other, host_key = _keys(tmp_path)
    srv = _RunnerServer()
    port = await srv.start(accept_pub=_pub_of(client_key))
    try:
        kh = tmp_path / "known_hosts"
        kh.write_text(_pin(port, srv))
        s = _settings(tmp_path, key=client_key, known_hosts=kh, port=port)
        sup = Supervisor(datapath=FakeDatapath(), settings=s,
                         state_file=str(tmp_path / "safety.json"))
        sup._mirror_dh = []
        sup._db_read_state = lambda: ({"latched": False, "latched_at": None,
                                       "reason": None}, None)
        calls = []
        real = safety_mod._runner_health_probe

        def counting(settings):
            calls.append(1)
            return real(settings)
        monkeypatch.setattr(safety_mod, "_runner_health_probe", counting)

        chk = await asyncio.to_thread(sup._runner_check)
        assert chk["ok"] is True, chk
        assert len(calls) == 1
        chk2 = await asyncio.to_thread(sup._runner_check)
        assert chk2["ok"] is True
        assert len(calls) == 1, "TTL memoization must absorb the page poll"
        # runner dies (server gone) — after the TTL the next check notices
        await srv.stop()
        sup._runner_probe_cache["until"] = _t.monotonic() - 1
        chk3 = await asyncio.to_thread(sup._runner_check)
        assert chk3["ok"] is False
        assert len(calls) == 2
    finally:
        await srv.stop()


async def test_supervisor_gate_refuses_unreachable_runner_end_to_end(
        tmp_path, _isolate_home):
    """Full begin path: production supervisor + valid qualifications +
    a runner that just died -> start_gate refuses citing the REAL ssh
    failure. No green anywhere in the report, no 'outside production'."""
    from srplatform.safety import Supervisor
    from srplatform.safety.datapath import StaticIsolationDatapath, \
        config_identity
    from tests.test_plan22_safety_qualification import ALL_KINDS, _aged

    client_key, _other, host_key = _keys(tmp_path)
    srv = _RunnerServer()
    port = await srv.start(accept_pub=_throwaway_pub())
    await srv.stop()
    kh = tmp_path / "known_hosts"
    kh.write_text(_pin(port, srv))
    s = _settings(tmp_path, key=client_key, known_hosts=kh, port=port,
                  sr_env="production")
    ident = config_identity(s)
    recs = {k: _aged(k, identity=ident) for k in ALL_KINDS}
    sup = Supervisor(datapath=StaticIsolationDatapath(), settings=s,
                     state_file=str(tmp_path / "safety.json"))
    sup._mirror_dh = []
    sup._records_reader = lambda: list(recs.values())
    sup._db_read_state = lambda: ({"latched": False, "latched_at": None,
                                   "reason": None}, None)
    sup._record_failures = []
    ok, reasons = sup.start_gate()
    assert ok is False
    runner_lines = [r for r in reasons if r.startswith("runner unavailable")]
    assert runner_lines, reasons
    low = " ".join(runner_lines).lower()
    assert "refused" in low or "transport" in low or "255" in low, low
    joined = " ".join(reasons).lower()
    assert "outside production" not in joined and "inapplicable" not in joined
