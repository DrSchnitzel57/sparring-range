"""M2 acceptance tests — Part 5/M2 'Accept when':

  SSH through the bastion into web01, run several commands; afterward
  (1) a replayable .cast of the session exists and
  (2) the corresponding auditd command events appear in `events` with the
      correct session_id.

Runs the REAL asyncssh bastion proxy against a fake range host (also asyncssh),
the real append-only DB, and the real ingest endpoint.
"""
import asyncio
import json
from pathlib import Path

import asyncssh
import pytest
from fastapi.testclient import TestClient

from srplatform.api.app import app
from srplatform.bastion.proxy import BastionProxy

pytestmark = pytest.mark.asyncio


# ------------------------------------------------------------------ fake range host
class _AllowAll(asyncssh.SSHServer):
    async def begin_auth(self, username: str) -> bool:
        return False  # trust within the fake range; bastion auth is what's tested


async def _target_handler(process: asyncssh.SSHServerProcess):
    if process.command is not None:
        process.stdout.write(f"target-ok: {process.command}\n")
        process.exit(0)
        return
    # interactive: echo lines back (a stand-in shell); "exit" ends the session
    while True:
        line = await process.stdin.readline()
        if not line or line.strip() == "exit":
            break
        process.stdout.write(f"{line.strip()}: target-ok\n")
    process.exit(0)


class _Ctx:
    pass


@pytest.fixture()
async def range_env(migrated_db, tmp_path):
    ctx = _Ctx()
    ctx.client = TestClient(app)

    # fake "web01" ssh server
    tk = asyncssh.generate_private_key("ssh-ed25519")
    tk_file = tmp_path / "target_host"
    tk.write_private_key(str(tk_file))
    srv = await asyncssh.create_server(_AllowAll, "127.0.0.1", 0,
                                       server_host_keys=[str(tk_file)],
                                       process_factory=_target_handler)
    ctx.target_port = srv.sockets[0].getsockname()[1]

    # a real session + token login pointing at it (through the API front door)
    sid = ctx.client.post("/sessions", json={"scenario_id": "web-foothold-01", "username": "drew"}).json()["session_id"]
    ctx.session_id = sid
    r = ctx.client.post("/tokens", json={"token": "tok_web01", "target_host": "127.0.0.1",
                                         "target_port": ctx.target_port, "session_id": sid})
    assert r.status_code == 201

    # the bastion under test
    async def resolve(token: str):
        r = ctx.client.get(f"/tokens/{token}")
        return r.json() if r.status_code == 200 else None

    inserted: list[dict] = []

    async def sink(event: dict):
        # production sink POSTs to the API (front door); tests use the same
        # ingest shape via the TestClient so the real endpoint is exercised
        r = ctx.client.post("/events", json=event)
        r.raise_for_status()
        inserted.append(event)

    ctx.sink_events = inserted
    bk = tmp_path / "bastion_key"
    ctx.proxy = BastionProxy(resolve, sink, recordings_dir=tmp_path / "rec", host_key_path=bk)
    ctx.bastion_port = await ctx.proxy.start()
    yield ctx
    await ctx.proxy.stop()
    srv.close()


async def test_m2_bastion_records_cast_and_events_with_session_id(range_env):
    ctx = range_env
    client_key = asyncssh.generate_private_key("ssh-ed25519")
    async with asyncssh.connect("127.0.0.1", ctx.bastion_port, username="tok_web01",
                                client_keys=[client_key], known_hosts=None) as conn:
        # non-interactive exec commands (the parseable channel)
        for cmd in ("whoami", "netstat -ant"):
            res = await conn.run(cmd, check=False)
            assert "target-ok" in res.stdout
        # and an interactive PTY session (tee'd verbatim; copy-paste friendly)
        proc = await conn.create_process(term_type="xterm-256color", term_size=(120, 32))
        proc.stdin.write("id\n")
        out = ""
        while "target-ok" not in out:
            out += await asyncio.wait_for(proc.stdout.read(1024), timeout=10)
        assert "id: target-ok" in out
        proc.stdin.write("exit\n")
        await asyncio.wait_for(proc.wait(), timeout=10)

    await asyncio.sleep(0.2)  # let the proxy close the cast file

    # (1) a replayable cast exists — asciinema v2, both directions recorded
    casts = list(Path(ctx.proxy.recordings_dir).glob("*.cast"))
    assert casts, "no .cast recording written"
    lines = casts[0].read_text().splitlines()
    header = json.loads(lines[0])
    assert header["version"] == 2
    events = [json.loads(l) for l in lines[1:]]
    assert any(e[1] == "o" for e in events), "target->client stream not recorded"
    assert any(e[1] == "i" for e in events), "client->target stream not recorded"

    # (2) events for this session in the log — bastion session boundaries and
    #     exec-channel commands, all with the CORRECT session_id
    logged = ctx.client.get("/events", params={"session_id": ctx.session_id}).json()
    types = [e["action_type"] for e in logged]
    assert "bastion_session_start" in types and "bastion_session_end" in types
    commands = [e for e in logged if e["action_type"] == "command"]
    assert any(c["payload"].get("command") == "whoami" for c in commands)
    assert any(c["payload"].get("command") == "netstat -ant" for c in commands)
    assert all(e["session_id"] == ctx.session_id for e in logged)


async def test_m2_auditd_ingest_ties_commands_to_live_session(migrated_db):
    c = TestClient(app)
    sid = c.post("/sessions", json={"scenario_id": "web-foothold-01"}).json()["session_id"]
    c.post("/tokens", json={"token": "tok_web02", "target_host": "web01", "session_id": sid})

    # the shipper (telemetry/shipper.py) POSTs execve records; session resolves
    # via the active login token for that host
    r = c.post("/ingest/auditd", json={
        "host": "web01", "uid": "1000", "comm": "bash", "exe": "/usr/bin/curl",
        "argv": "curl -s http://10.66.0.10/", "raw": {"type": "EXECVE"},
    })
    assert r.status_code == 201 and r.json()["session_id"] == sid

    logged = c.get("/events", params={"session_id": sid}).json()
    cmd = [e for e in logged if e["action_type"] == "command" and e["payload"].get("source") == "auditd"]
    assert cmd and cmd[-1]["payload"]["argv"] == "curl -s http://10.66.0.10/"
    assert cmd[-1]["actor"] == "telemetry" and cmd[-1]["host"] == "web01"
