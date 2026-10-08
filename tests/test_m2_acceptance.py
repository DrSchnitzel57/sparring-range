"""M2 acceptance tests — Part 5/M2 'Accept when':

  SSH through the bastion into web01, run several commands; afterward
  (1) a replayable .cast exists, registered under an OPAQUE id (F16), and
  (2) the corresponding command events appear in `events` with the correct
      session_id — telemetry identity comes from the capability, never the
      payload (F09).

Runs the REAL asyncssh bastion proxy against a fake range host, the real
append-only DB, and the real ingest endpoint.
"""
import asyncio
import json
from pathlib import Path

import asyncssh
import pytest
from fastapi.testclient import TestClient

from srplatform.bastion.proxy import BastionProxy

pytestmark = pytest.mark.asyncio  # db-marked tests derive automatically (milestone 01)


class _AllowAll(asyncssh.SSHServer):
    async def begin_auth(self, username: str) -> bool:
        return False  # trust within the fake range; bastion auth is what's tested


async def _target_handler(process: asyncssh.SSHServerProcess):
    if process.command is not None:
        process.stdout.write(f"target-ok: {process.command}\n")
        process.exit(0)
        return
    while True:
        line = await process.stdin.readline()
        if not line or line.strip() == "exit":
            break
        process.stdout.write(f"{line.strip()}: target-ok\n")
    process.exit(0)


class _Ctx:
    pass


@pytest.fixture()
async def range_env(client, users, tmp_path):
    ctx = _Ctx()
    ctx.client = client
    ctx.headers = users["member"]

    tk = asyncssh.generate_private_key("ssh-ed25519")
    tk_file = tmp_path / "target_host"
    tk.write_private_key(str(tk_file))
    srv = await asyncssh.create_server(_AllowAll, "127.0.0.1", 0,
                                       server_host_keys=[str(tk_file)],
                                       process_factory=_target_handler)
    ctx.target_port = srv.sockets[0].getsockname()[1]

    # real lifecycle: create + launch (launch issues per-host connection tokens)
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=ctx.headers).json()["session_id"]
    ctx.session_id = sid
    out = client.post(f"/sessions/{sid}/launch", headers=ctx.headers).json()
    ctx.login_token = out["connections"][0]["login_token"]
    # retarget that token at the fake ssh server (owner column unchanged)
    from sqlalchemy import select
    from srplatform.db.session import db as db_ctx
    from srplatform.db.models import LoginToken
    with db_ctx() as s:
        lt = s.get(LoginToken, ctx.login_token)
        lt.target_host, lt.target_port = "127.0.0.1", ctx.target_port
        s.commit()

    # bastion capability for the proxy's own event sink
    ctx.bastion_hdr = {"Authorization": "Bearer " + client.post(
        "/admin/service_tokens", json={"scope": "bastion"},
        headers=users["op"]).json()["token"]}

    async def resolve(token: str):
        r = client.get(f"/tokens/{token}", headers=ctx.bastion_hdr)
        return r.json() if r.status_code == 200 else None

    async def sink(event: dict):
        event = dict(event)
        event.pop("actor", None)  # server assigns actor from the capability
        r = client.post("/events", json=event, headers=ctx.bastion_hdr)
        r.raise_for_status()

    async def register(session_id, cast_path):
        r = client.post(f"/sessions/{session_id}/recordings",
                        json={"cast_path": cast_path}, headers=ctx.bastion_hdr)
        return r.json().get("recording_id") if r.status_code == 201 else None

    bk = tmp_path / "bastion_key"
    ctx.proxy = BastionProxy(resolve, sink, register_recording=register,
                             recordings_dir=tmp_path / "recordings", host_key_path=bk,
                             authorized_keys=lambda u, k: True)
    ctx.bastion_port = await ctx.proxy.start()
    yield ctx
    await ctx.proxy.stop()
    srv.close()


async def test_m2_bastion_records_cast_and_events_with_session_id(range_env):
    ctx = range_env
    client_key = asyncssh.generate_private_key("ssh-ed25519")
    async with asyncssh.connect("127.0.0.1", ctx.bastion_port, username=ctx.login_token,
                                client_keys=[client_key], known_hosts=None) as conn:
        for cmd in ("whoami", "netstat -ant"):
            res = await conn.run(cmd, check=False)
            assert "target-ok" in res.stdout
        proc = await conn.create_process(term_type="xterm-256color", term_size=(120, 32))
        proc.stdin.write("id\n")
        out = ""
        while "target-ok" not in out:
            out += await asyncio.wait_for(proc.stdout.read(1024), timeout=10)
        assert "id: target-ok" in out
        proc.stdin.write("exit\n")
        await asyncio.wait_for(proc.wait(), timeout=10)

    await asyncio.sleep(0.2)

    # (1) cast: asciinema v2, both directions, opaque filename (no token in
    # path). The exec-channel sessions record their OWN output-only casts, so
    # the interactive cast must be FOUND — glob order is filesystem luck and
    # picking casts[0] made this assertion flake.
    casts = list(Path(ctx.proxy.recordings_dir).glob("*.cast"))
    assert casts, "no .cast recording written"
    parsed = []
    for c in casts:
        assert "tok-" not in c.name
        lines = c.read_text().splitlines()
        header = json.loads(lines[0])
        assert header["version"] == 2 and "timestamp" in header  # epoch anchor (F17)
        parsed.append([json.loads(l) for l in lines[1:]])
    assert any(any(e[1] == "o" for e in ev) and any(e[1] == "i" for e in ev)
               for ev in parsed), \
        "no single cast recorded both directions (interactive session)"

    # (2) events carry the CORRECT session id and server-assigned bastion actor
    logged = ctx.client.get("/events", params={"session_id": ctx.session_id,
                                               "tail": 200}, headers=ctx.headers).json()
    types = [e["action_type"] for e in logged]
    assert "bastion_session_start" in types and "bastion_session_end" in types
    commands = [e for e in logged if e["action_type"] == "command"]
    assert {c["payload"]["command"] for c in commands} >= {"whoami", "netstat -ant"}
    assert all(e["session_id"] == ctx.session_id for e in logged)
    assert any((e["actor"] or "").startswith("blue:") for e in logged)

    # recording is retrievable by its OPAQUE id through the web endpoint
    recs = ctx.client.get(f"/sessions/{ctx.session_id}/recordings",
                          headers=ctx.headers).json()
    assert recs and "cast_path" not in json.dumps(recs)  # no filesystem paths leak
    one = ctx.client.get(f"/recordings/{recs[0]['recording_id']}", headers=ctx.headers)
    assert one.status_code == 200
    assert one.json()["header"]["version"] == 2


async def test_m2_auditd_ingest_identity_from_capability_and_dedup(client, users):
    import uuid as _uuid
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    tok = client.post("/admin/service_tokens",
                      json={"scope": "telemetry", "host": "web01", "session_id": sid},
                      headers=users["op"]).json()["token"]
    hdr = {"Authorization": f"Bearer {tok}"}

    batch = {"events": [
        {"kind": "command", "ts": "2026-10-04T15:04:05+00:00", "uid": "1000",
         "comm": "bash", "argv": "curl -s http://10.66.0.10/",
         "source_id": "4711", "boot_id": "bootA"},
        {"kind": "detection", "comm": "auditd", "audit_key": "sparring_persistence",
         "argv": "touch /etc/cron.d/backdoor", "source_id": "4712", "boot_id": "bootA"},
    ]}
    r = client.post("/ingest/auditd", json=batch, headers=hdr)
    assert r.status_code == 201 and r.json() == {"ok": True, "accepted": 2, "duplicates": 0}

    # retry with one duplicate — source identity dedups at the boundary
    r = client.post("/ingest/auditd", json=batch, headers=hdr)
    assert r.json()["duplicates"] == 2

    # host identity comes from the CAPABILITY even though the payload says nothing
    logged = client.get("/events", params={"session_id": sid, "tail": 50},
                        headers=users["member"]).json()
    cmd = [e for e in logged if e["action_type"] == "command"]
    det = [e for e in logged if e["action_type"] == "detection"]
    assert cmd and cmd[-1]["payload"]["argv"] == "curl -s http://10.66.0.10/"
    assert det[-1]["payload"]["audit_key"] == "sparring_persistence"
    assert all(e["host"] == "web01" and e["actor"] == "telemetry" for e in cmd + det)

    # a token bound to ANOTHER host records that host's identity — it cannot
    # launder events as web01 telemetry (host column comes from capability)
    tok2 = client.post("/admin/service_tokens",
                       json={"scope": "telemetry", "host": "db01", "session_id": sid},
                       headers=users["op"]).json()["token"]
    r = client.post("/ingest/auditd", json={"events": [{"argv": "x", "source_id": "9",
                  "boot_id": "bootZ"}]},
                    headers={"Authorization": f"Bearer {tok2}"})
    assert r.status_code == 201
    logged2 = client.get("/events", params={"session_id": sid, "tail": 50},
                         headers=users["member"]).json()
    foreign = [e for e in logged2 if e["payload"].get("argv") == "x"]
    assert foreign and foreign[0]["host"] == "db01"

    # unauthenticated / user-token ingest on the telemetry plane is rejected
    assert client.post("/ingest/auditd", json=batch,
                       headers=users["member"]).status_code in (401, 403)
    assert client.post("/ingest/auditd", json=batch).status_code == 401


def test_m2_shipper_groups_raw_auditd_lines():
    """The shipper parses REAL multi-record audit lines (EXECVE+SYSCALL+PROCTITLE)
    into one event per syscall id, and watch records into detection events."""
    import importlib.util
    from pathlib import Path as P
    spec_ = importlib.util.spec_from_file_location(
        "shipper", P(__file__).resolve().parents[1] / "telemetry" / "shipper.py")
    mod = importlib.util.module_from_spec(spec_)
    spec_.loader.exec_module(mod)

    raw = "\n".join([
        'type=PROCTITLE msg=audit(1695000000.123:4711): proctitle="-ls\x00"',
        'type=EXECVE msg=audit(1695000000.123:4711): argc=2 a0="ls" a1="-la"',
        'type=SYSCALL msg=audit(1695000000.123:4711): arch=c000003e syscall=257 '
        'success=yes exit=3 a0=-100 per=800000 uid=1000 gid=1000 comm="bash" '
        'exe="/usr/bin/ls" key="sparring_exec"',
        'type=SYSCALL msg=audit(1695000001.500:4712): arch=c000003e syscall=258 '
        'success=yes exit=0 uid=0 comm="evil" exe="/usr/bin/touch" key="sparring_persistence"',
    ])
    groups = list(mod.group_event_records(raw.splitlines()))
    assert [g["source_id"] for g in groups] == [4711, 4712]
    ev1 = mod.build_command_event("web01", groups[0], "mid", "bootA")
    assert ev1["kind"] == "command" and ev1["argv"] == "ls -la"
    assert ev1["uid"] == "1000" and ev1["audit_key"] == "sparring_exec"
    ev2 = mod.build_command_event("web01", groups[1], "mid", "bootA")
    assert ev2["kind"] == "detection" and ev2["audit_key"] == "sparring_persistence"
