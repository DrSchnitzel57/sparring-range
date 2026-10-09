"""M6 acceptance — the loop closes for a real user: one terminal, only CLI
commands and HTTP. The nine-line story from Part 0.5 with Drew's hardware
(Proxmox/GPU/range VMs) replaced by its doubles — but the REAL uvicorn server,
the REAL Typer CLI speaking real HTTP (auth tokens included), the REAL loop
over the REAL front door.
"""
import os
import socket
import threading
import time

import httpx
import pytest
import uvicorn
from typer.testing import CliRunner

from rangectl.cli import app as cli
from srplatform import verification_service
from srplatform.api import deps
from srplatform.api.app import app
from srplatform.api.coach_routes import set_coach_llm
from srplatform.red_agent.loop import RedAgentLoop
from srplatform.red_agent.sandbox import FakeSandbox
from srplatform.red_agent.transport import HttpTransport
from srplatform.safety import Supervisor, set_supervisor
from srplatform.safety.datapath import NoopDatapath
from srplatform.settings import get_settings
from tests.helpers import FakeLLM, make_runner_token, tool

pytestmark = pytest.mark.db

OP_PW = "operator-testpw-9"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture()
def live_api(migrated_db, test_db_url_owner, tmp_path, monkeypatch):
    """Real uvicorn on a free port; doubles injected into the in-process app."""
    from infra.proxmox_client import FakePVEHttp
    httpd = FakePVEHttp()
    for vmid in (9001, 9002, 9003, 9004):
        httpd.vms[vmid] = {"name": f"tpl{vmid}", "template": vmid, "status": "stopped"}
    from tests.conftest import wipe_data
    wipe_data(test_db_url_owner)
    from infra.broker.testing import make_broker_over, policy_from_settings
    from srplatform.settings import get_settings as _get_settings
    _broker, _broker_service = make_broker_over(
        httpd, policy=policy_from_settings(_get_settings()))
    deps.set_broker(_broker)
    set_supervisor(Supervisor(datapath=NoopDatapath(),
                              state_file=str(tmp_path / "safety.json")))

    monkeypatch.setenv("SR_ENV", "dev")
    monkeypatch.setenv("RECORDINGS_DIR", str(tmp_path / "rec"))
    monkeypatch.setenv("SAFETY_STATE_FILE", str(tmp_path / "safety.json"))
    monkeypatch.setenv("RUNNER_TRANSPORT", "local-dev")
    monkeypatch.setenv("ALLOW_LOCAL_DEV_FIXTURE", "1")
    get_settings.cache_clear()

    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    deadline = time.time() + 15
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started, "uvicorn did not start"

    base = f"http://127.0.0.1:{port}"
    monkeypatch.setenv("API_BASE_URL", base)
    get_settings.cache_clear()
    yield base
    server.should_exit = True
    t.join(timeout=10)
    deps.set_broker(None)
    set_coach_llm(None)
    verification_service.set_verifier_exec(None)
    get_settings.cache_clear()


def test_m6_full_practice_loop_over_cli_and_http(live_api, tmp_path, monkeypatch):
    base = live_api

    # bootstrap + login: the CLI authenticates like everything else (F04)
    r = httpx.post(f"{base}/auth/bootstrap", json={"username": "drew", "password": OP_PW})
    assert r.status_code == 201, r.text
    tok = httpx.post(f"{base}/auth/login",
                     json={"username": "drew", "password": OP_PW}).json()["token"]
    token_file = tmp_path / "tok"
    token_file.write_text(tok)
    monkeypatch.setenv("SR_CLI_TOKEN", tok)
    monkeypatch.setenv("RANGECTL_TOKEN_FILE", str(token_file))

    runner = CliRunner()

    # unauthenticated CLI must fail loudly, not silently half-work
    monkeypatch.delenv("SR_CLI_TOKEN")
    token_file.write_text("bogus")
    assert runner.invoke(cli, ["scenarios"]).exit_code != 0 or \
        "not authenticated" in runner.invoke(cli, ["sessions"]).output
    monkeypatch.setenv("SR_CLI_TOKEN", tok)

    # 1. browse the library
    res = runner.invoke(cli, ["scenarios"])
    assert res.exit_code == 0 and "web-foothold-01" in res.output

    # 2. ONE command: session + deploy + connection instructions
    res = runner.invoke(cli, ["launch", "web-foothold-01"])
    assert res.exit_code == 0, res.output
    assert "ssh " in res.output and "tok-web01-" in res.output
    sid = res.output.split("session ")[1].split()[0].strip()

    # 3. the red agent plays — REAL HTTP transport against the live server
    state = {"flag": None, "cron": ["e2scrub_all"]}

    def host_exec(host, command):
        if command.startswith("cat "):
            return (0, state["flag"]) if state["flag"] else (1, "no such file")
        if command.startswith("ls -1 /etc/cron.d/"):
            return 0, "\n".join(state["cron"]) + "\n---\n"
        if "awk" in command:
            return 0, ""
        return 127, "no route"
    verification_service.set_verifier_exec(host_exec)

    sandbox = FakeSandbox(script={
        "nmap": (0, "Nmap report: 80/tcp open http"),
        "exploit.py": lambda cmd: (state.__setitem__("flag", "FLAG{web01-root}") or (0, "pwned")),
        "persist.sh": lambda cmd: (state["cron"].append("backdoor") or (0, "ok")),
    })
    result = RedAgentLoop(sid, "web-foothold-01", HttpTransport(base, token=make_runner_token(sid)),
                          FakeLLM([
                              tool("recon", "nmap -sV 10.66.0.10"),
                              tool("pwn", "python3 exploit.py --target 10.66.0.10"),
                              tool("persist", "bash persist.sh"),
                          ]), sandbox, max_steps=8, compress_after=20, keep_recent=4).run()
    assert result["complete"] is True

    # 4. mid-session Socratic hint over HTTP
    class FakeCoach:
        def complete(self, system, user):
            assert "CONTEXT (live log)" in user and ("Nmap" in user or "exploit" in user)
            return "You found a way in — where would attackers leave a way back?"
    set_coach_llm(FakeCoach())
    res = runner.invoke(cli, ["hint", sid, "where next?"])
    assert res.exit_code == 0 and "way back" in res.output

    # 5. trusted score through the CLI (CLI never runs verifiers itself)
    res = runner.invoke(cli, ["score", sid])
    assert res.exit_code == 0 and "score:" in res.output

    # 6. status: live tail of the log
    res = runner.invoke(cli, ["status", sid])
    assert res.exit_code == 0 and "red" in res.output and "verifier" in res.output

    # 7. end -> final trusted score; graded AAR (cited); teardown; readyz
    set_coach_llm(None)
    res = runner.invoke(cli, ["end", sid])
    assert res.exit_code == 0 and "complete" in res.output

    res = runner.invoke(cli, ["report", sid])
    assert res.exit_code == 0, res.output
    assert "After-Action Review" in res.output

    res = runner.invoke(cli, ["teardown", sid])
    assert res.exit_code == 0 and "destroyed" in res.output

    res = runner.invoke(cli, ["readyz"])
    assert res.exit_code == 0
