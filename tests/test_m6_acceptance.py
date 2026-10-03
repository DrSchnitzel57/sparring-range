"""M6 acceptance — the loop closes for a real user: one terminal, only CLI
commands and HTTP. This is the nine-line story from Part 0.5 with Drew's
hardware (Proxmox/GPU/range VMs) replaced by its doubles, but with the REAL
uvicorn server, the REAL CLI, the REAL loop over the REAL HTTP front door.
"""
import socket
import threading
import time

import pytest
import uvicorn
from typer.testing import CliRunner

from infra.proxmox_client import FakeProxmox
from srplatform.api import deps
from srplatform.api.app import app
from srplatform.api.coach_routes import set_coach_llm
from srplatform.red_agent.loop import RedAgentLoop
from srplatform.red_agent.sandbox import FakeSandbox
from srplatform.red_agent.transport import HttpTransport
from srplatform.settings import get_settings
from rangectl.cli import app as cli


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@pytest.fixture(scope="module")
def live_api(migrated_db_module):
    fake = FakeProxmox()
    deps.set_proxmox(fake)
    port = _free_port()
    cfg = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(cfg)
    t = threading.Thread(target=server.run, daemon=True)
    t.start()
    deadline = time.time() + 15
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started, "uvicorn did not start"
    import os
    os.environ["API_BASE_URL"] = f"http://127.0.0.1:{port}"
    get_settings.cache_clear()
    yield f"http://127.0.0.1:{port}"
    server.should_exit = True
    t.join(timeout=10)
    deps.set_proxmox(None)
    set_coach_llm(None)


@pytest.fixture(scope="module")
def migrated_db_module(tmp_path_factory):
    """module-scoped migration (server fixture needs it before tests run)"""
    import os
    import subprocess
    from pathlib import Path
    REPO = Path(__file__).resolve().parents[1]
    owner = os.environ["POSTGRES_URL_OWNER"]
    subprocess.run(["su", "postgres", "-c",
                    'psql -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname=\'sparring_range_test\'"'],
                   capture_output=True)
    subprocess.run(["su", "postgres", "-c",
                    'psql -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS sparring_range_test"'],
                   check=True, capture_output=True)
    subprocess.run(["su", "postgres", "-c",
                    'psql -v ON_ERROR_STOP=1 -c "CREATE DATABASE sparring_range_test OWNER sr_owner ENCODING \'UTF8\' TEMPLATE template0 LC_COLLATE \'C\' LC_CTYPE \'C\'"'],
                   check=True, capture_output=True)
    r = subprocess.run([str(REPO / ".venv/bin/python"), "-m", "alembic", "upgrade", "head"],
                       cwd=REPO, env={**os.environ, "POSTGRES_URL_OWNER": owner, "DB_APP_ROLE": "sr_app"},
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    return owner


def test_m6_full_practice_loop_over_cli_and_http(live_api):
    runner = CliRunner()

    # 1. browse the library
    res = runner.invoke(cli, ["scenarios"])
    assert res.exit_code == 0 and "web-foothold-01" in res.output

    # 2. deploy the scenario (proxmox via the API's fake)
    res = runner.invoke(cli, ["deploy", "web-foothold-01"])
    assert res.exit_code == 0, res.output
    assert "cloned web-foothold-01-web01" in res.output

    # 3. create the session (run --no-start prints it)
    res = runner.invoke(cli, ["run", "web-foothold-01", "--no-start"])
    assert res.exit_code == 0, res.output
    sid = res.output.split("session ")[1].split()[0].strip()

    # 4. the red agent plays — HTTP transport against the live server (this is
    #    the first time the loop speaks real HTTP, not TestClient)
    sb = FakeSandbox(script={
        "nmap": (0, "Nmap report: 80/tcp open http"),
        "exploit.py": lambda cmd: _plant(sb, "/root/flag_foothold.txt", "FLAG{e2e}") or (0, "pwned"),
        "persist.sh": lambda cmd: (sb.fs.setdefault("web01", {}).__setitem__("/etc/cron.d/u", "cron") or (0, "ok")),
    })
    from tests.test_m3_acceptance import FakeLLM, tool
    result = RedAgentLoop(sid, "web-foothold-01", HttpTransport(live_api), FakeLLM([
        tool("recon", "nmap -sV 10.66.0.10"),
        tool("pwn", "python3 exploit.py --target 10.66.0.10"),
        tool("persist", "bash persist.sh"),
    ]), sb, max_steps=8, compress_after=20, keep_recent=4).run()
    assert result["complete"] is True

    # 5. a mid-session Socratic hint works over HTTP too
    class FakeCoach:
        def complete(self, system, user):
            assert "10.66.0.10" in user or "exploit" in user  # context-aware
            return "You found a way in — where would the attackers leave a way back?"
    set_coach_llm(FakeCoach())
    res = runner.invoke(cli, ["hint", sid, "where next?"])
    assert res.exit_code == 0 and "way back" in res.output

    # 6. status: live view of the log
    res = runner.invoke(cli, ["status", sid])
    assert res.exit_code == 0 and "red" in res.output and "verifier" in res.output

    # 7. the graded AAR (cited) — the payoff — then teardown
    set_coach_llm(False)
    res = runner.invoke(cli, ["report", sid])
    assert res.exit_code == 0, res.output
    assert "After-Action Review" in res.output and "Grade" in res.output

    res = runner.invoke(cli, ["teardown", "web-foothold-01"])
    assert res.exit_code == 0 and "destroyed" in res.output


def _plant(sb, path, content):
    sb.fs.setdefault("web01", {})[path] = content
    return None
