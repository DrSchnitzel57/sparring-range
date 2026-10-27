"""Plan 19 browser acceptance: the operator model-admin GUI against the
ACTUAL API on a disposable DB (browser + db layers).

Proven in the real browser on the real Next.js build:
* members are refused (the route is operator-only in the API; the page
  never renders data for them);
* creating a profile through the form stores the credential but the page
  can never show it back (masked shapes only — asserted on innerText);
* rotation creates a NEW visible version and demotes the old one;
* a probe admits through the queue like anything else and its job row
  SURVIVES a page reload (the queue is durable state, not component
  state);
* cancelling a queued job is a visible obligation, also across reload.

Reuses the stage-5 harness: pinned playwright-cli in a run-owned session,
fresh run-owned dist dir, uvicorn-thread API, real form login.
"""
from __future__ import annotations

import time

import httpx
import pytest

from tests.conftest import wipe_data
from tests.fake_model import FakeModelServer, text_response

# the stage-5 browser harness (run-owned playwright session, free ports,
# fresh run-owned dist dir) is fixtures — imported as fixtures, not copied
from tests.test_stage5_browser_e2e import (  # noqa: F401
    _body_has, browser, ports, web_app)

OP_PW = "operator-testpw-9"
MEM_PW = "member-testpw-9"

pytestmark = [pytest.mark.browser, pytest.mark.db]


def test_browser_model_administration(browser, web_app, ports, migrated_db,
                                      test_db_url_owner, tmp_path, monkeypatch):
    import threading

    import uvicorn

    from srplatform import settings as st
    from srplatform.api import deps
    from srplatform.api.app import app

    pw = browser
    API = ports["api_url"]
    WEB_URL = ports["web_url"]

    srv = FakeModelServer().start()
    monkeypatch.setenv("SR_ENV", "dev")
    monkeypatch.setenv("LLM_BASE_URL", srv.base_url)
    monkeypatch.setenv("LLM_API_KEY", "bootstrap-fake")
    monkeypatch.setenv("SAFETY_STATE_FILE", str(tmp_path / "safety.json"))
    monkeypatch.setenv("RECORDINGS_DIR", str(tmp_path / "rec"))
    monkeypatch.setenv("API_BASE_URL", API)
    monkeypatch.setenv("API_ALLOWED_ORIGINS", WEB_URL)
    st.get_settings.cache_clear()
    deps.set_broker(None)
    wipe_data(test_db_url_owner)

    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1",
                                           port=ports["api"],
                                           log_level="error"))
    threading.Thread(target=server.run, daemon=True).start()
    try:
        deadline = time.time() + 20
        while not server.started and time.time() < deadline:
            time.sleep(0.05)
        assert server.started, "API never started"

        assert httpx.post(f"{API}/auth/bootstrap",
                          json={"username": "drew",
                                "password": OP_PW}).status_code == 201
        op = {"Authorization": "Bearer " + httpx.post(
            f"{API}/auth/login",
            json={"username": "drew", "password": OP_PW}).json()["token"]}
        assert httpx.post(f"{API}/users", headers=op,
                          json={"username": "blue", "password": MEM_PW,
                                "role": "member"}).status_code == 201

        # ---- members are refused ------------------------------------------
        pw("open", f"{WEB_URL}/")
        _body_has(pw, "enter the gym")
        pw("fill", 'input[placeholder="username"]', "blue")
        pw("fill", 'input[placeholder="password"]', MEM_PW)
        pw("click", 'button[type="submit"]')
        _body_has(pw, "dashboard")
        pw("goto", f"{WEB_URL}/admin/models")
        _body_has(pw, "operator only")

        # ---- operator session -> the models page ---------------------------
        pw("goto", f"{WEB_URL}/")
        pw("fill", 'input[placeholder="username"]', "drew")
        pw("fill", 'input[placeholder="password"]', OP_PW)
        pw("click", 'button[type="submit"]')
        _body_has(pw, "dashboard")
        pw("click", 'nav a:has-text("models")')
        _body_has(pw, "model administration")
        # bootstrap profiles came up from the environment configuration
        _body_has(pw, "environment-red")

        # ---- create a profile through the FORM ------------------------------
        pw("fill", '[data-testid="field-name"]', "ui-profile")
        pw("fill", 'label:has-text("base URL") input', srv.base_url)
        pw("fill", '[data-testid="field-model"]', "gpt-4o")
        pw("fill", '[data-testid="field-key"]', "sk-ui-secret-99")
        pw("click", '[data-testid="create-profile"]')
        _body_has(pw, "profile created")
        body = _body_has(pw, "ui-profile")
        assert "sk-ui-secret-99" not in body, \
            "the write-only credential leaked back into the rendered page"
        assert '"sk-ui-secret-99"' not in pw(
            "--raw", "eval", "document.documentElement.innerHTML").stdout

        # bind it to the attacker role
        pw("select", 'p:has([data-testid="role-attacker"]) select',
           "ui-profile")
        _body_has(pw, "role attacker")
        body = _body_has(pw, "ui-profile")
        assert "sk-ui-secret-99" not in body

        # ---- NON-secret rotation: SUPERSEDE (pinned sessions keep running) --
        pw("eval", "document.querySelector('details').open = true")
        pw("fill", '[data-testid="field-model"]', "gpt-4o-b")
        pw("fill", '[data-testid="field-compaction"]', "0.7")
        pw("click", '[data-testid="rotate-ui-profile"]')
        _body_has(pw, "rotate ui-profile")          # form switched to rotate mode
        pw("click", '[data-testid="rotate-confirm"]')
        _body_has(pw, "SUPERSEDED")
        _body_has(pw, "gpt-4o-b")
        rows = _body_has(pw, "ui-profile")
        assert "superseded" in rows and "active" in rows
        assert "revoked" not in rows

        # ---- credential rotation: EVERY version carrying the replaced
        # credential is REVOKED (round-2 finding 2 — the superseded v1
        # copied K1 forward, so rotation invalidates it too) -----------
        pw("click", '[data-testid="rotate-ui-profile"]')
        pw("fill", '[data-testid="field-key"]', "sk-ui-rotated-2")
        pw("click", '[data-testid="rotate-confirm"]')
        _body_has(pw, "credential REPLACED")
        rows = _body_has(pw, "ui-profile")
        assert "revoked" in rows and "active" in rows
        assert "superseded" not in rows, \
            "a superseded version still carrying the replaced credential " \
            "survived rotation (the lineage sweep regressed)"

        # ---- discovery is a catalog read, not a completion -------------------
        pw("click", '[data-testid="discover-ui-profile-3"]')
        _body_has(pw, "coach-mini")      # catalog-only model id proves GET

        # ---- a custom thinking level MUST declare its mapping ---------------
        pw("select", '[data-testid="field-thinking"]', "custom…")
        _body_has(pw, "custom level name")
        pw("click", '[data-testid="create-profile"]')
        _body_has(pw, "needs a name AND a mapping")

        # ---- probe = queue member; the live job survives reload --------------
        # a LONG hang: the cancel must arrive while the call is genuinely
        # live (a fast answer would race the GUI past the obligation)
        srv.script([text_response("pong")], hang_s=15.0)
        pw("click", 'tr:has-text("ui-profile") button:has-text("probe")')
        _body_has(pw, "probe queued")
        # cancel the live job from the GUI — the button exists exactly while
        # the job is queued/running
        clicked = False
        for _ in range(15):
            r = pw("click", '[data-testid="cancel-job"]', check=False)
            if r.returncode == 0:
                clicked = True
                break
            time.sleep(0.4)
        assert clicked, "cancel button never appeared for the live job"
        _body_has(pw, "cancellation is an obligation")
        pw("reload")
        body = _body_has(pw, "model jobs")
        assert "probe" in body, "probe job vanished after reload — queue is " \
                               "not durable from the operator's view"
        # The watcher CLOSED the live request: that is an UNCERTAIN cessation
        # — an obligation the GUI surfaces and only an operator releases.
        deadline = time.time() + 45
        while time.time() < deadline:
            pw("reload")
            body = pw("--raw", "eval", "document.body.innerText").stdout
            if "cessation_unknown" in body:
                break
            time.sleep(2)
        assert "cessation_unknown" in body, \
            "a watcher-closed call must present as an unresolved obligation"
        _body_has(pw, "hold the slot")
        # resolve it through the GUI: bounded, explained, audited
        pw("click", '[data-testid="resolve-job"]')
        pw("fill", '[data-testid="resolve-text"]',
           "checked the endpoint: request finished; output discarded")
        pw("click", '[data-testid="resolve-confirm"]')
        _body_has(pw, "resolved and audited")
        pw("reload")
        body = _body_has(pw, "model jobs")
        assert "cessation_resolved" in body, \
            "resolution must survive reload — it is durable state"
    finally:
        server.should_exit = True
        srv.stop()
        st.get_settings.cache_clear()
