"""Plan 22 browser acceptance: the honesty surfaces in the real browser.

Proven on the fresh Next.js build against the actual API (browser + db):

* LIVE-07: with an unhealthy admission probe the member's session page
  NAMES the exact Begin blockers the server gate will apply (verbatim),
  marks BEGIN data-blocked, and the operator safety page separates the
  commissioning QUALIFICATION from the live admission checks;
* LIVE-06: the member session page states the key-enrollment truth, and
  the operator admin page lists enrolled accounts with their SHA256
  fingerprints after an API enrollment (the diagnosis that was
  impossible installed);
* F9: the replay declares WHICH attacker timing it shows
  (worker-claimed read time versus server persist time).

Reuses the stage-5/plan-19/plan-20 harness: pinned playwright-cli in a
run-owned session, fresh run-owned dist build, uvicorn-thread API, real
form login, disposable DB.
"""
from __future__ import annotations

import json
import time

import httpx
import pytest

from tests.conftest import wipe_data
from tests.fake_model import FakeModelServer

# harness fixtures and helpers (imported as fixtures, not copied)
from tests.test_plan20_browser import (  # noqa: F401
    MEM_PW,
    OP_PW,
    _bootstrap,
    _login,
    _member_headers,
    _server_env,
    _start_api,
)
from tests.test_stage5_browser_e2e import (  # noqa: F401
    _body_has,
    browser,
    ports,
    web_app,
)

pytestmark = [pytest.mark.browser, pytest.mark.db]


def _eval(pw, expr: str) -> str:
    return pw("--raw", "eval", expr).stdout.strip().strip('"')


def _tid(pw, tid: str, prop: str = "innerText", timeout: float = 40) -> str:
    """Poll for [data-testid=tid] and return its property (or '' absent)."""
    deadline = time.time() + timeout
    last = ""
    while time.time() < deadline:
        last = _eval(
            pw,
            f"String(document.querySelector('[data-testid=\"{tid}\"]')"
            f" ?.{prop} ?? '')")
        if last:
            return last
        time.sleep(0.5)
    return last


def _logout(pw):
    # web auth is a localStorage bearer token (see web/lib/api.js)
    _eval(pw, "(() => { ['sr_token','sr_user','sr_role'].forEach"
              "(k => localStorage.removeItem(k)); return 'ok'; })()")


def test_plan22_honesty_surfaces(ports, browser, web_app, migrated_db,
                                 test_db_url_owner, tmp_path, monkeypatch):
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import text
    from sqlalchemy.engine import create_engine

    from srplatform import settings as st
    from srplatform.api.app import app

    pw = browser
    API = ports["api_url"]
    WEB_URL = ports["web_url"]

    srv = FakeModelServer().start()
    _server_env(monkeypatch, tmp_path, API, WEB_URL, srv)
    # LIVE-06: this run owns its enrolled-key store; LIVE-07: an
    # unconfigured runner transport is a REAL failing admission probe.
    monkeypatch.setenv("BASTION_ENROLLED_KEYS_FILE",
                       str(tmp_path / "enrolled_keys"))
    st.get_settings.cache_clear()
    wipe_data(test_db_url_owner)
    server = _start_api(app, ports)
    eng = create_engine(test_db_url_owner)
    try:
        op = _bootstrap(API)
        mem = _member_headers(API)
        n = datetime.now(timezone.utc).replace(microsecond=0)

        # the server's own Begin eligibility, forced to a REAL unhealthy
        # state (operator killswitch engaged) — the page has to name the
        # resulting blockers verbatim, whatever their composition
        from srplatform.safety import get_supervisor
        sup = get_supervisor()
        sup.engage(reason="plan22 honesty acceptance: supervised begin block")
        qual = httpx.get(f"{API}/safety/qualification", headers=op).json()
        assert not qual["begin_allowed"] and qual["begin_blockers"], qual
        blocker = qual["begin_blockers"][0]

        # ---- member session, ready match, failing admission -------------
        sid = httpx.post(f"{API}/sessions", headers=mem,
                         json={"scenario_id": "web-foothold-01"}
                         ).json()["session_id"]
        with eng.begin() as c:
            c.execute(text("UPDATE sessions SET status='ready' "
                           "WHERE session_id=:s"), {"s": sid})
            c.execute(text("UPDATE matches SET state='ready', ready_at=:t "
                           "WHERE session_id=:s"), {"s": sid, "t": n})

        _login(pw, WEB_URL, "blue", MEM_PW)
        pw("goto", f"{WEB_URL}/session/{sid}")
        body = _body_has(pw, "begin is blocked", timeout=120)
        assert blocker in body, \
            "the page must name the server's blocker verbatim, not a hint"
        assert _tid(pw, "begin-blockers", timeout=10) \
            .startswith("begin is blocked:")
        assert _eval(pw, "String(document.querySelector"
                           "('[data-testid=\"begin-button\"]')"
                           ".getAttribute('data-blocked'))") == "yes", \
            "BEGIN must be marked blocked while admission is unhealthy"

        # ---- LIVE-06: member sees the key-enrollment truth ---------------
        warn = _tid(pw, "key-enrollment-warning", timeout=60)
        assert "NO public key enrolled" in warn, warn

        # operator enrolls the member's PUBLIC key through the API (a REAL
        # generated key — the store validates through the SSH layer)
        import asyncssh
        pub = asyncssh.generate_private_key("ssh-ed25519") \
            .export_public_key().decode().strip()
        r = httpx.post(f"{API}/admin/bastion/enrollment", headers=op, json={
            "username": "blue", "public_key": pub})
        assert r.status_code == 201, r.text
        assert r.json()["fingerprints"][0].startswith("SHA256:")

        # ---- operator: admin page shows the enrolled account -------------
        _logout(pw)
        _login(pw, WEB_URL, "drew", OP_PW)
        pw("goto", f"{WEB_URL}/admin/bastion")
        _body_has(pw, "bastion key enrollment", timeout=120)
        enrolled = _tid(pw, "enrolled-accounts", timeout=40)
        assert "blue" in enrolled and "SHA256:" in enrolled, enrolled

        # ---- operator: safety page separates qualification/admission -----
        pw("goto", f"{WEB_URL}/safety")
        _body_has(pw, "automatic admission checks", timeout=120)
        safety = _body_has(pw, "what blocks Begin right now", timeout=30)
        assert blocker in safety
        assert "runner" in _tid(pw, "admission-runner") \
            or "runner" in safety

        # ---- F9: replay states which attacker timing is shown ------------
        op_id = "f9op" + "7" * 24
        with eng.begin() as c:
            run_id = c.execute(text(
                "INSERT INTO runs (run_id, session_id, scenario_id, status)"
                " VALUES (gen_random_uuid(), :s, 'web-foothold-01',"
                " 'complete') RETURNING run_id"), {"s": sid}).scalar()
            for off, kind, payload in (
                    (0, "action_intent",
                     {"op_id": 1, "op_uuid": op_id, "command": "id",
                      "thought": "t"}),
                    (1, "action_result",
                     {"op_id": 1, "op_uuid": op_id, "command": "id",
                      "exit_code": 0, "timed_out": False,
                      "output_capture": {"chunks": 1, "complete": True}})):
                c.execute(text(
                    "INSERT INTO events (session_id, ts, actor, action_type,"
                    " payload) VALUES (:s, :t, 'red', :k, CAST(:p AS jsonb))"),
                    {"s": sid, "t": n + timedelta(seconds=off), "k": kind,
                     "p": json.dumps(payload)})
            c.execute(text(
                "INSERT INTO operation_outputs (run_id, session_id, op_id,"
                " seq, ts, kind, text, read_ts) VALUES (:r, :s, :op, 0,"
                " :persist, 'output', 'F9-TIMED-OUTPUT-42', :rd)"),
                {"r": str(run_id), "s": sid, "op": op_id,
                 "persist": n + timedelta(seconds=10),
                 "rd": (n + timedelta(seconds=25)).timestamp()})

        pw("goto", f"{WEB_URL}/session/{sid}?tab=replay")
        _body_has(pw, "attacker output", timeout=120)
        prov = _tid(pw, "timing-provenance", timeout=60)
        assert prov, "the replay must declare its timing provenance"
        assert "WORKER-CLAIMED" in prov, prov

        server.should_exit = True
        sup.release()   # leave no latch for the tests that follow
    finally:
        eng.dispose()
        st.get_settings.cache_clear()
