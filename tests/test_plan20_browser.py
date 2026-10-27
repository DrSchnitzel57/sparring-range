"""Plan 20 browser acceptance: the ACTUAL new UI on the real Next.js
build against the real API (browser + db layers).

Proven in a real browser, not a component mock:
* login lands on the dashboard; members never see the operator
  all-sessions toggle, operators do; history paginates and the
  interrupted/unscored badges render from the API's flags;
* the coach chat send is a real round trip: the user message appears,
  the pending answer is visible WHILE the (fake) model thinks, the
  scripted answer then renders as safe markdown — bold/inline code
  become elements, `<script>`/`onerror`/`javascript:` stay literal
  text (window.__xss never becomes defined, no img/script nodes),
  and a validated citation click deep-links the Activity tab to the
  exact event;
* the report tab generates on CLICK only and stays honest UNSCORED
  without a scorecard;
* replay without any defender cast still plays the attacker's timed
  output on one clock: play advances the clock, prev/next command
  moves the operation cursor, a timeline click seeks, and captured
  output plus a marked capture gap render — nothing is invented.

Reuses the stage-5 harness (pinned playwright-cli in a run-owned
session, free ports, fresh run-owned dist dir, real form login).
"""
from __future__ import annotations

import json
import time

import httpx
import pytest

from tests.conftest import wipe_data
from tests.fake_model import FakeModelServer, text_response

from tests.test_stage5_browser_e2e import (  # noqa: F401
    _body_has, browser, ports, web_app)

OP_PW = "operator-testpw-9"
MEM_PW = "member-testpw-9"

pytestmark = [pytest.mark.browser, pytest.mark.db]


def _login(pw, WEB_URL, user, pwstr):
    pw("goto", f"{WEB_URL}/")
    pw("fill", 'input[placeholder="username"]', user)
    pw("fill", 'input[placeholder="password"]', pwstr)
    pw("click", 'button[type="submit"]')


def _eval(pw, expr: str) -> str:
    return pw("--raw", "eval", expr).stdout.strip().strip('"')


def _member_headers(API):
    return {"Authorization": "Bearer " + httpx.post(
        f"{API}/auth/login",
        json={"username": "blue", "password": MEM_PW}).json()["token"]}


def _bootstrap(API):
    assert httpx.post(f"{API}/auth/bootstrap", json={
        "username": "drew", "password": OP_PW}).status_code == 201
    op = {"Authorization": "Bearer " + httpx.post(
        f"{API}/auth/login",
        json={"username": "drew", "password": OP_PW}).json()["token"]}
    assert httpx.post(f"{API}/users", headers=op, json={
        "username": "blue", "password": MEM_PW,
        "role": "member"}).status_code == 201
    return op


def _server_env(monkeypatch, tmp_path, API, WEB_URL, srv):
    from srplatform import settings as st
    from srplatform.api import deps
    monkeypatch.setenv("SR_ENV", "dev")
    monkeypatch.setenv("LLM_BASE_URL", srv.base_url)
    monkeypatch.setenv("LLM_API_KEY", "bootstrap-fake")
    monkeypatch.setenv("SAFETY_STATE_FILE", str(tmp_path / "safety.json"))
    monkeypatch.setenv("RECORDINGS_DIR", str(tmp_path / "rec"))
    monkeypatch.setenv("API_BASE_URL", API)
    monkeypatch.setenv("API_ALLOWED_ORIGINS", WEB_URL)
    st.get_settings.cache_clear()
    deps.set_broker(None)


def _start_api(app, ports):
    import threading

    import uvicorn
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1",
                                           port=ports["api"],
                                           log_level="error"))
    threading.Thread(target=server.run, daemon=True).start()
    deadline = time.time() + 20
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started, "API never started"
    return server


def test_browser_coach_chat_replay_and_xss_safety(browser, web_app, ports,
                                                  migrated_db,
                                                  test_db_url_owner,
                                                  tmp_path, monkeypatch):
    from sqlalchemy import text
    from sqlalchemy.engine import create_engine

    from srplatform.api.app import app

    pw = browser
    API = ports["api_url"]
    WEB_URL = ports["web_url"]

    srv = FakeModelServer().start()
    _server_env(monkeypatch, tmp_path, API, WEB_URL, srv)
    wipe_data(test_db_url_owner)
    server = _start_api(app, ports)
    eng = create_engine(test_db_url_owner)
    try:
        op = _bootstrap(API)
        mem = _member_headers(API)

        # coach role -> the fake provider (through the real admin API)
        r = httpx.post(f"{API}/admin/model/profiles", headers=op, json={
            "name": "coachprof", "base_url": srv.base_url,
            "model_name": "gpt-4o", "api_key": "sk-coach-9",
            "max_completion_tokens": 512})
        assert r.status_code == 201, r.text
        assert httpx.put(f"{API}/admin/model/roles", headers=op, json={
            "role": "coach", "profile_name": "coachprof"}).status_code == 200

        sid = httpx.post(f"{API}/sessions", headers=mem, json={
            "scenario_id": "web-foothold-01"}).json()["session_id"]
        # one authorized evidence event the coach may cite
        with eng.begin() as conn:
            eid = conn.execute(text(
                "INSERT INTO events (session_id, ts, actor, action_type,"
                " payload) VALUES (:s, now(), 'blue', 'note',"
                " CAST(:p AS jsonb)) RETURNING event_id"),
                {"s": sid, "p": json.dumps({"text": "web01 responded"})}
            ).scalar()

        # ---- member dashboard: toggle must NOT exist ----------------------
        _login(pw, WEB_URL, "blue", MEM_PW)
        _body_has(pw, "dashboard")
        body = pw("--raw", "eval", "document.body.innerText").stdout
        assert "all sessions" not in body, \
            "operator all-sessions control rendered for a member"
        assert "launch new scenario" in body

        # ---- coach chat: send -> pending -> safe-markdown answer -----------
        # the pending answer must be observable while the model "thinks"
        srv.script([text_response(
            f"Look at note #{eid} and try `ss -tlnp`. **Act on it.** "
            "<script>window.__xss=1</script>"
            "<img src=x onerror=\"window.__img=1\">"
            " [click](javascript:alert(1)) and ignore #999999")],
            hang_s=2.0)
        pw("goto", f"{WEB_URL}/session/{sid}?tab=coach")
        _body_has(pw, "practice coach")
        _body_has(pw, "request a hint")   # 18/19 hint surface preserved
        pw("fill", 'input[aria-label="Ask the coach"]',
           "what should I check on web01?")
        pw("click", 'form button[type="submit"]')
        _body_has(pw, "what should I check on web01?")  # user row persisted
        _body_has(pw, "working through the evidence")   # pending, from job

        # the answer renders when the (slowed) provider responds
        _body_has(pw, "Act on it", timeout=60)
        body = pw("--raw", "eval", "document.body.innerText").stdout
        assert "window.__xss" in body          # literal TEXT, not executed
        assert _eval(pw, "String(typeof window.__xss)") == "undefined"
        assert _eval(pw, "String(typeof window.__img)") == "undefined"
        # markdown became elements, and no raw HTML or javascript: link
        assert _eval(pw, "String(!!document.querySelector('#panel-coach "
                         "strong'))") == "true"
        assert _eval(pw, "String(!!document.querySelector('#panel-coach "
                         "code'))") == "true"
        assert _eval(pw, "String(document.querySelectorAll('#panel-coach "
                         "script, #panel-coach img').length)") == "0"
        assert _eval(pw, "String([...document.querySelectorAll('#panel-coach "
                         "a')].some(a => a.getAttribute('href').startsWith("
                         "'javascript:')))") == "false"

        # the citation is the SEEDED event only, and clicking it deep-links
        assert f"#{eid}" in body
        cited = body.split("evidence:")[-1]     # the validated citations row
        assert f"#{eid}" in cited and "#999999" not in cited
        pw("click", "a.md-cite >> nth=0")
        _body_has(pw, "activity")
        path = pw("--raw", "eval", "location.search").stdout
        assert f"tab=activity" in path and f"event={eid}" in path
        _body_has(pw, f"details #{eid}")

        # honest reload: the conversation is durable, not component state
        pw("goto", f"{WEB_URL}/session/{sid}?tab=coach")
        _body_has(pw, "what should I check on web01?")
        _body_has(pw, "Act on it")

        # ---- report tab: generate on CLICK, honest UNSCORED ----------------
        pw("goto", f"{WEB_URL}/session/{sid}?tab=report")
        _body_has(pw, "After-Action Review")
        _body_has(pw, "No report generated")
        srv.script([text_response("Narrative: the member enumerated "
                                  "services; next step was service "
                                  "version checks.")])
        pw("click", 'button:has-text("generate AAR")')
        _body_has(pw, "UNSCORED", timeout=60)
        body = pw("--raw", "eval", "document.body.innerText").stdout
        assert "no grade" in body.lower() or "no silent f" in body.lower()
        assert "generate AAR" not in body  # version now exists
    finally:
        server.should_exit = True
        eng.dispose()
        srv.stop()


def test_browser_dashboard_history_replay_without_cast(browser, web_app,
                                                       ports, migrated_db,
                                                       test_db_url_owner,
                                                       tmp_path, monkeypatch):
    from datetime import datetime, timedelta, timezone

    from sqlalchemy import text
    from sqlalchemy.engine import create_engine

    from srplatform.api.app import app

    pw = browser
    API = ports["api_url"]
    WEB_URL = ports["web_url"]

    srv = FakeModelServer().start()
    _server_env(monkeypatch, tmp_path, API, WEB_URL, srv)
    wipe_data(test_db_url_owner)
    server = _start_api(app, ports)
    eng = create_engine(test_db_url_owner)
    try:
        _bootstrap(API)
        mem = _member_headers(API)
        sid = httpx.post(f"{API}/sessions", headers=mem, json={
            "scenario_id": "web-foothold-01"}).json()["session_id"]

        now = datetime.now(timezone.utc)
        op_uuid = "p20browser" + "0" * 20
        # the attacker ran ONE command whose timed output exists —
        # and there is NO defender cast for this session
        with eng.begin() as conn:
            uid = conn.execute(text(
                "SELECT user_id FROM users WHERE username='blue'"),
            ).scalar()
            conn.execute(text(
                "UPDATE sessions SET status='complete', ended_at=now() "
                "WHERE session_id=:s"), {"s": sid})
            conn.execute(text(
                "INSERT INTO events (session_id, ts, actor, action_type,"
                " payload) VALUES (:s, :t, 'system', 'session_start',"
                " '{}'::jsonb)"), {"s": sid, "t": now - timedelta(seconds=60)})
            conn.execute(text(
                "INSERT INTO events (session_id, ts, actor, action_type,"
                " payload) VALUES (:s, :t, 'red', 'action_intent',"
                " CAST(:p AS jsonb))"),
                {"s": sid, "t": now - timedelta(seconds=45),
                 "p": json.dumps({"op_id": 1, "op_uuid": op_uuid,
                                  "command": "ss -tlnp", "thought": "t"})})
            conn.execute(text(
                "INSERT INTO events (session_id, ts, actor, action_type,"
                " payload) VALUES (:s, :t, 'red', 'action_result',"
                " CAST(:p AS jsonb))"),
                {"s": sid, "t": now - timedelta(seconds=40),
                 "p": json.dumps({"op_id": 1, "op_uuid": op_uuid,
                                  "command": "ss -tlnp", "exit_code": 0,
                                  "timed_out": False,
                                  "output_capture": {"chunks": 2,
                                                     "complete": False}})})
            run_id = conn.execute(text(
                "INSERT INTO runs (run_id, session_id, scenario_id, status)"
                " VALUES (gen_random_uuid(), :s, 'web-foothold-01',"
                " 'complete') RETURNING run_id"), {"s": sid}).scalar()
            conn.execute(text(
                "INSERT INTO operation_outputs (run_id, session_id, op_id,"
                " seq, ts, kind, text) VALUES (:r, :s, :op, 0, :t0,"
                " 'output', 'CAPTURED-OUTPUT-42 listening'),"
                " (:r, :s, :op, 1, :t1, 'gap', 'command timed out —"
                " capture ended at the deadline')"),
                {"r": str(run_id), "s": sid, "op": op_uuid,
                 "t0": now - timedelta(seconds=44),
                 "t1": now - timedelta(seconds=39)})
            # 14 more completed sessions -> history must paginate (12/page);
            # distinct started_at keeps the dashboard ordering deterministic
            for i in range(14):
                sess = conn.execute(text(
                    "INSERT INTO sessions (session_id, scenario_id,"
                    " user_id, status, outcome, started_at, ended_at)"
                    " VALUES (gen_random_uuid(), 'quick-win-01', :u,"
                    " 'complete', 'complete', :st, :en) RETURNING session_id"),
                    {"u": str(uid),
                     "st": now - timedelta(days=i + 1),
                     "en": now - timedelta(days=i + 1)}).scalar()
                if i == 0:  # one interrupted (worker failure)
                    conn.execute(text(
                        "UPDATE sessions SET status='failed',"
                        " outcome='worker_failure' WHERE session_id=:s"),
                        {"s": str(sess)})

        # ---- replay WITHOUT any cast still plays ---------------------------
        _login(pw, WEB_URL, "blue", MEM_PW)
        pw("goto", f"{WEB_URL}/session/{sid}?tab=replay")
        _body_has(pw, "no defender cast")
        assert _eval(pw, "document.querySelector('[data-mode]')"
                         ".getAttribute('data-mode')") == "commands-only"
        assert _eval(pw, "document.querySelector('[data-ops]')"
                         ".getAttribute('data-ops')") == "1"

        # play advances the master clock
        pw("click", 'button[aria-label="Play"]')
        deadline = time.time() + 15
        while time.time() < deadline:
            if float(_eval(pw, "document.querySelector('[data-now]')"
                               ".getAttribute('data-now')")) > 0.5:
                break
            time.sleep(0.2)
        else:
            pytest.fail("play never advanced the session clock")
        pw("click", 'button[aria-label="Pause"]')

        # next command steps the operation cursor and seeks the clock
        pw("click", 'button:has-text("next command")')
        assert _eval(pw, "document.querySelector('[data-op-cursor]')"
                         ".getAttribute('data-op-cursor')") == "0"
        body = pw("--raw", "eval", "document.body.innerText").stdout
        assert "$ ss -tlnp" in body

        # run the clock forward fast: the timed output chunk and the
        # honestly-marked capture gap appear at their own timestamps
        pw("select", 'select[aria-label="Playback speed"]', "8")
        pw("click", 'button[aria-label="Play"]')
        deadline = time.time() + 20
        while time.time() < deadline:
            if float(_eval(pw, "document.querySelector('[data-now]')"
                               ".getAttribute('data-now')")) >= 21.5:
                break
            time.sleep(0.2)
        else:
            pytest.fail("clock never reached the timed output/gap")
        if _eval(pw, "document.querySelector('[data-playing]')"
                     ".getAttribute('data-playing')") == "true":
            pw("click", 'button[aria-label="Pause"]')
        body = pw("--raw", "eval", "document.body.innerText").stdout
        assert "CAPTURED-OUTPUT-42" in body
        assert "capture ended at the deadline" in body   # gap, said so

        # a timeline click seeks: data-seek-at matches the row's offset
        row_off = _eval(pw, "document.querySelector('.tl-row')"
                            ".getAttribute('data-off')")
        assert row_off and row_off not in ("pre-rec", "")
        pw("click", ".tl-row >> nth=0")
        seek_at = _eval(pw, "document.querySelector('[data-seek-at]')"
                            ".getAttribute('data-seek-at')")
        assert seek_at and abs(float(seek_at) - float(row_off)) < 1.0, \
            f"seek {seek_at} did not match row offset {row_off}"
        # no asciinema player was mounted (nothing to mount)
        assert _eval(pw, "String(document.querySelectorAll('.ap-player')"
                         ".length)") == "0"

        # ---- dashboard history pagination + honest badges -------------------
        pw("goto", f"{WEB_URL}/home")
        _body_has(pw, "history")
        _body_has(pw, "page 1")
        rows = _eval(pw, "String(document.querySelectorAll('.panel table"
                         " tbody tr').length)")
        assert rows == "12", f"expected 12 history rows, got {rows}"
        body = pw("--raw", "eval", "document.body.innerText").stdout
        assert "older →" in body
        assert "interrupted" in body      # the worker_failure session
        assert "unscored" in body         # completed without a scorecard
        pw("click", 'button:has-text("older →")')
        _body_has(pw, "page 2")
        rows = _eval(pw, "String(document.querySelectorAll('.panel table"
                         " tbody tr').length)")
        assert rows == "3", f"expected 3 remaining rows, got {rows}"

        # operator login DOES get the all-sessions toggle
        _login(pw, WEB_URL, "drew", OP_PW)
        _body_has(pw, "all sessions (operator)")
    finally:
        server.should_exit = True
        eng.dispose()
        srv.stop()
