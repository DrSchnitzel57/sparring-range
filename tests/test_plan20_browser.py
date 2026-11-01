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
        # one authorized evidence event the coach may cite — and it must be
        # a kind that RENDERS in the compressed prompt timeline (finding 8:
        # citations are only approved for evidence actually shown; a bare
        # 'note' is compressed away and its id is correctly rejected)
        with eng.begin() as conn:
            eid = conn.execute(text(
                "INSERT INTO events (session_id, ts, actor, action_type,"
                " payload) VALUES (:s, now(), 'blue', 'remediation',"
                " CAST(:p AS jsonb)) RETURNING event_id"),
                {"s": sid, "p": json.dumps({"action": "restart sshd"})}
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
            f"Look at event #{eid} and try `ss -tlnp`. **Act on it.** "
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

        # Review finding 8 (UI half): the renderer links ONLY the approved
        # ids. #999999 stays visible verbatim but as an unverified label —
        # never an anchor, never deep-linked, no matter what the model said.
        anchors = _eval(pw, "String([...document.querySelectorAll('#panel-coach "
                            "a.md-cite')].map(a => a.getAttribute('href'))"
                            ".sort().join(' '))")
        assert anchors == f"?tab=activity&event={eid} ?tab=activity&event={eid}", \
            f"coach-pane citation links are not exactly the approved set: {anchors}"
        unver = _eval(pw, "String([...document.querySelectorAll('#panel-coach "
                          "span.md-cite-unverified')].map(s => s.textContent)"
                          ".join(','))")
        assert "#999999" in unver, "the rejected citation must still be VISIBLE"
        assert _eval(pw, "String(document.querySelectorAll('#panel-coach "
                         "span.md-cite-unverified a').length)") == "0"
        assert _eval(pw, "String([...document.querySelectorAll('#panel-coach "
                         "span.md-cite-unverified')].some(s => s.textContent"
                         ".includes('#" + str(eid) + "')))") == "false", \
            "an APPROVED citation must not render as unverified"

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
        # finding 8 on the report too: every link is an event deep-link and
        # an unverified label can never smuggle an anchor
        assert _eval(pw, "String([...document.querySelectorAll('#panel-report "
                         "a.md-cite')].every(a => /^\\?tab=activity&event="
                         "\\d+$/.test(a.getAttribute('href'))))") == "true"
        assert _eval(pw, "String(document.querySelectorAll('#panel-report "
                         "span.md-cite-unverified a').length)") == "0"
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
            # 450 bastion noise events: the first replay page (200 raw
            # events) folds them into one collapsed row, so the page cursor
            # MUST be the raw consumed id, not the last displayed one
            # (finding 11's collapsed-run counterexample)
            for i in range(450):
                conn.execute(text(
                    "INSERT INTO events (session_id, ts, actor,"
                    " action_type, payload) VALUES (:s, :t, 'system',"
                    " :k, '{}'::jsonb)"),
                    {"s": sid, "k": "bastion_session_start" if i % 2 else
                     "bastion_session_end",
                     "t": now - timedelta(seconds=38) +
                     timedelta(seconds=i * 0.02)})
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
        deadline = time.time() + 15
        while time.time() < deadline:
            if _eval(pw, "document.querySelector('[data-ops-ready]')"
                         ".getAttribute('data-ops-ready')") == "true":
                break
            time.sleep(0.2)
        assert _eval(pw, "document.querySelector('[data-ops]')"
                         ".getAttribute('data-ops')") == "1"
        # finding 11 (client half): the page loaded ONE page of each track —
        # no casts exist, and the command's output has NOT been bulk-fetched
        assert _eval(pw, "document.querySelector('[data-casts-loaded]')"
                         ".getAttribute('data-casts-loaded')") == "0"
        assert _eval(pw, "document.querySelector('[data-chunks-ops]')"
                         ".getAttribute('data-chunks-ops')") == "0"

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

        # next command steps the operation cursor and seeks the clock; the
        # approach of the command lazily pulls its output page
        pw("click", 'button:has-text("next command")')
        assert _eval(pw, "document.querySelector('[data-op-cursor]')"
                         ".getAttribute('data-op-cursor')") == "0"
        body = pw("--raw", "eval", "document.body.innerText").stdout
        assert "$ ss -tlnp" in body
        deadline = time.time() + 15
        while time.time() < deadline:
            if _eval(pw, "document.querySelector('[data-chunks-ops]')"
                             ".getAttribute('data-chunks-ops')") == "1":
                break
            time.sleep(0.2)
        else:
            pytest.fail("output never lazily loaded as the clock approached "
                        "its command")

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

        # finding 11 (collapsed-run counterexample, client-visible): the
        # first page folded ~197 noise events into one row, yet the page
        # cursor is the RAW consumed id — and the next page genuinely
        # ADVANCES instead of re-consuming the folded range
        tl1 = _eval(pw, "document.querySelector('[data-tl-next]')"
                        ".getAttribute('data-tl-next')")
        assert tl1.isdigit() and int(tl1) > 20, f"raw cursor not ahead: {tl1}"
        rows1 = int(_eval(pw, "String(document.querySelectorAll('.tl-row')"
                               ".length)"))
        pw("click", 'button:has-text("load older events →")')
        deadline = time.time() + 15
        while time.time() < deadline:
            tl2 = _eval(pw, "document.querySelector('[data-tl-next]')"
                            ".getAttribute('data-tl-next')")
            if tl2 == "" or int(tl2) > int(tl1):
                break
            time.sleep(0.2)
        else:
            pytest.fail(f"collapsed page did not advance the raw cursor "
                        f"({tl1} -> {tl2}): paging would spin")
        rows2 = int(_eval(pw, "String(document.querySelectorAll('.tl-row')"
                               ".length)"))
        assert rows2 >= rows1, "next timeline page rendered fewer rows"

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


def test_browser_replay_cast_epoch_and_read_time(browser, web_app, ports,
                                                 migrated_db,
                                                 test_db_url_owner,
                                                 tmp_path, monkeypatch):
    """Review findings 4 and 10, counterexamples in a real browser.

    (a) CAST EPOCH OFFSET: attacker evidence sits 100 s BEFORE the
        defender cast begins. The session clock starts at the earliest
        stamp, but the player's own clock is CAST-relative — seeking the
        master clock to 105 s must put the player at ~5 s (a conflated
        epoch would seek it to 105 s, past the end of this 40 s cast).
        The player's REPORTED time (data-player-at from
        getCurrentTime) is asserted, not bookkeeping.
    (b) READ VS PERSIST TIME: one chunk whose persist ts is at +20 s
        but whose observed read_ts is at +60 s must render at the READ
        time: absent at clock 30 s, present at clock 70 s.
    """
    import uuid as uuid_mod
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

        n = datetime.now(timezone.utc).replace(microsecond=0)
        op_a = "p20epoch" + "1" * 24
        op_b = "p20rdts" + "2" * 24

        # ---- session 1: cast starts 100 s AFTER the attacker's evidence ----
        sid1 = httpx.post(f"{API}/sessions", headers=mem, json={
            "scenario_id": "web-foothold-01"}).json()["session_id"]
        rec_dir = tmp_path / "rec"
        rec_dir.mkdir(exist_ok=True)
        cast = rec_dir / "epoch.cast"
        cast_epoch = int((n + timedelta(seconds=100)).timestamp())
        cast.write_text(
            json.dumps({"version": 2, "width": 80, "height": 24,
                        "timestamp": cast_epoch, "title": "epoch"}) + "\n"
            + json.dumps([0.0, "o", "CAST-FIRST-FRAME\r\n"]) + "\n"
            + json.dumps([40.0, "o", "CAST-LAST-FRAME\r\n"]) + "\n")
        sid2 = httpx.post(f"{API}/sessions", headers=mem, json={
            "scenario_id": "web-foothold-01"}).json()["session_id"]
        with eng.begin() as conn:
            for s in (sid1, sid2):
                conn.execute(text(
                    "UPDATE sessions SET status='complete', ended_at=now()"
                    " WHERE session_id=:s"), {"s": s})
            conn.execute(text(
                "INSERT INTO recordings (recording_id, session_id,"
                " cast_path, status, bytes) VALUES (:r, :s, :p, 'sealed',"
                " :b)"), {"r": str(uuid_mod.uuid4()), "s": sid1,
                          "p": str(cast), "b": cast.stat().st_size})
            for s, t, actor, kind, payload in (
                (sid1, n, "red", "action_intent",
                 {"op_id": 1, "op_uuid": op_a, "command": "epoch-probe-cmd",
                  "thought": "t"}),
                (sid1, n + timedelta(seconds=1), "red", "action_result",
                 {"op_id": 1, "op_uuid": op_a, "command": "epoch-probe-cmd",
                  "exit_code": 0, "timed_out": False}),
                (sid1, n + timedelta(seconds=105), "blue", "note",
                 {"text": "post-cast-start marker"}),
                (sid1, n + timedelta(seconds=130), "blue", "note",
                 {"text": "later marker"}),
                (sid2, n + timedelta(minutes=10), "red", "action_intent",
                 {"op_id": 1, "op_uuid": op_b, "command": "read-time-probe",
                  "thought": "t"}),
                (sid2, n + timedelta(minutes=10, seconds=1), "red",
                 "action_result",
                 {"op_id": 1, "op_uuid": op_b,
                  "command": "read-time-probe", "exit_code": 0,
                  "timed_out": False,
                  "output_capture": {"chunks": 1, "complete": True}}),
                (sid2, n + timedelta(minutes=10, seconds=30), "blue", "note",
                 {"text": "after persist before read"}),
                (sid2, n + timedelta(minutes=10, seconds=70), "blue", "note",
                 {"text": "after read"}),
            ):
                conn.execute(text(
                    "INSERT INTO events (session_id, ts, actor,"
                    " action_type, payload) VALUES (:s, :t, :a, :k,"
                    " CAST(:p AS jsonb))"),
                    {"s": s, "t": t, "a": actor, "k": kind,
                     "p": json.dumps(payload)})
            run_id = conn.execute(text(
                "INSERT INTO runs (run_id, session_id, scenario_id, status)"
                " VALUES (gen_random_uuid(), :s, 'web-foothold-01',"
                " 'complete') RETURNING run_id"), {"s": sid2}).scalar()
            conn.execute(text(
                "INSERT INTO operation_outputs (run_id, session_id, op_id,"
                " seq, ts, kind, text, read_ts) VALUES (:r, :s, :op, 0,"
                " :persist, 'output', 'READ-TIMED-OUTPUT-77', :rd)"),
                {"r": str(run_id), "s": sid2, "op": op_b,
                 "persist": n + timedelta(minutes=10, seconds=20),
                 "rd": (n + timedelta(minutes=10,
                                      seconds=60)).timestamp()})

        def _mark_seek_rows(target_off: float, tag: str):
            pw("--raw", "eval", f"""(() => {{
                document.querySelectorAll('.tl-row').forEach(r => {{
                    const o = parseFloat(r.getAttribute('data-off'));
                    if (!r.dataset.{tag} && Math.abs(o - {target_off}) < 2)
                        r.dataset.{tag} = '1';
                }}); return 'ok'; }})()""")
            return f'.tl-row[data-{tag}="1"] >> nth=0'

        _login(pw, WEB_URL, "blue", MEM_PW)

        # ============ (a) cast epoch ============
        pw("goto", f"{WEB_URL}/session/{sid1}?tab=replay")
        _body_has(pw, "defender cast")
        assert _eval(pw, "document.querySelector('[data-mode]')"
                         ".getAttribute('data-mode')") == "cast+commands"
        assert _eval(pw, "document.querySelector('[data-cast-offset]')"
                         ".getAttribute('data-cast-offset')") == "100"
        deadline = time.time() + 30
        while time.time() < deadline:
            perr = _eval(pw, "document.querySelector('[data-player-error]')"
                             ".getAttribute('data-player-error')")
            if perr:
                pytest.fail(f"player error: {perr}")
            if (_eval(pw, "String(!!document.querySelector('.ap-player'))")
                    == "true"
                    and _eval(pw, "String(!!document.querySelector("
                                  "'.ap-term-text'))") == "true"):
                break
            time.sleep(0.3)
        else:
            pytest.fail("asciinema-player never mounted")

        row = _mark_seek_rows(105.0, "epochseek")
        off = float(_eval(pw, "document.querySelector"
                              "('.tl-row[data-epochseek]')"
                              ".getAttribute('data-off')"))
        assert abs(off - 105.0) < 2.0, f"seek row off {off}"
        player_at = ""
        deadline = time.time() + 25
        while time.time() < deadline:
            pw("click", row)
            time.sleep(0.7)
            player_at = _eval(pw, "document.querySelector('[data-player-at]')"
                                  ".getAttribute('data-player-at')")
            if player_at and abs(float(player_at) - (off - 100.0)) <= 1.5:
                break
        else:
            pytest.fail(f"player never followed the EPOCH-OFFSET clock: "
                        f"data-player-at={player_at!r} expected ~"
                        f"{off - 100.0} (session offset was {off})")
        # the player time must NOT be the raw session offset either — that
        # would mean the epoch was conflated (and is past this cast's end)
        assert float(player_at) < 40.0
        term = _eval(pw, "document.querySelector('.ap-term-text')"
                         ".textContent")
        assert "CAST-FIRST-FRAME" in term and "CAST-LAST-FRAME" not in term, \
            f"rendered terminal does not match player time {player_at}"

        # ---- and a second, deeper seek keeps tracking the offset ----------
        row2 = _mark_seek_rows(130.0, "epochseek2")
        deadline = time.time() + 25
        while time.time() < deadline:
            pw("click", row2)
            time.sleep(0.7)
            pa2 = _eval(pw, "document.querySelector('[data-player-at]')"
                            ".getAttribute('data-player-at')")
            if pa2 and abs(float(pa2) - 30.0) <= 1.5:
                break
        else:
            pytest.fail(f"second seek lost the epoch offset: {pa2!r}")

        # ============ (b) read time, not persist time ============
        # (sid2 also has the API's own session_start at creation, so the
        # probe's offsets are ~+600 s: persist +620, READ +660, rows +630/+670)
        pw("goto", f"{WEB_URL}/session/{sid2}?tab=replay")
        _body_has(pw, "attacker output")
        deadline = time.time() + 15
        while time.time() < deadline:
            if _eval(pw, "document.querySelector('[data-ops-ready]')"
                             ".getAttribute('data-ops-ready')") == "true":
                break
            time.sleep(0.2)
        # the command is 10 minutes into the session — at clock 0 NOTHING of
        # it has been fetched (bounded laziness, finding 11)
        assert _eval(pw, "document.querySelector('[data-chunks-ops]')"
                         ".getAttribute('data-chunks-ops')") == "0"

        # seek to +630 s: PERSIST time (+620) has passed, READ time (+660)
        # has not — placing by persist would leak the text here
        row30 = _mark_seek_rows(630.0, "rdts30")
        deadline = time.time() + 20
        while time.time() < deadline:
            pw("click", row30)
            time.sleep(0.7)
            now_v = _eval(pw, "document.querySelector('[data-now]')"
                              ".getAttribute('data-now')")
            if now_v and abs(float(now_v) - 630.0) <= 2.0:
                break
        else:
            pytest.fail("never seeked to +630s")
        # the seek approach must NOW lazily pull the op's output
        deadline = time.time() + 15
        while time.time() < deadline:
            if _eval(pw, "document.querySelector('[data-chunks-ops]')"
                             ".getAttribute('data-chunks-ops')") == "1":
                break
            time.sleep(0.2)
        else:
            dbg = _eval(pw, "['chunks-ops','ops'].map(k => k + '=' + "
                            "(document.querySelector('[data-' + k + ']')"
                            "?.getAttribute('data-' + k) ?? 'NO-PANEL'))"
                            ".join(' | ')")
            pytest.fail(f"output did not lazily load near its command: {dbg}")
        body = pw("--raw", "eval", "document.body.innerText").stdout
        assert "READ-TIMED-OUTPUT-77" not in body, \
            "output rendered at its PERSIST time, not its read time"

        row70 = _mark_seek_rows(670.0, "rdts70")
        deadline = time.time() + 20
        while time.time() < deadline:
            pw("click", row70)
            time.sleep(0.7)
            body = pw("--raw", "eval", "document.body.innerText").stdout
            if "READ-TIMED-OUTPUT-77" in body:
                break
            time.sleep(0.3)
        else:
            pytest.fail("output never rendered at its observed read time")
    finally:
        server.should_exit = True
        eng.dispose()
        srv.stop()
