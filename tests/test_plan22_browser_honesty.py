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


def test_browser_replay_pre_cast_suppression(ports, browser, web_app,
                                             migrated_db, test_db_url_owner,
                                             tmp_path, monkeypatch):
    """Plan 22 review (item 7), in the REAL browser: seeking the session
    clock to BEFORE the recording's coverage must not show the future.

    Frame zero of a cast IS recorded content — the previous fix (hold
    frame zero) therefore still rendered the first recorded screen while
    the clock sat 100 s before the recording started. The terminal is now
    SUPPRESSED with an explicit honest state until the clock reaches the
    cast, and the suppression must survive the sequences that previously
    reintroduced the frame: reverse-seek after watching in-coverage
    frames, timeline filter changes, and switching to a SECOND cast whose
    epoch differs. In-coverage seeks still show the real frames.
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

    def _visible_flag() -> str:
        return _eval(pw, "document.querySelector('[data-cast-visible]')"
                         "?.getAttribute('data-cast-visible') ?? 'absent'")

    def _computed_visibility() -> str:
        return _eval(pw, "String(getComputedStyle(document.querySelector"
                         "('[data-cast-visible]')).visibility)")

    def _note() -> str:
        return _eval(pw, "document.querySelector('[data-precast-note]')"
                         "?.innerText ?? ''")

    def _term_text() -> str:
        return _eval(pw, "document.querySelector('.ap-term-text')"
                         "?.innerText ?? ''")

    def _cast_offset() -> str:
        return _eval(pw, "document.querySelector('[data-cast-offset]')"
                         "?.getAttribute('data-cast-offset') ?? ''")

    def _seek_row(target_off: float, tag: str):
        """Tag (lower-case attribute, set explicitly) and wait for at least
        one timeline row at the requested offset to exist."""
        attr = f"data-{tag.lower()}"
        deadline = time.time() + 20
        while time.time() < deadline:
            marked = _eval(pw, f"""(() => {{
                let n = 0;
                document.querySelectorAll('.tl-row').forEach(r => {{
                    const o = parseFloat(r.getAttribute('data-off'));
                    if (!r.hasAttribute('{attr}')
                        && Math.abs(o - {target_off}) < 2) {{
                        r.setAttribute('{attr}', '1'); n++; }}
                }}); return String(n); }})()""")
            found = _eval(pw, f"String(document.querySelectorAll"
                              f"('.tl-row[{attr}]').length)")
            if found != "0":
                return f'.tl-row[{attr}="1"] >> nth=0'
            time.sleep(0.4)
        pytest.fail(f"no timeline row near offset {target_off} "
                    f"(tag {tag}, marked {marked})")

    try:
        _bootstrap(API)
        mem = _member_headers(API)
        n = datetime.now(timezone.utc).replace(microsecond=0)

        sid = httpx.post(f"{API}/sessions", headers=mem, json={
            "scenario_id": "web-foothold-01"}).json()["session_id"]
        rec_dir = tmp_path / "rec"
        rec_dir.mkdir(exist_ok=True)

        def make_cast(fname: str, offset: int, first: str, last: str):
            p = rec_dir / fname
            p.write_text(
                json.dumps({"version": 2, "width": 80, "height": 24,
                            "timestamp": int((n + timedelta(seconds=offset))
                                             .timestamp()),
                            "title": fname}) + "\n"
                + json.dumps([0.0, "o", f"{first}\r\n"]) + "\n"
                + json.dumps([40.0, "o", f"{last}\r\n"]) + "\n")
            return p

        cast_a = make_cast("a.cast", 100, "CAST-A-FIRST-FRAME",
                           "CAST-A-LAST-FRAME")
        cast_b = make_cast("b.cast", 200, "CAST-B-FIRST-FRAME",
                           "CAST-B-LAST-FRAME")
        with eng.begin() as c:
            c.execute(text("UPDATE sessions SET status='complete', "
                           "ended_at=now() WHERE session_id=:s"), {"s": sid})
            for rec in (cast_a, cast_b):
                c.execute(text(
                    "INSERT INTO recordings (recording_id, session_id,"
                    " cast_path, status, bytes) VALUES (:r, :s, :p,"
                    " 'sealed', :b)"),
                    {"r": str(uuid_mod.uuid4()), "s": sid,
                     "p": str(rec), "b": rec.stat().st_size})
            for off, actor, kind, payload in (
                (0, "red", "action_intent",
                 {"op_id": 1, "op_uuid": "p22pre" + "1" * 24,
                  "command": "earliest-attacker-cmd", "thought": "t"}),
                (1, "red", "action_result",
                 {"op_id": 1, "op_uuid": "p22pre" + "1" * 24,
                  "command": "earliest-attacker-cmd", "exit_code": 0,
                  "timed_out": False}),
                (50, "red", "action_intent",
                 {"op_id": 2, "op_uuid": "p22pre" + "2" * 24,
                  "command": "pre-cast-cmd", "thought": "t"}),
                (105, "blue", "note", {"text": "in-cast-A marker"}),
                (205, "blue", "note", {"text": "in-cast-B marker"}),
            ):
                c.execute(text(
                    "INSERT INTO events (session_id, ts, actor,"
                    " action_type, payload) VALUES (:s, :t, :a, :k,"
                    " CAST(:p AS jsonb))"),
                    {"s": sid, "t": n + timedelta(seconds=off), "a": actor,
                     "k": kind, "p": json.dumps(payload)})

        _login(pw, WEB_URL, "blue", MEM_PW)
        pw("goto", f"{WEB_URL}/session/{sid}?tab=replay")
        _body_has(pw, "defender terminal", timeout=120)
        deadline = time.time() + 40
        while time.time() < deadline:
            if _eval(pw, "String(!!document.querySelector('.ap-term-text'))") \
                    == "true":
                break
            time.sleep(0.3)
        else:
            pytest.fail("asciinema-player never mounted")

        # ---- the clock starts BEFORE the selected cast: suppressed -------
        def _select_cast_option(i: int):
            _eval(pw, """(() => {
                const sel = [...document.querySelectorAll('label')]
                    .find(l => (l.textContent || '').includes('defender cast'))
                    ?.querySelector('select');
                if (!sel) return 'no-selector';
                const set = Object.getOwnPropertyDescriptor(
                    window.HTMLSelectElement.prototype, 'value').set;
                set.call(sel, '__I__');
                sel.dispatchEvent(new Event('change', { bubbles: true }));
                return 'ok'; })()""".replace("__I__", str(i)))

        assert _cast_offset() in ("100", "200")
        if _cast_offset() != "100":
            _select_cast_option(0)
            time.sleep(1.0)
            if _cast_offset() != "100":
                _select_cast_option(1)
                deadline = time.time() + 15
                while time.time() < deadline and _cast_offset() != "100":
                    time.sleep(0.4)
        assert _cast_offset() == "100", "cast A (+100) never selectable"
        assert _visible_flag() == "false", \
            "the terminal must be suppressed while the clock predates the cast"
        assert _computed_visibility() == "hidden"
        note = _note()
        assert "no recording yet" in note and "+100" in note, note

        # ---- seek INSIDE coverage: the real frames show through ----------
        pw("click", _seek_row(105.0, "p22aina"), timeout=30)
        deadline = time.time() + 20
        while time.time() < deadline:
            if _cast_offset() == "100" and _visible_flag() == "true" \
                    and "CAST-A-FIRST-FRAME" in _term_text():
                break
            time.sleep(0.4)
        else:
            pytest.fail(f"never showed the in-coverage A frame "
                        f"(offset={_cast_offset()} flag={_visible_flag()} "
                        f"text={_term_text()[:80]!r})")
        assert _note() == ""

        # ---- REVERSE seek back before coverage: suppressed AGAIN ---------
        # (the exact counterexample: after frame zero rendered once, the
        #  old panel kept the future content on screen)
        pw("click", _seek_row(0.0, "p22back"), timeout=30)
        deadline = time.time() + 15
        while time.time() < deadline:
            if _visible_flag() == "false":
                break
            time.sleep(0.3)
        else:
            pytest.fail("reverse seek left the pre-cast terminal visible")
        assert _computed_visibility() == "hidden"
        assert "no recording yet" in _note()

        # ---- filter changes must not resurrect the frame -----------------
        _eval(pw, """(() => {
            const sel = [...document.querySelectorAll('select')]
                .find(s => s.getAttribute('aria-label') === 'Actor filter');
            const set = Object.getOwnPropertyDescriptor(
                window.HTMLSelectElement.prototype, 'value').set;
            set.call(sel, 'red');
            sel.dispatchEvent(new Event('change', { bubbles: true }));
            return 'ok'; })()""")
        time.sleep(1.0)
        assert _visible_flag() == "false", \
            "filtering the timeline must not expose the pre-cast terminal"
        assert "no recording yet" in _note()
        _eval(pw, """(() => {
            const sel = [...document.querySelectorAll('select')]
                .find(s => s.getAttribute('aria-label') === 'Actor filter');
            const set = Object.getOwnPropertyDescriptor(
                window.HTMLSelectElement.prototype, 'value').set;
            set.call(sel, '');
            sel.dispatchEvent(new Event('change', { bubbles: true }));
            return 'ok'; })()""")
        time.sleep(0.6)
        assert _visible_flag() == "false"

        # ---- MULTIPLE CASTS: suppression follows the SELECTED cast -------
        _select_cast_option(0)
        time.sleep(1.0)
        if _cast_offset() != "200":
            _select_cast_option(1)
            deadline = time.time() + 20
            while time.time() < deadline and _cast_offset() != "200":
                time.sleep(0.4)
        assert _cast_offset() == "200", "cast switch never applied"
        assert _visible_flag() == "false", \
            "the newly selected cast is still pre-coverage at this clock"
        assert "+200" in _note(), _note()
        pw("click", _seek_row(205.0, "p22inb"), timeout=30)
        deadline = time.time() + 20
        while time.time() < deadline:
            if _visible_flag() == "true" \
                    and "CAST-B-FIRST-FRAME" in _term_text():
                break
            time.sleep(0.4)
        else:
            pytest.fail(f"B cast never showed its frames "
                        f"(flag={_visible_flag()} text={_term_text()[:80]!r})")
        server.should_exit = True
    finally:
        eng.dispose()
