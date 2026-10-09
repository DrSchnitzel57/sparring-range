"""Milestone-02 CI repair — write visibility across the request boundary.

Root cause of the intermittent CI DB failures (M01-R4, compose "401 after
login", r02 "KeyError: 'token'", stage5 "launch 404 after create 201"):
FastAPI >= 0.142 runs generator dependencies with the DEFAULT ("request")
scope AFTER the response has been sent, so `get_db`'s commit landed after the
client had already fired the next request — which then read pre-commit state.
The API now pins the session to the FUNCTION dependency scope
(srplatform/api/deps.DbSession): a 2xx response is only observable once its
writes are committed.

Two independent regressions:
  * structural (fast): every route's DB dependency must be function-scoped —
    a future route using the default scope silently reintroduces the race;
  * behavioural (db): with a deliberately SLOW commit, the immediately next
    request must still see the previous request's writes over real HTTP.
"""
from __future__ import annotations

import inspect
import threading
import time


# --------------------------------------------------------------------------- #
# Structural: no generator dependency may run its teardown after the response #
# --------------------------------------------------------------------------- #

def _walk_dependants(dependant):
    yield dependant
    for sub in dependant.dependencies:
        yield from _walk_dependants(sub)


def test_every_db_dependency_is_function_scoped():
    """A generator dependency with the default scope closes AFTER the response
    is sent (FastAPI >= 0.142), so its commit can land after the client's next
    request is already in flight. Every generator dependency reachable from a
    route must therefore pin scope='function'."""
    from srplatform.api.app import app
    from srplatform.api.deps import get_db

    db_dependants = 0
    for route in app.routes:
        dependant = getattr(route, "dependant", None)
        if dependant is None:
            continue
        for dep in _walk_dependants(dependant):
            call = dep.call
            if call is None:
                continue
            fn = getattr(call, "__wrapped__", call)
            if inspect.isgeneratorfunction(fn) or inspect.isasyncgenfunction(fn):
                assert dep.scope == "function", (
                    f"dependency {getattr(fn, '__qualname__', fn)} on route "
                    f"{getattr(route, 'path', route)} has scope {dep.scope!r}; "
                    "request-scoped generators commit AFTER the response is "
                    "sent — the next request can read pre-commit state "
                    "(use Depends(..., scope='function') / api.deps.DbSession)")
            if fn is get_db:
                db_dependants += 1
    assert db_dependants >= 30, (
        f"only {db_dependants} route dependencies resolve through api.deps.get_db "
        "— the shared session was bypassed or the wiring regressed")


# --------------------------------------------------------------------------- #
# Behavioural: a committed 2xx is visible to the very next request            #
# --------------------------------------------------------------------------- #

def _free_port():
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def test_write_is_visible_to_the_immediately_next_request(migrated_db,
                                                          test_db_url_owner,
                                                          tmp_path, monkeypatch):
    """Real uvicorn, REAL app, deliberately slow commit (150 ms): bootstrap →
    login → create session → read session must all succeed back-to-back.
    With the old request-scoped session the commit lands ~150 ms AFTER the
    response, so login gets 401 ('no such user') and the session read gets
    404 — exactly the intermittent CI signature, made deterministic here."""
    import uvicorn

    from srplatform import settings as st
    from srplatform.api import deps as api_deps
    from srplatform.api.app import app
    from tests.conftest import wipe_data
    from tests.helpers import api_json

    real_db = api_deps._db_ctx
    SLOW_MS = 0.15

    from contextlib import contextmanager

    @contextmanager
    def slow_db():
        with real_db() as s:
            yield s
            time.sleep(SLOW_MS)   # widens the pre-commit window on purpose

    monkeypatch.setattr(api_deps, "_db_ctx", slow_db)
    monkeypatch.setenv("SR_ENV", "dev")
    monkeypatch.setenv("SAFETY_STATE_FILE", str(tmp_path / "safety.json"))
    monkeypatch.setenv("RECORDINGS_DIR", str(tmp_path / "rec"))
    st.get_settings.cache_clear()

    wipe_data(test_db_url_owner)
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port,
                                           log_level="error"))
    threading.Thread(target=server.run, daemon=True).start()
    deadline = time.time() + 15
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started, "uvicorn never started — requests below would be noise"
    base = f"http://127.0.0.1:{port}"
    try:
        t0 = time.monotonic()
        api_json("POST", f"{base}/auth/bootstrap",
                 body={"username": "drew", "password": "operator-testpw-9"},
                 expect=(201,))
        elapsed = time.monotonic() - t0
        # the probe must actually be armed: the response may only arrive AFTER
        # the slowed commit (function scope), i.e. never before SLOW_MS.
        assert elapsed >= SLOW_MS, (
            f"bootstrap returned in {elapsed*1000:.0f}ms — the commit was not "
            "on the response path, so this test proves nothing")

        tok = api_json("POST", f"{base}/auth/login",
                       body={"username": "drew",
                             "password": "operator-testpw-9"})["token"]
        H = {"Authorization": f"Bearer {tok}"}
        sid = api_json("POST", f"{base}/sessions",
                       body={"scenario_id": "quick-win-01"}, headers=H,
                       expect=(201,))["session_id"]
        # immediate follow-up reads — the exact handoff that failed in CI
        sess = api_json("GET", f"{base}/sessions/{sid}", headers=H)
        assert sess["session_id"] == sid
    finally:
        server.should_exit = True
        st.get_settings.cache_clear()
