"""Plan 13 phase 4 — network-plane separation and the release-stage ladder.

DB layer: drives the real app. The ingest-only listener must expose nothing
but the authenticated enrollment/ingest routes; the stage ladder must
distinguish install-ready / lab-ready / attack-authorized with the explicit
operator gate.
"""
from __future__ import annotations

import pytest


@pytest.fixture
def _ingest_only():
    from srplatform.settings import get_settings
    import os
    os.environ["SR_API_INGEST_ONLY"] = "1"
    get_settings.cache_clear()
    yield
    os.environ.pop("SR_API_INGEST_ONLY", None)
    get_settings.cache_clear()


@pytest.mark.db
def test_ingest_only_listener_exposes_only_enroll_and_ingest(client, users,
                                                             _ingest_only):
    # general API/web/auth surface: invisible (404, not 401 — no advertising)
    for path in ("/sessions", "/healthz", "/readyz", "/stages", "/users",
                 "/scenarios"):
        r = client.get(path, headers=users["op"])
        assert r.status_code == 404, (path, r.status_code)
    # the two ingest routes ARE routed (auth/model errors prove routing)
    r = client.post("/ingest/auditd", json={}, headers=users["member"])
    assert r.status_code != 404
    r = client.post("/enroll/confirm", json={}, headers=users["member"])
    assert r.status_code != 404
    # methods are part of the allowlist
    r = client.get("/ingest/auditd", headers=users["member"])
    assert r.status_code == 404


@pytest.mark.db
def test_ingest_only_listener_bounds_bodies(client, users, _ingest_only):
    big = b"x" * 300_000  # > ingest_max_body_bytes (262144)
    r = client.post("/ingest/auditd", content=big,
                    headers={**users["member"],
                             "Content-Type": "application/json"})
    assert r.status_code == 413


@pytest.mark.db
def test_internal_listener_unaffected(client, users):
    # default (loopback/internal plane): full app, guard inert
    assert client.get("/healthz").status_code == 200


@pytest.mark.db
def test_stages_ladder_requires_operator(client, users):
    r = client.get("/stages", headers=users["member"])
    assert r.status_code == 403


@pytest.mark.db
def test_stages_ladder_progression(client, users):
    import os

    from srplatform.settings import get_settings
    r = client.get("/stages", headers=users["op"])
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["install_ready"] is True, body["issues"]
    assert body["lab_ready"] is True          # fake broker latch answers
    assert body["attack_authorized"] is False  # explicit gate defaults off
    assert body["operator_gate"] is False

    os.environ["SR_ATTACK_AUTHORIZED"] = "1"
    get_settings.cache_clear()
    try:
        body = client.get("/stages", headers=users["op"]).json()
        assert body["attack_authorized"] is True
    finally:
        os.environ.pop("SR_ATTACK_AUTHORIZED", None)
        get_settings.cache_clear()


def test_ingest_only_listener_skips_startup_reconciliation(monkeypatch):
    """A second copy of the app serving the guest range address must NEVER
    reconcile runs, clear operation claims, or start schedulers: a listener
    restart would otherwise interrupt live operations and remove their
    serialization."""
    import srplatform.api.app as appmod
    calls = []
    monkeypatch.setattr(appmod.runs_svc, "reconcile_on_startup",
                        lambda: calls.append("runs"))
    monkeypatch.setenv("SR_API_INGEST_ONLY", "1")
    from srplatform.settings import get_settings
    get_settings.cache_clear()
    try:
        appmod._startup()
    finally:
        monkeypatch.delenv("SR_API_INGEST_ONLY", raising=False)
        get_settings.cache_clear()
    assert calls == [], calls


def test_ingest_body_cap_counts_actual_bytes_not_headers():
    """Chunked (lengthless) oversized bodies get 413: the cap is enforced
    on bytes received, never on Content-Length."""
    import asyncio

    from fastapi import Request
    from srplatform.api.app import _ingest_only_guard
    import os
    os.environ["SR_API_INGEST_ONLY"] = "1"
    os.environ["SR_INGEST_MAX_BODY_BYTES"] = "16"
    from srplatform.settings import get_settings
    get_settings.cache_clear()
    try:
        chunks = [b"x" * 8, b"y" * 8, b"z" * 8]  # 24 > 16, no length header
        it = iter([{"type": "http.request", "body": c, "more_body": True}
                   for c in chunks[:-1]] + [
                       {"type": "http.request", "body": chunks[-1],
                        "more_body": False}])

        async def receive():
            return next(it)

        scope = {"type": "http", "method": "POST", "path": "/ingest/auditd",
                 "headers": []}  # no content-length: chunked-style
        req = Request(scope, receive)
        called = []

        async def downstream(r):
            body = await r.body()
            called.append(body)
            from fastapi.responses import JSONResponse
            return JSONResponse({"ok": True})

        resp = asyncio.get_event_loop().run_until_complete(
            _ingest_only_guard(req, downstream))
        assert resp.status_code == 413, resp.status_code
        assert called == [], "oversized body must not reach the route"
    finally:
        os.environ.pop("SR_API_INGEST_ONLY", None)
        os.environ.pop("SR_INGEST_MAX_BODY_BYTES", None)
        get_settings.cache_clear()
