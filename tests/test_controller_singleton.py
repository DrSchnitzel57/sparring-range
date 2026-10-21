"""The controller singleton and the visible startup contract (plan 15).

Only ONE API process may act as the controller: the reconciler, the claim
cleaner and the control-lease heartbeat.  A process that does not hold the
controller lock must not run them, and it must say so - silently pretending
to be healthy is the failure mode this closes.
"""
from __future__ import annotations

import pytest

from srplatform.controller_lock import CONTROLLER_LOCK_KEY, ControllerLock


def test_lock_key_is_namespaced_and_stable():
    assert CONTROLLER_LOCK_KEY == 0x53524331
    assert ControllerLock().key == CONTROLLER_LOCK_KEY


def test_a_lock_that_cannot_reach_the_database_is_not_a_silent_success():
    lock = ControllerLock()
    got = lock.acquire("postgresql://nobody@127.0.0.1:1/none", timeout_s=0.2)
    assert got is False
    assert lock.acquired is False
    assert lock.detail, "the failure reason must be recorded"


def test_readiness_reports_the_controller_and_startup_failures():
    from srplatform.api import app as app_mod

    app_mod.app.state.startup_issues = ["reconcile on startup: boom"]
    app_mod.app.state.controller = False
    app_mod.app.state.controller_detail = "another controller holds the lock"
    try:
        body = app_mod.readyz()
    finally:
        app_mod.app.state.startup_issues = []
        app_mod.app.state.controller = True
        app_mod.app.state.controller_detail = "controller lock held"
    assert body["controller"]["ok"] is False
    assert "another controller holds the lock" in " ".join(body["issues"])
    assert any("reconcile on startup" in i for i in body["issues"])
    assert body["ready"] is False


def test_readiness_reports_a_healthy_controller():
    from srplatform.api import app as app_mod

    app_mod.app.state.startup_issues = []
    app_mod.app.state.controller = True
    app_mod.app.state.controller_detail = "controller lock held"
    body = app_mod.readyz()
    assert body["controller"]["ok"] is True
    assert not any(i.startswith("controller:") for i in body["issues"])


@pytest.mark.db
def test_only_one_process_can_be_the_controller(client):
    """Two locks against the same database: the second one is refused."""
    from srplatform.settings import get_settings

    first = ControllerLock()
    assert first.acquire(get_settings().postgres_url, timeout_s=5.0) is True
    try:
        second = ControllerLock()
        assert second.acquire(get_settings().postgres_url, timeout_s=1.0) is False
        assert "another controller" in second.detail
    finally:
        first.release()
    third = ControllerLock()
    assert third.acquire(get_settings().postgres_url, timeout_s=5.0) is True
    third.release()
