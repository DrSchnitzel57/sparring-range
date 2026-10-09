"""Milestone 02 forward-upgrade contract: legacy deployments latch the range.

Migration 0011 is a DATA step: deployments that predate the broker authority
must NOT remain startable after the upgrade — the Supervisor latches until an
operator runs brokerctl reconcile-legacy and releases explicitly.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.db

REPO = Path(__file__).resolve().parents[1]
PY = os.sys.executable


def _alembic(*args) -> None:
    env = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1"}
    r = subprocess.run([PY, "-m", "alembic", *args], cwd=REPO, env=env,
                       capture_output=True, text=True)
    assert r.returncode == 0, f"alembic {' '.join(args)} failed:\n{r.stdout}\n{r.stderr}"


def _safety_row():
    from sqlalchemy import text
    from srplatform.db.session import db
    with db() as s:
        return s.execute(text(
            "SELECT latched, reason FROM safety_state WHERE id = 1")).fetchone()


def test_m0011_upgrade_latches_legacy_deployments(client, users):
    from sqlalchemy import text
    from srplatform.db.models import Deployment
    from srplatform.db.session import db

    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    with db() as s:
        s.add(Deployment(session_id=sid, scenario_id="quick-win-01",
                         status="ready",
                         resources=[{"vmid": 210, "host": "web01",
                                     "state": "created", "name": "legacy"}]))
        s.commit()

    _alembic("downgrade", "0010")
    # pre-upgrade shape: no latch row forced by the migration yet
    _alembic("upgrade", "head")
    row = _safety_row()
    assert row is not None and row[0] is True, \
        "legacy deployments survived the upgrade unlatched"
    assert "reconcile-legacy" in (row[1] or "")
    with db() as s:
        rec = s.execute(text(
            "SELECT detail FROM safety_records WHERE config_identity = "
            "'migration-0011'")).fetchone()
    assert rec is not None, "upgrade latch left no durable record"

    # idempotent: re-running the upgrade changes nothing further
    _alembic("upgrade", "head")
    assert _safety_row()[0] is True

    # the Supervisor's conservative reconciliation HONORS the DB mirror:
    # even with an unlatched state FILE, the DB latch denies starts.
    from srplatform.safety import Supervisor
    from srplatform.safety.datapath import NoopDatapath
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        state = Path(td) / "state.json"
        # an UNLATCHED state file written directly (bypassing the supervisor,
        # which would mirror to the DB): the DB mirror must still deny.
        state.write_text('{"latched": false}')
        sup = Supervisor(datapath=NoopDatapath(), state_file=str(state))
        st = sup.latch_status()
        assert st["latched"] is True, "DB upgrade latch was ignored"
        ok, reasons = sup.start_gate()
        assert not ok and any("latched" in r.lower() for r in reasons)


def test_m0011_upgrade_without_legacy_deployments_does_not_latch(client, users):
    _alembic("downgrade", "0010")
    _alembic("upgrade", "head")
    row = _safety_row()
    assert row is None or row[0] is False, \
        "a clean upgrade of an empty range must not latch"
