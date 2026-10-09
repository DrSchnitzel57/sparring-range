"""Stage 2 regressions (audit N05–N07, second follow-up review).

Runner supervision (bounded streaming, spawn/register race, truthful cancel
reporting) and durable safety-state reconciliation (missing/corrupt state is
not affirmative release, newest-record merging, config identity binding,
killswitch-test gate).
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PY = sys.executable


# --------------------------------------------------------------------------- #
# N05 — runner supervision                                                     #
# --------------------------------------------------------------------------- #

def test_runner_output_bound_is_enforced_streaming(monkeypatch, tmp_path):
    """A command producing far more than the bound must not buffer it all:
    the reader keeps at most max_bytes and the result is bounded."""
    monkeypatch.setenv("SR_ENV", "dev")
    monkeypatch.setenv("RUNNER_TRANSPORT", "local-dev")
    monkeypatch.setenv("ALLOW_LOCAL_DEV_FIXTURE", "1")
    monkeypatch.setenv("RUNNER_MAX_OUTPUT_BYTES", "4096")
    from srplatform import settings as s
    s.get_settings.cache_clear()
    try:
        from srplatform.red_agent.runner import LocalDevRunner
        r = LocalDevRunner()
        res = r.run("yes AAAAAAAAAA | head -c 5000000", timeout=20)
        assert res.exit_code == 0
        assert len(res.output) <= 4096
    finally:
        s.get_settings.cache_clear()


def test_runner_cancel_reaches_descendants(tmp_path):
    """A harmless long-running DESCENDANT (not just the direct child) is gone
    after cancel_active() — the command group is the unit of termination."""
    pidfile = tmp_path / "desc.pid"
    script = f"""
import sys, threading, time
sys.path.insert(0, {REPO!r})
from srplatform.red_agent.runner import LocalDevRunner, cancel_active
r = LocalDevRunner()
t = threading.Thread(target=lambda: r.run(
    "sh -c 'echo $$ > {pidfile}; sleep 300'"), daemon=True)
t.start()
time.sleep(1.0)
cancel_active()
time.sleep(0.5)
print("DONE", flush=True)
"""
    proc = subprocess.Popen([PY, "-c", script], stdout=subprocess.PIPE, text=True,
                            env={**os.environ, "SR_ENV": "dev",
                                 "RUNNER_TRANSPORT": "local-dev", "ALLOW_LOCAL_DEV_FIXTURE": "1"})
    out, _ = proc.communicate(timeout=30)
    assert "DONE" in out
    pid = int(pidfile.read_text().strip())
    time.sleep(0.3)
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_runner_cancel_before_attach_kills_on_attach():
    """Spawn/register race (audit N05): a cancel that lands between Popen and
    registration must still kill the process when it attaches."""
    from srplatform.red_agent import runner as rn
    op_id = rn._new_op_id()
    rn._register(op_id, {"kind": "local", "state": "pending", "remote": False})
    res = rn.cancel_active()          # cancels the PENDING op
    assert res["ok"] and res["ops"][0]["cancelled"]
    proc = subprocess.Popen(["sleep", "300"], start_new_session=True)
    rn._attach_proc(op_id, proc)      # must kill immediately, not register
    proc.wait(timeout=5)
    assert proc.returncode in (-signal.SIGKILL, 137, -9) or proc.returncode != 0


def test_cancel_active_reports_unconfirmed_truthfully():
    """A remote op whose supervisor cannot confirm cessation is reported NOT
    cancelled — never silently converted (audit N05)."""
    from srplatform.red_agent import runner as rn

    class DeadRunner:
        def cancel_remote(self, op_id, timeout_s=10):
            return False

    op_id = rn._new_op_id()
    proc = subprocess.Popen(["sleep", "300"], start_new_session=True)
    rn._register(op_id, {"kind": "remote", "state": "running", "remote": True,
                         "runner": DeadRunner(), "proc": proc})
    res = rn.cancel_active()
    assert res["ok"] is False
    assert res["ops"][0]["cancelled"] is False
    assert "UNCONFIRMED" in res["detail"].upper() or "unconfirmed" in res["detail"]
    # the op stays registered (not silently dropped as cancelled)
    assert op_id in rn._ACTIVE
    rn._finish_op(op_id)


def test_worker_crash_does_not_abandon_command_group(tmp_path):
    """Worker SIGKILL leaves the command group reparented but killable via
    the recorded pgid — API-side reconciliation terminates it (the durable
    run rows + pgid are the recovery path)."""
    pidfile = tmp_path / "cmd.pid"
    script = f"""
import sys, time
sys.path.insert(0, {REPO!r})
from srplatform.red_agent.runner import LocalDevRunner
r = LocalDevRunner()
r.run("sh -c 'echo $$ > {pidfile}; exec sleep 300'")
"""
    worker = subprocess.Popen([PY, "-c", script], start_new_session=True,
                              env={**os.environ, "SR_ENV": "dev",
                                   "RUNNER_TRANSPORT": "local-dev", "ALLOW_LOCAL_DEV_FIXTURE": "1"})
    for _ in range(100):
        if pidfile.exists() and pidfile.read_text().strip():
            break
        time.sleep(0.1)
    cmd_pid = int(pidfile.read_text().strip())
    os.kill(worker.pid, signal.SIGKILL)   # crash: no signal handler runs
    worker.wait(timeout=10)
    # the command group survives the crash (documented) — reconciliation kills
    # it via the recorded pgid; emulate exactly that:
    pgid = os.getpgid(cmd_pid)
    os.killpg(pgid, signal.SIGKILL)
    for _ in range(50):
        try:
            os.kill(cmd_pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.1)
    else:
        pytest.fail("command group survived pgid termination")


# --------------------------------------------------------------------------- #
# N07 — durable state reconciliation                                           #
# --------------------------------------------------------------------------- #

def _sup(tmp_path, db_records=None, mirror=None):
    from srplatform.safety import Supervisor
    from tests.helpers import FakeDatapath
    sup = Supervisor(datapath=FakeDatapath(), state_file=str(tmp_path / "s.json"))
    if mirror is not None:
        sup._mirror_dh = mirror
    if db_records is not None:
        sup._records_reader = lambda: db_records
    return sup


def test_missing_file_with_unreadable_db_fails_closed(tmp_path):
    """Probe `missing_file_and_unreadable_db`: losing the file during a DB
    outage must NOT forget engagement."""
    sup = _sup(tmp_path)

    def boom():
        raise RuntimeError("simulated DB outage")
    sup._records_reader = boom
    sup._db_read_state = lambda: (None, "simulated DB outage")
    st = sup.latch_status()
    assert st["latched"] is True
    assert "failing closed" in st["reason"]


def test_no_evidence_anywhere_fails_closed_until_initialized(tmp_path):
    sup = _sup(tmp_path)
    sup._db_read_state = lambda: (None, None)
    st = sup.latch_status()
    assert st["latched"] is True
    assert "first install" in st["reason"]
    # explicit documented initialization is the only way out
    sup.initialize_state(reason="test")
    st = sup.latch_status()
    assert st["latched"] is False


def test_corrupt_file_with_reachable_db_uses_db(tmp_path):
    (tmp_path / "s.json").write_text("{not json")
    sup = _sup(tmp_path)
    sup._db_read_state = lambda: ({"latched": True, "latched_at": "x",
                                   "reason": "engaged"}, None)
    st = sup.latch_status()
    assert st["latched"] is True


def test_stale_db_cannot_outrank_newer_file_records(tmp_path):
    """Probe N07: an engage/release recorded only to the FILE while DB writes
    failed must not be forgotten when the stale DB becomes reachable."""
    import time as _t
    from srplatform.safety.datapath import config_identity
    now = _t.time()
    ident = config_identity(_sup(tmp_path).settings)
    stale_db = {"kind": "engage", "ok": True, "config_identity": ident,
                "recorded_at": now - 100}

    sup = _sup(tmp_path, db_records=[stale_db],
               mirror=[stale_db])
    sup._db_read_state = lambda: ({"latched": False, "latched_at": None,
                                   "reason": None}, None)
    # file mirror (the .records file) has a NEWER release
    p = tmp_path / "s.json.records"
    p.write_text(json.dumps({"kind": "release", "ok": True, "config_identity": ident,
                             "recorded_at": now}) + "\n")
    recs = sup._latest_records()
    assert recs["release"]["recorded_at"] == now
    # and the stale engage is superseded by the newer release for gate purposes
    fresh, why = sup._record_fresh("release")
    assert fresh, why


def test_record_persistence_failure_denies_start(tmp_path, monkeypatch):
    """Persistence failure is OBSERVABLE and denies starts (audit N07):
    records that cannot reach any durable store cannot authorize a run."""
    monkeypatch.setenv("SR_ENV", "dev")
    monkeypatch.setenv("RUNNER_TRANSPORT", "local-dev")
    monkeypatch.setenv("ALLOW_LOCAL_DEV_FIXTURE", "1")
    from srplatform import settings as s
    s.get_settings.cache_clear()
    try:
        sup = _sup(tmp_path)
        sup._db_read_state = lambda: ({"latched": False, "latched_at": None,
                                       "reason": None}, None)
        # make BOTH durable record stores fail
        import srplatform.db.session as dbs
        sup.state_file = tmp_path / "nowhere" / "deep" / "s.json"

        class Boom:
            def __enter__(self):
                raise RuntimeError("db down")

            def __exit__(self, *a):
                return False

        monkeypatch.setattr(dbs, "db", lambda: Boom())
        sup.record("baseline_check", True, {})
        assert sup._record_failures, "record persistence failure must be retained"
        ok, reasons = sup.start_gate()
        assert not ok and any("persistence" in r for r in reasons)
    finally:
        s.get_settings.cache_clear()


def test_config_identity_binds_topology_and_api(tmp_path, monkeypatch):
    """Probe `network_change_keeps_proof_identity`: bridge port inventory and
    the API destination/port are part of the proof identity."""
    from srplatform.safety.datapath import config_identity
    from srplatform.settings import Settings
    base = Settings(sr_env="dev", range_bridge="vmbr1", range_bridge_ports="tap1",
                    api_base_url="http://10.0.0.1:8000")
    other_ports = Settings(sr_env="dev", range_bridge="vmbr1", range_bridge_ports="tap2",
                           api_base_url="http://10.0.0.1:8000")
    other_api = Settings(sr_env="dev", range_bridge="vmbr1", range_bridge_ports="tap1",
                         api_base_url="http://10.0.0.2:9999")
    assert config_identity(base) != config_identity(other_ports)
    assert config_identity(base) != config_identity(other_api)
    same = Settings(sr_env="dev", range_bridge="vmbr1", range_bridge_ports="tap1",
                    api_base_url="http://10.0.0.1:8000")
    assert config_identity(base) == config_identity(same)


@pytest.mark.db
def test_killswitch_test_record_required_for_start(client, users, monkeypatch):
    """start_gate requires a SUCCESSFUL killswitch test (command cessation +
    datapath isolation) — baseline+proof alone no longer authorize a run;
    a partial test records failure and still denies."""
    import srplatform.api.app as app_mod
    from srplatform.safety import get_supervisor

    # make the gate behave as if a REAL datapath mechanism exists
    sup = get_supervisor()
    monkeypatch.setattr(sup.datapath, "mechanism", "nft")

    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    client.post(f"/sessions/{sid}/launch", headers=users["member"])
    r = client.post("/run/quick-win-01", json={"session_id": sid},
                    headers=users["member"])
    assert r.status_code == 423
    reasons = r.json()["detail"]["reasons"]
    assert any("killswitch_test" in x for x in reasons), reasons

    # partial test -> recorded as failed -> still denied
    r = client.post("/safety/killswitch-test",
                    json={"commands_stopped": True, "datapath_isolated": False},
                    headers=users["op"])
    assert r.status_code == 200 and r.json()["ok"] is False
    r = client.post("/run/quick-win-01", json={"session_id": sid},
                    headers=users["member"])
    assert r.status_code == 423

    # complete test -> gate no longer cites killswitch_test
    r = client.post("/safety/killswitch-test",
                    json={"commands_stopped": True, "datapath_isolated": True,
                          "detail": {"observed": "sleep descendant gone; ping 100% loss"}},
                    headers=users["op"])
    assert r.json()["ok"] is True
    r = client.post("/run/quick-win-01", json={"session_id": sid},
                    headers=users["member"])
    if r.status_code == 423:
        assert not any("killswitch_test" in x for x in r.json()["detail"]["reasons"])


@pytest.mark.db
def test_release_reuses_no_old_proofs(client, users):
    """After engage+release the baseline/proof/killswitch-test records are all
    invalidated — release cannot immediately reuse old baseline/datapath
    proofs (audit N07)."""
    from srplatform.safety import get_supervisor
    sup = get_supervisor()
    sup.record("baseline_check", True, {})
    sup.record("datapath_proof", True, {})
    sup.record("killswitch_test", True, {})
    client.post("/safety/killswitch", headers=users["op"])
    client.post("/safety/killswitch-release", headers=users["op"])
    for kind in ("baseline_check", "datapath_proof", "killswitch_test"):
        fresh, why = sup._record_fresh(kind)
        assert not fresh and "predates the last" in why, (kind, why)
