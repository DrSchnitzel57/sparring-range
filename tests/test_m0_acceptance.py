"""M0 acceptance tests — one test per acceptance criterion from Part 5/M0.

  1. Range datapath is default-DENY and machine-checkable: the rendered nft
     rulesets are default-drop and parse (nft -c when available), and the
     emergency ruleset drops ALL range traffic.
  2. killswitch stops red agent worker processes AND drops the range datapath —
     independently, truthfully reported, and the latch survives a restart.
  3. db migrate creates the full schema; an UPDATE on events RAISES.
"""
import shutil
import signal
import subprocess

import pytest

REPO = "infra/firewall"


# --- criterion 1 ---------------------------------------------------------------
def test_m0_rendered_rulesets_are_default_deny_and_parse():
    from srplatform.safety.firewall import (render_baseline_ruleset,
                                             render_emergency_ruleset)

    base = render_baseline_ruleset()
    # default-deny semantics: everything from the range that is not an
    # EXPLICIT allow before this point hits an unconditional drop
    assert "meta nfproto ipv4 drop" in base and "meta nfproto ipv6 drop" in base
    assert "10.66.0.0/24" in base          # range-scoped
    assert "vmbr1" in base                 # management bridges untouched

    em = render_emergency_ruleset()
    assert 'iifname "vmbr1" drop' in em and 'oifname "vmbr1" drop' in em
    assert "table bridge" in em            # no same-bridge L2 escape


@pytest.mark.packet
def test_m0_rendered_rulesets_pass_the_real_nft_parser():
    """Machine-checkable parsing with the REAL nft ruleset parser (milestone
    01 layer split: this needs the nft binary, so it is part of the required
    packet layer instead of skipping in the infrastructure-free default)."""
    from tests.helpers import require_packet_prereq
    require_packet_prereq()
    from srplatform.safety.firewall import (render_baseline_ruleset,
                                             render_emergency_ruleset)

    nft = shutil.which("nft")
    for rs in (render_baseline_ruleset(), render_emergency_ruleset()):
        with open(f"/tmp/sr-m0-check-{abs(hash(rs)) % 9999}.nft", "w") as f:
            f.write(rs)
            name = f.name
        r = subprocess.run([nft, "-c", "-f", name], capture_output=True, text=True)
        import os
        os.unlink(name)
        assert r.returncode == 0, f"nft -c rejected ruleset:\n{r.stderr}"


# --- criterion 2 ---------------------------------------------------------------
def test_m0_killswitch_stops_workers_and_drops_datapath(tmp_path):
    from srplatform.safety import Supervisor
    from srplatform.safety.runregistry import RunHandle, run_registry
    from tests.helpers import FakeDatapath

    proc = subprocess.Popen(["sleep", "300"], start_new_session=True)
    dp = FakeDatapath()
    sup = Supervisor(datapath=dp, state_file=str(tmp_path / "state.json"))
    run_registry.add(RunHandle(run_id="r1", pid=proc.pid, pgid=proc.pid,
                               process=proc, meta={}))
    try:
        result = sup.engage("test")
        assert result["killswitch"] == "engaged"
        # (a) worker process GROUP terminated
        assert proc.poll() is not None or proc.wait(timeout=5) in (-signal.SIGTERM, 143, -15)
        # (b) datapath controller invoked INDEPENDENTLY of (a)
        assert "apply_emergency" in dp.calls
        assert result["latched"] is True
    finally:
        if proc.poll() is None:
            proc.kill()

    # the latch outlives process restarts (fresh Supervisor, same state file)
    sup2 = Supervisor(datapath=dp, state_file=str(tmp_path / "state.json"))
    assert sup2.latch_status()["latched"] is True
    allowed, reasons = sup2.start_gate()
    assert not allowed and any("LATCHED" in r for r in reasons)


def test_m0_partial_engagement_is_reported_truthfully(tmp_path):
    from srplatform.safety import Supervisor
    from tests.helpers import FakeDatapath

    class BadDatapath(FakeDatapath):
        def apply_emergency(self):
            raise RuntimeError("nft exploded")

    sup = Supervisor(datapath=BadDatapath(), state_file=str(tmp_path / "s.json"))
    result = sup.engage("test")
    assert result["killswitch"] == "engaged-partial"
    assert "Datapath drop FAILED" in result["warning"]


def test_m0_release_requires_datapath_and_invalidates_evidence(tmp_path):
    from srplatform.safety import Supervisor
    from tests.helpers import FakeDatapath

    dp = FakeDatapath()
    sup = Supervisor(datapath=dp, state_file=str(tmp_path / "s.json"))
    sup.engage("test")
    out = sup.release()
    assert out["killswitch"] == "released"
    assert sup.latch_status()["latched"] is False
    # after release, the gate DEMANDS FRESH evidence (mechanism != noop) —
    # unconditional: a conditional assertion here once let the test pass when
    # the claimed invalidation did not happen (follow-up review R04)
    allowed, reasons = sup.start_gate()
    assert not allowed, "release must invalidate evidence — start cannot stay authorized"
    assert any("baseline verification" in r or "datapath proof" in r for r in reasons), reasons


# --- criterion 3 -----------------------------------------------------------------
@pytest.mark.db
def test_m0_migrate_creates_schema_and_update_events_raises(migrated_db, test_db_url_app):
    import sqlalchemy as sa
    from sqlalchemy import create_engine

    eng_owner = create_engine(migrated_db)
    eng_app = create_engine(test_db_url_app)

    with eng_owner.connect() as c:
        for t in ("users", "sessions", "events", "agent_state", "login_tokens",
                  "service_tokens", "range_lease", "deployments", "runs",
                  "safety_state", "safety_records", "recordings"):
            assert c.execute(sa.text(f"SELECT 1 FROM {t} LIMIT 1")).fetchall() is not None
        # scoring view from migration 0005
        assert c.execute(sa.text("SELECT 1 FROM v_score_items LIMIT 1")).fetchall() is not None

    with eng_app.connect() as c:
        c.execute(sa.text(
            "INSERT INTO events (session_id, ts, actor, action_type, payload) "
            "VALUES (NULL, now(), 'system', 'verifier', '{\"test\": true}')"
        ))
        c.commit()

    with eng_app.connect() as c:
        with pytest.raises(sa.exc.ProgrammingError):
            c.execute(sa.text("UPDATE events SET action_type='x' WHERE action_type='verifier'"))

    # trigger also stops the OWNER (defence in depth: nothing edits the evidence)
    with eng_owner.connect() as c:
        with pytest.raises(sa.exc.InternalError):
            c.execute(sa.text("UPDATE events SET action_type='x' WHERE action_type='verifier'"))
        with pytest.raises(sa.exc.InternalError):
            c.execute(sa.text("DELETE FROM events WHERE action_type='verifier'"))
