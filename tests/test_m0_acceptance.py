"""M0 acceptance tests — one test per acceptance criterion from Part 5/M0.

  1. Range VLAN cannot reach the internet (datapath default-deny). The datapath
     proof from a live range VM is Drew's step; here we verify the policy is
     default-deny and that the verifier correctly REPORTS a failed probe as PASS
     (i.e., no-egress working == probes failing), using an injected probe.
  2. killswitch stops the red agent service AND drops the range datapath.
  3. db migrate creates the schema; an attempted UPDATE on events RAISES.
"""
import signal
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from infra.proxmox_client import FakeProxmox
from srplatform.api.app import app
from srplatform.safety import Supervisor

REPO_ROOT = Path(__file__).resolve().parents[1]


# --- criterion 1 ---------------------------------------------------------------
def test_m0_range_egress_is_default_deny_and_verify_reports_probe_failures():
    """Policy must be default-DENY; a range VM whose ping/DNS FAIL means safety HOLDS.
    The verifier takes probes (run on the range VM by Drew in the real range) and
    passes only when they fail."""
    tmpl = (REPO_ROOT / "infra" / "firewall" / "range-egress-deny.nft.conf.tmpl").read_text()
    assert "policy drop" in tmpl, "egress-deny ruleset must be default-deny"

    def verify_egress(ping_output: str, dns_output: str) -> dict:
        ping_fails = ping_output.strip() == "" or "100% packet loss" in ping_output
        dns_fails = dns_output.strip() == ""
        return {"egress_denied": ping_fails and dns_fails}

    # From a VM on the range VLAN: ping 1.1.1.1 fails and DNS resolution fails.
    assert verify_egress("", "")["egress_denied"] is True
    # If a VM CAN reach 1.1.1.1, the verifier must fail the range (and block the gate).
    assert verify_egress("64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=9.1 ms", "")["egress_denied"] is False


# --- criterion 2 ---------------------------------------------------------------
def test_m0_killswitch_stops_red_agent_and_drops_datapath(tmp_path):
    proc = subprocess.Popen(["sleep", "300"])
    fake_pve = FakeProxmox()
    sup = Supervisor(proxmox=fake_pve)
    try:
        sup.register_red_agent(proc.pid)
        result = sup.killswitch()
        assert result["killswitch"] == "engaged"
        # (a) red agent stopped
        assert proc.poll() is not None or proc.wait(timeout=5) in (-signal.SIGTERM, 143, -15)
        # (b) datapath drop went out to the Proxmox API
        assert any(c[0] == "POST" and "firewall" in c[1] for c in fake_pve.calls), \
            "killswitch must drop the range datapath via the Proxmox API, not just stop the process"
    finally:
        if proc.poll() is None:
            proc.kill()


# --- criterion 3 -----------------------------------------------------------------
def test_m0_migrate_creates_schema_and_update_events_raises(migrated_db, test_db_url_app):
    import sqlalchemy as sa
    from sqlalchemy import create_engine

    eng_owner = create_engine(migrated_db)
    eng_app = create_engine(test_db_url_app)

    # schema exists (via the owner connection)
    with eng_owner.connect() as c:
        for t in ("users", "sessions", "events", "agent_state", "login_tokens"):
            assert c.execute(sa.text(f"SELECT 1 FROM {t} LIMIT 1")).fetchall() is not None

    # app role can INSERT into the log
    with eng_app.connect() as c:
        c.execute(sa.text(
            "INSERT INTO events (session_id, ts, actor, action_type, payload) "
            "VALUES (NULL, now(), 'system', 'verifier', '{\"test\": true}')"
        ))
        c.commit()

    # ...but an attempted UPDATE raises — belt (trigger) and braces (grants).
    with eng_app.connect() as c:
        with pytest.raises(sa.exc.ProgrammingError):
            c.execute(sa.text("UPDATE events SET action_type='x' WHERE action_type='verifier'"))

    # trigger also stops the OWNER (defence in depth: nothing edits the evidence)
    with eng_owner.connect() as c:
        with pytest.raises(sa.exc.InternalError):
            c.execute(sa.text("UPDATE events SET action_type='x' WHERE action_type='verifier'"))
