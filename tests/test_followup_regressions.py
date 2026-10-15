"""Follow-up review regressions (docs/FOLLOWUP_REVIEW.md R01–R12).

One focused production-boundary test per acceptance blocker. These are written
against the REAL code paths (real HTTP where the finding was about a boundary),
not doubles that implement a different protocol than production.
"""
import asyncio
import json
import os
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
PY = sys.executable

from tests.helpers import ScriptedHostExec, api_json, tool  # noqa: E402
from tests.conftest import launch_and_wait, wait_operation, wipe_data


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# =========================================================================== #
# R10 — model gateway: a timeout during execution must not kill the queue    #
# =========================================================================== #

def test_r10_timeout_during_execution_keeps_worker_and_queue_alive():
    from srplatform.model_gateway import PRIORITY_RED, ModelGateway

    gw = ModelGateway()
    started = threading.Event()

    def slow():
        started.set()
        time.sleep(1.0)
        return "late"

    fut = gw.submit(PRIORITY_RED, "slow", slow)
    started.wait(5)
    with pytest.raises(Exception):  # TimeoutError from Future.result
        gw.wait(fut, timeout=0.05)

    # the sole worker thread must survive; a queued request must complete
    f2 = gw.submit(PRIORITY_RED, "next", lambda: "ok")
    assert f2.result(timeout=5) == "ok"
    assert gw._worker.is_alive()


def test_r10_task_exception_does_not_kill_worker(monkeypatch):
    from srplatform.model_gateway import PRIORITY_RED, ModelGateway
    import srplatform.model_gateway as mg
    # Pilot step 3 added the bounded retry policy (3 attempts, 5/15 s); this
    # test is about the GATEWAY WORKER surviving an exhausted task — patch
    # the retry sleep so the attempts land immediately (the retry policy
    # itself has its own tests in tests/test_pilot_sustained_attacker.py).
    monkeypatch.setattr(mg, "_sleep", lambda s: None)

    gw = ModelGateway()

    def boom():
        raise RuntimeError("model exploded")

    f1 = gw.submit(PRIORITY_RED, "boom", boom)
    with pytest.raises(RuntimeError):
        f1.result(timeout=5)
    f2 = gw.submit(PRIORITY_RED, "after", lambda: 42)
    assert f2.result(timeout=5) == 42
    assert gw._worker.is_alive()


# =========================================================================== #
# R11 — auditd parsing: record order, EOF flush, delivery independence       #
# =========================================================================== #

_SYSCALL_FIRST = [
    'type=SYSCALL msg=audit(1700000000.100:42): entry=1 success=yes exit=0 a0=1 uid=1000 '
    'comm="bash" exe="/usr/bin/bash" key="sparring_persistence"',
    'type=EXECVE msg=audit(1700000000.100:42): argc=3 a0="/bin/sh" a1="63" a2="746f756368"',
    'type=PROCTITLE msg=audit(1700000000.100:42): proctitle=2F62696E2F736800',
]
_SYSCALL_LAST = [
    'type=EXECVE msg=audit(1700000000.200:43): argc=1 a0="id"',
    'type=SYSCALL msg=audit(1700000000.200:43): success=yes exit=0 uid=0 comm="id" '
    'exe="/usr/bin/id" key="sparring_accounts"',
]


def test_r11_syscall_first_event_keeps_attribution_fields():
    from telemetry.shipper import build_command_event, group_event_records

    groups = list(group_event_records(iter(_SYSCALL_FIRST)))
    assert len(groups) == 1, "SYSCALL-first event must group into ONE event"
    ev = build_command_event("h", groups[0], "m", "b")
    assert ev is not None
    # attribution fields come from SYSCALL and must NOT be lost
    assert ev["uid"] == "1000" and ev["comm"] == "bash" and ev["exe"] == "/usr/bin/bash"
    assert ev["audit_key"] == "sparring_persistence"
    assert ev["argv"].startswith("/bin/sh")  # EXECVE decoded in the same event


def test_r11_trailing_group_flushed_on_eof_and_eoe():
    from telemetry.shipper import group_event_records

    # trailing group with NO SYSCALL yet (interleaved stream) must flush at EOF
    lines = list(_SYSCALL_FIRST) + [
        'type=EXECVE msg=audit(1700000000.300:44): argc=1 a0="whoami"',
    ]
    groups = list(group_event_records(iter(lines)))
    assert [g["source_id"] for g in groups] == [42, 44]

    # EOE closes an event
    eoe = list(_SYSCALL_FIRST[:1]) + [
        'type=EOE msg=audit(1700000000.100:42):']
    groups = list(group_event_records(iter(eoe)))
    assert len(groups) == 1


def test_r11_delivery_backoff_on_false_and_idle_flush(tmp_path):
    """Delivery must run WITHOUT new input (idle outage recovery) and the
    false-return path must drive exponential backoff."""
    import telemetry.shipper as sh

    spool = sh.Spooler(str(tmp_path / "spool"), max_bytes=10_000)
    spool.append({"argv": "id", "source_id": "1"})
    sleeps = []
    calls = {"n": 0}

    def fake_ship(api, token, events):
        calls["n"] += 1
        return calls["n"] > 2  # fail twice, then recover

    orig = sh.ship_events
    sh.ship_events = fake_ship
    try:
        loop = sh.DeliveryLoop("http://x", "t", spool, sleeper=sleeps.append)
        assert loop.flush_once() is False
        assert loop.flush_once() is False
        assert loop.flush_once() is True
        assert sleeps == [1.0, 2.0], f"backoff must grow: {sleeps}"
        assert spool.pending() == []
    finally:
        sh.ship_events = orig


def test_r11_spool_byte_bounds_and_atomic_trim(tmp_path):
    import telemetry.shipper as sh

    spool = sh.Spooler(str(tmp_path / "sp"), max_bytes=400)
    for i in range(50):
        spool.append({"i": i, "pad": "x" * 40})
    size = os.path.getsize(spool.path)
    assert size <= 400, f"spool exceeded byte bound: {size}"
    assert spool.dropped > 0
    assert Path(spool.gap_path).exists()
    # no temp litter; pending still parses
    assert not (tmp_path / "sp" / "pending.ndjson.tmp").exists()
    assert spool.pending()


# =========================================================================== #
# R06 — Proxmox clone uses the documented `newid`; fake rejects inventions   #
# =========================================================================== #

def test_r06_clone_posts_documented_newid_and_fake_rejects_unknowns():
    from infra.proxmox_client import FakePVEHttp, ProxmoxClient  # adapter-level test

    http = FakePVEHttp()
    http.vms[9001] = {"name": "tpl", "template": 9001, "status": "stopped"}
    c = ProxmoxClient(api=http)
    upid = c.clone_template("n", 9001, 300, "vm-x")
    c.wait_for_task("n", upid, poll_s=0)
    clone_req = [r for r in http.requests if "/clone" in r[1]][0]
    assert clone_req[2].get("newid") == 300, "documented parameter is newid"
    assert "newvmid" not in clone_req[2]

    # the fake REJECTS invented parameters instead of mirroring them
    with pytest.raises(RuntimeError, match="unrecognized"):
        http.post("/nodes/n/qemu/9001/clone", newvmid=301, name="y")
    with pytest.raises(RuntimeError, match="newid"):
        http.post("/nodes/n/qemu/9001/clone", name="y")


# =========================================================================== #
# R09 — backend scoring must forward the requested polarity                  #
# =========================================================================== #

pytestmark_db = pytest.mark.db


@pytest.mark.db
def test_r09_absent_polarity_flips_with_host_state(client, users, fake_pve,
                                                   monkeypatch):
    from srplatform import verification_service

    sid, out = None, None
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    ip = launch_and_wait(client, users["member"], sid)["result"]["connections"][0]["ip"]

    def cron_card(cron_d_lines):
        execd = ScriptedHostExec({ip: [
            ("ls -1 /etc/cron.d", (0, cron_d_lines + "\n---\n")),
        ]})
        verification_service.set_verifier_exec(execd)
        try:
            from srplatform.db.session import db as db_ctx
            with db_ctx() as s:
                return verification_service.build_scorecard(s, sid)
        finally:
            verification_service.set_verifier_exec(None)

    clean = cron_card("e2scrub_all")
    cron_items = [i for i in clean["items"] if i["verifier"] == "cron_persistence_present"]
    assert cron_items and cron_items[0]["expected"] == "absent"
    assert cron_items[0]["status"] == "passed" and cron_items[0]["awarded"] == 10, \
        "clean host must EARN the expect:absent check"

    compromised = cron_card("e2scrub_all\nbackdoor")
    cron_items = [i for i in compromised["items"] if i["verifier"] == "cron_persistence_present"]
    assert cron_items[0]["status"] == "failed" and cron_items[0]["awarded"] == 0, \
        "persistence present must NOT earn the expect:absent check"


# =========================================================================== #
# R04 — latch fail-closed, evidence invalidation, attestation schema         #
# =========================================================================== #

# The safety Supervisor mirrors latch/record state to the DB (audit N07), so
# this gate regression REQUIRES the disposable database — it was the baseline's
# unmarked-DB-dependency leak (milestone 01: honest layer classification).
@pytest.mark.db
def test_r04_release_invalidates_previously_valid_evidence(migrated_db,
                                                           tmp_path, monkeypatch):
    monkeypatch.setenv("SR_ENV", "dev")
    monkeypatch.setenv("RUNNER_TRANSPORT", "local-dev")
    monkeypatch.setenv("ALLOW_LOCAL_DEV_FIXTURE", "1")
    from srplatform.settings import get_settings
    get_settings.cache_clear()
    try:
        from srplatform.safety import Supervisor
        from tests.helpers import FakeDatapath

        sup = Supervisor(datapath=FakeDatapath(), state_file=str(tmp_path / "s.json"))
        sup.initialize_state(reason="test bootstrap")
        # valid, fresh evidence recorded BEFORE an engage/release cycle
        sup.record("baseline_check", True, {})
        sup.record("datapath_proof", True, {})
        sup.record("killswitch_test", True, {})
        ok, why = sup.start_gate()
        assert ok, f"fresh evidence should pass the gate pre-cycle: {why}"

        sup.engage("test")
        sup.release()
        ok, reasons = sup.start_gate()
        assert not ok, "pre-release evidence must NOT re-authorize a start"
        assert any("predates the last" in r for r in reasons), reasons
    finally:
        get_settings.cache_clear()


def test_r04_probe_schema_distinguishes_isolation_from_reachability():
    from srplatform.safety import probes_attest_isolation

    ok, _ = probes_attest_isolation({"ping": "2 packets transmitted, 100% packet loss",
                                     "dns": "server fail", "ipv6": "no default route"})
    assert ok
    ok, reasons = probes_attest_isolation({"ping": "0% packet loss, 1 ms", "dns": "answers: 93.184.216.34"})
    assert not ok and any("REACHABLE" in r for r in reasons)
    ok, reasons = probes_attest_isolation({"ping": "it worked", "dns": "fine"})
    assert not ok, "ambiguous observations must fail closed"


@pytest.mark.db
def test_r04_corrupt_local_latch_cannot_forget_engaged_db_mirror(client, users):
    from srplatform.safety import get_supervisor
    from srplatform.settings import get_settings

    sup = get_supervisor()
    r = client.post("/safety/killswitch", headers=users["op"])
    assert r.status_code == 200
    state_file = Path(get_settings().safety_state_file)
    state_file.write_text("{corrupt json!!")
    st = sup.latch_status()
    assert st["latched"] is True, "corrupt local file must not forget the DB mirror"
    assert "persistence_error" in st

    state_file.unlink()
    assert sup.latch_status()["latched"] is True, "missing file must not forget the mirror"


@pytest.mark.db
def test_r04_attestation_endpoints_fail_closed(client, users):
    # datapath proof with REACHABLE egress observations must be rejected
    r = client.post("/safety/datapath-proof", headers=users["op"], json={
        "probes": {"ping": "0% packet loss", "dns": "answers: 1.1.1.1"},
        "vm_hostname": "web01"})
    assert r.status_code == 422, r.text
    # ...while honest isolation observations are accepted
    r = client.post("/safety/datapath-proof", headers=users["op"], json={
        "probes": {"ping": "100% packet loss", "dns": "no servers could be reached"},
        "vm_hostname": "web01"})
    assert r.status_code == 200, r.text
    # baseline override: cannot record ok=True while the live check fails
    r = client.post("/safety/baseline-check", headers=users["op"], json={"ok": True})
    assert r.status_code == 409, r.text


# =========================================================================== #
# R03 — stop/killswitch must reach the ACTUAL processes                      #
# =========================================================================== #

_WORKER_TERM_SCRIPT = """
import sys, threading
from srplatform.red_agent.runner import LocalDevRunner, install_cancellation_handlers
install_cancellation_handlers()
pidfile = sys.argv[1]
r = LocalDevRunner()
t = threading.Thread(target=lambda: r.run(
    "sh -c 'echo $$ > %s; exec sleep 300'" % pidfile), daemon=True)
t.start()
import time; time.sleep(120)
"""


def test_r03_worker_sigterm_kills_the_command_group(tmp_path):
    pidfile = tmp_path / "cmd.pid"
    env = {**os.environ, "SR_ENV": "dev", "RUNNER_TRANSPORT": "local-dev", "ALLOW_LOCAL_DEV_FIXTURE": "1",
           "PYTHONPATH": str(REPO)}
    proc = subprocess.Popen([PY, "-c", _WORKER_TERM_SCRIPT, str(pidfile)],
                            cwd=REPO, env=env, start_new_session=True)
    deadline = time.time() + 20
    while not pidfile.exists() and time.time() < deadline:
        time.sleep(0.1)
    assert pidfile.exists(), "command did not start"
    cmd_pid = int(pidfile.read_text().strip())

    proc.terminate()  # SIGTERM to the worker group — what stop_run does
    proc.wait(timeout=15)
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            os.kill(cmd_pid, 0)
            time.sleep(0.2)
        except ProcessLookupError:
            break
    else:
        pytest.fail(f"command process {cmd_pid} SURVIVED the worker stop")
    assert True


@pytest.mark.db
def test_r03_killswitch_kills_recovered_groups_and_reconcile_reregisters(client, users):
    from srplatform.api import runs as runs_svc
    from srplatform.db.models import Run
    from srplatform.db.session import db as db_ctx
    from srplatform.safety.runregistry import pgid_start_time, run_registry

    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    proc = subprocess.Popen(["sleep", "300"], start_new_session=True)
    pgid = os.getpgid(proc.pid)
    pstart = pgid_start_time(proc.pid)
    with db_ctx() as s:
        s.add(Run(session_id=uuid.UUID(sid), scenario_id="quick-win-01",
                  status="running", pid=proc.pid, pgid=pgid, pgid_pstart=pstart))
        s.commit()

    # startup reconciliation must RE-REGISTER the surviving group (not just note it)
    runs_svc.reconcile_on_startup()
    assert any(h.pgid == pgid for h in run_registry.active()), \
        "surviving group must re-enter supervision"

    r = client.post("/safety/killswitch", headers=users["op"])
    assert r.status_code == 200
    body = r.json()
    assert any(res.get("run_id") and res.get("ok") for res in body["workers"]["results"]), body
    deadline = time.time() + 10
    while proc.poll() is None and time.time() < deadline:
        time.sleep(0.1)
    assert proc.poll() is not None, "recovered group survived the killswitch"
    run_registry.remove(str([h.run_id for h in run_registry.active()
                             if h.pgid == pgid][0])) if any(
        h.pgid == pgid for h in run_registry.active()) else None


def test_r03_terminate_group_refuses_reused_pgid_identity():
    from srplatform.safety.runregistry import RunRegistry, pgid_start_time

    proc = subprocess.Popen(["sleep", "60"], start_new_session=True)
    try:
        pgid = os.getpgid(proc.pid)
        wrong = pgid_start_time(proc.pid) + 12345  # a DIFFERENT process's start time
        res = RunRegistry.terminate_group(pgid, expected_pstart=wrong)
        assert res["ok"] is False and "reuse" in res["detail"].lower()
        assert proc.poll() is None, "identity mismatch must refuse to signal"
    finally:
        proc.kill()
        proc.wait()


# =========================================================================== #
# R05 — nft controller: topology-correct render, atomic apply, both removals #
# =========================================================================== #

def test_r05_baseline_render_is_destination_constrained_and_port_aware(monkeypatch):
    monkeypatch.setenv("API_BASE_URL", "http://10.9.8.7:9999")
    from srplatform.settings import get_settings
    get_settings.cache_clear()
    try:
        from srplatform.safety.firewall import render_baseline_ruleset
        base = render_baseline_ruleset()
        assert "ip saddr @range_hosts ip daddr @range_hosts accept" in base
        assert "tcp dport 9999" in base, "ingest port must come from settings"
        # audit N06: reply directions are EXPLICIT (replies to control paths
        # arrive on the range bridge, destination-scoped) — no blanket
        # established accept, and no mistaken `ip protocol ip`
        # audit N06 + T03: reply directions are EXPLICIT and PORT-SCOPED —
        # established traffic only for the management SSH port and the API
        # ingest port, never destination-wide (a pre-established range->
        # management connection to an arbitrary port must not survive).
        assert 'ct state established,related ip daddr 10.0.0.0/24 tcp sport 22 iifname "vmbr1" accept' in base
        assert 'ct state established,related ip daddr 10.9.8.7 tcp dport 9999 iifname "vmbr1" accept' in base
        assert "ip protocol ip" not in base, "ip protocol is the UPPER-LAYER field, not 'is IPv4'"
    finally:
        get_settings.cache_clear()


def test_r05_emergency_render_uses_port_topology_and_atomic_removal(monkeypatch):
    monkeypatch.setenv("RANGE_BRIDGE_PORTS", "tap100, tap101")
    from srplatform.settings import get_settings
    get_settings.cache_clear()
    try:
        from srplatform.safety.firewall import render_emergency_removal, render_emergency_ruleset
        em = render_emergency_ruleset()
        assert '"tap100"' in em and '"tap101"' in em
        assert "iifname @sr_ports drop" in em, "bridge family must match PORTS"
        rm = render_emergency_removal()
        assert "delete table inet sr_emergency" in rm
        assert "delete table bridge sr_emergency_l2" in rm, "release must remove BOTH families"
    finally:
        get_settings.cache_clear()


def test_r05_controller_applies_atomically_and_verifies_both_families(monkeypatch):
    import json as _json
    from srplatform.safety import datapath as dp
    from srplatform.safety import firewall
    from srplatform.settings import get_settings

    nft = dp.NftDatapath.__new__(dp.NftDatapath)
    nft.s = get_settings()
    # coverage validated independently (its own tests); focus: atomicity
    monkeypatch.setattr(firewall, "validate_port_coverage", lambda s: (True, "ports ok"))
    calls = {"stdin": [], "run": []}
    state = {"tables": {f"inet {dp.EMERGENCY_TABLE}", f"bridge {dp.EMERGENCY_TABLE}_l2",
                        f"inet {dp.BASELINE_TABLE}"}}

    def fake_stdin(ruleset):
        calls["stdin"].append(ruleset)
        if "table inet sr_emergency {" in ruleset:  # apply transaction
            state["tables"] |= {f"inet {dp.EMERGENCY_TABLE}", f"bridge {dp.EMERGENCY_TABLE}_l2"}
        elif "delete table" in ruleset:            # pure removal transaction
            for line in ruleset.splitlines():
                if line.startswith("delete table "):
                    state["tables"].discard(line.split("delete table ")[1].strip())
        return 0, ""

    def fake_run(args):
        calls["run"].append(args)
        if args[:2] == ["-nn", "list"] or args[:3] == ["-nn", "-j", "list"]:
            name = args[-1]
            if name not in state["tables"]:
                return 1, "Error: Could not process rule: No such file or directory"
            if "-j" in args:
                fam = name.split()[0]
                # REAL nft JSON: flat entries — table, then chain with hook
                doc = {"nftables": [
                    {"table": {"family": fam, "name": name.split()[1], "handle": 1}},
                    {"chain": {"family": fam, "table": name.split()[1], "name": "c",
                               "handle": 2, "type": "filter", "hook": "forward",
                               "prio": -150, "policy": "accept"}}]}
                return 0, _json.dumps(doc)
            return 0, f"table {name}"
        return 0, ""

    nft._run_nft_stdin = fake_stdin
    nft._run_nft = fake_run
    nft.baseline_status = lambda: {"ok": True, "detail": "baseline ok (faked)",
                                   "mechanism": "nft"}

    res = nft.apply_emergency()
    assert res["ok"], res
    assert len(calls["stdin"]) == 1, "apply must be ONE atomic nft -f transaction"
    assert "delete table inet" in calls["stdin"][0], "existing tables replaced atomically"
    # post-apply BOTH families verified hooked
    checked = [a[-1] for a in calls["run"] if a[:3] == ["-nn", "-j", "list"]]
    assert f"inet {dp.EMERGENCY_TABLE}" in checked and f"bridge {dp.EMERGENCY_TABLE}_l2" in checked

    # removal: BASELINE CHECKED FIRST, one atomic transaction covering BOTH
    # families, then verification
    res = nft.remove_emergency()
    assert res["ok"], res
    removal = calls["stdin"][-1]
    assert "delete table inet sr_emergency" in removal
    assert "delete table bridge sr_emergency_l2" in removal
    checked = [a[-1] for a in calls["run"] if a[:3] == ["-nn", "-j", "list"]]
    assert f"inet {dp.EMERGENCY_TABLE}" in checked and f"bridge {dp.EMERGENCY_TABLE}_l2" in checked
    # removal verification must have RE-INSPECTED after the delete transaction
    assert len([a for a in calls["run"] if a[:3] == ["-nn", "-j", "list"]]) >= 4


def test_r06_apply_refused_without_port_coverage(monkeypatch):
    """Audit N06 item 1: missing/stale port coverage must PREVENT a
    full-success emergency — a warning riding with ok=true was the fail-open
    the probe reproduced (missing_bridge_ports_apply)."""
    from srplatform.safety import datapath as dp
    from srplatform.safety import firewall
    from srplatform.settings import get_settings

    nft = dp.NftDatapath.__new__(dp.NftDatapath)
    nft.s = get_settings()
    monkeypatch.setattr(firewall, "validate_port_coverage",
                        lambda s: (False, "RANGE_BRIDGE_PORTS not configured"))
    applied = []
    nft._run_nft_stdin = lambda rs: (applied.append(rs) or (0, ""))
    res = nft.apply_emergency()
    assert res["ok"] is False
    assert applied == [], "no nft transaction may run when coverage is unestablished"


def test_r06_table_presence_combinations(monkeypatch):
    """Audit N06 item 5: apply/release are atomic for neither/inet-only/
    bridge-only/both — only EXISTING tables are deleted."""
    import json as _json
    from srplatform.safety import datapath as dp
    from srplatform.safety import firewall
    from srplatform.settings import get_settings

    for inet_present, bridge_present in ((False, False), (True, False),
                                         (False, True), (True, True)):
        nft = dp.NftDatapath.__new__(dp.NftDatapath)
        nft.s = get_settings()
        monkeypatch.setattr(firewall, "validate_port_coverage",
                            lambda s: (True, "ports ok"))
        state = {"tables": set()}
        if inet_present:
            state["tables"].add(f"inet {dp.EMERGENCY_TABLE}")
        if bridge_present:
            state["tables"].add(f"bridge {dp.EMERGENCY_TABLE}_l2")
        txns = []

        def fake_stdin(ruleset):
            txns.append(ruleset)
            if "table inet sr_emergency {" in ruleset:
                state["tables"] |= {f"inet {dp.EMERGENCY_TABLE}",
                                    f"bridge {dp.EMERGENCY_TABLE}_l2"}
            elif "delete table" in ruleset:
                for line in ruleset.splitlines():
                    if line.startswith("delete table "):
                        state["tables"].discard(line.split("delete table ")[1].strip())
            return 0, ""

        def fake_run(args):
            if args[:2] == ["-nn", "list"] or args[:3] == ["-nn", "-j", "list"]:
                name = args[-1]
                if name not in state["tables"]:
                    return 1, "Error: Could not process rule: No such file or directory"
                if "-j" in args:
                    fam = name.split()[0]
                    doc = {"nftables": [
                        {"table": {"family": fam, "name": name.split()[1],
                                   "handle": 1}},
                        {"chain": {"family": fam, "table": name.split()[1],
                                   "name": "c", "handle": 2, "type": "filter",
                                   "hook": "forward", "prio": -150,
                                   "policy": "accept"}}]}
                    return 0, _json.dumps(doc)
                return 0, f"table {name}"
            return 0, ""

        nft._run_nft_stdin = fake_stdin
        nft._run_nft = fake_run
        nft.baseline_status = lambda: {"ok": True, "detail": "faked", "mechanism": "nft"}

        res = nft.apply_emergency()
        assert res["ok"], (inet_present, bridge_present, res)
        txn = txns[-1]
        assert (("delete table inet" in txn) == inet_present), txn
        assert (("delete table bridge" in txn) == bridge_present), txn

        res = nft.remove_emergency()
        assert res["ok"], (inet_present, bridge_present, res)
        assert not state["tables"], state["tables"]


def test_r06_release_refuses_and_retains_when_baseline_unverified(monkeypatch):
    """Audit N06 item 6: emergency protection is never dropped before the
    baseline is verified; a failed baseline check retains the emergency."""
    from srplatform.safety import datapath as dp
    from srplatform.safety import firewall
    from srplatform.settings import get_settings

    nft = dp.NftDatapath.__new__(dp.NftDatapath)
    nft.s = get_settings()
    monkeypatch.setattr(firewall, "validate_port_coverage", lambda s: (True, "ok"))
    stdin_calls = []
    nft._run_nft_stdin = lambda rs: (stdin_calls.append(rs) or (0, ""))
    nft.inspect_table = lambda t: ("present", None, "faked")
    nft.baseline_status = lambda: {"ok": False, "detail": "baseline broken", "mechanism": "nft"}
    res = nft.remove_emergency()
    assert res["ok"] is False
    assert stdin_calls == [], "emergency removal ran despite unverified baseline"


def test_r05_baseline_verification_checks_rules_not_just_table():
    from srplatform.safety import datapath as dp

    nft = dp.NftDatapath.__new__(dp.NftDatapath)
    from srplatform.settings import get_settings
    nft.s = get_settings()
    nft._run_nft = lambda args: (0, "table inet sr_range_baseline { chain forward_x { } }")
    res = nft.baseline_status()
    assert res["ok"] is False, "an EMPTY baseline table must NOT verify"


@pytest.mark.packet
def test_r05_real_nft_apply_remove_roundtrip(tmp_path):
    """Real nftables round-trip INSIDE A DISPOSABLE NETWORK NAMESPACE with a
    disposable bridge — never the developer's real range namespace (audit
    N06: privileged tests only in disposable test namespaces)."""
    from tests.helpers import require_packet_prereq
    require_packet_prereq()
    import subprocess as sp
    import uuid
    from srplatform.safety import datapath as dp
    from srplatform.settings import Settings

    ns = f"srtest{uuid.uuid4().hex[:8]}"
    br, p1, p2 = "srbr0", "srp1", "srp2"

    def ip(*args, check=True):
        return sp.run(["ip", *args], capture_output=True, text=True, check=check)

    ip("netns", "add", ns)
    try:
        def n(*args, check=True):
            return ip("netns", "exec", ns, "ip", *args, check=check)

        n("link", "add", br, "type", "bridge")
        n("link", "add", p1, "type", "veth", "peer", "name", f"{p1}e")
        n("link", "add", p2, "type", "veth", "peer", "name", f"{p2}e")
        n("link", "set", p1, "master", br)
        n("link", "set", p2, "master", br)
        for d in (p1, f"{p1}e", p2, f"{p2}e", br):
            n("link", "set", d, "up")

        s = Settings(sr_env="dev", range_bridge=br, range_bridge_ports=f"{p1},{p2}",
                     api_base_url="http://10.66.0.1:8000", datapath_controller="nft",
                     nft_command_prefix=f"ip netns exec {ns} ", safety_state_file=str(tmp_path / "st"))
        nft = dp.NftDatapath(s)
        try:
            res = nft.apply_emergency()
            assert res["ok"], res
            assert nft.table_exists(f"inet {dp.EMERGENCY_TABLE}")
            assert nft.table_exists(f"bridge {dp.EMERGENCY_TABLE}_l2")
            # JSON verification sees the REAL hooked chains
            base = nft.baseline_status()
            assert base["ok"] is False and "ABSENT" in base["detail"]
            # release REFUSES while the baseline is absent (removing the
            # emergency with no deny behind it would open the range)
            refused = nft.remove_emergency()
            assert refused["ok"] is False and "baseline" in refused["detail"].lower()
            assert nft.table_exists(f"inet {dp.EMERGENCY_TABLE}")
            # install the baseline, THEN release atomically
            code, out = nft._run_nft_stdin(nft.render_baseline())
            assert code == 0, out
        finally:
            res = nft.remove_emergency() if nft.table_exists(
                f"inet {dp.EMERGENCY_TABLE}") else {"ok": True}
        assert res["ok"], res
        assert not nft.table_exists(f"inet {dp.EMERGENCY_TABLE}")
        assert not nft.table_exists(f"bridge {dp.EMERGENCY_TABLE}_l2")
        # baseline survives the emergency removal (release never strips the deny)
        assert nft.baseline_status()["ok"] is True
    finally:
        ip("netns", "del", ns, check=False)


@pytest.mark.packet
def test_r06_disposable_netns_packet_semantics(tmp_path, monkeypatch):
    """Audit N06 packet evidence in DISPOSABLE namespaces: with the rendered
    baseline applied, intra-range IPv4 is allowed, range WAN egress and IPv6
    are dropped, routed management SSH into the range works INCLUDING its
    replies (the reply-direction rule the review found missing), range->API
    ingest works while other control-plane ports are dropped, and the
    emergency drop severs intra-range traffic."""
    from tests.helpers import require_packet_prereq
    require_packet_prereq()
    import subprocess as sp
    import uuid
    from srplatform.safety import datapath as dp
    from srplatform.safety import firewall
    from srplatform.settings import Settings

    uid = uuid.uuid4().hex[:6]
    ns, RANGE1, RANGE2, WAN, MGMT, SRV = (f"sr_{u}{uid}" for u in
                                          ("rt", "r1", "r2", "wn", "mg", "sv"))
    R1_IP, R2_IP, GW_IP = "10.66.0.10", "10.66.0.11", "10.66.0.1"
    WAN_GW, WAN_IP = "10.99.0.1", "10.99.0.20"
    MGMT_GW, MGMT_IP = "10.0.0.1", "10.0.0.2"
    SRV_GW, SRV_IP, API_PORT = "10.88.0.1", "10.88.0.2", 8000
    br = "srbr0"

    def ip(*args, check=True):
        return sp.run(["ip", *args], capture_output=True, text=True, check=check)

    def inns(target, *args, check=True):
        return ip("netns", "exec", target, "ip", *args, check=check)

    def sysctl_ns(target, key, value):
        # /proc/sys must be the namespace's own — remount proc privately
        path = "/proc/sys/" + key.replace(".", "/")
        return ip("netns", "exec", target, "unshare", "-m", "--mount-proc",
                  "sh", "-c", f"echo {value} > {path}")

    created = []
    try:
        for name in (ns, RANGE1, RANGE2, WAN, MGMT, SRV):
            ip("netns", "add", name)
            created.append(name)

        def link_pair(a_ns, a_name, b_ns, b_name, a_ip=None, b_ip=None, via=None):
            ip("link", "add", f"x{a_name}", "type", "veth", "peer", "name", f"x{b_name}")
            ip("link", "set", f"x{a_name}", "netns", a_ns)
            ip("link", "set", f"x{b_name}", "netns", b_ns)
            inns(a_ns, "link", "set", f"x{a_name}", "name", a_name)
            inns(b_ns, "link", "set", f"x{b_name}", "name", b_name)
            for t, d in ((a_ns, a_name), (b_ns, b_name)):
                inns(t, "link", "set", d, "up")
            if a_ip:
                inns(a_ns, "addr", "add", a_ip, "dev", a_name)
            if b_ip:
                inns(b_ns, "addr", "add", b_ip, "dev", b_name)
            if via:
                inns(b_ns, "route", "add", "default", "via", via, check=False)

        # router: bridge with two range hosts
        inns(ns, "link", "add", br, "type", "bridge")
        inns(ns, "addr", "add", f"{GW_IP}/24", "dev", br)
        inns(ns, "link", "set", br, "up")
        sysctl_ns(ns, "net.ipv4.ip_forward", 1)
        br_ports = []
        for name, ipaddr in ((RANGE1, R1_IP), (RANGE2, R2_IP)):
            a = f"v{name[3:5]}"
            br_ports.append(a)
            ip("link", "add", f"x{a}", "type", "veth", "peer", "name", f"y{a}")
            ip("link", "set", f"x{a}", "netns", ns)
            ip("link", "set", f"y{a}", "netns", name)
            inns(ns, "link", "set", f"x{a}", "name", a)
            inns(ns, "link", "set", a, "master", br)
            inns(ns, "link", "set", a, "up")
            inns(name, "link", "set", f"y{a}", "name", "eth0")
            inns(name, "link", "set", "eth0", "up")
            inns(name, "addr", "add", f"{ipaddr}/24", "dev", "eth0")
            inns(name, "route", "add", "default", "via", GW_IP)
        # WAN, management and API server: routed through the router netns
        link_pair(ns, "wan0", WAN, "eth0", a_ip=f"{WAN_GW}/24", b_ip=f"{WAN_IP}/24",
                  via=WAN_GW)
        link_pair(ns, "mgmt0", MGMT, "eth0", a_ip=f"{MGMT_GW}/24", b_ip=f"{MGMT_IP}/24",
                  via=MGMT_GW)
        link_pair(ns, "srv0", SRV, "eth0", a_ip=f"{SRV_GW}/24", b_ip=f"{SRV_IP}/24",
                  via=SRV_GW)

        # Ports DECLARED (production requirement): same-subnet range traffic
        # is BRIDGED, and the bridge forward hook sees the PORTS, never the
        # master — an empty declaration would leave the emergency L2 drop
        # matching nothing, severing intra-range traffic only if the host
        # happens to have br_netfilter loaded (audit N06: undeclared ports
        # mean INCOMPLETE coverage, not a pass).
        s = Settings(sr_env="dev", range_bridge=br, range_cidr="10.66.0.0/24",
                     management_cidr="10.0.0.0/24", range_bridge_ports=",".join(br_ports),
                     api_base_url=f"http://{SRV_IP}:{API_PORT}", datapath_controller="nft",
                     nft_command_prefix=f"ip netns exec {ns} ",
                     safety_state_file=str(tmp_path / "st"))
        nft = dp.NftDatapath(s)
        monkeypatch.setattr(firewall, "validate_port_coverage",
                            lambda s_: (True, "netns test"))

        def ping(target, src=RANGE1, v6=False):
            args = ["-6"] if v6 else []
            r = ip("netns", "exec", src, "ping", *args, "-c", "1", "-W", "2",
                   target, check=False)
            return r.returncode == 0

        def tcp_probe(target_ns, hostport, expect, timeout=3):
            return ip("netns", "exec", target_ns, "python3", "-c",
                        "import socket\n"
                        "try:\n"
                        f"    s=socket.create_connection(('{hostport[0]}',{hostport[1]}),{timeout})\n"
                        "    d=s.recv(32)\n"
                        "    print('OPEN', d.decode())\n"
                        "except Exception:\n"
                        "    print('BLOCKED')", check=False)

        # listeners (background, inside their netns)
        def listener(netns, bind, port, reply):
            return sp.Popen(["ip", "netns", "exec", netns, "python3", "-c",
                             "import socket\n"
                             "s=socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n"
                             f"s.bind(('{bind}',{port})); s.listen(1)\n"
                             "c,_=s.accept(); c.sendall(b'" + reply + "'); c.close()"],
                            stdout=sp.DEVNULL, stderr=sp.DEVNULL)

        # 1. baseline applied and STRUCTURALLY verified against real nft
        code, out = nft._run_nft_stdin(nft.render_baseline())
        assert code == 0, out
        status = nft.baseline_status()
        assert status["ok"] is True, status["detail"]

        # 2. intra-range IPv4 allowed
        assert ping(R2_IP), "intra-range IPv4 must be allowed"
        # 3. range WAN egress dropped (including pre-existing routes)
        assert not ping(WAN_IP), "range WAN egress must be dropped"
        # 4. IPv6 dropped
        assert not ping("fd00:66::2", v6=True), "range IPv6 must be dropped"

        # 5. routed management SSH into the range, replies included
        l = listener(RANGE1, R1_IP, 22, "banner")
        try:
            import time
            time.sleep(0.4)
            r = tcp_probe(MGMT, (R1_IP, 22), "banner")
            assert "OPEN" in r.stdout and "banner" in r.stdout, \
                f"management SSH flow (incl. replies) must work: {r.stdout}{r.stderr}"
        finally:
            l.terminate(); l.wait(timeout=5)

        # 6. range -> API ingest allowed with replies; other ports dropped
        l = listener(SRV, SRV_IP, API_PORT, "ok")
        try:
            import time
            time.sleep(0.4)
            r = tcp_probe(RANGE2, (SRV_IP, API_PORT), "ok")
            assert "OPEN" in r.stdout and "ok" in r.stdout, \
                f"range->API ingest flow must work: {r.stdout}{r.stderr}"
        finally:
            l.terminate(); l.wait(timeout=5)
        r = tcp_probe(RANGE2, (SRV_IP, 9999), "BLOCKED", timeout=2)
        assert "BLOCKED" in r.stdout, "non-ingest control-plane ports must be dropped"

        # 7. EMERGENCY severs intra-range traffic
        res = nft.apply_emergency()
        assert res["ok"], res
        assert not ping(R2_IP), "emergency must sever intra-range traffic"
    finally:
        for name in created:
            ip("netns", "del", name, check=False)


# =========================================================================== #
# R12 — Compose credential split + bastion wiring + golden-image installer   #
# =========================================================================== #

def test_r12_compose_splits_credentials_and_wires_bastion():
    import yaml

    compose = yaml.safe_load((REPO / "docker-compose.yml").read_text())
    api, bastion = compose["services"]["api"], compose["services"]["bastion"]

    # the API must NOT load the whole .env (it contains the OWNER URL)
    assert "env_file" not in api, "API env_file re-introduces the owner credential"
    assert "POSTGRES_URL_OWNER" not in api.get("environment", {})
    # the API must actually mount the recordings volume the bastion writes to
    api_volumes = [str(v) for v in api.get("volumes", [])]
    assert any("recordings" in v for v in api_volumes), \
        "API does not mount the shared recordings volume"
    # the bastion's documented wiring must exist in THIS stack
    benv = bastion.get("environment", {})
    assert "SR_BASTION_TOKEN" in benv
    assert "BASTION_AUTHORIZED_KEYS_FILE" in benv
    assert "BASTION_TARGETS_KNOWN_HOSTS" in benv


def test_stage5_compose_seeds_bastion_key_volume():
    """Stage 5 item 3: the bastion-keys volume and recordings dir must be
    POPULATED by a seed step, with wiring consistent with what the bastion
    reads. (docker compose config / fresh-volume boot: BLOCKED here — no
    docker — so this YAML-level check is the honest substitute.)"""
    import yaml

    compose = yaml.safe_load((REPO / "docker-compose.yml").read_text())
    services = compose["services"]
    seed = services.get("seed-bastion-keys")
    assert seed, "no compose seed step provisions the bastion-keys volume"
    assert seed.get("restart") == "no"
    assert any("seed_bastion_keys" in str(a) for a in seed.get("command", [])), \
        "seed step does not run the seed script"

    bastion = services["bastion"]
    benv = bastion["environment"]
    seed_vols = [str(v) for v in seed.get("volumes", [])]

    # seed writes into the SAME volume the bastion reads, at the exact parent
    # dirs of the bastion's key paths
    keys_mounts = [v for v in seed_vols if v.startswith("bastion-keys:")]
    assert keys_mounts, "seed does not mount the bastion-keys volume"
    keys_dest = keys_mounts[0].split(":")[1]
    for k in ("BASTION_AUTHORIZED_KEYS_FILE", "BASTION_TARGETS_KNOWN_HOSTS",
              "BASTION_HOST_KEY_PATH"):
        assert str(benv[k]).rsplit("/", 1)[0] == keys_dest, \
            f"{k} lives outside the seeded bastion-keys mount"
    rec_mounts = [v for v in seed_vols if v.startswith("recordings:")]
    assert rec_mounts, "seed does not mount the recordings volume"
    assert rec_mounts[0].split(":")[1] == benv["RECORDINGS_DIR"], \
        "seeded recordings path != bastion RECORDINGS_DIR"

    # operator key material is bind-mounted READ-ONLY (never written back)
    assert any(v.endswith(":ro") for v in seed_vols), \
        "operator key dir must be mounted read-only"
    # the bastion only starts after a SUCCESSFUL seed
    dep = bastion.get("depends_on", {}).get("seed-bastion-keys", {})
    assert dep.get("condition") == "service_completed_successfully", \
        "bastion must wait for the seed step to succeed"

    # volume wiring consistency: every named volume used is declared, every
    # declared volume is actually used (bind mounts/vars excluded)
    declared = set(compose.get("volumes", {}))
    used = {str(v).split(":")[0] for s in services.values() for v in s.get("volumes", [])
            if not str(v).startswith((".", "/", "$"))}
    assert used <= declared, f"services use undeclared volumes: {used - declared}"
    assert declared <= used, f"declared-but-never-mounted volumes: {declared - used}"

    # the seed script exists and fails loudly (no silent keyless bastion)
    script = (REPO / "infra/dev/seed_bastion_keys.sh").read_text()
    for needle in ("authorized_keys", "target_known_hosts", "ERROR", "exit 1"):
        assert needle in script, f"seed script missing: {needle}"


def test_r12_golden_image_calls_the_real_installer():
    script = (REPO / "infra/images/provision-linux-golden.sh").read_text()
    assert "telemetry/install.sh" in script, \
        "golden image must call the real installer (unit + format + spool)"
    installer = (REPO / "telemetry/install.sh").read_text()
    assert "sparring-shipper.service" in installer and "systemd" in installer.lower()
    # The HONEST provisioning contract (audit N10) is enforced by CODE, not
    # by literal runbook prose (milestone 01: replace prose-coupled checks
    # with installer/readiness-contract assertions):
    #   * every scenario host MUST name a prebuilt golden template — the
    #     schema has no default, so "cloud-init applied" cannot substitute;
    #   * deploy only clones from that template and reaches `ready` solely
    #     after every host is created; any failure stays visible as failed.
    import inspect

    from srplatform.scenario_engine import loader, orchestrator

    tmpl = loader.Host.model_fields["template_vmid"]
    assert tmpl.is_required(), \
        "prebuilt-template requirement must be enforced by the scenario schema"
    deploy_src = inspect.getsource(orchestrator.deploy)
    assert "clone_and_wait" in deploy_src, \
        "deploy must provision by cloning the golden template"
    assert "cloud-init" not in deploy_src.lower() and "cloudinit" not in deploy_src.lower(), \
        "deploy must not claim service provisioning the template does not perform"
    assert 'dep.status = "ready"' in deploy_src and 'dep.status = "failed"' in deploy_src, \
        "readiness must be enforced: ready only after every host, failure stays visible"


# =========================================================================== #
# R07/R08 — lease & deployment invariants                                    #
# =========================================================================== #

@pytest.mark.db
def test_r07_teardown_failure_retains_lease_until_destroy_succeeds(client, users, fake_pve):
    sid, out = None, None
    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    r = client.post(f"/sessions/{sid}/launch", headers=users["member"])
    assert r.status_code == 202, r.text
    wait_operation(client, users["member"], sid)

    # make destroys fail -> teardown must NOT claim completion, lease retained
    fake_pve.api.fail_task_fragments = ("/qemu",)
    t = client.post(f"/sessions/{sid}/teardown", headers=users["member"])
    assert t.status_code == 200
    body = t.json()
    assert body.get("complete") is False, body
    assert client.post(f"/sessions/{sid}/end", headers=users["member"]).status_code == 200

    sid2 = client.post("/sessions", json={"scenario_id": "db-exfil-01"},
                       headers=users["op"]).json()["session_id"]
    assert client.post(f"/sessions/{sid2}/launch", headers=users["op"]).status_code == 409, \
        "failed destroys keep the range reserved"

    # retry with working infra -> complete -> lease frees
    fake_pve.api.fail_task_fragments = ()
    t = client.post(f"/sessions/{sid}/teardown", headers=users["member"])
    assert t.json().get("complete") is True, t.json()
    launch_and_wait(client, users["op"], sid2)


@pytest.mark.db
def test_r07_reset_requires_the_lease(client, users, fake_pve):
    sid_a = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                        headers=users["member"]).json()["session_id"]
    launch_and_wait(client, users["member"], sid_a)
    # PILOT STEP 4: end destroys the owned machines and frees the range, so
    # B CAN launch after A ends. The R07 invariant this test guards remains:
    # a completed session's reset must not proceed over a range B now holds.
    client.post(f"/sessions/{sid_a}/end", headers=users["member"])
    sid_b = client.post("/sessions", json={"scenario_id": "db-exfil-01"},
                        headers=users["op"]).json()["session_id"]
    launch_and_wait(client, users["op"], sid_b)
    # A holds no lease -> A's reset conflicts with B's active range
    assert client.post(f"/sessions/{sid_a}/reset", headers=users["member"]).status_code == 409


@pytest.mark.db
def test_r08_crash_after_clone_leaves_vm_owned_and_resumable(client, users, fake_pve):
    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    # fail AFTER the clone task completes, during config -> pending row must own it
    fake_pve.api.fail_request_fragments = ("/config",)
    r = client.post(f"/sessions/{sid}/launch", headers=users["member"])
    assert r.status_code == 202, r.text  # accepted; the executor fails loudly
    crashed = wait_operation(client, users["member"], sid)
    assert crashed["state"] == "failed", crashed
    fake_pve.api.fail_request_fragments = ()

    from srplatform.db.session import db as db_ctx
    from srplatform.db.models import Deployment
    from sqlalchemy import select
    with db_ctx() as s:
        dep = s.execute(select(Deployment).where(Deployment.session_id == uuid.UUID(sid))
                        .order_by(Deployment.created_at.desc())).scalars().first()
        assert dep is not None and dep.resources, "pending intent must be durable"
        assert any(x.get("state") == "pending" and x.get("vmid") for x in dep.resources)
        vmids = [x["vmid"] for x in dep.resources]
    assert any(v in fake_pve.api.vms for v in vmids), "cloned VM must be inside inventory"

    # RESUME: relaunch reuses the deployment, reconciles the existing VM, no dupes
    resumed = launch_and_wait(client, users["member"], sid)
    assert resumed["state"] == "succeeded", resumed
    assert not getattr(client, "_dup_vmids", False)
    # teardown removes everything owned, including the previously-pending VM
    t = client.post(f"/sessions/{sid}/teardown", headers=users["member"])
    assert t.json().get("complete") is True
    remaining = [v for v in fake_pve.api.vms if v not in (9001, 9002, 9003, 9004)]
    assert remaining == [], f"orphaned VMs after teardown: {remaining}"


@pytest.mark.db
def test_r08_launch_is_idempotent(client, users, fake_pve):
    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    r1 = client.post(f"/sessions/{sid}/launch", headers=users["member"])
    assert r1.status_code == 202, r1.text
    first = wait_operation(client, users["member"], sid)
    assert first["state"] == "succeeded", first
    vms_after_1 = set(fake_pve.api.vms)
    # a second launch is a NEW attempt on the same session: the idempotent
    # deploy path RETURNS the existing ready deployment, never re-clones
    second = launch_and_wait(client, users["member"], sid)
    assert second["state"] == "succeeded", second
    assert set(fake_pve.api.vms) == vms_after_1, "repeated launch must not clone more VMs"
    assert second["result"]["deployment"]["deployment_id"] == \
        first["result"]["deployment"]["deployment_id"]


@pytest.mark.db
def test_r08_teardown_never_deletes_foreign_vmid(client, users, fake_pve):
    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    launch_and_wait(client, users["member"], sid)
    from srplatform.db.session import db as db_ctx
    from srplatform.db.models import Deployment
    from sqlalchemy import select
    with db_ctx() as s:
        dep = s.execute(select(Deployment).where(Deployment.session_id == uuid.UUID(sid))
                        .order_by(Deployment.created_at.desc())).scalars().first()
        res = dict(dep.resources[0])
    # simulate VMID reuse: the machine at that VMID is now someone else's
    vm = fake_pve.api.vms[res["vmid"]]
    vm["name"] = "unrelated-other-tenant"
    vm.setdefault("config", {})["tags"] = "somethingelse"
    vm["config"]["name"] = "unrelated-other-tenant"

    t = client.post(f"/sessions/{sid}/teardown", headers=users["member"])
    body = t.json()
    assert res["vmid"] in fake_pve.api.vms, "FOREIGN machine at a stale VMID was deleted!"
    assert body.get("skipped_foreign"), body


# =========================================================================== #
# R01 — real run-scoped credential + REAL worker against the REAL API        #
# =========================================================================== #

@pytest.mark.db
def test_r01_run_credential_authenticates_and_dies_with_the_run(client, users):
    from tests.helpers import make_runner_token
    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    tok = make_runner_token(sid)
    # the run credential authenticates the evidence plane for ITS session
    r = client.get("/events", params={"session_id": sid}, headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200, r.text
    r = client.post("/events", json={"session_id": sid, "action_type": "action_intent",
                                     "payload": {"op_id": 1, "command": "x", "thought": ""}},
                    headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 201, r.text

    # ...and is REVOKED once the run is no longer active
    from srplatform.db.session import db as db_ctx
    from srplatform.db.models import Run
    from sqlalchemy import select
    with db_ctx() as s:
        run = s.execute(select(Run).where(Run.session_id == uuid.UUID(sid))).scalars().first()
        run.status = "cancelled"
        s.commit()
    r = client.get("/events", params={"session_id": sid}, headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 401, "inactive run credential must not authenticate"


@pytest.mark.db
def test_r01_completion_callback_is_one_shot_and_terminal_final(client, users):
    from tests.helpers import make_runner_token
    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    tok = make_runner_token(sid)
    from srplatform.db.session import db as db_ctx
    from srplatform.db.models import Run
    from sqlalchemy import select
    with db_ctx() as s:
        run = s.execute(select(Run).where(Run.session_id == uuid.UUID(sid))).scalars().first()
        run_id = str(run.run_id)

    r = client.post(f"/internal/runs/{run_id}/complete", json={"outcome": "complete"},
                    headers={"X-Worker-Token": tok})
    assert r.status_code == 200, r.text
    # ONE-SHOT: the consumed credential cannot call back again
    r = client.post(f"/internal/runs/{run_id}/complete", json={"outcome": "complete"},
                    headers={"X-Worker-Token": tok})
    assert r.status_code == 403, "callback credential must be one-shot"
    from srplatform.api import runs as runs_svc
    with db_ctx() as s:
        run = s.get(Run, uuid.UUID(run_id))
        assert run.status == "completed"
        with pytest.raises(PermissionError):
            runs_svc.complete_run(s, run_id, tok, {"outcome": "hacked"})

    # TERMINAL-FINAL: a run that reached a terminal state by OTHER means
    # (watchdog failure — token not yet consumed) still rejects the callback.
    sid2 = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                       headers=users["member"]).json()["session_id"]
    tok2 = make_runner_token(sid2)
    with db_ctx() as s:
        run2 = s.execute(select(Run).where(Run.session_id == uuid.UUID(sid2))
                         .order_by(Run.started_at.desc())).scalars().first()
        run2.status = "failed"  # watchdog marked it failed; token still set
        s.commit()
        run2_id = str(run2.run_id)
    with pytest.raises(runs_svc.RunStateError):
        with db_ctx() as s:
            runs_svc.complete_run(s, run2_id, tok2, {"outcome": "resurrect"})


# --------------------------------------------------------------------------- #
# The full practice loop: REAL worker subprocess → REAL HTTP API → REAL       #
# runner (local-dev) → trusted backend verification. Fake boundaries are the  #
# model server (fake OpenAI HTTP) and Proxmox (fake PVE HTTP) only.           #
# --------------------------------------------------------------------------- #

class FakeOpenAI(threading.Thread):
    """Minimal OpenAI-compatible chat endpoint serving a scripted loop."""

    def __init__(self):
        from http.server import BaseHTTPRequestHandler, HTTPServer
        outer = self
        self.script = [
            tool("recon", "echo pwned"),
            tool("done", "DONE"),
            tool("done2", "DONE"),
            tool("done3", "DONE"),
        ]

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("content-length", 0))
                self.rfile.read(length)
                content = outer.script.pop(0) if outer.script else json.dumps(
                    {"thought": "x", "tool": "shell", "args": {"command": "DONE"}})
                body = json.dumps({
                    "id": "fake", "object": "chat.completion", "created": 0,
                    "model": "fake", "choices": [{"index": 0,
                        "message": {"role": "assistant", "content": content},
                        "finish_reason": "stop"}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.port = _free_port()
        self.server = HTTPServer(("127.0.0.1", self.port), H)
        super().__init__(daemon=True)

    def run(self):
        self.server.serve_forever()

    def stop(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.mark.db
def test_r01_real_worker_end_to_end_over_http(migrated_db, test_db_url_owner, tmp_path,
                                              monkeypatch):
    import httpx
    import uvicorn

    from infra.proxmox_client import FakePVEHttp
    from srplatform import verification_service
    from srplatform.api import deps
    from srplatform.api.app import app
    from srplatform.safety import Supervisor, set_supervisor
    from srplatform.safety.datapath import NoopDatapath
    from srplatform.settings import get_settings

    httpd = FakePVEHttp()
    for vmid in (9001, 9002, 9003, 9004):
        httpd.vms[vmid] = {"name": f"tpl{vmid}", "template": vmid, "status": "stopped"}
    wipe_data(test_db_url_owner)
    from infra.broker.testing import make_broker_over, policy_from_settings
    from srplatform.settings import get_settings as _get_settings
    _broker, _broker_service = make_broker_over(
        httpd, policy=policy_from_settings(_get_settings()))
    deps.set_broker(_broker)

    monkeypatch.setenv("SR_ENV", "dev")
    monkeypatch.setenv("RECORDINGS_DIR", str(tmp_path / "rec"))
    monkeypatch.setenv("SAFETY_STATE_FILE", str(tmp_path / "safety.json"))
    monkeypatch.setenv("RUNNER_TRANSPORT", "local-dev")
    monkeypatch.setenv("ALLOW_LOCAL_DEV_FIXTURE", "1")
    get_settings.cache_clear()
    sup = Supervisor(datapath=NoopDatapath(), state_file=str(tmp_path / "s.json"))
    sup.initialize_state(reason="test fixture initialization")
    set_supervisor(sup)

    fake_model = FakeOpenAI()
    fake_model.start()
    monkeypatch.setenv("LLM_BASE_URL", f"http://127.0.0.1:{fake_model.port}/v1")
    monkeypatch.setenv("LLM_API_KEY", "fake")

    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    threading.Thread(target=server.run, daemon=True).start()
    deadline = time.time() + 15
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started, ("uvicorn never started within 15s (port bind or "
                            "startup failure) — requests below would be noise")
    base = f"http://127.0.0.1:{port}"
    monkeypatch.setenv("API_BASE_URL", base)
    get_settings.cache_clear()

    try:
        api_json("POST", f"{base}/auth/bootstrap",
                 body={"username": "drew", "password": "operator-testpw-9"},
                 expect=(201,))
        tok = api_json("POST", f"{base}/auth/login",
                       body={"username": "drew",
                             "password": "operator-testpw-9"})["token"]
        H = {"Authorization": f"Bearer {tok}"}
        # NO retry band-aid here (M02 CI repair): the old "tolerate a transient
        # lock from the previous test's teardown" loop masked the real defect —
        # the previous request's commit racing this request's read. The API
        # now commits before the response (api.deps.DbSession), so a failure
        # below is a genuine regression, not CI noise.
        r = httpx.post(f"{base}/sessions", json={"scenario_id": "quick-win-01"}, headers=H)
        assert r.status_code == 201, r.text
        sid = r.json()["session_id"]
        r = httpx.post(f"{base}/sessions/{sid}/launch", headers=H)
        assert r.status_code == 202, r.text
        _dl = time.monotonic() + 180
        while True:
            _op = httpx.get(f"{base}/sessions/{sid}/operation",
                            headers=H).json()
            if _op["state"] in ("succeeded", "failed", "interrupted"):
                break
            assert time.monotonic() < _dl, f"launch stuck: {_op}"
            time.sleep(0.5)
        assert _op["state"] == "succeeded", _op

        r = httpx.post(f"{base}/run/quick-win-01", json={"session_id": sid}, headers=H)
        assert r.status_code == 202, r.text
        run_id = r.json()["run_id"]

        # the REAL worker subprocess authenticates with its run credential and
        # drives the whole loop; wait for it to finish
        status = None
        deadline = time.time() + 90
        while time.time() < deadline:
            status = httpx.get(f"{base}/runs/{run_id}", headers=H).json()["status"]
            if status not in ("queued", "running"):
                break
            time.sleep(0.5)
        assert status in ("completed", "failed"), f"run never finished: {status}"

        events = httpx.get(f"{base}/events", params={"session_id": sid, "tail": 500},
                           headers=H).json()
        types = {e["action_type"] for e in events}
        # worker-issued bearer auth worked for reads AND appends...
        assert "action_intent" in types and "action_result" in types, types
        red_events = [e for e in events if e["actor"] == "red"]
        assert red_events, "no red-attributed events — worker auth failed"
        # ...and the trusted backend appended verifier evidence (requested by the
        # worker over the SAME credential)
        assert "verifier" in types, "trusted verification never happened"
        run = httpx.get(f"{base}/runs/{run_id}", headers=H).json()
        assert run["result"], "completion callback never landed"
    finally:
        server.should_exit = True
        fake_model.stop()
        deps.set_broker(None)
        set_supervisor(None)
        verification_service.set_verifier_exec(None)
        get_settings.cache_clear()


# =========================================================================== #
# R02 — bastion token login binds the OWNER's provisioned key                #
# =========================================================================== #

@pytest.mark.db
def test_r02_bastion_token_login_binds_owner_key(migrated_db, test_db_url_owner, tmp_path,
                                                 monkeypatch):
    import asyncssh
    import httpx
    import uvicorn

    from srplatform.api import deps
    from srplatform.api.app import app
    from srplatform.bastion.proxy import BastionProxy, _BastionServer, api_resolve_token
    from srplatform.safety import Supervisor, set_supervisor
    from srplatform.safety.datapath import NoopDatapath
    from srplatform.settings import get_settings
    from infra.proxmox_client import FakePVEHttp

    httpd = FakePVEHttp()
    for vmid in (9001, 9002, 9003, 9004):
        httpd.vms[vmid] = {"name": f"tpl{vmid}", "template": vmid, "status": "stopped"}
    wipe_data(test_db_url_owner)
    from infra.broker.testing import make_broker_over, policy_from_settings
    from srplatform.settings import get_settings as _get_settings
    _broker, _broker_service = make_broker_over(
        httpd, policy=policy_from_settings(_get_settings()))
    deps.set_broker(_broker)

    # operator-provisioned member keys (the PRODUCTION keys file, not an override)
    key_blue = asyncssh.generate_private_key("ssh-ed25519")
    key_other = asyncssh.generate_private_key("ssh-ed25519")
    keys_file = tmp_path / "authorized_keys"
    keys_file.write_text(
        f"blue {key_blue.export_public_key().decode()}\n"
        f"other {key_other.export_public_key().decode()}\n")
    key_blue, key_other = key_blue.convert_to_public(), key_other.convert_to_public()

    monkeypatch.setenv("SR_ENV", "dev")
    monkeypatch.setenv("RECORDINGS_DIR", str(tmp_path / "rec"))
    monkeypatch.setenv("SAFETY_STATE_FILE", str(tmp_path / "safety.json"))
    monkeypatch.setenv("BASTION_AUTHORIZED_KEYS_FILE", str(keys_file))
    get_settings.cache_clear()
    sup = Supervisor(datapath=NoopDatapath(), state_file=str(tmp_path / "s.json"))
    sup.initialize_state(reason="test fixture initialization")
    set_supervisor(sup)

    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    threading.Thread(target=server.run, daemon=True).start()
    deadline = time.time() + 15
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started, ("uvicorn never started within 15s (port bind or "
                            "startup failure) — requests below would be noise")
    base = f"http://127.0.0.1:{port}"
    monkeypatch.setenv("API_BASE_URL", base)
    get_settings.cache_clear()

    try:
        # every handoff is self-explanatory (M01-R4 lesson: a discarded body
        # made the intermittent CI failure unclassifiable)
        api_json("POST", f"{base}/auth/bootstrap",
                 body={"username": "drew", "password": "operator-testpw-9"},
                 expect=(201,))
        tok = api_json("POST", f"{base}/auth/login",
                       body={"username": "drew",
                             "password": "operator-testpw-9"})["token"]
        H = {"Authorization": f"Bearer {tok}"}
        api_json("POST", f"{base}/users", headers=H, expect=(201,),
                 body={"username": "blue", "password": "member-testpw-9",
                       "role": "member"})
        tok_b = api_json("POST", f"{base}/auth/login",
                         body={"username": "blue",
                               "password": "member-testpw-9"})["token"]
        HB = {"Authorization": f"Bearer {tok_b}"}
        sid = api_json("POST", f"{base}/sessions",
                       body={"scenario_id": "quick-win-01"}, headers=HB,
                       expect=(201,))["session_id"]
        r = httpx.post(f"{base}/sessions/{sid}/launch", headers=HB)
        assert r.status_code == 202, r.text
        _dl = time.monotonic() + 180
        while True:
            _op = httpx.get(f"{base}/sessions/{sid}/operation",
                            headers=HB).json()
            if _op["state"] in ("succeeded", "failed", "interrupted"):
                break
            assert time.monotonic() < _dl, f"launch stuck: {_op}"
            time.sleep(0.5)
        assert _op["state"] == "succeeded", _op
        login_token = _op["result"]["connections"][0]["login_token"]

        # bastion service capability (production resolver uses SR_BASTION_TOKEN)
        svc = httpx.post(f"{base}/admin/service_tokens", headers=H,
                         json={"scope": "bastion"}).json()["token"]
        monkeypatch.setenv("SR_BASTION_TOKEN", svc)

        # 1) the PRODUCTION resolver must return the owner's USERNAME
        target = asyncio.run(api_resolve_token(login_token))
        assert target and target.get("username") == "blue", \
            "resolver must bind the token to the owner's username"

        # 2) the PRODUCTION keys file + server logic: owner key yes, foreign key no
        proxy = BastionProxy(api_resolve_token, event_sink=_noop_sink,
                             recordings_dir=tmp_path / "rec",
                             host_key_path=tmp_path / "hostkey")
        srv = _BastionServer(proxy)
        assert asyncio.run(srv.validate_public_key(login_token, key_blue)) is True
        assert asyncio.run(srv.validate_public_key(login_token, key_other)) is False, \
            "another member's key must NOT authorize this token"
        # direct member login still works for the member's own key
        assert asyncio.run(srv.validate_public_key("blue", key_blue)) is True
    finally:
        server.should_exit = True
        deps.set_broker(None)
        set_supervisor(None)
        get_settings.cache_clear()


async def _noop_sink(event):
    return None
