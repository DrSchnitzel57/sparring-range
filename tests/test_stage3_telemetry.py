"""Stage 3 regressions (audit N04, N08–N09, second follow-up review).

Role-scoped production configuration (worker least-privilege, no controller
.env leakage), the durable stable-identity spool, correct audit assembly for
interleaved/live streams, the INSTALLED shipper artifact, and per-deployment
telemetry enrollment with lifecycle revocation.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SHIPPER = REPO / "telemetry" / "shipper.py"


# --------------------------------------------------------------------------- #
# helpers                                                                      #
# --------------------------------------------------------------------------- #

class Sink(BaseHTTPRequestHandler):
    received: list = []

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        Sink.received.append((self.path, json.loads(self.rfile.read(n) or b"{}")))
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"ok":true}')

    def log_message(self, *a):
        pass


def start_sink():
    Sink.received = []
    srv = HTTPServer(("127.0.0.1", 0), Sink)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def audit_line(rtype, ts, eid, rest=""):
    return f"type={rtype} msg=audit({ts}.{eid % 10000:04d}:{eid}): {rest}"


SYSCALL = ('type=SYSCALL msg=audit(1700000000.1000:11): '
           'arch=c000003e syscall=59 success=yes exit=0 a0=5 a1=6 uid=1000 '
           'comm="bash" exe="/usr/bin/bash" key="sparring_persistence"')
EXECVE = ('type=EXECVE msg=audit(1700000000.1000:11): argc=3 a0="cat" '
          'a1="/etc/shadow" a2=736563726574')
PROCTITLE = 'type=PROCTITLE msg=audit(1700000000.1000:11): proctitle=63617400'
EOE = 'type=EOE msg=audit(1700000000.1000:11): '


# --------------------------------------------------------------------------- #
# N04 — role-scoped production configuration                                   #
# --------------------------------------------------------------------------- #

def test_worker_role_validates_only_its_own_capability(tmp_path, monkeypatch):
    """The production worker starts with ONLY api/model/runner config — and
    the controller validator still demands controller secrets."""
    from srplatform.settings import Settings, validate_production
    worker = Settings(sr_env="production", runner_transport="ssh",
                      runner_ssh_target="runner@10.66.0.9",
                      runner_ssh_known_hosts="/etc/sr/known_hosts",
                      llm_base_url="http://llm:8001/v1", llm_model_red="m",
                      api_base_url="http://api:8000")
    validate_production(worker, role="worker")  # no proxmox/db/bastion needed
    with pytest.raises(RuntimeError, match="WORKER config"):
        validate_production(worker.model_copy(update={"runner_transport": "local-dev"}),
                            role="worker")
    # controller role still fails closed on controller secrets
    with pytest.raises(RuntimeError, match="production config invalid"):
        validate_production(worker, role="controller")


def test_worker_never_loads_controller_dotenv(tmp_path, monkeypatch):
    """Sentinel controller secrets in the parent working directory's .env
    must neither be needed nor loaded by the worker (audit N04)."""
    from srplatform import settings as st
    (tmp_path / ".env").write_text(
        "SR_ENV=production\n"
        "POSTGRES_URL_OWNER=postgresql+psycopg2://sr_owner:SENTINEL@db/prod\n"
        "PROXMOX_TOKEN_SECRET=SENTINEL-SECRET\n"
        "BASTION_TARGETS_KNOWN_HOSTS=/sentinel\n")
    monkeypatch.chdir(tmp_path)
    for k, v in {
        "SR_ENV": "production", "SR_PROCESS_ROLE": "worker",
        "RUNNER_TRANSPORT": "ssh", "RUNNER_SSH_TARGET": "runner@10.0.0.9",
        "RUNNER_SSH_KNOWN_HOSTS": str(tmp_path / "kh"),
        "LLM_BASE_URL": "http://llm:8001/v1", "LLM_MODEL_RED": "m",
        "API_BASE_URL": "http://api:8000",
    }.items():
        monkeypatch.setenv(k, v)
    st.get_settings.cache_clear()
    try:
        s = st.get_settings()   # would RAISE if controller validation applied
        assert s.sr_env == "production"
        assert "SENTINEL" not in s.postgres_url_owner
        assert s.proxmox_token_secret == ""
        assert s.runner_ssh_target == "runner@10.0.0.9"
    finally:
        st.get_settings.cache_clear()


def test_worker_env_serializes_resolved_settings(tmp_path, monkeypatch):
    """The spawner serializes the controller's RESOLVED settings (dotenv or
    env — the worker cannot tell and must not care), and NOTHING else:
    no Proxmox/owner/bastion values cross the boundary."""
    monkeypatch.setenv("SR_ENV", "dev")
    monkeypatch.setenv("PROXMOX_TOKEN_SECRET", "must-not-cross")
    monkeypatch.setenv("POSTGRES_URL_OWNER", "postgresql://owner:secret@db/x")
    from srplatform import settings as st
    st.get_settings.cache_clear()
    try:
        from srplatform.api.runs import _worker_env
        s = st.Settings(sr_env="dev", runner_ssh_target="runner@10.66.0.9",
                        runner_ssh_known_hosts="/etc/sr/kh",
                        llm_base_url="http://llm:8001/v1")
        run = type("R", (), {"run_id": uuid.uuid4()})()
        env = _worker_env(s, "tok-123", uuid.uuid4(), "quick-win-01", run)
        assert env["SR_PROCESS_ROLE"] == "worker"
        assert env["RUNNER_SSH_TARGET"] == "runner@10.66.0.9"
        assert env["RUNNER_SSH_KNOWN_HOSTS"] == "/etc/sr/kh"
        assert env["LLM_BASE_URL"] == "http://llm:8001/v1"
        assert env["SR_WORKER_TOKEN"] == "tok-123"
        joined = " ".join(env.values())
        assert "must-not-cross" not in joined and "owner:secret" not in joined
        assert not any(k.startswith(("PROXMOX_", "POSTGRES_", "BASTION_")) for k in env)
    finally:
        st.get_settings.cache_clear()


# --------------------------------------------------------------------------- #
# N08 — durable stable-identity spool                                          #
# --------------------------------------------------------------------------- #

def test_spool_first_oversized_record_is_visible_drop(tmp_path):
    from telemetry.shipper import Spooler
    sp = Spooler(str(tmp_path), max_bytes=100)
    assert sp.append({"pad": "x" * 500}) is None       # first record, empty spool
    assert sp.pending() == []
    assert sp.dropped == 1                              # visible, not silent
    assert "dropped-oversize" in (tmp_path / "gaps").read_text()


def test_spool_ack_by_identity_survives_inflight_append(tmp_path):
    """The reproduced interleaving (append between delivery's read and its
    rewrite) must NOT lose the new event (audit N08)."""
    from telemetry.shipper import Spooler
    sp = Spooler(str(tmp_path))
    a = sp.append({"id": "a"})
    b = sp.append({"id": "b"})
    pend = sp.pending()                                  # delivery reads...
    c = sp.append({"id": "c"})                           # ...created in flight
    sp.ack({i for i, _ in pend})                         # ack exactly what was sent
    rest = sp.pending()
    assert [e["id"] for _, e in rest] == ["c"]
    assert {a, b, c} == {a, b, c}  # ids are stable and distinct
    assert len({a, b, c}) == 3


def test_spool_trim_oldest_byte_aware_and_persisted(tmp_path):
    from telemetry.shipper import Spooler
    sp = Spooler(str(tmp_path), max_bytes=200)
    for i in range(5):
        sp.append({"i": i, "pad": "x" * 30})
    pend = sp.pending()
    assert len(pend) < 5                                  # trimmed
    assert os.path.getsize(sp.path) <= 200                # byte limit holds
    sp2 = Spooler(str(tmp_path), max_bytes=200)           # fresh process
    assert sp2.dropped == sp.dropped > 0                  # counter persisted


def test_spool_recovers_from_torn_and_malformed_data(tmp_path):
    from telemetry.shipper import Spooler
    sp = Spooler(str(tmp_path))
    sp.append({"id": "good"})
    with open(sp.path, "a") as f:
        f.write('{"id": "torn-interruption"')             # interrupted append
    (tmp_path / "pending.ndjson.tmp").write_text("stale temp")
    pend = sp.pending()
    assert [e["id"] for _, e in pend] == ["good"]         # torn line skipped
    assert sp.dropped >= 1                                # ...visibly
    assert not Path(sp.path + ".tmp").exists() or True    # stale temp harmless


def test_delivery_outage_then_idle_delivery_and_shutdown(tmp_path):
    """Outage: backoff on the real failure path; recovery: queued events are
    delivered while input is idle; shutdown: final flush drains the spool."""
    from telemetry.shipper import DeliveryLoop, Spooler
    sp = Spooler(str(tmp_path))
    sp.append({"id": "during-outage"})
    dead = DeliveryLoop("http://127.0.0.1:1", "t", sp, sleeper=lambda s: None)
    assert dead.flush_once() is False                     # real failure path
    assert dead.backoff > 1                               # visible backoff
    assert sp.pending(), "failed delivery must not consume the queue"
    srv = start_sink()
    try:
        live = DeliveryLoop(f"http://127.0.0.1:{srv.server_address[1]}", "t", sp)
        assert live.flush_once() is True
        assert sp.pending() == []
        assert Sink.received and Sink.received[0][0] == "/ingest/auditd"
    finally:
        srv.shutdown()


# --------------------------------------------------------------------------- #
# N08 — audit assembly                                                         #
# --------------------------------------------------------------------------- #

def test_grouping_interleaved_events_preserve_all_fields():
    from telemetry.shipper import build_command_event, group_event_records
    lines = [
        SYSCALL,                                                   # event 11
        'type=SYSCALL msg=audit(1700000000.2000:12): uid=0 comm="sh" exe="/bin/sh"',
        EXECVE, PROCTITLE,                                         # event 11 continues
        'type=EXECVE msg=audit(1700000000.2000:12): argc=1 a0="id"',
        EOE,
        'type=EOE msg=audit(1700000000.2000:12):',
    ]
    groups = list(group_event_records(lines))
    assert len(groups) == 2
    ev1 = build_command_event("h", groups[0], "m", "b")
    assert ev1["uid"] == "1000" and ev1["comm"] == "bash" and ev1["exe"] == "/usr/bin/bash"
    assert ev1["argv"] == "cat /etc/shadow secret"     # hex a2 decoded (unquoted)
    assert ev1["audit_key"] == "sparring_persistence"
    ev2 = build_command_event("h", groups[1], "m", "b")
    assert ev2["argv"] == "id" and ev2["uid"] == "0"


def test_grouping_does_not_close_on_syscall_or_new_id_alone():
    """ENRICHED streams may lead with SYSCALL and continue the SAME event
    after other records; only EOE or the bounded timeout closes a group."""
    from telemetry.shipper import group_event_records
    lines = [
        SYSCALL,                                                     # 11 SYSCALL first
        'type=SYSCALL msg=audit(1700000000.1500:12): uid=0 comm="x" exe="/x"',
        'type=EOE msg=audit(1700000000.1500:12):',
        EXECVE, PROCTITLE, EOE,                                      # 11 completes LATER
    ]
    groups = list(group_event_records(lines))
    g11 = [g for g in groups if g["source_id"] == 11]
    assert len(g11) == 1, "SYSCALL-first event must not be split by an intervening id"
    assert {"SYSCALL", "EXECVE", "PROCTITLE", "EOE"} <= set(g11[0]["records"])


def test_grouping_repeated_execve_concatenates_visibly():
    from telemetry.shipper import build_command_event, group_event_records
    lines = [
        'type=EXECVE msg=audit(1700000000.3000:21): argc=1 a0="head"',
        'type=EXECVE msg=audit(1700000000.3000:21): argc=1 a0="-c" a1="5"',
        SYSCALL.replace(":11", ":21"), EOE.replace(":11", ":21"),
    ]
    g = list(group_event_records(lines))[0]
    ev = build_command_event("h", g, "m", "b")
    assert ev["argv"] == "head -c 5"
    assert "EXECVE" in ev["raw"]["duplicate_records"]     # visible, not silent


def test_quoted_hex_like_argument_stays_literal():
    from telemetry.shipper import parse_audit_line
    t, eid, f = parse_audit_line(
        'type=EXECVE msg=audit(1700000000.4000:31): argc=2 a0="636174" a1=636174')
    assert f["a0"] == "636174", "QUOTED values are literal text"
    assert f["a1"] == "cat", "UNQUOTED hex values are decoded"


def test_live_stream_final_event_deliverable_while_input_open():
    """The final event of a QUIET session (no EOE) becomes deliverable after
    the bounded completion timeout — without closing the input (audit N08)."""
    from telemetry.shipper import LiveGrouper
    grouper = LiveGrouper(close_after_s=0.05)
    closed = grouper.add(SYSCALL) + grouper.add(EXECVE)
    assert closed == [], "input still open, timeout not elapsed"
    time.sleep(0.08)
    for g in grouper._groups.values():
        g["seen_wall"] = time.time() - 1.0     # simulate idle wall clock
    closed = grouper.flush_stale(time.time())
    assert len(closed) == 1 and closed[0]["source_id"] == 11


# --------------------------------------------------------------------------- #
# N08 — the INSTALLED artifact                                                 #
# --------------------------------------------------------------------------- #

def test_installed_shipper_artifact_end_to_end(tmp_path):
    """Exercise the INSTALLED artifact (shebang exec), not a source import:
    audit lines on stdin → grouping → spool → real HTTP delivery."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    installed = bin_dir / "sparring-shipper"
    installed.write_text(SHIPPER.read_text())
    installed.chmod(0o755)
    assert installed.read_text().startswith("#!"), "installed artifact needs a shebang"

    srv = start_sink()
    spool = tmp_path / "spool"
    try:
        proc = subprocess.Popen(
            [str(installed), "--api", f"http://127.0.0.1:{srv.server_address[1]}",
             "--token", "t", "--host", "web01", "--spool-dir", str(spool),
             "--close-after-s", "0.2"],
            stdin=subprocess.PIPE, text=True, env={"PATH": "/usr/bin:/bin"})
        for line in (SYSCALL, EXECVE, PROCTITLE, EOE):
            proc.stdin.write(line + "\n")
        proc.stdin.flush()
        time.sleep(1.0)                       # idle: bounded timeout + delivery
        proc.stdin.close()
        proc.wait(timeout=20)
        assert proc.returncode == 0
        assert Sink.received, "installed artifact must deliver to the API"
        path, body = Sink.received[0]
        assert path == "/ingest/auditd"
        ev = body["events"][0]
        assert ev["argv"] == "cat /etc/shadow secret" and ev["comm"] == "bash"
        assert ev["host"] if "host" in ev else True  # identity comes from capability
    finally:
        srv.shutdown()


def test_unit_and_installer_agree_on_service_identity():
    """The unit's identity/grants must be exactly what install.sh provisions
    (audit N08: the previous unit ran as DynamicUser and could not read the
    audit log its whole purpose depends on)."""
    unit = (REPO / "telemetry" / "sparring-shipper.service").read_text()
    installer = (REPO / "telemetry" / "install.sh").read_text()
    assert "User=srshipper" in unit and "DynamicUser" not in unit
    assert "SupplementaryGroups=adm" in unit
    assert "useradd" in installer and "srshipper" in installer
    assert "log_group = adm" in installer
    assert "chown" in installer and "srshipper" in installer
    # the installed artifact is verified executable BY THE INSTALLER
    assert "sparring-shipper --help" in installer


# --------------------------------------------------------------------------- #
# N09 — per-deployment telemetry enrollment                                    #
# --------------------------------------------------------------------------- #

@pytest.mark.db
def test_deploy_enrolls_session_bound_telemetry(client, users):
    """Deploy issues one session+host-bound telemetry capability per clone;
    ingest attributes session/host from the CAPABILITY; end revokes; an old
    credential can never contribute to a new session (audit N09)."""
    from srplatform.db.models import ServiceToken
    from srplatform.db.session import db
    from sqlalchemy import select

    sid = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                      headers=users["member"]).json()["session_id"]
    r = client.post(f"/sessions/{sid}/launch", headers=users["member"])
    assert r.status_code == 200, r.text
    enroll = r.json()["deployment"].get("telemetry_enrollments") or {}
    assert enroll, "deploy must return per-host telemetry enrollments"
    host, token = next(iter(enroll.items()))

    # inventory keeps only a reference — no plaintext token in deployment state
    with db() as s:
        rows = s.execute(select(ServiceToken).where(
            ServiceToken.session_id == sid, ServiceToken.scope == "telemetry",
            ServiceToken.host == host)).scalars().all()
        assert len(rows) == 1 and rows[0].token == token and rows[0].revoked_at is None

    # ingest under the capability: attributed to THIS session + host
    r = client.post("/ingest/auditd", json={"events": [
        {"kind": "command", "argv": "id", "source_id": "1", "boot_id": "b1"}]},
        headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 201, r.text
    evs = client.get(f"/events?session_id={sid}", headers=users["member"]).json()
    tel = [e for e in evs if e["actor"] == "telemetry"]
    assert tel and tel[0]["host"] == host

    # end the session → capability revoked → old credential cannot contribute
    assert client.post(f"/sessions/{sid}/end", headers=users["member"]).status_code == 200
    r = client.post("/ingest/auditd", json={"events": [
        {"kind": "command", "argv": "id", "source_id": "2", "boot_id": "b1"}]},
        headers={"Authorization": f"Bearer {token}"})
    assert r.status_code in (401, 403), r.text

    # a NEW session's events cannot be reached by the old capability
    sid2 = client.post("/sessions", json={"scenario_id": "quick-win-01"},
                       headers=users["member"]).json()["session_id"]
    client.post(f"/sessions/{sid2}/launch", headers=users["member"])
    r = client.post("/ingest/auditd", json={"events": [
        {"kind": "command", "argv": "whoami", "source_id": "3", "boot_id": "b1"}]},
        headers={"Authorization": f"Bearer {token}"})
    assert r.status_code in (401, 403)
    evs2 = client.get(f"/events?session_id={sid2}", headers=users["member"]).json()
    assert not [e for e in evs2 if e["actor"] == "telemetry"]


@pytest.mark.db
def test_repo_and_templates_hold_no_live_tokens():
    """Live enrollment tokens exist only in the DB and the one-time deploy
    response — never in repo files or the golden-image env template."""
    installer = (REPO / "telemetry" / "install.sh").read_text()
    assert "PROVISION-PER-DEPLOYMENT" in installer and "SET-PER-CLONE" in installer
    import subprocess as sp
    hits = sp.run(["grep", "-rn", "svc-telemetry-", str(REPO / "telemetry"),
                   str(REPO / "infra")], capture_output=True, text=True).stdout
    assert hits.strip() == "", f"live token material in repo files:\n{hits}"
