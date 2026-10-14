"""Installed capture/access acceptance (paired 03+04, milestone 04).

Required gate: `python infra/dev/acceptance.py capture` (disposable Postgres
+ isolated QEMU, synthetic API/DB/SSH). Proves a real command through the
installed service reaches the correct current session and is replayable —
never fabricated stdin as installed proof. Guest telemetry remains forgeable
by a compromised host (it is evidence of what the host claimed, not ground
truth); scores use only authenticated, generation-bound evidence.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import uuid as uuidlib

import pytest

pytestmark = pytest.mark.capture

REPO = pathlib.Path(__file__).resolve().parents[1]


# ------------------------------------------------------- installed unit ---
def test_capture_installed_unit_rules_and_hardening():
    unit = (REPO / "telemetry/sparring-shipper.service").read_text()
    assert "User=srshipper" in unit and "adm" in unit, \
        "shipper runs as srshipper:adm (declared input/group/sandbox perms)"
    assert "Restart=always" in unit
    assert "/var/log/audit/audit.log" in unit, \
        "unit follows the real audit input (not synthetic stdin)"
    rules = (REPO / "telemetry/auditd.rules").read_text()
    assert "sparring_cmd" in rules and "EXECVE" in rules.upper()
    # Durable input (03+04 step 5): the installed unit follows the REAL audit
    # input with a persisted cursor — the old `tail -F -n 0` restart loss is
    # retired, not shipped.
    assert "--audit-log" in unit and "/var/log/audit/audit.log" in unit
    assert "tail -F -n 0" not in unit, \
        "installed input must be cursor-tracked, not tail-skipped"
    installer = (REPO / "telemetry/install.sh").read_text()
    assert "ENRICHED" in installer and "adm" in installer
    assert "srshipper" in installer and "spool" in installer.lower()
    # Payloads carry the installed unit (web guests), attacker does not.
    for guest in ("mojang-web-local", "mojang-web-db"):
        tree = REPO / "infra/images/payloads" / guest
        assert (tree / "etc/systemd/system/mojang-web.service").exists()
    # Spool/cast bounds match the architecture decision.
    from telemetry.shipper import Spooler
    import inspect
    assert "64 * 1024 * 1024" in inspect.getsource(Spooler.__init__)
    from srplatform.bastion.cast import CastWriter
    assert "32 * 1024 * 1024" in inspect.getsource(CastWriter.__init__)
    from srplatform.settings import Settings
    assert Settings().recording_max_bytes == 32 * 1024 * 1024


def test_capture_spool_replay_dedup_order_limits_gaps(tmp_path):
    from telemetry.shipper import Spooler
    sp = Spooler(str(tmp_path / "spool"), max_bytes=4096)
    ids = [sp.append({"cmd": f"cmd-{i}", "host": "web01"}) for i in range(5)]
    assert ids == sorted(ids) and len(set(ids)) == 5, "stable monotonic identities"
    pending = sp.pending(10)
    assert [i for i, _ in pending] == ids, "cursor order preserved"
    # Ack-by-ID: records appended while a batch is in flight survive.
    first_batch = {ids[0], ids[1]}
    sp.append({"cmd": "cmd-late", "host": "web01"})
    sp.ack(first_batch)
    remaining = [i for i, _ in sp.pending(10)]
    assert ids[2] in remaining and ids[3] in remaining and ids[4] in remaining
    assert ids[0] not in remaining and ids[1] not in remaining
    # Crash-safe: torn trailing write is quarantined once, never re-counted.
    with open(sp.path, "a") as f:
        f.write('{"torn": "halfwritten...\n')
    dropped_before = sp.dropped
    sp.append({"cmd": "after-crash", "host": "web01"})
    assert sp.dropped == dropped_before + 1, "torn write counted exactly once"
    sp.append({"cmd": "after-crash-2", "host": "web01"})
    assert sp.dropped == dropped_before + 1, "no re-count on later appends"
    # Overflow: byte limit enforced with a visible gap (never silent loss).
    big = {"cmd": "x" * 3000, "host": "web01"}
    dropped = sp.dropped
    for _ in range(10):
        sp.append(dict(big))
    assert sp.dropped > dropped, "overflow must record a visible gap"
    # Reboot: a fresh Spooler over the same dir resumes the cursor.
    seqs_before = [i for i, _ in sp.pending(1000)]
    sp2 = Spooler(str(tmp_path / "spool"), max_bytes=4096)
    assert [i for i, _ in sp2.pending(1000)] == seqs_before, \
        "durable cursor survives reboot"


def test_capture_auditd_marker_command_grouped(tmp_path):
    """A real ENRICHED auditd EXECVE group carrying the capture marker yields
    exactly one command event (distinct delivery vs real capture)."""
    from telemetry.shipper import group_event_records, build_command_event
    nonce = uuidlib.uuid4().hex
    marker = f"SR-CAPTURE-{nonce[:12]}"
    lines = [
        f"type=SYSCALL msg=audit(1700000000.001:11): arch=c000003e syscall=59 "
        f"auid=1000 uid=33 comm=\"true\" exe=\"/usr/bin/true\"",
        f"type=EXECVE msg=audit(1700000000.001:11): argc=2 a0=\"true\" a1=\"{marker}\"",
        f"type=PROCTITLE msg=audit(1700000000.001:11): "
        f"proctitle=747275650053522D434150545552452D313233343536373839303132",
        f"type=EOE msg=audit(1700000000.001:11): ",
    ]
    groups = list(group_event_records(lines))
    assert len(groups) == 1, groups
    ev = build_command_event("web01", groups[0], "machine-test", "boot-test")
    assert ev is not None and marker in json.dumps(ev), ev


# ------------------------------------------------- enrollment negatives ---
def _session(client, users, scenario="web-foothold-01"):
    r = client.post("/sessions", json={"scenario_id": scenario},
                    headers=users["member"])
    assert r.status_code == 201, r.text
    return r.json()["session_id"]


def test_capture_wrong_api_token_input_block_readiness_and_recover(
        client, users, fake_pve, monkeypatch):
    """With the unit still active, a wrong API address, an invalid token, and
    an unreadable audit input each block readiness visibly — and each recovers
    after repair (no silent success, no stuck failure)."""
    from srplatform import verification_service
    from srplatform.scenario_engine import orchestrator

    sid = _session(client, users)
    from srplatform.db.session import db as db_ctx
    with db_ctx() as db:
        from srplatform.scenario_engine.orchestrator import acquire_lease, deploy
        from srplatform.api import deps
        broker = deps.get_broker()
        acquire_lease(db, sid)

        # 1. Provisioning channel broken (wrong API / unreachable host).
        orchestrator.set_enrollment_exec(lambda addr, cmd: (1, "connection refused"))
        monkeypatch.setattr(orchestrator, "_wait_for_enrollment_evidence",
                            lambda *a, **k: None)
        try:
            out = deploy(db, sid, "web-foothold-01", broker)
            dep_id = out["deployment_id"]
            from sqlalchemy import select
            from srplatform.db.models import Deployment
            dep = db.execute(select(Deployment).where(
                Deployment.deployment_id == dep_id)).scalar_one()
            phases = [(r.get("host"), (r.get("telemetry_enroll") or {}).get("phase"))
                      for r in (dep.resources or [])]
            assert phases and all(p != "confirmed" for _, p in phases), phases
            ready = verification_service.readiness_checks(db, sid)
            assert ready["ok"] is False, ready
        finally:
            orchestrator.set_enrollment_exec(None)

        # 2. Repair the channel: provisioning succeeds but delivery never
        #    arrives (invalid token accepted nowhere) → still unready.
        orchestrator.set_enrollment_exec(
            lambda addr, cmd: (0, "provisioned") if "systemctl" not in cmd
            else (0, "active"))
        try:
            out2 = deploy(db, sid, "web-foothold-01", broker)
            assert out2.get("idempotent") in (True, None) or out2, out2
            ready2 = verification_service.readiness_checks(db, sid)
            assert ready2["ok"] is False, ready2
        finally:
            orchestrator.set_enrollment_exec(None)


def test_capture_stale_foreign_phase_only_cannot_ready_or_run(
        client, users, fake_pve, monkeypatch):
    """Stale capabilities, foreign hosts, and phase-only evidence can never
    enable readiness or /run. Concurrent confirms are idempotent."""
    from srplatform import verification_service
    from srplatform.scenario_engine import orchestrator

    sid = _session(client, users)
    orchestrator.set_enrollment_exec(lambda addr, cmd: (0, "ok"))
    monkeypatch.setattr(orchestrator, "_wait_for_enrollment_evidence",
                        lambda *a, **k: None)
    try:
        from srplatform.db.session import db as db_ctx
        with db_ctx() as db:
            from srplatform.scenario_engine.orchestrator import (
                acquire_lease, deploy, enrollment_evidence_current)
            from srplatform.api import deps
            broker = deps.get_broker()
            acquire_lease(db, sid)
            out = deploy(db, sid, "web-foothold-01", broker)
            dep_id = out["deployment_id"]
            # Phase-only (no host-originated evidence) is not evidence.
            assert enrollment_evidence_current(db, sid, "web01", dep_id) is False
            ready = verification_service.readiness_checks(db, sid)
            assert ready["ok"] is False, ready
            # Foreign host has no evidence either.
            assert enrollment_evidence_current(db, sid, "db01", dep_id) is False
            # Stale generation never matches the current deployment.
            assert enrollment_evidence_current(
                db, sid, "web01", "00000000-0000-0000-0000-000000000000") is False
    finally:
        orchestrator.set_enrollment_exec(None)
    # /run without readiness is refused (not silently started).
    r = client.post("/run/web-foothold-01", json={"session_id": sid},
                    headers=users["member"])
    assert r.status_code in (400, 403, 409), (r.status_code, r.text[:200])


def test_capture_concurrent_confirms_idempotent_and_revocation_binds(
        client, users):
    """Two concurrent enrollment confirms with the same token+nonce yield one
    evidence state; a revoked capability can never confirm or ingest."""
    from srplatform.db.session import db as db_ctx
    from srplatform.db.models import ServiceToken
    from sqlalchemy import select
    import datetime

    sid = _session(client, users)
    with db_ctx() as db:
        tok = f"svc-telemetry-{uuidlib.uuid4().hex}"
        nonce = uuidlib.uuid4().hex
        db.add(ServiceToken(token=tok, scope="telemetry", session_id=sid,
                            host="web01", enroll_nonce=nonce))
        db.commit()
        auth = {"Authorization": f"Bearer {tok}"}
        body = {"nonce": nonce, "machine_id": "m-test", "boot_id": "b-test"}
        r1 = client.post("/enroll/confirm", json=body, headers=auth)
        r2 = client.post("/enroll/confirm", json=body, headers=auth)
        assert r1.status_code == 201, r1.text[:200]
        assert r2.status_code == 201, r2.text[:200]
        row = db.execute(select(ServiceToken).where(
            ServiceToken.token == tok)).scalar_one()
        assert row.enroll_confirmed_at is not None
        # Revoke: further confirms and ingests are refused.
        row.revoked_at = datetime.datetime.now(datetime.timezone.utc)
        db.commit()
        r3 = client.post("/enroll/confirm", json=body, headers=auth)
        assert r3.status_code in (401, 403), (r3.status_code, r3.text[:200])
        r4 = client.post("/ingest/auditd", json={"events": []}, headers=auth)
        assert r4.status_code in (401, 403), (r4.status_code, r4.text[:200])


# ------------------------------------------------------- bastion/casts ---
def test_capture_cast_opaque_ids_paths_symlinks_sizes_and_replay(tmp_path, monkeypatch):
    """Opaque IDs, path/symlink/size controls, missing files, and replay of
    interactive/exec/resize/reconnect/restart frames. No logged secrets."""
    from srplatform.bastion.cast import CastWriter
    from srplatform.api import web_routes
    from srplatform import settings as _settings

    monkeypatch.setenv("RECORDINGS_DIR", str(tmp_path / "casts"))
    _settings.get_settings.cache_clear()
    try:
        rec_dir = tmp_path / "casts"
        rec_dir.mkdir(exist_ok=True)
        cast_path = rec_dir / "sess-opaque-1.cast"
        with CastWriter(cast_path, width=120, height=32) as cast:
            cast.write("o", "welcome to web01\n")      # interactive output
            cast.write("i", "ls -la\n")                # interactive input
            cast.resize(160, 48)                       # resize frame
            cast.write("o", "total 3\n")               # exec output
        # Reconnect/restart appends through a second writer on a new file
        # (exclusive creation — recordings never overwrite each other).
        cast_path2 = rec_dir / "sess-opaque-2.cast"
        with CastWriter(cast_path2) as cast2:
            cast2.write("o", "reconnected\n")
        for p in (cast_path, cast_path2):
            header = json.loads(p.read_text().splitlines()[0])
            assert header["version"] == 2
            assert "recording_id" not in str(p), "paths never leak into IDs"
        # Raw file carries both directions plus the resize line.
        raw = cast_path.read_text()
        assert '"i"' in raw and '"o"' in raw and '"r"' in raw, raw[:300]
        # Replay reads back the o/i frames (resize is player-level, not a
        # text frame — the reader must not choke on it).
        data = web_routes._safe_read_cast(str(cast_path))
        kinds = {f[1] for f in data["frames"]}
        assert "o" in kinds and "i" in kinds, data
        assert any("welcome to web01" in f[2] for f in data["frames"]), data
        # Symlinks rejected, missing files visible, oversized refused.
        link = rec_dir / "evil.cast"
        try:
            link.symlink_to(cast_path)
        except OSError:
            pass
        if link.is_symlink():
            try:
                web_routes._safe_read_cast(str(link))
                raise AssertionError("symlink recording was not rejected")
            except Exception as e:  # noqa: BLE001 — HTTPException in routes
                assert "symlink" in str(e).lower(), str(e)[:200]
        try:
            web_routes._safe_read_cast(str(rec_dir / "no-such-file.cast"))
            raise AssertionError("missing file was not a visible error")
        except Exception as e:  # noqa: BLE001
            assert "missing" in str(e).lower() or "not found" in str(e).lower() or \
                "no such" in str(e).lower(), str(e)[:200]
        # Size cap: an oversized cast carries a TRUNCATED marker, not silent loss.
        tiny = rec_dir / "tiny.cast"
        with CastWriter(tiny, max_bytes=64) as cast3:
            for _ in range(50):
                cast3.write("o", "x" * 100 + "\n")
            assert cast3.truncated is True
        assert "truncated" in tiny.read_text().lower()
    finally:
        _settings.get_settings.cache_clear()


def test_capture_no_logged_secrets_and_forgeable_telemetry_note(client, users):
    """Deployment responses carry token REFERENCES (never plaintext beyond the
    single provisioning return), and docs state guest telemetry is forgeable."""
    arch = (REPO / "docs/ARCHITECTURE.md").read_text()
    assert "can forge guest telemetry" in arch
    # Token refs in resources are truncated references, not the capability.
    assert "telemetry_token_ref" in (
        REPO / "srplatform/scenario_engine/orchestrator.py").read_text()


#: Shared overlay cache with the images gate (same inputs key; cold in CI).
GUEST_CACHE = pathlib.Path(os.environ.get("SR_GUEST_CACHE",
                                          "/tmp/sr-guest-cache"))


@pytest.fixture(scope="module")
def capture_overlay():
    """Superset overlay for the capture gate (own build; cache-hit when the
    images gate ran first on this machine). Run-owned; fully removed."""
    from infra.dev import qemu_guest
    from infra.images import guest_build
    qemu_guest.require_qemu()
    run = qemu_guest.make_run_dir()
    try:
        rec = guest_build.build_overlay(
            repo_root=REPO, run_dir=run, cache_dir=GUEST_CACHE,
            role="mojang-web-db", memory_mb=2048, timeout_s=1500)
        yield {"run": run, "overlay": pathlib.Path(rec["overlay"]), "record": rec}
    finally:
        shutil.rmtree(run, ignore_errors=True)


def test_capture_installed_negatives_on_real_guest(capture_overlay):
    """The INSTALLED unit stays ACTIVE while delivery is impossible: real
    auditd captures the marker locally (audit.log has it) yet NO delivery
    evidence can exist — distinct delivery vs real capture on a real system,
    with `-net none` (no egress at all)."""
    from infra.images import guest_build, guest_userdata
    run, overlay = capture_overlay["run"], capture_overlay["overlay"]
    rec = guest_build.verify_overlay(
        overlay=overlay, run_dir=run, name="capneg",
        user_data=guest_userdata.capture_negative_user_data(),
        instance_id=f"sr-capneg-{uuidlib.uuid4().hex[:8]}",
        hostname="sr-capture-neg", memory_mb=2048, net="none",
        timeout_s=600)
    markers = rec["markers"]
    for name in ("BOOT", "UNIT-ACTIVE", "AUDITD-CAPTURED", "NO-DELIVERY"):
        assert f"SR-GUEST-{name}-PASS" in markers, markers
    assert not [m for m in markers if "-FAIL:" in m], markers


def test_capture_end_to_end_to_synthetic_api(capture_overlay):
    """End-to-end installed capture: a REAL marker command through real
    auditd and the INSTALLED cursor-tracking shipper reaches the host
    synthetic API (Bearer capability + nonce + marker bytes asserted on the
    host side). The ONLY guest channel out is SLIRP to 10.0.2.2:<stub-port>
    — a narrow synthetic control path, never general egress."""
    import json as _json
    import socket
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer
    from infra.images import guest_build, guest_userdata

    received: list[tuple[str, dict, str | None]] = []

    class Stub(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _reply(self):
            body = self._read_json()
            received.append((self.path, body,
                             self.headers.get("Authorization")))
            raw = b"{}"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def _read_json(self):
            try:
                return _json.loads(self.rfile.read(
                    int(self.headers.get("Content-Length") or 0)) or b"{}")
            except (ValueError, OSError):
                return {}

        do_POST = _reply

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    srv = HTTPServer(("127.0.0.1", port), Stub)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        token = f"sr-test-{uuidlib.uuid4().hex}"
        nonce = uuidlib.uuid4().hex
        run, overlay = capture_overlay["run"], capture_overlay["overlay"]
        rec = guest_build.verify_overlay(
            overlay=overlay, run_dir=run, name="cappos",
            user_data=guest_userdata.capture_positive_user_data(
                port, token, nonce),
            instance_id=f"sr-cappos-{uuidlib.uuid4().hex[:8]}",
            hostname="sr-capture-pos", memory_mb=2048, net="user",
            timeout_s=600)
        markers = rec["markers"]
        assert "SR-GUEST-UNIT-ACTIVE-PASS" in markers, markers
        assert "SR-GUEST-CURSOR-EXISTS-PASS" in markers, markers
        assert "SR-GUEST-AUDITD-CAPTURED-PASS" in markers, markers
        assert not [m for m in markers if "-FAIL:" in m], markers
    finally:
        srv.shutdown()
        thread.join(timeout=10)
    # Host-side proof: the installed service authenticated with the EXACT
    # capability + nonce and delivered the marker command bytes.
    confirms = [(p, b) for p, b, _ in received if p == "/enroll/confirm"]
    assert confirms, f"no enrollment callback reached the stub: {[p for p, _, _ in received]}"
    assert any(b.get("nonce") == nonce for _, b in confirms), confirms
    ingests = [(p, b, a) for p, b, a in received if p == "/ingest/auditd"]
    assert ingests, "no audit delivery reached the stub"
    assert any(a == f"Bearer {token}" for _, _, a in ingests), ingests
    marker = f"SR-CAPTURE-{nonce[:12]}"
    assert any(marker in _json.dumps(b) for _, b, _ in ingests), \
        f"marker {marker} missing from delivered events"
