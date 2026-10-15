"""Plan 13 phase 6 — match contract (fast layer): bounded snapshot choices
and schedule-aware observation coverage."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest


# --------------------------------------------------------------------------- #
# bounded, versioned snapshot choices
# --------------------------------------------------------------------------- #

def test_bounded_choices_accepted():
    from srplatform.lifecycle import MATCH_MODES, PACE_CHOICES, START_CONDITIONS
    assert set(MATCH_MODES) == {"practice", "competition"}
    assert set(START_CONDITIONS) == {"network-entry", "assumed-breach"}
    assert set(PACE_CHOICES) == {0, 15, 30, 60}  # 60/30/15 max cadence + fixture 0


def test_create_match_validates_before_storing():
    """create_match raises BEFORE db.add on any unbounded choice (the route
    maps ValueError to 422; nothing is stored)."""
    from unittest.mock import MagicMock

    from srplatform.lifecycle import create_match
    db = MagicMock()
    with pytest.raises(ValueError, match="mode"):
        create_match(db, "sid", "web-foothold-01", mode="anything")
    with pytest.raises(ValueError, match="start_condition"):
        create_match(db, "sid", "web-foothold-01", start_condition="auto")
    with pytest.raises(ValueError, match="pace_seconds"):
        create_match(db, "sid", "web-foothold-01", pace_seconds=5)
    db.add.assert_not_called()


def test_snapshot_freezes_versioned_choices():
    from unittest.mock import MagicMock

    from srplatform.lifecycle import create_match
    db = MagicMock()
    m = create_match(db, "sid", "mojang-web-db-01", duration_minutes=45,
                     pace_seconds=15, mode="competition",
                     start_condition="assumed-breach", injects_enabled=False,
                     actor="drew")
    snap = m.snapshot
    assert snap["snapshot_version"] == 2
    assert snap["mode"] == "competition"
    assert snap["start_condition"] == "assumed-breach"
    assert snap["injects_enabled"] is False
    assert snap["pace_seconds"] == 15 and snap["duration_minutes"] == 45


def test_snapshot_freezes_scenario_and_effective_versions():
    """History can never be re-scored against a later library state."""
    from unittest.mock import MagicMock

    from srplatform.lifecycle import create_match
    db = MagicMock()
    m = create_match(db, "sid", "mojang-web-db-01",
                     scenario_versions={"scenario_version": 3,
                                        "image_version": "noble-20260926",
                                        "scenario_sha256": "ab" * 32},
                     effective_settings={"uptime_scoring_enabled": True})
    assert m.snapshot["scenario_versions"]["image_version"] == "noble-20260926"
    assert m.snapshot["scenario_versions"]["scenario_sha256"] == "ab" * 32
    assert m.snapshot["effective_settings"]["uptime_scoring_enabled"] is True


# --------------------------------------------------------------------------- #
# schedule-aware coverage
# --------------------------------------------------------------------------- #

def _t(mins=0):
    return datetime(2026, 10, 14, 12, tzinfo=timezone.utc) + timedelta(minutes=mins)


def test_coverage_gaps_are_visible_never_fabricated():
    from srplatform.uptime import coverage
    # 10 minutes at 10 s cadence => 60 expected; only 10 arrived
    c = coverage(["up"] * 8 + ["unknown"] * 2, started_at=_t(0), ended_at=_t(10))
    assert c["expected_checks"] == 60 and c["received"] == 10
    assert c["missed"] == 50 and c["unknown"] == 2
    assert c["coverage_pct"] == 16.7
    assert c["scored"] and c["pct_up"] == 100.0  # unknown awarded nothing


def test_coverage_zero_valid_is_unscored_and_down_is_not_unknown():
    from srplatform.uptime import coverage
    c = coverage(["unknown"] * 5, started_at=_t(0), ended_at=_t(1))
    assert not c["scored"] and c["pct_up"] is None
    assert c["down"] == 0  # ambiguous transport NEVER counts as downtime
    c2 = coverage(["up", "down"], started_at=_t(0),
                  ended_at=_t(0) + timedelta(seconds=20))
    assert c2["pct_up"] == 50.0 and c2["expected_checks"] == 2


def test_coverage_open_clock_and_empty_window():
    from srplatform.uptime import coverage
    now = datetime.now(timezone.utc)
    c = coverage([], started_at=now - timedelta(seconds=100), ended_at=None)
    assert c["expected_checks"] == 10 and c["missed"] == 10
    assert not c["scored"] and c["received"] == 0


# --------------------------------------------------------------------------- #
# MySQL business probe (plan 13 phase 6)
# --------------------------------------------------------------------------- #

def test_mysql_probe_command_is_select_only_with_in_guest_password():
    from srplatform.uptime import mysql_probe_command
    cmd = mysql_probe_command()
    assert "SELECT COUNT(*)" in cmd and "INSERT" not in cmd.upper().replace(
        "SELECT", "")
    # credential never crosses the channel: read INSIDE the guest
    assert "--password=\"$(cat /etc/mojang-web/reader-pw)\"" in cmd
    assert "--host=127.0.0.1" in cmd


def test_mysql_probe_three_truths_separate():
    from srplatform.uptime import ProbeInfraError, probe_mysql

    def runner(rc, out):
        return lambda ip, cmd: (rc, out)

    assert probe_mysql(runner(0, "12\n"), "10.0.0.5")[0] == "up"
    # reachable DB, WRONG business answer => down (not up, not unknown)
    assert probe_mysql(runner(0, "9\n"), "10.0.0.5")[0] == "down"
    # session never established => cannot tell whether the query ran
    assert probe_mysql(runner(255, "ssh: connect"), "10.0.0.5")[0] == "unknown"
    # refused connection => target down
    assert probe_mysql(runner(1, "ERROR 2002: Can't connect to "
                                 "local MySQL server (111)"),
                       "10.0.0.5")[0] == "down"
    # OUR credential broken => probe infrastructure, never target downtime
    try:
        probe_mysql(runner(1, "ERROR 1045: Access denied for user"),
                    "10.0.0.5")
        raise AssertionError("expected ProbeInfraError")
    except ProbeInfraError:
        pass
    # channel machinery itself failing => infrastructure too
    def broken(ip, cmd):
        raise OSError("ssh binary vanished")
    try:
        probe_mysql(broken, "10.0.0.5")
        raise AssertionError("expected ProbeInfraError")
    except ProbeInfraError:
        pass


def test_prober_dispatches_http_and_mysql_targets():
    from srplatform.uptime import Prober
    seen = []
    p = Prober("s1", [("web01", "http://x/"), ("db01", "mysql",
                                                 lambda: ("up", 5, "rows"))],
               record=lambda h, s, l, d: seen.append((h, s)),
               interrupt=lambda r: seen.append(("interrupt", r)))
    p._get = lambda url, timeout: type("R", (), {"status_code": 200,
                                                 "text": "Minecraft Legends"})()
    p.run_once()
    assert ("web01", "up") in seen and ("db01", "up") in seen
    assert len(seen) == 2


# --------------------------------------------------------------------------- #
# injects (plan 13 phase 6)
# --------------------------------------------------------------------------- #

def test_inject_catalog_is_versioned_and_typed():
    from srplatform.injects import CATALOG
    assert all(k.endswith("@1") for k in CATALOG)
    kinds = {k: v["kind"] for k, v in CATALOG.items()}
    assert kinds["incident-report@1"] == "written"
    assert sum(1 for v in CATALOG.values() if v["kind"] == "technical") == 3
    # written work can never carry a verifier (advisory only)
    assert CATALOG["incident-report@1"]["verifier"] is None


def test_inject_schedule_derives_from_frozen_duration():
    from datetime import datetime, timezone
    from srplatform.injects import schedule_times
    start = datetime(2026, 10, 14, 12, tzinfo=timezone.utc)
    times = schedule_times(start, 60)
    assert len(times) == 4
    # 20/40/60/80% release, each open 20% of the clock
    assert times[0][0] == start + timedelta(minutes=12)
    assert times[0][1] == start + timedelta(minutes=24)
    assert times[3][1] == start + timedelta(minutes=60)


def test_disabled_inject_set_releases_nothing():
    """injects_enabled=false: schedule returns [] BEFORE touching the db."""
    from unittest.mock import MagicMock
    from srplatform.injects import schedule
    db = MagicMock()
    match = MagicMock()
    match.snapshot = {"injects_enabled": False}
    assert schedule(db, "sid", match, {"topology": {"hosts": []}}) == []
    db.add.assert_not_called()
    db.commit.assert_not_called()


# --------------------------------------------------------------------------- #
# probe infrastructure failure (plan 13 phase 6: DB failure + dead threads)
# --------------------------------------------------------------------------- #

def test_prober_survives_db_failure_and_records_unknown_truth():
    from srplatform.uptime import Prober
    recorded = []
    p = Prober("s1", [("web01", "http://x/"), ("db01", "mysql",
                                                 lambda: ("up", 1, ""))],
               record=lambda h, s, l, d: recorded.append((h, s, d)),
               interrupt=lambda r: None)

    def record_then_stop(host, state, latency, detail):
        recorded.append((host, state, detail))
        p._stop.set()          # end the loop after the first fallback record

    p.run_once = lambda: (_ for _ in ()).throw(
        RuntimeError("db connection lost"))
    p._record = record_then_stop
    p.interval_s = 0.01
    p.loop()                    # must NOT raise: a DB hiccup is survivable
    assert recorded[0][0] == "web01"
    assert recorded[0][1] == "unknown"      # never fabricated downtime
    assert "prober error" in recorded[0][2]

    # DB FULLY down: the loop keeps running (no crash), samples just stop —
    # the schedule gap shows the truth instead.
    p2 = Prober("s2", [("web01", "http://x/")],
                record=lambda *a: None, interrupt=lambda r: None)

    def dead_record(*a):
        p2._stop.set()
        raise RuntimeError("db gone")

    p2.run_once = lambda: (_ for _ in ()).throw(RuntimeError("db gone"))
    p2._record = dead_record
    p2.interval_s = 0.01
    p2.loop()                   # one full failing iteration, no exception


def test_dead_prober_is_detectable_never_fakes_coverage():
    from srplatform.uptime import Prober, coverage
    p = Prober("s1", [("web01", "http://x/")],
               record=lambda *a: None, interrupt=lambda r: None)
    assert p.alive() is False          # never started: NOT alive
    p._get = lambda url, timeout: type("R", (), {"status_code": 200,
                                                 "text": "Minecraft Legends"})()
    p.start()
    assert p.alive() is True
    p.stop()
    assert p.alive() is False          # dead thread is detectable
    # and a dead prober shows as schedule GAPS, never as downtime:
    now = datetime.now(timezone.utc)
    c = coverage(["up"] * 3, started_at=now - timedelta(seconds=100),
                 ended_at=now)
    assert c["missed"] == 7 and c["down"] == 0


def test_filter_scorecard_keeps_totals_seals_items():
    from srplatform.api.visibility import filter_scorecard
    card = {"status": "scored", "earned": 10, "total": 25, "items": [
        {"verifier": "flag_file_present", "host": "web01", "domain": "x",
         "points": 10, "awarded": 10, "status": "passed",
         "evidence": {"path": "/root/flag"}, "error": None}]}
    out = filter_scorecard(card)
    assert out["earned"] == 10 and out["total"] == 25
    assert out["items"] == [{"verifier": "flag_file_present", "host": "web01",
                             "domain": "x", "points": 10, "sealed":
                             "competition — sealed until the match completes"}]


def test_mysql_via_proves_the_network_service_path():
    """The web-origin probe executes the business transaction against the
    DB's range address: loopback-green + broken web→DB path reads DOWN
    (grants/firewall/listener), never healthy. The credential never
    appears in recorded details."""
    from srplatform.uptime import ProbeInfraError, probe_mysql_via

    seen = {}

    def runner(ip, cmd):
        seen["ip"] = ip
        seen["cmd"] = cmd
        return runner.rc, runner.out

    runner.rc, runner.out = 0, "12\n"
    st, _, detail = probe_mysql_via(runner, "10.66.0.10", "10.66.0.11",
                                    "pw-secret-1")
    assert st == "up" and seen["ip"] == "10.66.0.10"
    assert "--host=10.66.0.11" in seen["cmd"] and "pw-secret-1" in seen["cmd"]
    assert "pw-secret" not in detail
    # loopback would be green here — the network path is what failed
    runner.rc, runner.out = 1, "ERROR 2002: Can't connect to MySQL server"
    assert probe_mysql_via(runner, "10.66.0.10", "10.66.0.11",
                           "pw")[0] == "down"
    runner.rc, runner.out = 1, "ERROR 1045: Access denied for user"
    try:
        probe_mysql_via(runner, "10.66.0.10", "10.66.0.11", "pw")
        raise AssertionError("expected ProbeInfraError")
    except ProbeInfraError:
        pass
    runner.rc, runner.out = 255, "ssh: connect"
    assert probe_mysql_via(runner, "10.66.0.10", "10.66.0.11",
                           "pw")[0] == "unknown"


def test_mysql_banner_verifies_greeting_without_guest_code():
    from srplatform.uptime import probe_mysql_banner

    class FakeSock:
        def __init__(self, data):
            self._data = data
        def settimeout(self, t):
            pass
        def recv(self, n):
            return self._data
        def close(self):
            pass

    # real MySQL handshake opening: len(3) + seq 0 + protocol 10
    greeting = b"\x4a\x00\x00\x00\x0a" + b"8.0.36\x00" + b"\x00" * 40
    st, _, detail = probe_mysql_banner(
        "10.66.0.11", connect=lambda addr, timeout=None: FakeSock(greeting))
    assert st == "up" and "no guest code" in detail
    # wrong service on the port
    st, _, _ = probe_mysql_banner(
        "10.66.0.11",
        connect=lambda addr, timeout=None: FakeSock(b"SSH-2.0-x\r\n"))
    assert st == "down"
    # closed/filtered port
    def refused(addr, timeout=None):
        raise OSError("refused")
    assert probe_mysql_banner("10.66.0.11", connect=refused)[0] == "down"


def test_mysql_integrity_flags_disagreeing_paths():
    from datetime import datetime, timezone
    from srplatform.uptime import mysql_integrity
    from unittest.mock import MagicMock

    def rows(pairs):
        rs = []
        for host, detail in pairs:
            r = MagicMock()
            r.host, r.detail = host, detail
            rs.append(r)
        return rs

    import uuid as _uuid
    DEP_ID = _uuid.uuid4()

    def mock_db(sample_rows):
        db = MagicMock()
        dep = MagicMock()
        dep.resources = [{"host": "db01", "mysql_probe": True}]
        db.get.return_value = dep
        db.execute.return_value.scalars.return_value.all.return_value = \
            sample_rows
        return db

    db = mock_db(rows([
        ("db01", "purchases=12"),
        ("web01:db-path", "purchases=12 via network path")]))
    out = mysql_integrity(db, "sid", DEP_ID)
    assert out["agree"] is True and out["host"] == "db01", out

    db = mock_db(rows([
        ("db01", "purchases=12"),
        ("web01:db-path", "purchases=9 via network path")]))
    out = mysql_integrity(db, "sid", DEP_ID)
    assert out["agree"] is False and out["host"] == "db01", out
    assert out["legs"]["loopback"] == "purchases=12"
    assert out["legs"]["network"] == "purchases=9"

    # loopback up + network DOWN without a count: incomparable, and the
    # pair is NOT agreement (the old code returned agree:true here)
    db = mock_db(rows([
        ("db01", "purchases=12"),
        ("web01:db-path", "network path: connection refused")]))
    out = mysql_integrity(db, "sid", DEP_ID)
    assert out["agree"] is False, out

    # single leg only: unknown, never agreement
    db = mock_db(rows([("db01", "purchases=12")]))
    assert mysql_integrity(db, "sid") is None


def test_mysql_direct_authenticates_and_reads_without_guest_code():
    """Controller-side authenticated transaction over canned byte streams:
    handshake → scramble auth → COM_QUERY → first cell. No guest executes
    anything; wrong passwords, auth-switch demands, error packets and
    non-read queries all fail closed."""
    import hashlib
    import struct
    from srplatform import mysql_direct as md

    seed = b"12345678abcdefgh1234"
    plugin = b"mysql_native_password\x00"
    # server handshake: proto 10, version, conn id, part1, caps, ..., part2
    hs = (b"\x0a" + b"8.0.36\x00" + struct.pack("<I", 7) + seed[:8] + b"\x00"
          + struct.pack("<H", 0xFFFF) + b"\x21" + struct.pack("<H", 2)
          + struct.pack("<H", 0xFFFF) + bytes([len(seed) + 1]) + b"\x00" * 10
          + seed[8:] + b"\x00" + plugin)
    coldef = b"\x03def\x06mojang\x09purchases\x09purchases\x08COUNT(*)\x08COUNT(*)\x0c\x21\x00\x0b\x00\x00\x00\x03\x00\x00"
    script = []

    def fake_connect(addr, timeout=None):
        script.append(("connect", addr))
        blobs = [
            struct.pack("<I", len(hs))[:3] + b"\x00" + hs,          # handshake
            b"\x07\x00\x00\x02\x00\x00\x00\x02\x00\x00\x00",          # OK
            b"\x01\x00\x00\x01\x01",                                 # 1 column
            struct.pack("<I", len(coldef))[:3] + b"\x02" + coldef,   # coldef
            b"\x05\x00\x00\x03\xfe\x00\x00\x02\x00",                  # EOF
            b"\x03\x00\x00\x04\x0212",                               # row "12"
            b"\x05\x00\x00\x05\xfe\x00\x00\x02\x00",                  # EOF
        ]
        data = b"".join(blobs)
        state = {"sent": []}

        class Sock:
            def settimeout(self, t):
                pass
            def sendall(self, b):
                state["sent"].append(b)
            def recv(self, n):
                nonlocal data
                if not data:
                    raise OSError("closed")
                out, data = data[:n], data[n:]
                return out
            def close(self):
                pass
        script.append(("sock", state))
        return Sock()

    got = md.select_one("10.66.0.11", "mojang_reader", "secretpw", "mojang",
                        "SELECT COUNT(*) FROM purchases", connect=fake_connect)
    assert got == "12", got
    sent = script[1][1]["sent"]
    auth = sent[0]
    assert b"secretpw" not in auth, "password must be scrambled, never sent"
    assert auth[4:8] == struct.pack("<I", md._CLIENT_CAPS)
    assert sent[1][4:5] == b"\x03" and b"SELECT COUNT" in sent[1]
    # non-read queries refused client-side (never touch the wire)
    try:
        md.select_one("h", "u", "p", "d", "DROP TABLE purchases",
                      connect=fake_connect)
        raise AssertionError("expected MySQLError")
    except md.MySQLError:
        pass
    assert len([s for s in script if s[0] == "connect"]) == 1


def test_mysql_direct_classifies_controller_observations(monkeypatch):
    """The controller-side probe never logs or returns the credential;
    auth refusal reads DOWN (the guest no longer serves what was
    provisioned), transport failure reads DOWN, ambiguity reads unknown."""
    from srplatform import mysql_direct as md
    from srplatform.uptime import probe_mysql_direct

    def fake_select(ip, user, password, database, query, **kw):
        assert user == "mojang_reader" and database == "mojang"
        assert "DROP" not in query
        return fake_select.value

    monkeypatch.setattr(md, "select_one", fake_select)
    fake_select.value = "12"
    st, _, detail = probe_mysql_direct("10.66.0.11", "mojang_reader", "pw")
    assert st == "up" and detail == "purchases=12 (controller-direct)"
    assert "pw" not in detail.replace("purchases", "")
    fake_select.value = "9"
    assert probe_mysql_direct("10.66.0.11", "mojang_reader", "pw")[0] == "down"

    def boom(*a, **k):
        raise md.MySQLError("auth refused: Access denied")
    monkeypatch.setattr(md, "select_one", boom)
    assert probe_mysql_direct("10.66.0.11", "mojang_reader", "pw")[0] == "down"

    def lost(*a, **k):
        raise md.MySQLError("mysql port unreachable: refused")
    monkeypatch.setattr(md, "select_one", lost)
    assert probe_mysql_direct("10.66.0.11", "mojang_reader", "pw")[0] == "down"
