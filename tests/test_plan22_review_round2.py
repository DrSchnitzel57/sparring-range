"""Plan-22 review ROUND 2 (candidate 5c9509f): the four residual gaps, each
proven at the REAL producer/consumer boundary.

F1 (HIGH): a malformed broker reply was read as "no engagement active".
The admission check must validate the latch CONTRACT (``{latched: strict
bool, reason, latched_at}``) through the actual typed client — real broker
service answers both ways, and every malformed raw reply over the real
transport (None, {}, [], null/0/string "latched", missing field, truncated
body, HTTP error, timeout) BLOCKS with a clear reason and never leaks a
traceback.

F2 (MEDIUM): the runner health memo was keyed by file PATHS. Through the
real SSH wire: warm a genuine success, replace the host-pin contents IN
PLACE (same path, foreign key) — the very next check must fail, not replay
the cached pass; unchanged content stays memoized. (practice layer)

F3 (MEDIUM): /readyz reported runner.ok from configured strings while
Begin refused. Both surfaces now read the SAME deterministic config fact
(key present, non-empty host trust) — missing key / empty trust refuse on
both, a real positive passes /readyz without any live probe, and the
field labels itself as config-readiness, never health.

F4 (MEDIUM): the recovery instruction named a command that did not exist.
The documented ``rangectl safety reclassify KIND --reason ...`` is now the
SUPPORTED path end to end: CLI --help, real subprocess -> authenticated
API -> appended DB classification (operator, source digest, current
identity), original untouched; wrong kind/role/moved source all refuse.
"""
from __future__ import annotations

import http.server
import json
import os
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path

import pytest

from tests.helpers import FakeDatapath

import srplatform.safety as safety_mod
from srplatform.settings import Settings

REPO = Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------- F1 -- #
_LATCH_OK = {"latched": False, "reason": None, "latched_at": None}


def _f1_sup(tmp_path, broker):
    from srplatform.safety import Supervisor
    return Supervisor(
        datapath=FakeDatapath(),
        settings=Settings(sr_env="dev", runner_transport="local-dev",
                          allow_local_dev_fixture=True,
                          safety_state_file=str(tmp_path / "s.json")),
        broker=broker, state_file=str(tmp_path / "s.json"))


class _Raw:
    """broker stub returning a raw reply (or raising)."""

    def __init__(self, reply=None, exc=None):
        self._reply, self._exc = reply, exc

    def latch_status(self):
        if self._exc:
            raise self._exc
        return self._reply


def test_real_broker_contract_both_ways(tmp_path):
    """The production pair through the actual typed client + real ledger:
    a valid UNLATCHED record passes, an ENGAGED one blocks — and the pass
    is phrased as contract-answered, never a blank truthiness win."""
    from infra.broker.testing import make_fake_broker
    client, service, _http = make_fake_broker()
    sup = _f1_sup(tmp_path, client)
    out = sup._broker_check()
    assert out["ok"] is True and "latch contract" in out["detail"]
    service.ledger.set_latch(True, "review-round-2 drill")
    out = sup._broker_check()
    assert out["ok"] is False and "ACTIVE" in out["detail"]
    assert "drill" in out["detail"]


def test_malformed_replies_all_block_never_release(tmp_path):
    """The counterexamples: None, {}, [], latched null/0/string, missing
    fields, non-dict — every one BLOCKS; only the exact contract shape
    passes. Nothing raises."""
    cases = [
        (None, "UNTRUSTED"),
        ({}, "missing"),
        ([], "UNTRUSTED"),
        ("down", "UNTRUSTED"),
        ({"latched": None, "reason": None, "latched_at": None}, "UNTRUSTED"),
        ({"latched": 0, "reason": None, "latched_at": None}, "UNTRUSTED"),
        ({"latched": "false", "reason": None, "latched_at": None},
         "UNTRUSTED"),
        ({"latched": False, "reason": None}, "missing"),      # no latched_at
        ({"reason": None, "latched_at": None}, "missing"),    # no latched
    ]
    for reply, word in cases:
        out = _f1_sup(tmp_path, _Raw(reply))._broker_check()
        assert out["ok"] is False, f"{reply!r} was released: {out}"
        assert word in out["detail"], (reply, out)
        assert "Traceback" not in out["detail"]
    good = _f1_sup(tmp_path, _Raw(dict(_LATCH_OK)))._broker_check()
    assert good["ok"] is True


def test_unreachable_authority_blocks_clearly(tmp_path):
    out = _f1_sup(tmp_path, _Raw(exc=TimeoutError("connect timed out"))
                  )._broker_check()
    assert out["ok"] is False and "unreachable" in out["detail"]
    assert "Traceback" not in out["detail"]


class _WireHandler(BaseHTTPRequestHandler):
    """One scripted raw reply per request on a real Unix socket: the
    ACTUAL HttpTransport + BrokerClient parse it (transport and JSON
    contract included)."""

    def do_POST(self):  # noqa: N802
        n = int(self.headers.get("Content-Length") or 0)
        self.rfile.read(n)
        code, body = self.server.script.pop(0) if self.server.script else (
            200, b'{"result": {"latched": false, "reason": null,'
                 b' "latched_at": null}}')
        if callable(body):
            body = body()          # e.g. a slow reply to force a timeout
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):  # silence
        pass


class _UnixHTTPServer(http.server.ThreadingHTTPServer):
    address_family = socket.AF_UNIX

    def server_bind(self):
        if os.path.exists(self.server_address):
            os.unlink(self.server_address)
        super().server_bind()


def _unix_broker(tmp_path, script, timeout=5.0):
    from infra.broker.client import BrokerClient, HttpTransport

    sock = tmp_path / "b.sock"
    srv = _UnixHTTPServer(str(sock), _WireHandler)
    srv.script = list(script)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, BrokerClient(HttpTransport(f"unix://{sock}",
                                           timeout=timeout))


def test_typed_client_wire_variants_block(tmp_path):
    """Malformed-over-the-wire is not health either: the real typed client
    (unix transport, JSON contract) feeds the same blocking verdicts."""
    cases = [
        (b'{"result": null}', "UNTRUSTED"),                  # None result
        (b'{"result": {}}', "missing"),
        (b'{"result": {"latched": null, "reason": null, "latched_at": 1}}',
         "UNTRUSTED"),
        (b'{"result": {"latched": false, "reason": null',       # truncated
         "malformed"),
        (b'{"nondict-payload": 1}', "malformed"),               # no result
    ]
    for body, word in cases:
        srv, client = _unix_broker(tmp_path, [(200, body)])
        try:
            out = _f1_sup(tmp_path, client)._broker_check()
            assert out["ok"] is False, (body, out)
            assert word in out["detail"] or "unreachable" in out["detail"], \
                (body, out)
        finally:
            srv.shutdown()
            srv.server_close()
    # HTTP-level refusal (wrong authority / broken service)
    srv, client = _unix_broker(tmp_path, [(503, b"nope")])
    try:
        out = _f1_sup(tmp_path, client)._broker_check()
        assert out["ok"] is False and "unreachable" in out["detail"]
    finally:
        srv.shutdown()
        srv.server_close()

    # connection timeout: BOTH read attempts (the typed client retries a
    # failed READ once) must miss the bound — then it blocks as unreachable
    def _slow():
        time.sleep(1.5)
        return b'{"result": {"latched": false, "reason": null, "latched_at": null}}'

    srv, client = _unix_broker(tmp_path, [(200, _slow), (200, _slow)],
                               timeout=0.4)
    try:
        out = _f1_sup(tmp_path, client)._broker_check()
        assert out["ok"] is False and "unreachable" in out["detail"]
    finally:
        srv.shutdown()
        srv.server_close()
    # and the healthy wire reply passes
    srv, client = _unix_broker(tmp_path, [])
    try:
        out = _f1_sup(tmp_path, client)._broker_check()
        assert out["ok"] is True
    finally:
        srv.shutdown()
        srv.server_close()


# --------------------------------------------------------------------- F2 -- #
from tests.test_plan22_runner_probe import (  # noqa: E402 — real wire harness
    _RunnerServer, _isolate_home, _keys, _pin, _pub_of, _settings,
    _throwaway_pub)


def _ssh_sup(tmp_path, settings):
    from srplatform.safety import Supervisor
    return Supervisor(datapath=FakeDatapath(), settings=settings,
                      state_file=str(tmp_path / "sup.json"))


@pytest.mark.practice
async def test_in_place_pin_swap_defeats_cached_health(tmp_path,
                                                       _isolate_home,
                                                       monkeypatch):
    """Warm a REAL ssh success, then replace the known_hosts CONTENT at the
    SAME path with a foreign pin: the memo key is the trust IDENTITY, so
    the next check must re-probe and refuse — the cached pass may not
    survive its own authority. Unchanged content stays memoized."""
    import asyncio

    client_key, _other, _host = _keys(tmp_path)
    srv = _RunnerServer()
    port = await srv.start(accept_pub=_pub_of(client_key))
    try:
        kh = tmp_path / "known_hosts"
        kh.write_text(_pin(port, srv))
        s = _settings(tmp_path, key=client_key, known_hosts=kh, port=port)
        sup = _ssh_sup(tmp_path, s)

        calls = []
        real = safety_mod._runner_health_probe

        def counting(settings):
            calls.append(1)
            return real(settings)

        monkeypatch.setattr(safety_mod, "_runner_health_probe", counting)

        # the probe runs on a worker thread — the asyncssh SERVER answers
        # from THIS loop (exact harness pattern), so never block it
        async def check():
            return await asyncio.to_thread(sup._runner_check)

        r1 = await check()
        assert r1["ok"] is True, r1["detail"]
        r2 = await check()                        # memoized, no probe
        assert r2["ok"] is True and len(calls) == 1

        kh.write_text(f"[127.0.0.1]:{port} {_throwaway_pub()}\n")
        r3 = await check()                        # identity changed NOW
        assert len(calls) == 2, "pin swap did not invalidate the memo"
        assert r3["ok"] is False, "foreign host pin was accepted"

        # deleting the identity entirely also refuses (not cached away)
        kh.write_text(_pin(port, srv))            # trusted content back
        await check()                             # re-warm
        before = len(calls)
        client_key.unlink()
        r4 = await check()
        assert len(calls) == before, \
            "missing key must fail on the deterministic fact, not a probe"
        assert r4["ok"] is False and "private key missing" in r4["detail"]
    finally:
        await srv.stop()


# --------------------------------------------------------------------- F3 -- #
def _ssh_settings(tmp_path, *, key_ok: bool, trust_text: str | None):
    key = tmp_path / "runner_key"
    if key_ok:
        key.write_text("dummy-private-key\n")
        # review F3: OpenSSH (and now the shared readiness fact) refuses
        # group/other-accessible keys — a usable config carries 0600
        key.chmod(0o600)
    kh = tmp_path / "known_hosts"
    if trust_text is not None:
        kh.write_text(trust_text)
    return Settings(sr_env="production", runner_transport="ssh",
                    runner_ssh_target="runner@10.10.10.60:22",
                    runner_ssh_key_path=str(key),
                    runner_ssh_known_hosts=str(kh),
                    safety_state_file=str(tmp_path / "s.json"))


def _f3_sup(tmp_path, settings):
    from srplatform.safety import Supervisor, set_supervisor
    sup = Supervisor(datapath=FakeDatapath(), settings=settings,
                     state_file=str(tmp_path / "s.json"))
    set_supervisor(sup)
    return sup


def test_readyz_runner_fact_matches_the_classifier(tmp_path, client, users):
    """Review F3 counterexamples on the REAL API: missing private key and
    EMPTY host trust must NOT answer runner.ok TRUE while Begin refuses —
    /readyz reports the exact same shared config fact, labeled as
    readiness and never as health, with no live probe on the path."""
    # (a) configured but the private key does not exist
    s = _ssh_settings(tmp_path, key_ok=False,
                      trust_text="ssh-ed25519 AAAA c\n")
    _f3_sup(tmp_path, s)
    body = client.get("/readyz").json()
    assert body["runner"]["ok"] is False
    assert "private key missing" in body["runner"]["detail"]
    assert "config-readiness" in body["runner"]["fact"]
    # the SAME fact drives Begin eligibility — the surfaces cannot disagree
    q = client.get("/safety/qualification", headers=users["member"]).json()
    runner_check = [c for c in q["admission"]["checks"]
                    if c["check"] == "runner"][0]
    assert runner_check["ok"] is False
    assert runner_check["detail"] == body["runner"]["detail"]
    assert not q["begin_allowed"]
    assert any("runner" in b.lower() or "key" in b.lower()
               for b in q["begin_blockers"])

    # (b) key present but the trust file is EMPTY
    s = _ssh_settings(tmp_path, key_ok=True, trust_text="")
    _f3_sup(tmp_path, s)
    body = client.get("/readyz").json()
    assert body["runner"]["ok"] is False and "EMPTY" in body["runner"]["detail"]

    # (c) real positive: facts present -> honest readiness true, but the
    # field never claims health (nothing opened a connection: the detail
    # says CONFIGURED, never reachable)
    s = _ssh_settings(tmp_path, key_ok=True,
                      trust_text="[10.10.10.60]:22 ssh-ed25519 AAAA\n")
    _f3_sup(tmp_path, s)
    body = client.get("/readyz").json()
    assert body["runner"]["ok"] is True
    assert "key + non-empty host trust present" in body["runner"]["detail"]
    assert "reachable" not in body["runner"]["detail"]
    assert "health" in body["runner"]["fact"]  # names where health lives


# --------------------------------------------------------------------- F4 -- #
def _seed_legacy(kind: str = "baseline_check", *, ok: bool = True,
                 age_h: float = 100.0) -> float:
    """A pre-contract record exactly as it exists installed: appended
    BEFORE the contract marker, honest ok, old identity, empty detail."""
    from sqlalchemy import text

    from srplatform.db.session import db as db_ctx
    with db_ctx() as s:
        s.execute(text(
            "INSERT INTO safety_records (kind, ok, config_identity, detail,"
            " recorded_at) VALUES (:k, :ok, 'legacy-identity-17', '{}'::jsonb,"
            " now() - make_interval(hours => :h))"),
            {"k": kind, "ok": ok, "h": int(age_h)})
    with db_ctx() as s:
        return float(s.execute(text(
            "SELECT extract(epoch from recorded_at) FROM safety_records"
            " WHERE kind = :k ORDER BY record_id DESC LIMIT 1"),
            {"k": kind}).scalar_one())


def _reclassify_rows(kind: str):
    from sqlalchemy import text

    from srplatform.db.session import db as db_ctx
    with db_ctx() as s:
        return s.execute(text(
            "SELECT ok, detail FROM safety_records WHERE kind ="
            " :k ORDER BY record_id"), {"k": kind}).fetchall()


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_reclassify_cli_to_api_to_db_end_to_end(tmp_path, client, users):
    """The documented recovery is REAL: the blocker names
    ``rangectl safety reclassify <kind> --reason ...``; that exact command
    (a real subprocess, real HTTP, authenticated) appends the
    classification to the database — operator, source digest, current
    identity — leaving the original untouched; then the surfaces read the
    kind as current usable evidence. Negatives refuse."""
    import uvicorn

    at = _seed_legacy()
    # the classification surface that PRODUCES the instruction names the
    # real command verbatim (same report Begin cites):
    report = safety_mod.get_supervisor().qualification_report()
    base = next(x for x in report["qualifications"]
                if x["kind"] == "baseline_check")
    assert base["provenance"] == "legacy-unclassified"
    assert any("rangectl safety reclassify baseline_check --reason" in p
               for p in base["problems"])

    # start a REAL server for the CLI subprocess (same DB, same app, and
    # the SAME config identity — the classification is bound to it)
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(
        "srplatform.api.app:app", host="127.0.0.1", port=port,
        log_level="error"))
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    deadline = time.time() + 30
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started, "uvicorn did not start for the CLI leg"

    env = {**os.environ,
           "HOME": str(tmp_path),
           "PYTHONPATH": str(REPO),
           "SR_API_BASE_URL": f"http://127.0.0.1:{port}",
           "SR_CLI_TOKEN": users["op_token"]}
    py = sys.executable

    def cli(*args, timeout=120):
        return subprocess.run([py, "-m", "rangectl.cli", *args],
                              capture_output=True, text=True, env=env,
                              cwd=str(REPO), timeout=timeout)

    try:
        h = cli("safety", "--help")
        assert h.returncode == 0 and "reclassify" in h.stdout, h.stdout
        # wrong kind: refused, non-zero, names the kind (422 path)
        bad = cli("safety", "reclassify", "not_a_kind",
                  "--reason", "drill ref R-1")
        assert bad.returncode != 0 and "kind" in (bad.stdout + bad.stderr)
        # the documented command itself — VERBATIM shape, no secrets in it
        ok = cli("safety", "reclassify", "baseline_check",
                 "--reason", "signed commissioning report ref R-17",
                 "--expect-recorded-at", str(at))
        assert ok.returncode == 0, ok.stdout + ok.stderr
        assert json.loads(ok.stdout)["ok"] is True
    finally:
        server.should_exit = True
        th.join(timeout=15)

    # DB facts: exactly one NEW row, classification detail complete, the
    # legacy original untouched.
    rows = _reclassify_rows("baseline_check")
    assert len(rows) == 2
    assert rows[0][1] == {}                       # original verbatim
    d = rows[1][1]
    assert rows[1][0] is True
    assert d["one_time_reclassification"] is True
    assert d["operator"] == "drew"
    assert d["reason"] == "signed commissioning report ref R-17"
    assert d["original_detail_digest"]
    assert abs(float(d["reclassified_record_at"]) - at) < 2
    assert d["bound_identity"] and len(d["bound_identity"]) == 16

    # the surfaces now see current, usable evidence for that kind (the
    # server process recorded it under THIS environment's identity)
    q = client.get("/safety/qualification", headers=users["op"]).json()
    base = next(x for x in q["qualifications"]
                if x["kind"] == "baseline_check")
    assert base["provenance"] == "current" and base["usable"], base


def test_reclassify_api_negatives(client, users):
    """Role, kind, absent-source, failed-source, already-contracted and a
    MOVED source (concurrent replacement) each refuse with a real status;
    none of them appends a record."""
    from sqlalchemy import text

    from srplatform.db.session import db as db_ctx

    def count() -> int:
        with db_ctx() as s:
            return int(s.execute(text(
                "SELECT count(*) FROM safety_records")).scalar_one())

    count0 = count()
    url = "/safety/reclassify-qualification"
    assert client.post(url, headers=users["member"], json={
        "kind": "baseline_check", "reason": "member should not classify"},
    ).status_code == 403
    assert client.post(url, headers=users["op"], json={
        "kind": "engage", "reason": "not a qualification kind"},
    ).status_code == 422
    assert client.post(url, headers=users["op"], json={
        "kind": "datapath_proof", "reason": "nothing recorded yet"},
    ).status_code == 404

    at = _seed_legacy("baseline_check")
    _seed_legacy("baseline_check", ok=False, age_h=1)   # newest FAILED
    r = client.post(url, headers=users["op"], json={
        "kind": "baseline_check", "reason": "classify a passing record"})
    assert r.status_code == 409 and "FAILED" in r.json()["detail"]
    # ...and even the exact-source expectation cannot launder a failure
    r = client.post(url, headers=users["op"], json={
        "kind": "baseline_check", "reason": "classify a passing record",
        "expect_recorded_at": at})
    assert r.status_code == 409

    # concurrent replacement: the operator examined AT, but a newer row
    # arrived — the stale expectation must refuse (409, not silent newest)
    kt = _seed_legacy("killswitch_test")
    _seed_legacy("killswitch_test", age_h=1)            # record moved
    r = client.post(url, headers=users["op"], json={
        "kind": "killswitch_test", "reason": "stale examination",
        "expect_recorded_at": kt})
    assert r.status_code == 409 and "no longer" in r.json()["detail"]

    # a fresh classification succeeds; classifying it AGAIN is refused
    # because the newest record now carries the contract itself
    fresh = _seed_legacy("datapath_proof", age_h=2)
    ok = client.post(url, headers=users["op"], json={
        "kind": "datapath_proof", "reason": "verified provenance ref R-2",
        "expect_recorded_at": fresh})
    assert ok.status_code == 200, ok.text
    again = client.post(url, headers=users["op"], json={
        "kind": "datapath_proof", "reason": "second bite at the apple"})
    assert again.status_code == 409 and "contract" in again.json()["detail"]

    # exactly the one accepted write (plus this test's 5 seeded records)
    assert count() == count0 + 6
