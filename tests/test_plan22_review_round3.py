"""Plan-22 review ROUND 3 (candidate 7ed7e0b) — the five residual gaps,
proven at the real boundary, under the OWNER SYSTEM CONTRACT:

    RECLASSIFICATION TIME IS NOT OBSERVATION TIME. The compatibility
    decision appends an AUDIT event now; the effective observation time,
    scope and provenance remain the ORIGINAL test's. Publication is one
    authoritative serialized read-validate-append (row-locked CAS); no
    unfenced fallback publish exists.

F1: classification of a 4000 h legacy record keeps age 4000 h and stays
    BLOCKED when a release followed the original observation (API+DB);
    a valid original after the last transition stays usable AT ITS REAL
    AGE; a nested classification chain evaluates from the oldest original.
F2: two real HTTP classifiers race one source behind a barrier — exactly
    ONE wins (row-locked CAS), the loser gets the truthful conflict, the
    original stays immutable; persistence failure is a truthful 503 with
    zero published rows; a later FAILED still blocks (nothing laundered).
F3 (practice): on the REAL SSH wire a warm success with a 0600 key turns
    into an immediate refusal at 0644 WITHOUT any probe (OpenSSH would
    refuse; so does the shared fact), unreadable refuses, restoring 0600
    re-probes and recovers, and in-place key replacement invalidates.
F4: the broker metadata fields are typed per the real ledger contract
    (reason TEXT|NULL, latched_at finite numeric epoch|NULL) over the
    REAL unix transport; legitimate NULLs pass, dict/list/number/
    string/bool/Infinity metadata blocks as UNTRUSTED.
F5: the short browser alias is allocated by EXCLUSIVE creation only —
    foreign sentinels (file, dir, symlink) at candidate names are never
    unlinked — and cleanup removes only the exact owned inode.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import threading
import time
from pathlib import Path

import pytest

from tests.helpers import FakeDatapath

REPO = Path(__file__).resolve().parents[1]
_LATCH_OK = {"latched": False, "reason": None, "latched_at": None}


def _f1_sup(tmp_path, broker):
    from srplatform.safety import Supervisor
    from srplatform.settings import Settings
    return Supervisor(
        datapath=FakeDatapath(),
        settings=Settings(sr_env="dev", runner_transport="local-dev",
                          allow_local_dev_fixture=True,
                          safety_state_file=str(tmp_path / "s.json")),
        broker=broker, state_file=str(tmp_path / "s.json"))


class _Raw:
    def __init__(self, reply=None, exc=None):
        self._reply, self._exc = reply, exc

    def latch_status(self):
        if self._exc:
            raise self._exc
        return self._reply


# --------------------------------------------------------------------- F4 -- #
def test_broker_metadata_typed_per_the_ledger_contract(tmp_path):
    """get_latch ships ``{latched: bool, reason: str|None,
    latched_at: epoch-number|None}``. Malformed metadata is a malformed
    ANSWER — blocked as UNTRUSTED — while legitimate NULLs pass; nothing
    is reduced to truthiness."""
    cases = [
        # legitimate ledger representations (unlatched) PASS
        ({"latched": False, "reason": None, "latched_at": None}, True),
        ({"latched": False, "reason": None, "latched_at": 1730000000.5},
         True),
        ({"latched": False, "reason": "prior drill", "latched_at": 17},
         True),
        # metadata the real ledger CANNOT produce -> UNTRUSTED
        ({"latched": False, "reason": {}, "latched_at": []}, False),
        ({"latched": False, "reason": 7, "latched_at": None}, False),
        ({"latched": False, "reason": None,
         "latched_at": "not-a-timestamp"}, False),
        ({"latched": False, "reason": None, "latched_at": True}, False),
        ({"latched": False, "reason": None, "latched_at": [1]}, False),
        # engaged stays engaged, with honest metadata
        ({"latched": True, "reason": "operator stop",
         "latched_at": 1730000000}, False),
    ]
    for reply, want_ok in cases:
        out = _f1_sup(tmp_path, _Raw(dict(reply)))._broker_check()
        assert out["ok"] is want_ok, (reply, out)
        if not want_ok:
            bad_meta = reply["latched"] is False
            word = "UNTRUSTED" if bad_meta else "ACTIVE"
            assert word in out["detail"], (reply, out)
    # non-finite numbers (json Infinity/NaN land as float) block too
    for weird in (float("inf"), float("nan")):
        out = _f1_sup(tmp_path, _Raw({"latched": False, "reason": None,
                                      "latched_at": weird}))._broker_check()
        assert out["ok"] is False and "UNTRUSTED" in out["detail"], weird


# --------------------------------------------------------------------- F5 -- #
def _load_acceptance():
    name = "sr_acceptance_under_test"
    spec = importlib.util.spec_from_file_location(
        name, REPO / "infra" / "dev" / "acceptance.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_pw_alias_ownership_exclusive_allocation(tmp_path):
    """A pre-existing path at a candidate name — the exact thing an
    earlier reviewer hit — is SKIPPED UNTOUCHED, never unlinked; cleanup
    removes only the owned symlink pointing at the owned target."""
    acc = _load_acceptance()

    target = tmp_path / "run" / "pw-tmp"
    target.mkdir(parents=True)

    sentinel_dir = tmp_path / "sentinel-dir"
    sentinel_dir.mkdir()
    (sentinel_dir / "keep.me").write_text("reviewer data")
    sentinel_file = tmp_path / "sentinel-file"
    sentinel_file.write_text("do not delete me")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    sentinel_link = tmp_path / "sentinel-link"
    os.symlink(str(elsewhere), str(sentinel_link))
    inodes_before = {p: p.stat().st_ino for p in
                     (sentinel_dir, sentinel_file, sentinel_link)}

    good = tmp_path / "short-owned-alias"
    alias = acc._pw_alias_allocate(target, iter(
        [sentinel_dir, sentinel_file, sentinel_link, good]))
    assert alias == good
    assert alias.is_symlink() and Path(os.readlink(str(good))) == \
        target.resolve()
    for p, ino in inodes_before.items():
        assert p.is_symlink() if p == sentinel_link else p.exists()
        assert p.stat().st_ino == ino, f"{p} was disturbed"
    assert sentinel_file.read_text() == "do not delete me"
    assert (sentinel_dir / "keep.me").read_text() == "reviewer data"
    assert os.readlink(str(sentinel_link)) == str(elsewhere)

    # normal cleanup removes exactly the owned alias, target intact
    acc._pw_alias_release(alias, target)
    assert not good.exists() and not good.is_symlink()
    assert target.is_dir()

    # exhausted candidates: RuntimeError, NOTHING deleted
    with pytest.raises(RuntimeError):
        acc._pw_alias_allocate(target, iter(
            [sentinel_dir, sentinel_file, sentinel_link]))
    assert sentinel_file.read_text() == "do not delete me"

    # hostile cleanup races: alias replaced by a DIRECTORY, or retargeted
    alias2 = acc._pw_alias_allocate(target, iter([tmp_path / "a2"]))
    alias2.unlink()
    alias2.mkdir()
    acc._pw_alias_release(alias2, target)
    assert alias2.is_dir(), "a foreign directory took the name — left alone"
    alias2.rmdir()

    alias3 = acc._pw_alias_allocate(target, iter([tmp_path / "a3"]))
    alias3.unlink()
    os.symlink(str(elsewhere), str(alias3))
    acc._pw_alias_release(alias3, target)
    assert alias3.is_symlink() and os.readlink(str(alias3)) == str(elsewhere)
    acc._pw_alias_release(alias3, target)   # ours again -> removable
    alias3.unlink(missing_ok=True)


def test_pw_alias_is_short_enough_for_chromium(tmp_path):
    """The default name pool yields REAL /tmp names far under the unix
    socket cap (~107 chars for the socket, so keep the alias < 40)."""
    acc = _load_acceptance()
    target = tmp_path
    alias = acc._pw_alias_allocate(target)
    try:
        assert str(alias).startswith("/tmp/srpw-")
        assert len(str(alias)) < 40
    finally:
        acc._pw_alias_release(alias, target)
    assert not alias.exists() and not alias.is_symlink()


# --------------------------------------------------------------- F1 & F2 --- #
# (real API + PostgreSQL lanes below)
def _seed(kind, *, ok=True, ident="legacy-identity-17", detail=None,
          age_h=4000.0, detail_json=None):
    from sqlalchemy import text

    from srplatform.db.session import db as db_ctx
    d = detail_json if detail_json is not None else (
        detail if detail is not None else {})
    with db_ctx() as s:
        s.execute(text(
            "INSERT INTO safety_records (kind, ok, config_identity, detail,"
            " recorded_at) VALUES (:k, :ok, :i, CAST(:d AS jsonb),"
            " now() - make_interval(hours => :h))"),
            {"k": kind, "ok": ok, "i": ident, "d": json.dumps(d),
             "h": int(age_h)})


def _rows(kind):
    from sqlalchemy import text

    from srplatform.db.session import db as db_ctx
    with db_ctx() as s:
        return [(r[0], r[1], r[2], float(r[3]))
                for r in s.execute(text(
                    "SELECT record_id, ok, detail, extract(epoch from recorded_at)"
                    " FROM safety_records WHERE kind = :k ORDER BY record_id"),
                    {"k": kind}).fetchall()]


def _qual(client, users, kind):
    q = client.get("/safety/qualification", headers=users["op"]).json()
    return next(x for x in q["qualifications"] if x["kind"] == kind), q


def test_reclassification_keeps_the_original_observation_time(
        client, users):
    """F1 core counterexample, end-to-end on API+DB: a 4000 h legacy
    source with a LATER release stays blocked after the classification —
    and the age stays 4000 h. A valid original after the last transition
    stays usable AT ITS REAL AGE (never 0.0, never a daily ritual)."""
    now = time.time()
    _seed("baseline_check", age_h=4000)
    _seed("release", age_h=1)
    r = client.post("/safety/reclassify-qualification", headers=users["op"],
                    json={"kind": "baseline_check",
                          "reason": "signed commissioning report R-3"})
    assert r.status_code == 200, r.text
    body = r.json()
    src_at = _rows("baseline_check")[0][3]
    assert abs(float(body["observed_at"]) - src_at) < 2   # ORIGINAL time
    assert now - float(body["observed_at"]) / 1.0 > 3990 * 3600

    q, _ = _qual(client, users, "baseline_check")
    assert q["provenance"] == "current"
    assert q["usable"] is False, "a release AFTER the observation must " \
                                 "keep blocking, classification or not"
    assert any("predates the last release" in p for p in q["problems"])
    assert 3990 < q["age_h"] < 4010, q["age_h"]     # age 4000h, not 0.0
    # the UI can explain the two dates: observation vs decision
    assert abs(q["observed_at"] - src_at) < 2
    assert abs(q["classified_at"] - now) < 120

    # DB truth: exactly one new row; source kept byte-identical; the
    # audit fields name the source and separate the decision time.
    rows = _rows("baseline_check")
    assert len(rows) == 2                          # legacy + classification
    assert rows[0][2] == {}                        # original untouched
    cls = rows[1][2]
    assert cls["observed_at"] == pytest.approx(src_at, abs=2)
    assert cls["source_record_id"] == rows[0][0]
    assert cls["original_detail_digest"]
    assert cls["classification_decided_at"] > cls["observed_at"]


def test_classification_after_last_transition_usable_at_real_age(
        client, users):
    """A source recorded AFTER the last transition classifies cleanly and
    remains usable at its true age (advisory only — no expiry, no
    laundering to age 0)."""
    _seed("release", age_h=5000)
    _seed("baseline_check", age_h=100)
    r = client.post("/safety/reclassify-qualification", headers=users["op"],
                    json={"kind": "baseline_check",
                          "reason": "verified provenance ref R-4"})
    assert r.status_code == 200, r.text
    q, _ = _qual(client, users, "baseline_check")
    assert q["usable"] is True, q
    assert 99 < q["age_h"] < 101, q["age_h"]
    assert any("advisory" in a or "advisories" in a or "old" in a
               for a in q["advisories"]) or q["advisories"] == []


def test_nested_classification_chain_uses_oldest_original(client, users):
    """A classification whose source was ITSELF classified evaluates age
    and transition invalidation from the OLDEST original observation."""
    from srplatform.settings import get_settings
    from srplatform.safety.datapath import config_identity
    now = time.time()
    observed = now - 6000 * 3600
    _seed("datapath_proof", ident="legacy-identity-17", age_h=6000,
          detail_json={"qualification_contract": 1,
                       "one_time_reclassification": True,
                       "observed_at": observed,
                       "reason": "seeded chain", "operator": "seed"})
    _seed("release", age_h=5900, detail_json={})   # between obs and audit
    q, _ = _qual(client, users, "datapath_proof")
    assert q["usable"] is False
    assert any("predates the last release" in p for p in q["problems"])
    assert 5990 < q["age_h"] < 6010, q["age_h"]    # chain-walked age
    assert abs(q["observed_at"] - observed) < 2


def test_concurrent_classifications_exactly_one_wins(users):
    """F2: REAL HTTP requests from REAL threads released by ONE barrier
    at the same source. The publication is a row-locked read-validate-
    append transaction, so the race is FORCED to serialize: exactly one
    classifier can find the source newest-and-classifiable after the
    winner's commit — the others get the truthful conflict. No scheduling
    luck involved: any interleaving that let two through would mean two
    committed transactions each saw the other's row absent while holding
    the same row lock."""
    import httpx
    import uvicorn

    import socket as _sock
    with _sock.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(
        "srplatform.api.app:app", host="127.0.0.1", port=port,
        log_level="error"))
    th = threading.Thread(target=server.run, daemon=True)
    th.start()
    deadline = time.time() + 30
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started

    _seed("baseline_check", age_h=4000)
    at = _rows("baseline_check")[0][3]
    n = 6
    barrier = threading.Barrier(n)
    results = []

    def worker(i: int):
        barrier.wait()
        try:
            r = httpx.post(
                f"http://127.0.0.1:{port}/safety/reclassify-qualification",
                json={"kind": "baseline_check",
                      "reason": f"concurrent classifier {i}",
                      "expect_recorded_at": at},
                headers=users["op"], timeout=60)
            results.append((r.status_code, r.text))
        except Exception as exc:  # noqa: BLE001
            results.append((0, str(exc)))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=90)
    server.should_exit = True
    th.join(timeout=15)

    codes = sorted(c for c, _ in results)
    assert codes.count(200) == 1, results
    assert codes.count(409) == n - 1, results
    for code, text in results:
        if code == 409:
            assert ("contract" in text or "no longer" in text), text
    rows = _rows("baseline_check")
    assert len(rows) == 2                          # ONE classification only
    assert rows[0][2] == {}                        # original immutable
    assert rows[1][2]["one_time_reclassification"] is True


def test_persistence_failure_refuses_without_publishing(client, users,
                                                        monkeypatch):
    """No authoritative store => NO publish: truthful 503, zero new rows,
    and a later retry succeeds once the store is back (sequential
    failure/positive)."""
    _seed("baseline_check", age_h=4000)
    import srplatform.db.session as dbs

    def _broken():
        raise RuntimeError("connection pool exhausted (test)")

    real = dbs.db
    monkeypatch.setattr(dbs, "db", lambda: _broken())
    r = client.post("/safety/reclassify-qualification", headers=users["op"],
                    json={"kind": "baseline_check", "reason": "store down"})
    assert r.status_code == 503, r.text
    assert "authoritative" in r.json()["detail"]
    monkeypatch.setattr(dbs, "db", real)
    assert len(_rows("baseline_check")) == 1       # NOTHING published
    r = client.post("/safety/reclassify-qualification", headers=users["op"],
                    json={"kind": "baseline_check",
                          "reason": "store recovered ref R-5"})
    assert r.status_code == 200, r.text
    assert len(_rows("baseline_check")) == 2


def test_newer_failed_record_still_blocks_after_classification(client,
                                                               users):
    """The CAS never overrides reality: a FAILED record appended AFTER
    the accepted classification becomes the newest truth and blocks —
    'classification succeeded' cannot launder over it."""
    _seed("baseline_check", age_h=100)
    r = client.post("/safety/reclassify-qualification", headers=users["op"],
                    json={"kind": "baseline_check",
                          "reason": "verified ref R-6"})
    assert r.status_code == 200, r.text
    q, _ = _qual(client, users, "baseline_check")
    assert q["usable"] is True
    _seed("baseline_check", ok=False, age_h=0,
          detail_json={"qualification_contract": 1,
                       "observed": "fresh failed re-check"})
    q, _ = _qual(client, users, "baseline_check")
    assert q["usable"] is False
    assert any("FAILED" in p for p in q["problems"])


# --------------------------------------------------------------------- F3 -- #
pytestmark_practice = pytest.mark.practice
from tests.test_plan22_runner_probe import (  # noqa: E402 — real wire harness
    _RunnerServer, _isolate_home, _keys, _pin, _pub_of, _settings)


def _ssh_sup(tmp_path, settings):
    from srplatform.safety import Supervisor
    return Supervisor(datapath=FakeDatapath(), settings=settings,
                      state_file=str(tmp_path / "sup.json"))


@pytest.mark.practice
async def test_key_security_change_defeats_cache_and_recovers(
        tmp_path, _isolate_home, monkeypatch):
    """Warm REAL ssh health with a 0600 key; widen to 0644 (bytes
    unchanged): OpenSSH now REFUSES the key, so the shared fact must
    refuse IMMEDIATELY (no cached release, no probe — the cache may not
    outlive its security context); unreadable refuses; restoring 0600
    re-probes and returns healthy; in-place replacement of the key
    content re-probes and refuses. No secret material in any detail."""
    import asyncio

    import srplatform.safety as safety_mod
    client_key, other_key, _host = _keys(tmp_path)
    srv = _RunnerServer()
    port = await srv.start(accept_pub=_pub_of(client_key))
    try:
        kh = tmp_path / "known_hosts"
        kh.write_text(_pin(port, srv))
        s = _settings(tmp_path, key=client_key, known_hosts=kh, port=port)
        assert client_key.stat().st_mode & 0o077 == 0   # ssh-keygen 0600
        sup = _ssh_sup(tmp_path, s)

        calls = []
        real = safety_mod._runner_health_probe

        def counting(settings):
            calls.append(1)
            return real(settings)

        monkeypatch.setattr(safety_mod, "_runner_health_probe", counting)

        async def check():
            return await asyncio.to_thread(sup._runner_check)

        r1 = await check()
        assert r1["ok"] is True, r1["detail"]
        assert len(calls) == 1

        client_key.chmod(0o644)                   # same bytes, unsafe mode
        r2 = await check()
        assert r2["ok"] is False and "group/other-accessible" in r2["detail"]
        assert "0644" in r2["detail"]
        assert len(calls) == 1, "must refuse BEFORE any cached/probed health"
        ok_cfg, why_cfg = sup.runner_available()
        assert ok_cfg is False and why_cfg == r2["detail"]  # one fact

        client_key.chmod(0o200)                   # no read for the owner
        r3 = await check()
        assert r3["ok"] is False and "unreadable" in r3["detail"]
        assert len(calls) == 1

        client_key.chmod(0o600)                   # healthy restore
        r4 = await check()
        assert r4["ok"] is True, r4["detail"]
        # The restored file is byte-, mode- and owner-IDENTICAL to what
        # the probe actually verified (identity digest matches), so the
        # short memo may still answer — but ANY change to the security
        # identity must force a fresh probe:
        kh.write_text(_pin(port, srv) + "# re-pinned\n")
        r4b = await check()
        assert r4b["ok"] is True, r4b["detail"]
        assert len(calls) == 2, "trust edit must not reuse stale health"

        client_key.write_bytes(other_key.read_bytes())
        client_key.chmod(0o600)                   # in-place replacement
        r5 = await check()
        assert r5["ok"] is False, "a replaced (foreign) key stayed healthy"
        assert len(calls) == 3
        assert "PRIVATE KEY" not in r5["detail"]  # no key material logged
    finally:
        await srv.stop()
