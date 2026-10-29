"""Plan 22 LIVE-07: qualification versus admission health.

Commissioning evidence (baseline check, datapath proof, killswitch test) is
bound to the configuration it was collected under and stays usable while
that configuration and the safety latches are unchanged — its AGE is an
advisory, never a silently-forged renewal or a midnight-expiring failure.
Bounded non-disruptive admission probes run automatically at every Begin
and are recorded as their own evidence kind. Missing, failed, unknown,
incompatible or config-changed evidence still fails closed, with reasons
the operator can act on.
"""
from __future__ import annotations

import json
import time

import pytest

from tests.helpers import FakeDatapath


def _sup(tmp_path, monkeypatch, mirror=None, records=None):
    monkeypatch.setenv("SR_ENV", "dev")
    monkeypatch.setenv("RUNNER_TRANSPORT", "local-dev")
    monkeypatch.setenv("ALLOW_LOCAL_DEV_FIXTURE", "1")
    from srplatform.settings import get_settings
    get_settings.cache_clear()
    from srplatform.safety import Supervisor
    sup = Supervisor(datapath=FakeDatapath(), state_file=str(tmp_path / "s.json"))
    sup._mirror_dh = mirror if mirror is not None else []
    if records is not None:
        sup._records_reader = lambda: list(records.values())
    sup._db_read_state = lambda: ({"latched": False, "latched_at": None,
                                   "reason": None}, None)
    sup.initialize_state(reason="test bootstrap")
    sup._record_failures = []          # bootstrap records: env has no DB here
    return sup


@pytest.fixture
def _no_db(monkeypatch):
    """Fast lane: absorb the DB leg of record() (file mirror still applies)."""
    import srplatform.db.session as dbs

    class _Null:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def add(self, _o):
            pass

    monkeypatch.setattr(dbs, "db", lambda: _Null())


def _identity():
    from srplatform.safety.datapath import config_identity
    from srplatform.settings import get_settings
    return config_identity(get_settings())


def _aged(kind, age_h=100.0, ok=True, identity=None, detail=None):
    return {"kind": kind, "ok": ok,
            "config_identity": identity if identity is not None else _identity(),
            "detail": {"observed": "fixture"} if detail is None else detail,
            "recorded_at": time.time() - age_h * 3600}


ALL_KINDS = ("baseline_check", "datapath_proof", "killswitch_test")


def _aged_set(**over):
    recs = {k: _aged(k, **over.get(k, {})) for k in ALL_KINDS}
    recs.update(over.get("extra", {}))
    return recs


# ------------------------------------------------------------ age advisory -- #
def test_aged_qualification_still_admits_with_advisory(tmp_path, monkeypatch,
                                                       _no_db):
    recs = _aged_set()
    sup = _sup(tmp_path, monkeypatch, records=recs)
    report = sup.qualification_report()
    assert all(q["usable"] for q in report["qualifications"])
    assert report["begin_allowed"], report["begin_blockers"]
    # age is SAID, not enforced
    assert len(report["advisories"]) == 3
    assert all("advisory lifetime" in a or "age alone" in a
               for a in report["advisories"])
    ok, reasons = sup.start_gate()
    assert ok, reasons
    assert not any("stale" in r for r in reasons)


def test_provenance_classes_legacy_and_current(tmp_path, monkeypatch, _no_db):
    recs = _aged_set()
    sup = _sup(tmp_path, monkeypatch, records=recs)
    prov = {q["kind"]: q["provenance"]
            for q in sup.qualification_report()["qualifications"]}
    # records WITHOUT the marker are honored as legacy-compatible, never
    # rewritten and never re-minted
    assert prov == {k: "legacy-compatible" for k in ALL_KINDS}
    # a NEWLY recorded qualification carries the contract marker and reads
    # as current, with the same usability
    mirror = sup._mirror_dh
    sup.record("baseline_check", True, {"observed": "re-collected"})
    fresh = [r for r in mirror if r["kind"] == "baseline_check"][-1]
    assert fresh["detail"]["qualification_contract"] == 1
    recs["baseline_check"] = fresh
    q = next(q for q in sup.qualification_report()["qualifications"]
             if q["kind"] == "baseline_check")
    assert q["provenance"] == "current" and q["usable"]


# ------------------------------------------------------- still fails closed -- #
def test_config_change_invalidates_every_qualification(tmp_path, monkeypatch,
                                                       _no_db):
    recs = _aged_set()
    old_ident = recs["baseline_check"]["config_identity"]
    sup = _sup(tmp_path, monkeypatch, records=recs)
    assert sup.qualification_report()["begin_allowed"]
    # simulate a relevant configuration change: every record now carries a
    # FOREIGN identity
    for k in ALL_KINDS:
        recs[k] = dict(recs[k], config_identity=old_ident + "x")
    report = sup.qualification_report()
    assert not report["begin_allowed"]
    assert sum("identity mismatch" in r for r in report["begin_blockers"]) == 3
    for k in ALL_KINDS:
        assert any("re-collect" in r for r in report["begin_blockers"]
                   if k in r or True)


def test_failed_or_unknown_or_incompatible_block(tmp_path, monkeypatch,
                                                 _no_db):
    sup = _sup(tmp_path, monkeypatch, records=_aged_set())
    # failed newest record
    recs = _aged_set()
    recs["killswitch_test"] = dict(recs["killswitch_test"], ok=False)
    sup._records_reader = lambda: list(recs.values())
    report = sup.qualification_report()
    assert not report["begin_allowed"]
    assert any("FAILED" in r for r in report["begin_blockers"])
    # missing record
    recs2 = _aged_set()
    del recs2["datapath_proof"]
    sup._records_reader = lambda: list(recs2.values())
    assert any("no datapath_proof" in r
               for r in sup.qualification_report()["begin_blockers"])
    # incompatible provenance: an unrecognized contract version fails closed
    recs3 = _aged_set()
    recs3["baseline_check"] = dict(
        recs3["baseline_check"],
        detail={"qualification_contract": 99})
    sup._records_reader = lambda: list(recs3.values())
    report = sup.qualification_report()
    assert not report["begin_allowed"]
    assert any("contract" in r for r in report["begin_blockers"])
    # malformed detail (not a dict) cannot be classified
    recs4 = _aged_set()
    recs4["baseline_check"] = dict(recs4["baseline_check"], detail="yes")
    sup._records_reader = lambda: list(recs4.values())
    assert any("cannot classify" in r
               for r in sup.qualification_report()["begin_blockers"])


def test_latch_transition_still_invalidates(tmp_path, monkeypatch, _no_db):
    recs = _aged_set()
    sup = _sup(tmp_path, monkeypatch, records=recs)
    assert sup.qualification_report()["begin_allowed"]
    recs["engage"] = {"kind": "engage", "ok": True,
                      "config_identity": _identity(), "detail": {},
                      "recorded_at": time.time()}
    report = sup.qualification_report()
    assert not report["begin_allowed"]
    assert sum("predates the last engage" in r
               for r in report["begin_blockers"]) == 3


# ------------------------------------------------------- admission probes ---- #
def test_admission_probe_runs_and_is_recorded(tmp_path, monkeypatch, _no_db):
    recs = _aged_set()
    mirror = []
    sup = _sup(tmp_path, monkeypatch, mirror=mirror, records=recs)
    ok, reasons = sup.start_gate()
    assert ok, reasons
    probes = [r for r in mirror if r["kind"] == "admission_probe"]
    assert len(probes) == 1 and probes[0]["ok"] is True
    names = {c["check"] for c in probes[0]["detail"]["checks"]}
    assert {"runner", "datapath_structure"} <= names
    # probes are their own evidence kind — never a re-minted qualification
    assert all(r["kind"] != "baseline_check" or r["detail"].get(
        "qualification_contract") for r in mirror
        if r["kind"] == "baseline_check")


def test_failed_admission_probe_denies(tmp_path, monkeypatch, _no_db):
    recs = _aged_set()
    sup = _sup(tmp_path, monkeypatch, records=recs)
    sup.datapath = FakeDatapath(ok=False)   # structure check fails
    ok, reasons = sup.start_gate()
    assert not ok
    assert any("datapath_structure" in r for r in reasons)
    # and it is truthful to the report the UI shows
    report = sup.qualification_report()
    assert report["begin_blockers"] == reasons


def test_advisory_age_never_appears_as_a_blocker(tmp_path, monkeypatch,
                                                 _no_db):
    recs = _aged_set(baseline_check={"age_h": 4000.0})
    sup = _sup(tmp_path, monkeypatch, records=recs)
    report = sup.qualification_report()
    assert report["begin_allowed"]
    assert any("4000" in a or "advisory" in a for a in report["advisories"])
    assert not report["begin_blockers"]


# ------------------------------------------------------------------- API ---- #
@pytest.mark.db
def test_qualification_route_agrees_with_begin(client, users, monkeypatch):
    """The UI endpoint and the gate are ONE classifier: what
    GET /safety/qualification lists as blockers is what Begin cites."""
    from srplatform.safety import get_supervisor
    from tests.helpers import FakeDatapath
    sup = get_supervisor()
    monkeypatch.setattr(sup, "datapath", FakeDatapath())

    r = client.get("/safety/qualification", headers=users["member"])
    assert r.status_code == 200
    q = r.json()
    kinds = {x["kind"] for x in q["qualifications"]}
    assert kinds == set(ALL_KINDS)
    assert any("runner" == c["check"] for c in q["admission"]["checks"])

    # incomplete qualification -> refused, and every blocker is actionable
    if not q["begin_allowed"]:
        assert q["begin_blockers"]
    # complete it the supported way, then it agrees again
    r = client.post("/safety/baseline-check", json={"ok": True},
                    headers=users["op"])
    assert r.status_code == 200, r.text
    r = client.post("/safety/datapath-proof",
                    json={"probes": {"ping": "100% packet loss",
                                     "dns": "no servers could be reached"},
                          "vm_hostname": "defender-1"},
                    headers=users["op"])
    assert r.status_code == 200, r.text
    r = client.post("/safety/killswitch-test",
                    json={"commands_stopped": True, "datapath_isolated": True,
                          "detail": {"observed": "fixture"}},
                    headers=users["op"])
    assert r.status_code == 200, r.text
    q = client.get("/safety/qualification", headers=users["member"]).json()
    assert all(x["usable"] for x in q["qualifications"]), q
    assert q["begin_allowed"], q["begin_blockers"]
    allowed, reasons = sup.start_gate()
    assert allowed == q["begin_allowed"]
    assert reasons == q["begin_blockers"]


@pytest.mark.db
def test_aged_records_admit_with_advisory_over_api(client, users, monkeypatch,
                                                    pg_names,
                                                    test_db_url_owner):
    """The LIVE-07 installation defect, end over the wire: 3-day-old
    qualification blocked Begin. Now: usable + advisory, and the BEGIN-
    relevant refusal ONLY happens for a real change."""
    import sqlalchemy as sa
    from sqlalchemy import create_engine
    from srplatform.safety import get_supervisor
    from tests.helpers import FakeDatapath
    sup = get_supervisor()
    monkeypatch.setattr(sup, "datapath", FakeDatapath())
    assert client.post("/safety/baseline-check", json={"ok": True},
                       headers=users["op"]).status_code == 200
    assert client.post("/safety/datapath-proof",
                       json={"probes": {"ping": "100% packet loss",
                                        "dns": "no servers could be reached"},
                             "vm_hostname": "defender-1"},
                       headers=users["op"]).status_code == 200
    assert client.post("/safety/killswitch-test",
                       json={"commands_stopped": True,
                             "datapath_isolated": True,
                             "detail": {"observed": "fixture"}},
                       headers=users["op"]).status_code == 200
    eng = create_engine(test_db_url_owner)
    with eng.begin() as s:
        s.execute(sa.text("UPDATE safety_records SET recorded_at = "
                          "now() - interval '72 hours'"))
    eng.dispose()
    # and the file mirror too — the newest-per-kind merge would otherwise
    # legitimately pick the still-fresh mirrored copy
    import json as _json
    import pathlib as _p
    from srplatform.settings import get_settings
    sf = _p.Path(get_settings().safety_state_file)
    mirror = sf.parent / (sf.name + ".records")
    if mirror.is_file():
        lines = []
        for line in mirror.read_text().splitlines():
            d = _json.loads(line)
            d["recorded_at"] -= 72 * 3600
            lines.append(_json.dumps(d))
        mirror.write_text("\n".join(lines) + "\n")
    q = client.get("/safety/qualification", headers=users["op"]).json()
    assert q["begin_allowed"], q["begin_blockers"]
    assert len(q["advisories"]) == 3
    assert all(x["usable"] and x["age_h"] and x["age_h"] > 70
               for x in q["qualifications"])
    # and the marker proves they were NOT re-minted: same recorded rows,
    # still 72h old
    from srplatform.db.session import db as db_ctx
    with db_ctx() as s:
        n = s.execute(sa.text(
            "SELECT count(*) FROM safety_records WHERE kind = ANY(:k) "
            "AND recorded_at > now() - interval '1 hour'"),
            {"k": list(ALL_KINDS)}).scalar()
    assert n == 0
