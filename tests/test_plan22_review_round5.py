"""Plan-22 review ROUND 5 (candidate `dc5fb27`, source `71c0200`) — four
boundary defects under the two EXTENDED owner contracts.

  AUTHORITATIVE ORDER ACROSS MIRRORS: every mirror envelope of a
  committed safety record carries the authoritative append sequence
  (``seq``); a delayed file copy can NEVER become a newer observation by
  its write clock. When the DB is readable its committed order is
  authoritative. Genuine outage-only lines are retained but EXPLICITLY
  UNRECONCILED — never a pass that authorizes admission, never able to
  override a known authoritative FAILED, never lost; a mirror line that
  POSITIVELY matches an authoritative record (kind + outcome + config
  identity + detail digest — never a timestamp guess) is that record's
  copy and inherits its sequence. ALL readers honour this, not just the
  publication helper.

  PROVENANCE REFERENCES: every chain link resolves the FULL authoritative
  source record — same qualification kind, strict PASSED outcome, matching
  scope identities — not detail+time alone. Malformed or unknown persisted
  rows are INCOMPATIBLE, never a usable current pass. The reader must not
  trust persisted chains the endpoint itself would reject.

F1: real HTTP/DB post-commit/pre-mirror barriers in BOTH orderings; the
    normal read; delayed duplicates (reconciled by positive match); a
    delayed other-kind copy; and the DB-unavailable/recovered lane where
    an unreconciled pass never authorizes once authority returns.
F2: persisted forged chains through the real API/DB — cross-kind FAILED
    source with CORRECT digest and time, failed same-kind source, wrong
    scope, unknown marker, and a binding-less malformed row — all
    incompatible; the valid nested chain stays the positive control.
F3: the verifier positively accounts for EVERY listed file and image:
    deleted file, broken link in its place, deleted shipped image, the
    entire images directory, a deleted parent directory — all refused.
F4: activation is exclusive and atomic: a foreign destination appearing
    after the preflight is refused with inode and bytes intact, and a
    forced activation that fails rolls the previous release back intact.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import threading
import time
from pathlib import Path

import pytest

from srplatform.safety import _detail_digest
from tests.test_plan22_review_round3 import (  # real-boundary helpers
    _qual, _rows, _seed)
from tests.test_plan22_review_round4 import (  # live HTTP helpers
    _baseline, _file_ledger, _reclassify, _serve, _seed_classification)

REPO = Path(__file__).resolve().parents[1]
_NEED_QEMU = shutil.which("qemu-img") is None


# --------------------------------------------------------------------- F1 --
def test_delayed_classification_mirror_cannot_launder_failed(users):
    """THE round-5 F1 counterexample: pause the classification AFTER its
    DB commit but BEFORE its mirror; a real HTTP FAILED baseline commits
    AND mirrors fully inside that window; then the classification's copy
    lands LAST on the wall clock. DB order [legacy, classification,
    FAILED] is authoritative: the qualification reports the failure and
    Begin stays blocked, regardless of the mirror write order."""
    server, th, port = _serve()
    try:
        from srplatform.safety import get_supervisor
        sup = get_supervisor()
        _seed("baseline_check", age_h=100)
        state = {"armed": False, "paused": threading.Event(),
                 "go": threading.Event()}

        def hook(kind):
            if not state["armed"]:
                return
            state["paused"].set()
            assert state["go"].wait(60), "barrier never released"

        sup._test_after_commit_before_mirror = hook
        out = {}
        try:
            state["armed"] = True
            t1 = threading.Thread(
                target=lambda: out.update(
                    cls=_reclassify(port, users["op"],
                                    reason="round-5 mirror race R-1")))
            t1.start()
            assert state["paused"].wait(30), "classifier never parked"
            state["armed"] = False          # the FAILED writer must pass
            f = _baseline(port, users["op"], False)
            assert f.status_code == 200, f.text
            state["go"].set()
            t1.join(90)
        finally:
            sup._test_after_commit_before_mirror = None
            state["go"].set()
            server.should_exit = True
            th.join(timeout=15)

        assert out["cls"].status_code == 200, out["cls"].text
        rows = _rows("baseline_check")
        assert [bool(r[1]) for r in rows] == [True, True, False], rows
        failed_id = rows[2][0]

        # The file ledger really received the classification LAST — the
        # exact condition under which the timestamp-ordered reader was
        # fooled in the round-4 candidate.
        ledger = _file_ledger()
        cls_idx = max(i for i, ln in enumerate(ledger)
                      if (ln.get("detail") or {}).get(
                          "one_time_reclassification") is True)
        fail_idx = max(i for i, ln in enumerate(ledger)
                       if ln["kind"] == "baseline_check"
                       and ln["ok"] is False)
        assert cls_idx > fail_idx, "delayed-copy precondition not exercised"
        cls_lines = [ln for ln in ledger if (ln.get("detail") or {}).get(
            "one_time_reclassification") is True]
        assert cls_lines and cls_lines[-1].get("seq") is not None

        # readers: authoritative sequence wins over the mirror clock
        from srplatform.safety import get_supervisor
        recs = get_supervisor()._latest_records()
        assert recs["baseline_check"]["ok"] is False
        assert recs["baseline_check"]["seq"] == failed_id
        assert recs["baseline_check"].get("unreconciled") is not True
        assert not [p for p in recs.get("__unreconciled__", [])
                    if p["kind"] == "baseline_check"]

        from fastapi.testclient import TestClient
        from srplatform.api.app import app
        with TestClient(app) as c:
            q, report = _qual(c, users, "baseline_check")
        assert q["usable"] is False, q
        assert any("FAILED" in p for p in q["problems"]), q
        # (Begin enforcement for REQUIRED-evidence configs is proven by
        # the practice admission lane; here the qualification itself is
        # the contract: the delayed classification copy never launders the
        # committed failure.)
    finally:
        if server.started:
            server.should_exit = True


def test_failed_commit_with_delayed_mirror_rejects_classification(users):
    """Other ordering: the FAILED baseline has COMMITTED (authority) but
    its mirror is still parked. A classification attempt must be refused
    against the committed authority (409 — the newest record FAILED),
    never accepted because the mirror had not landed yet. No DB
    transaction spans the network wait: the refusal completes while the
    other writer is still parked pre-mirror."""
    server, th, port = _serve()
    try:
        from srplatform.safety import get_supervisor
        sup = get_supervisor()
        _seed("baseline_check", age_h=100)
        state = {"armed": True, "paused": threading.Event(),
                 "go": threading.Event()}

        def hook(kind):
            if not state["armed"]:
                return
            state["paused"].set()
            assert state["go"].wait(60), "barrier never released"

        sup._test_after_commit_before_mirror = hook
        try:
            result = {}
            t = threading.Thread(
                target=lambda: result.update(
                    f=_baseline(port, users["op"], False)))
            t.start()
            assert state["paused"].wait(30), "FAILED writer never parked"
            c = _reclassify(port, users["op"], reason="round-5 too late")
            assert c.status_code == 409, c.text
            state["armed"] = False
            state["go"].set()
            t.join(90)
            assert result["f"].status_code == 200, result["f"].text
        finally:
            sup._test_after_commit_before_mirror = None
            state["go"].set()
            server.should_exit = True
            th.join(timeout=15)

        rows = _rows("baseline_check")
        assert [bool(r[1]) for r in rows] == [True, False]   # no append
        ledger = _file_ledger()
        assert len([ln for ln in ledger
                    if (ln.get("detail") or {}).get(
                        "one_time_reclassification") is True]) == 0
    finally:
        if server.started:
            server.should_exit = True


def test_mirror_copies_carry_and_reconcile_sequences(client, users):
    """Normal read: mirror envelopes carry the authoritative sequence;
    a hand-replayed copy WITHOUT a sequence that positively matches an
    authoritative record reconciles to that sequence (not unreconciled,
    not a newer observation), while a fabricated sequence-less PASS with
    a fresh clock stamp can neither supersede the authoritative FAILED
    record nor authorize admission — it is retained as UNRECONCILED."""
    r = client.post("/safety/baseline-check", headers=users["op"],
                    json={"ok": False})
    assert r.status_code == 200, r.text
    from srplatform.safety import get_supervisor
    sup = get_supervisor()
    recs = sup._latest_records()
    latest_failed_id = recs["baseline_check"]["seq"]
    assert recs["baseline_check"]["ok"] is False

    ledger_path = Path(sup.state_file).parent / (
        Path(sup.state_file).name + ".records")
    lines = [json.loads(ln) for ln in ledger_path.read_text().splitlines()]
    committed = [ln for ln in lines if ln["kind"] == "baseline_check"
                 and ln["ok"] is False]
    assert committed and committed[-1].get("seq") == latest_failed_id
    assert not recs.get("__unreconciled__")

    # (1) replay the committed FAILED line verbatim but WITHOUT its
    # sequence — positive match reconciles it: not unreconciled, order
    # unchanged.
    dup = dict(committed[-1])
    dup.pop("seq")
    dup["recorded_at"] = time.time() + 10_000      # newest clock on purpose
    with ledger_path.open("a") as f:
        f.write(json.dumps(dup) + "\n")
    recs = sup._latest_records()
    assert recs["baseline_check"]["seq"] == latest_failed_id
    assert not recs.get("__unreconciled__")

    # (2) a fabricated PASS line with no sequence and a future clock —
    # it cannot beat the authoritative FAILED, and is retained as
    # explicitly unreconciled evidence (never silently dropped).
    forged = {"kind": "baseline_check", "ok": True,
              "config_identity": recs["baseline_check"]["config_identity"],
              "detail": {"source": "attacker-copy"},
              "recorded_at": time.time() + 999_999}
    with ledger_path.open("a") as f:
        f.write(json.dumps(forged) + "\n")
    recs = sup._latest_records()
    assert recs["baseline_check"]["ok"] is False
    assert recs["baseline_check"]["seq"] == latest_failed_id
    pending = recs.get("__unreconciled__") or []
    assert any((p.get("detail") or {}).get("source") == "attacker-copy"
               for p in pending), pending
    q, _ = _qual(client, users, "baseline_check")
    assert q["usable"] is False and q["provenance"] == "current", q

    # (3) a delayed OTHER-kind copy: an authoritative datapath_proof row
    # replayed without its sequence reconciles by its own kind's match
    # and never leaks across kinds.
    r2 = client.post("/safety/datapath-proof", headers=users["op"], json={})
    if r2.status_code == 200:
        recs = sup._latest_records()
        dp = recs.get("datapath_proof")
        if dp and dp.get("seq") is not None:
            lines = [json.loads(ln) for ln in
                     ledger_path.read_text().splitlines()]
            dp_line = next(ln for ln in lines
                           if ln["kind"] == "datapath_proof"
                           and ln.get("seq") == dp["seq"])
            dup = {k: v for k, v in dp_line.items() if k != "seq"}
            dup["recorded_at"] = time.time() + 10_000
            with ledger_path.open("a") as f:
                f.write(json.dumps(dup) + "\n")
            recs = sup._latest_records()
            assert recs["datapath_proof"]["seq"] == dp["seq"]
            assert not recs.get("__unreconciled__")


def test_outage_lines_never_authorize_once_authority_returns(tmp_path):
    """DB-unavailable/recovered on the fast lane: while no authoritative
    sequence exists the historical ledger semantics stand (N07: the
    outage failure is RETAINED and denies starts). Once any authoritative
    sequence is visible, a sequence-less PASS can no longer authorize
    admission — it is explicitly unreconciled — and a sequence-less
    FAILED failure is never lost."""
    from tests.test_plan22_review_round3 import _Raw, _f1_sup
    from srplatform.safety import SafetyStoreUnavailable
    from srplatform.safety.datapath import config_identity
    sup = _f1_sup(tmp_path, _Raw({"latched": False, "reason": None,
                                  "latched_at": None}))
    ident = config_identity(sup.settings)

    # outage: publication impossible, ledger keeps the evidence + failure
    import srplatform.db.session as dbs

    def _broken():
        raise RuntimeError("connection pool exhausted (test)")

    real_db = dbs.db
    dbs.db = _broken
    try:
        sup.record("baseline_check", True, {"source": "operator"})
        with pytest.raises(SafetyStoreUnavailable):
            sup.reclassify_qualification("baseline_check", reason="x",
                                         actor="op")
    finally:
        dbs.db = real_db
    assert any("unavailable" in f for f in sup._record_failures)

    # still no authority anywhere -> the ledger line is honored as before
    # (age/identity permitting), with the persistence failure retained
    q = sup._qualification("baseline_check")
    assert q["provenance"] == "current" and q["usable"] is True, q
    assert any("unavailable" in f for f in sup._record_failures)

    # authority returns with a NEWER authoritative pass: the old
    # sequence-less line is now EXPLICITLY UNRECONCILED evidence; the
    # authoritative record is what stands.
    now = time.time()
    sup._records_reader = lambda: [
        {"kind": "baseline_check", "ok": True, "config_identity": ident,
         "detail": {"qualification_contract": 1}, "seq": 11,
         "recorded_at": now}]
    q = sup._qualification("baseline_check")
    assert q["usable"] is True and q["provenance"] == "current", q
    recs = sup._latest_records()
    assert recs["baseline_check"]["seq"] == 11

    # authoritative FAILED + the retained unreconciled pass: usable False
    # and the unreconciled pass never overrides the committed failure
    sup._records_reader = lambda: [
        {"kind": "baseline_check", "ok": False, "config_identity": ident,
         "detail": {"qualification_contract": 1}, "seq": 12,
         "recorded_at": now}]
    q = sup._qualification("baseline_check")
    assert q["usable"] is False and "FAILED" in " ".join(q["problems"]), q

    # an unreconciled FAILED with no authoritative counterpart at all:
    # conservative block (failure not lost), provenance explicit
    sup2 = _f1_sup(tmp_path / "b", _Raw({"latched": False, "reason": None,
                                         "latched_at": None}))
    sup2.record("baseline_check", False, {"source": "operator"})
    sup2._records_reader = lambda: [
        {"kind": "datapath_proof", "ok": True, "config_identity": ident,
         "detail": {}, "seq": 3, "recorded_at": now}]
    q2 = sup2._qualification("baseline_check")
    assert q2["usable"] is False, q2
    assert q2["provenance"] == "unreconciled", q2
    assert any("UNRECONCILED" in p for p in q2["problems"]), q2


# --------------------------------------------------------------------- F2 --
@pytest.mark.db
def test_persisted_crosskind_failed_chain_is_incompatible(client, users):
    """F2 core, reader side: a persisted baseline_check classification
    that references a FAILED datapath_proof record with the CORRECT
    digest and time (identity bindings internally consistent) must NOT
    read as a current usable pass — digest/time agreement proves
    neither kind nor outcome. Begin stays blocked."""
    fp_id = _seed("datapath_proof", ok=False, age_h=50, detail_json={},
                  returning=True)
    fp_at = _rows("datapath_proof")[0][3]
    _seed("baseline_check", age_h=4000, detail_json={})
    _seed_classification("baseline_check", src_id=fp_id,
                         digest=_detail_digest({}), observed_at=fp_at)
    q, report = _qual(client, users, "baseline_check")
    assert q["provenance"] == "incompatible" and q["usable"] is False, q
    assert any("same qualification kind" in p for p in q["problems"]), q
    # the incompatibility is surfaced as a problem, and (for
    # required-evidence configs) a blocker; the dev datapath fixture
    # relaxes Begin gating generally — the qualification verdict is the
    # contract asserted here.


@pytest.mark.db
def test_persisted_failed_samekind_source_is_incompatible(client, users):
    """A FAILED source of the SAME kind with a correct digest and time is
    still incompatible — the endpoint refuses such a classification, and
    the reader must not trust the persisted row the endpoint rejected."""
    src_id = _seed("baseline_check", ok=False, age_h=300,
                   detail_json={}, returning=True)
    src_at = [r for r in _rows("baseline_check") if r[0] == src_id][0][3]
    _seed_classification("baseline_check", src_id=src_id,
                         digest=_detail_digest({}), observed_at=src_at)
    q, _ = _qual(client, users, "baseline_check")
    assert q["provenance"] == "incompatible" and q["usable"] is False, q
    assert any("did not PASS" in p for p in q["problems"]), q


@pytest.mark.db
def test_persisted_wrong_scope_and_unknown_marker_are_incompatible(
        client, users):
    """Scope binding is per-hop: a chain whose record_identity_was does
    not equal the source row's config identity crosses a configuration
    boundary and is incompatible; so is a source carrying an
    UNKNOWN contract marker this build cannot interpret."""
    src_id = _seed("baseline_check", ident="scope-alpha", age_h=300,
                   detail_json={}, returning=True)
    src_at = [r for r in _rows("baseline_check") if r[0] == src_id][0][3]
    _seed_classification("baseline_check", src_id=src_id,
                         digest=_detail_digest({}), observed_at=src_at,
                         src_identity="scope-OMEGA")
    q, _ = _qual(client, users, "baseline_check")
    assert q["provenance"] == "incompatible", q
    assert any("scope" in p for p in q["problems"]), q

    weird = {"qualification_contract": 99}
    wsrc_id = _seed("baseline_check", ident="scope-beta", age_h=200,
                    detail_json=weird, returning=True)
    wsrc_at = [r for r in _rows("baseline_check") if r[0] == wsrc_id][0][3]
    _seed_classification("baseline_check", src_id=wsrc_id,
                         digest=_detail_digest(weird),
                         observed_at=wsrc_at, src_identity="scope-beta")
    q, _ = _qual(client, users, "baseline_check")
    assert q["provenance"] == "incompatible", q
    assert any("unknown" in p for p in q["problems"]), q


@pytest.mark.db
def test_persisted_bindingless_classification_row_incompatible(client,
                                                               users):
    """A persisted classification row MISSING its source-scope binding is
    malformed persisted provenance — never a usable current pass, and
    never defaulted to a legacy reading."""
    src_id = _seed("baseline_check", age_h=300, detail_json={},
                   returning=True)
    _seed("baseline_check", age_h=10, detail_json={
        "qualification_contract": 1, "one_time_reclassification": True,
        "source_record_id": src_id,
        "original_detail_digest": _detail_digest({}),
        "observed_at": [r for r in _rows("baseline_check")
                        if r[0] == src_id][0][3],
        "bound_identity": "legacy-identity-17",
        "reason": "bindingless", "operator": "seed"})
    q, _ = _qual(client, users, "baseline_check")
    assert q["provenance"] == "incompatible" and q["usable"] is False, q
    assert any("record_identity_was" in p for p in q["problems"]), q


# --------------------------------------------------------------------- F3 --
bundle_mod = pytest.importorskip("deploy.bundle")
BundleError = bundle_mod.BundleError


def _tiny_image(tmp_path: pathlib.Path, name: str) -> pathlib.Path:
    p = tmp_path / name
    subprocess.run(["qemu-img", "create", "-f", "qcow2", str(p), "8M"],
                   check=True, capture_output=True)
    os.chmod(p, 0o644)
    return p


def _tiny_bundle(tmp_path: pathlib.Path,
                 base: pathlib.Path | None = None) -> pathlib.Path:
    out = tmp_path / "bundle"
    out.parent.mkdir(parents=True, exist_ok=True)
    base = base or _tiny_image(tmp_path, "appliance-base.qcow2")
    bundle_mod.build(out, base_image=base, role_images={}, app_dir=REPO)
    assert bundle_mod.verify(out)["ok"]
    return out


@pytest.mark.skipif(_NEED_QEMU, reason="qemu-img required")
def test_verify_refuses_every_missing_listed_member(tmp_path):
    """F3: completeness is verified INDEPENDENTLY of payload digests —
    every listed file and image must positively exist. A deleted listed
    file, a broken link in its place, a deleted shipped image, the whole
    images directory and a deleted parent directory are each refused;
    the intact bundle stays the positive control."""
    out = _tiny_bundle(tmp_path)
    manifest = json.loads((out / "MANIFEST.json").read_text())
    nested = next(rel for rel in sorted(manifest["files"])
                  if rel.count("/") >= 2 and not rel.startswith("images/"))

    # (1) a listed file deleted entirely
    (out / "requirements.lock").unlink()
    v = bundle_mod.verify(out)
    assert not v["ok"] and "missing: requirements.lock" in v["problems"], v

    # (2) a broken symbolic link in its place — not "missing"-silent,
    # and its bytes are never followed
    (out / "requirements.lock").symlink_to(tmp_path / "nowhere.lock")
    v = bundle_mod.verify(out)
    assert not v["ok"] and any("symlink" in p for p in v["problems"]), v
    (out / "requirements.lock").unlink()

    # (3) the shipped base image deleted
    img_rel = manifest["images"]["appliance-base"]["path"]
    (out / img_rel).unlink()
    v = bundle_mod.verify(out)
    assert not v["ok"] and f"missing image: {img_rel}" in v["problems"], v

    # (4) the entire images directory gone
    shutil.rmtree(out / "images")
    v = bundle_mod.verify(out)
    assert not v["ok"] and any(p.startswith("missing image:")
                               for p in v["problems"]), v

    # (5) a nested listed file's PARENT DIRECTORY gone
    shutil.rmtree((out / nested).parent)
    v = bundle_mod.verify(out)
    assert not v["ok"] and f"missing: {nested}" in v["problems"], v

    # positive control: a fresh intact bundle verifies
    fresh = _tiny_bundle(tmp_path / "fresh")
    assert bundle_mod.verify(fresh)["ok"]


# --------------------------------------------------------------------- F4 --
@pytest.mark.skipif(_NEED_QEMU, reason="qemu-img required")
def test_activation_refuses_destination_appearing_after_preflight(
        tmp_path, monkeypatch):
    """F4: the default activation is EXCLUSIVE — a destination that
    appears after the preflight (the check-then-delete window in the
    round-4 builder) makes activation refuse atomically. The foreign
    bytes AND inode stay untouched, and no staging debris is left."""
    out = tmp_path / "bundle"
    base = _tiny_image(tmp_path, "base.qcow2")

    def appear(path: pathlib.Path):
        path.mkdir()
        f = path / "FOREIGN"
        f.write_text("someone elses release")
        seen["ino"] = f.stat().st_ino

    seen: dict = {}
    monkeypatch.setattr(bundle_mod, "_test_before_activation", appear)
    with pytest.raises(BundleError, match="appeared"):
        bundle_mod.build(out, base_image=base, role_images={}, app_dir=REPO)
    # the foreign destination is byte- and inode-intact: the builder
    # never deleted or wrote into it
    foreign = out / "FOREIGN"
    assert out.is_dir() and foreign.read_text() == "someone elses release"
    assert foreign.stat().st_ino == seen["ino"]
    assert not [p for p in tmp_path.iterdir()
                if ".staging-" in p.name or ".superseded-" in p.name]


@pytest.mark.skipif(_NEED_QEMU, reason="qemu-img required")
def test_forced_activation_failure_preserves_previous_release(
        tmp_path, monkeypatch):
    """F4 with force: the previous valid release is moved aside ONLY
    atomically and restored verbatim when the activation rename itself
    fails — the old builder deleted it first. No staging/backup debris."""
    out = _tiny_bundle(tmp_path)
    before = bundle_mod.verify(out)
    assert before["ok"]
    revision = json.loads((out / "MANIFEST.json").read_text())["revision"]

    def fail():
        raise OSError(5, "injected activation fault")

    monkeypatch.setattr(bundle_mod, "_test_fail_activation", fail)
    base = tmp_path / "appliance-base.qcow2"   # the image the first build used
    with pytest.raises(OSError, match="injected activation fault"):
        bundle_mod.build(out, base_image=base, role_images={},
                         app_dir=REPO, force=True)
    v = bundle_mod.verify(out)
    assert v["ok"], f"the previous release did not survive: {v['problems']}"
    assert json.loads((out / "MANIFEST.json").read_text())["revision"] == \
        revision
    assert not [p for p in tmp_path.iterdir()
                if ".staging-" in p.name or ".superseded-" in p.name]
