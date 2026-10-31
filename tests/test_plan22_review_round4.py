"""Plan-22 review ROUND 4 (candidate 034ac0b) — five boundary defects,
proven at the real seam, under the two OWNER CONTRACT DECISIONS:

  PUBLICATION: every safety writer that affects a selected qualification
  shares ONE authoritative serialization/publication boundary (advisory
  lock + newest read + validate + append in one transaction). A classifier
  cannot interleave with an ordinary observation; mirrors are written only
  consistently with committed authority; no proven publication -> fail
  closed.

  PROVENANCE: an UNMARKED original's effective observation time is its
  authoritative record timestamp — never an arbitrary detail field. A
  classification carries a derived time only when its contract and
  immutable source id/digest chain resolve to that original record.
  Missing / future / unbounded / cyclic / inconsistent provenance is
  INCOMPATIBLE — never a passed new observation, never a "now" fallback.

F1 (HIGH): a real HTTP FAILED observation interleaved between a paused
    classifier's source read and its append can no longer be laundered —
    the observation queues on the shared lock; both commit orders leave
    the newest failure authoritative. A moved source yields 409. The
    file-ledger mirror consumer receives exactly the committed events.
F2 (HIGH): a future injected observed_at on an unmarked legacy source is
    ignored; forged digests, wrong ids, missing/future carried times and
    cyclic chains are incompatible; the 4000 h / 6000 h age positives
    stand.
F3 (MEDIUM): alias cleanup owns the allocation-time device+inode — a
    replacement symlink with the SAME target but a different inode
    survives and is reported, never unlinked.
F4 (MEDIUM): the builder preflights every input and refuses an existing
    output BEFORE any mutation (explicit force to replace) and builds in
    staging — invalid or missing inputs leave the destination byte- and
    inode-intact.
F5 (MEDIUM): --link-images refuses symlink sources (regular files only),
    and the verifier independently rejects symlink files, symlink
    components and directory escapes before trusting any bytes; real
    hardlinked images still verify.
"""
from __future__ import annotations

import httpx
import json
import os
import pathlib
import shutil
import subprocess
import threading
import time
from pathlib import Path

import pytest

_NEED_QEMU = shutil.which("qemu-img") is None

from tests.test_plan22_review_round3 import (  # real-boundary helpers
    _qual, _rows, _seed)

REPO = Path(__file__).resolve().parents[1]


# --------------------------------------------------------------- helpers ---
def _serve():
    """A REAL uvicorn server on a REAL port (the interleavings below are
    about real cross-request serialization)."""
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
    return server, th, port


def _reclassify(port, headers, **body):
    return httpx.post(
        f"http://127.0.0.1:{port}/safety/reclassify-qualification",
        json={"kind": "baseline_check", **body},
        headers=headers, timeout=90)


def _baseline(port, headers, ok):
    return httpx.post(f"http://127.0.0.1:{port}/safety/baseline-check",
                      json={"ok": ok}, headers=headers, timeout=90)


def _file_ledger():
    from srplatform.safety import get_supervisor
    sf = Path(get_supervisor().state_file)
    p = sf.parent / (sf.name + ".records")
    return [json.loads(ln) for ln in p.read_text().splitlines()] \
        if p.exists() else []


# --------------------------------------------------------------------- F1 --
def test_interleaved_failed_observation_cannot_be_laundered(client, users):
    """THE round-4 counterexample, deterministic: pause the classifier
    AFTER its source SELECT (inside the shared boundary), POST a real
    FAILED baseline through the API (it must now QUEUE on the same
    advisory lock instead of slipping in), then release. Committed order
    is [legacy passed, classification, FAILED observation] and the
    qualification honors the newest row: a FAILED observation can never be
    hidden by a classification that raced it."""
    server, th, port = _serve()
    try:
        from srplatform.safety import get_supervisor
        sup = get_supervisor()
        _seed("baseline_check", age_h=4000)
        paused, go = threading.Event(), threading.Event()

        def hook():
            paused.set()
            assert go.wait(60), "classifier never released"

        sup._test_after_source_read = hook
        out = {}
        try:
            t1 = threading.Thread(
                target=lambda: out.update(
                    cls=_reclassify(port, users["op"],
                                    reason="round-4 race ref R-7")))
            t1.start()
            assert paused.wait(30), "classifier never reached the seam"
            t2 = threading.Thread(
                target=lambda: out.update(
                    fail=_baseline(port, users["op"], False)))
            t2.start()
            time.sleep(1.0)     # the FAILED POST is queued on the lock
            go.set()
            t1.join(90)
            t2.join(90)
        finally:
            sup._test_after_source_read = None
            server.should_exit = True
            th.join(timeout=15)

        assert out["cls"].status_code == 200, out["cls"].text
        assert out["fail"].status_code == 200, out["fail"].text
        rows = _rows("baseline_check")
        assert [bool(r[1]) for r in rows] == [True, True, False], rows
        assert rows[1][2]["one_time_reclassification"] is True
        assert rows[2][2].get("source") == "operator"

        # the newest committed row is authoritative regardless of clocks
        q, _ = _qual(client, users, "baseline_check")
        assert q["usable"] is False, q
        assert any("FAILED" in p for p in q["problems"]), q

        # MIRROR consumer: exactly the two committed events for
        # baseline_check beyond nothing else — one classification, one
        # honest failure, no phantom republish.
        ledger = _file_ledger()
        cls = [ln for ln in ledger
               if ln["kind"] == "baseline_check" and (ln.get("detail") or
               {}).get("one_time_reclassification") is True]
        fails = [ln for ln in ledger if ln["kind"] == "baseline_check"
                 and ln["ok"] is False]
        assert len(cls) == 1 and len(fails) == 1, ledger
    finally:
        if server.started:
            server.should_exit = True


def test_failed_observation_first_classifier_gets_409(users):
    """Other ordering: the FAILED observation commits BEFORE the
    classifier starts — the source moved, so classification is refused
    truthfully (409), never appended over the failure."""
    server, th, port = _serve()
    try:
        _seed("baseline_check", age_h=4000)
        r = _baseline(port, users["op"], False)
        assert r.status_code == 200, r.text
        c = _reclassify(port, users["op"], reason="round-4 too late")
        assert c.status_code == 409, c.text
        rows = _rows("baseline_check")
        assert [bool(r0[1]) for r0 in rows] == [True, False]  # no append
    finally:
        server.should_exit = True
        th.join(timeout=15)


def test_moved_source_yields_truthful_409(users):
    """A NEWER passed observation between display and classification also
    yields the truthful conflict (the operator must re-examine)."""
    server, th, port = _serve()
    try:
        _seed("baseline_check", age_h=4000)
        at = _rows("baseline_check")[0][3]
        _seed("baseline_check", age_h=0)          # newer ordinary record
        c = _reclassify(port, users["op"], reason="round-4 stale panel",
                        expect_recorded_at=at)
        assert c.status_code == 409, c.text
        assert "no longer" in c.text, c.text
        assert len(_rows("baseline_check")) == 2  # nothing appended
    finally:
        server.should_exit = True
        th.join(timeout=15)


# --------------------------------------------------------------------- F2 --
@pytest.mark.db
def test_injected_future_observed_at_on_legacy_source_is_ignored(client,
                                                                 users):
    """F2 core counterexample, API+DB: a 4000 h UNMARKED legacy source
    whose detail carries an injected FUTURE observed_at must NOT launder
    itself into a fresh observation — the effective time is the source's
    authoritative timestamp, so the later release keeps blocking and the
    age stays ~4000 h (never -24 h)."""
    now = time.time()
    _seed("baseline_check", age_h=4000,
          detail_json={"observed_at": now + 86400.0})
    _seed("release", age_h=1)
    r = client.post("/safety/reclassify-qualification", headers=users["op"],
                    json={"kind": "baseline_check",
                          "reason": "verified provenance ref R-8"})
    assert r.status_code == 200, r.text
    src_at = _rows("baseline_check")[0][3]
    body = r.json()
    assert abs(float(body["observed_at"]) - src_at) < 2   # NOT the future
    assert float(body["observed_at"]) < now
    q, _ = _qual(client, users, "baseline_check")
    assert q["usable"] is False, q
    assert any("predates the last release" in p for p in q["problems"])
    assert 3990 < q["age_h"] < 4010, q["age_h"]


@pytest.mark.db
def test_marked_ordinary_record_injected_time_also_ignored(client, users):
    """An ordinary (marked, NOT classification) record with an injected
    future observed_at: only recognized CLASSIFICATIONS may carry derived
    time; observations live by their own authoritative timestamp."""
    now = time.time()
    _seed("killswitch_test", age_h=4000, detail_json={
        "qualification_contract": 1,
        "observed_at": now + 48 * 3600})
    _seed("release", age_h=1)
    q, report = _qual(client, users, "killswitch_test")
    assert q["usable"] is False, q
    assert any("predates the last release" in p for p in q["problems"])


def _seed_classification(kind, *, src_id, digest, observed_at, age_h=10,
                         drop_observed=False, src_identity="legacy-identity-17",
                         own_identity="legacy-identity-17"):
    det = {"qualification_contract": 1, "one_time_reclassification": True,
           "source_record_id": src_id,
           "original_detail_digest": digest,
           "record_identity_was": src_identity,
           "bound_identity": own_identity,
           "reason": "forged seed", "operator": "seed"}
    if not drop_observed:
        det["observed_at"] = observed_at
    return _seed(kind, age_h=age_h, detail_json=det, returning=True)


@pytest.mark.db
def test_forged_or_broken_provenance_is_incompatible(client, users):
    """Recognized classification rows whose immutable chain cannot be
    verified — wrong source id, wrong digest, future or missing carried
    time — are INCOMPATIBLE: never usable, never defaulted to now."""
    from srplatform.safety import _detail_digest
    now = time.time()
    src_at = now - 4000 * 3600

    # (a) source id points at nothing
    _seed("baseline_check", age_h=4000, detail_json={})
    _seed_classification("baseline_check", src_id=999_999,
                         digest="0" * 16, observed_at=src_at)
    q, _ = _qual(client, users, "baseline_check")
    assert q["provenance"] == "incompatible" and q["usable"] is False, q
    assert any("provenance" in p for p in q["problems"]), q

    # (b) right id, forged digest
    rows = _rows("baseline_check")
    orig_id = rows[0][0]
    _seed("baseline_check", age_h=300, detail_json={})
    rows = _rows("baseline_check")
    second_id = [r[0] for r in rows if r[3] < now - 100][-1]
    _seed_classification("baseline_check", src_id=second_id,
                         digest="f" * 16, observed_at=src_at)
    q, _ = _qual(client, users, "baseline_check")
    assert q["provenance"] == "incompatible", q
    assert any("digest" in p for p in q["problems"]), q

    # (c) carried observed_at in the future
    _seed_classification("baseline_check", src_id=second_id,
                         digest=_detail_digest({}),
                         observed_at=now + 30 * 3600)
    q, _ = _qual(client, users, "baseline_check")
    assert q["provenance"] == "incompatible", q
    assert any("future" in p for p in q["problems"]), q

    # (d) carried observed_at missing entirely
    _seed_classification("baseline_check", src_id=second_id,
                         digest=_detail_digest({}), observed_at=None,
                         drop_observed=True)
    q, _ = _qual(client, users, "baseline_check")
    assert q["provenance"] == "incompatible", q
    assert "age_h" not in q or q["age_h"] is None


def test_resolver_rejects_paths_without_authority(tmp_path):
    """Fast-lane resolution matrix (no DB): every non-finite, non-
    plausible or chain-broken provenance — INCLUDING cross-kind, failed
    sources, wrong scope and unknown markers (round 5) — raises
    SafetyProvenanceError. A stored field alone never establishes when a
    test ran or what it proved."""
    from srplatform.safety import (SafetyProvenanceError,
                                   _detail_digest,
                                   _is_recognized_classification)
    from tests.test_plan22_review_round3 import _Raw, _f1_sup
    sup = _f1_sup(tmp_path, _Raw())
    now = time.time()
    SRC_ID, SRC_IDENTITY = 1, "cid-src"

    def cls_detail(**kw):
        d = {"qualification_contract": 1, "one_time_reclassification": True,
             "source_record_id": SRC_ID, "original_detail_digest":
                 _detail_digest({}), "observed_at": now - 3600,
             "record_identity_was": SRC_IDENTITY,
             "bound_identity": "cid-self"}
        d.update(kw)
        return d

    SELF = {"record_id": 42, "config_identity": "cid-self"}

    def _row(**kw):
        r = {"record_id": SRC_ID, "kind": "baseline_check", "ok": True,
             "detail": {}, "config_identity": SRC_IDENTITY,
             "recorded_at": now - 3600}
        r.update(kw)
        return r

    ok_fetch = lambda rid: _row() if rid == SRC_ID else None  # noqa

    def resolve(det, fetch=ok_fetch, **kw):
        return sup._resolve_provenance(det, now, fetch,
                                       kind="baseline_check",
                                       self_row=SELF, now=now, **kw)

    for bad, why in (
        ({"observed_at": float("nan")}, "nan"),
        ({"observed_at": float("inf")}, "inf"),
        ({"observed_at": True}, "bool"),
        ({"observed_at": "yesterday"}, "string"),
        ({"observed_at": None}, "null"),
        ({"observed_at": now + 10 * 3600}, "future"),
        ({"observed_at": now - 3600, "source_record_id": None}, "no id"),
        ({"observed_at": now - 3600,
          "original_detail_digest": 7}, "digest type"),
        ({"observed_at": now - 3600,
          "record_identity_was": None}, "no scope binding"),
        ({"observed_at": now - 3600,
          "bound_identity": "cid-other"}, "foreign self-binding"),
    ):
        det = cls_detail()
        det.update(bad)
        with pytest.raises(SafetyProvenanceError):
            resolve(det)

    # unmarked original: an injected observed_at has NO authority — the
    # record timestamp rules, even if the field says "now"
    assert sup._resolve_provenance({"observed_at": now}, now - 5000 * 3600,
                                   lambda rid: None,
                                   now=now) == pytest.approx(
                                       now - 5000 * 3600)

    # F2 (round 5): the chain reference must resolve to a PASSED record of
    # the SAME kind with the SAME scope — digest/time agreement alone
    # proves nothing.
    with pytest.raises(SafetyProvenanceError, match="same qualification"):
        resolve(cls_detail(), lambda rid: _row(kind="datapath_proof")
                if rid == SRC_ID else None)
    with pytest.raises(SafetyProvenanceError, match="did not PASS"):
        resolve(cls_detail(), lambda rid: _row(ok=False)
                if rid == SRC_ID else None)
    with pytest.raises(SafetyProvenanceError, match="scope"):
        resolve(cls_detail(), lambda rid: _row(config_identity="cid-evil")
                if rid == SRC_ID else None)
    with pytest.raises(SafetyProvenanceError, match="digest"):
        resolve(cls_detail(original_detail_digest="0" * 16))
    # an unknown future/legacy contract marker in the SOURCE is unknown —
    # never a trusted hop or terminal
    evil = {"qualification_contract": 99}
    with pytest.raises(SafetyProvenanceError, match="unknown"):
        resolve(cls_detail(original_detail_digest=_detail_digest(evil)),
                lambda rid: _row(detail=evil) if rid == SRC_ID else None)
    # a malformed hop: classification flag without a marker
    evil2 = {"one_time_reclassification": True}
    with pytest.raises(SafetyProvenanceError, match="malformed"):
        resolve(cls_detail(original_detail_digest=_detail_digest(evil2)),
                lambda rid: _row(detail=evil2) if rid == SRC_ID else None)

    # cyclic chain: a classification whose source chain points back at a
    # record already visited (a self-pointer is the minimal cycle)
    rec1 = cls_detail(source_record_id=SRC_ID, bound_identity=SRC_IDENTITY)
    rec1["original_detail_digest"] = _detail_digest({})
    cyc = {SRC_ID: _row(detail=rec1)}

    def cyc_fetch(rid):
        return cyc.get(rid)

    det = cls_detail(source_record_id=SRC_ID,
                     original_detail_digest=_detail_digest(rec1))
    with pytest.raises(SafetyProvenanceError, match="cyclic"):
        resolve(det, cyc_fetch)

    # disagreement between the carried time and the resolved original
    with pytest.raises(SafetyProvenanceError, match="inconsistent"):
        resolve(cls_detail(observed_at=now - 999 * 3600))

    # a genuinely resolvable one-hop chain passes and yields the ORIGINAL
    assert resolve(cls_detail()) == pytest.approx(now - 3600)
    assert _is_recognized_classification(cls_detail())


# --------------------------------------------------------------------- F3 --
def _load_acceptance():
    import importlib.util
    name = "sr_acceptance_round4"
    spec = importlib.util.spec_from_file_location(
        name, REPO / "infra" / "dev" / "acceptance.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_pw_alias_same_target_different_inode_survives(tmp_path):
    """Round-4 F3: ownership is the allocation-time device+inode. A
    replacement symlink pointing at the SAME target — the exact reviewer
    counterexample — is a different inode and must survive cleanup,
    reported, while the real owned inode is still removable."""
    acc = _load_acceptance()
    target = tmp_path / "run"
    target.mkdir()

    h = acc._pw_alias_allocate(target, iter([tmp_path / "alias"]))
    st = os.lstat(str(h.path))
    assert (st.st_dev, st.st_ino) == (h.dev, h.ino)

    # reviewer's move: keep our inode alive under another name, install a
    # DIFFERENT symlink with the SAME target at the alias path
    os.rename(str(h.path), str(tmp_path / "kept"))
    os.symlink(str(target.resolve()), str(h.path))
    assert os.lstat(str(h.path)).st_ino != h.ino

    note = acc._pw_alias_release(h)
    assert note and "DIFFERENT inode" in note
    assert h.path.is_symlink(), "replacement with same target was deleted!"

    # the inode we actually own (renamed aside) is untouched until its
    # own path disappears — and a release after it vanishes is a no-op
    assert os.path.islink(str(tmp_path / "kept"))
    os.unlink(str(h.path))
    assert acc._pw_alias_release(h) is None          # path gone -> no-op
    assert os.path.islink(str(tmp_path / "kept"))
    os.unlink(str(tmp_path / "kept"))

    # own success cleanup still works normally
    h2 = acc._pw_alias_allocate(target, iter([tmp_path / "alias2"]))
    assert acc._pw_alias_release(h2) is None
    assert not h2.path.exists() and not h2.path.is_symlink()


# ---------------------------------------------------------------- F4 & F5 --
bundle_mod = pytest.importorskip("deploy.bundle")
BundleError = bundle_mod.BundleError


def _img(tmp_path: pathlib.Path, name: str) -> pathlib.Path:
    p = tmp_path / name
    subprocess.run(["qemu-img", "create", "-f", "qcow2", str(p), "8M"],
                   check=True, capture_output=True)
    os.chmod(p, 0o644)          # already sealed-mode regular source
    return p


@pytest.mark.skipif(_NEED_QEMU, reason='qemu-img required')
def test_build_refuses_existing_output_before_any_mutation(tmp_path):
    """F4: the preflight is BEFORE the deletion — an existing destination
    and a missing input both fail with the destination byte- and
    inode-identical, and no staging debris is left behind."""
    out = tmp_path / "bundle"
    out.mkdir()
    sentinel = out / "SENTINEL"
    sentinel.write_text("release artifact")
    ino = sentinel.stat().st_ino

    base = _img(tmp_path, "base.qcow2")
    with pytest.raises(BundleError, match="refusing to replace"):
        bundle_mod.build(out, base_image=base, role_images={},
                         app_dir=REPO)
    assert sentinel.read_text() == "release artifact"
    assert sentinel.stat().st_ino == ino

    # missing inputs fail even with no output — and create nothing
    missing = tmp_path / "nope.qcow2"
    out2 = tmp_path / "bundle2"
    with pytest.raises(BundleError, match="missing"):
        bundle_mod.build(out2, base_image=missing, role_images={},
                         app_dir=REPO)
    assert not out2.exists()
    assert not [p for p in tmp_path.iterdir() if ".staging-" in p.name]


@pytest.mark.skipif(_NEED_QEMU, reason='qemu-img required')
def test_force_replaces_but_failed_build_preserves(tmp_path):
    """Explicit force replaces; a build that fails AFTER preflight (bad
    image during staging) leaves the previous release verifiable."""
    out = tmp_path / "bundle"
    base = _img(tmp_path, "base.qcow2")
    bundle_mod.build(out, base_image=base, role_images={}, app_dir=REPO)
    assert bundle_mod.verify(out)["ok"]

    # failing staging input, WITH force: the existing bundle survives
    bad = tmp_path / "bad"
    bad.parent.mkdir(exist_ok=True)
    symlink_src = tmp_path / "link-src.qcow2"
    os.symlink(str(base), str(symlink_src))
    with pytest.raises(BundleError, match="regular non-symlink"):
        bundle_mod.build(out, base_image=symlink_src, role_images={},
                         app_dir=REPO, link_images=True, force=True)
    assert bundle_mod.verify(out)["ok"], "a failed rebuild damaged the release"
    assert not [p for p in tmp_path.iterdir() if ".staging-" in p.name]

    # explicit force with valid input genuinely replaces
    bundle_mod.build(out, base_image=base, role_images={}, app_dir=REPO,
                     force=True)
    assert bundle_mod.verify(out)["ok"]


@pytest.mark.skipif(_NEED_QEMU, reason='qemu-img required')
def test_link_images_ships_regular_hardlinks_without_touching_source(
        tmp_path):
    """F5 positive: a regular 0644 source hardlinks into the bundle;
    bytes, mode and the source inode's metadata are untouched."""
    out = tmp_path / "bundle"
    base = _img(tmp_path, "base.qcow2")
    before = base.stat()
    result = bundle_mod.build(out, base_image=base, role_images={},
                              app_dir=REPO, link_images=True)
    assert result["images"]["appliance-base"]["path"]
    v = bundle_mod.verify(out)
    assert v["ok"], v
    shipped = out / "images" / base.name
    assert shipped.stat().st_nlink == 2                # shared inode
    assert shipped.stat().st_ino == base.stat().st_ino
    after = base.stat()
    assert (after.st_mode, after.st_size) == (before.st_mode,
                                              before.st_size)
    assert int(after.st_mtime) == int(before.st_mtime)


@pytest.mark.skipif(_NEED_QEMU, reason='qemu-img required')
def test_link_images_refuses_symlink_source(tmp_path):
    out = tmp_path / "bundle"
    base = _img(tmp_path, "base.qcow2")
    link = tmp_path / "base-link.qcow2"
    os.symlink(str(base), str(link))
    with pytest.raises(BundleError, match="regular non-symlink"):
        bundle_mod.build(out, base_image=link, role_images={},
                         app_dir=REPO, link_images=True)
    assert not out.exists()
    assert not [p for p in tmp_path.iterdir() if ".staging-" in p.name]


@pytest.mark.skipif(_NEED_QEMU, reason='qemu-img required')
def test_verify_rejects_symlink_escapes_before_trusting_bytes(tmp_path):
    """F5 verifier: a listed file replaced by a symlink whose TARGET has
    the exact expected bytes (old verify would pass on the digest) is
    refused — external and internal alike — as is a symlinked directory;
    ordinary tampering still refuses too."""
    out = tmp_path / "bundle"
    base = _img(tmp_path, "base.qcow2")
    bundle_mod.build(out, base_image=base, role_images={}, app_dir=REPO)
    assert bundle_mod.verify(out)["ok"]

    victim = out / "requirements.lock"
    data = victim.read_bytes()
    outside = tmp_path / "outside.lock"
    outside.write_bytes(data)
    victim.unlink()
    os.symlink(str(outside), str(victim))
    v = bundle_mod.verify(out)
    assert not v["ok"] and any("symlink component refused" in p
                               for p in v["problems"]), v

    # internal symlink: target inside the bundle but unlisted
    inside = out / "inside-copy.lock"
    inside.write_bytes(data)
    victim.unlink() if victim.is_symlink() else None
    os.symlink(str(inside), str(victim))
    v = bundle_mod.verify(out)
    assert not v["ok"] and any("symlink component refused" in p
                               for p in v["problems"]), v
    inside.unlink()
    victim.unlink()
    victim.write_bytes(data)          # restore before the next scenario

    # symlinked DIRECTORY: the deploy tree moved out, pointer left behind
    shutil_move = pathlib.Path(out / "deploy")
    real = tmp_path / "deploy-moved"
    shutil_move.rename(real)
    os.symlink(str(real), str(shutil_move))
    v = bundle_mod.verify(out)
    assert not v["ok"] and any("symlink" in p for p in v["problems"]), v

    # restore + ordinary tamper still refused
    shutil_move.unlink()
    real.rename(shutil_move)
    assert bundle_mod.verify(out)["ok"]
    (out / "requirements.lock").write_bytes(b"tampered\n")
    v = bundle_mod.verify(out)
    assert not v["ok"] and any("drift" in p for p in v["problems"]), v
