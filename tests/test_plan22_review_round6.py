"""Plan-22 review ROUND 6 (candidate `da735cc`, source `2c9cad4`) — three
demonstrated defects under the three OWNER CONTRACTS.

  CONTRACT 1 — A MIRROR SEQUENCE IS A REFERENCE, NOT AUTHORITY: every
  non-authoritative line claiming a ``seq`` must resolve to an actual
  committed record whose content POSITIVELY matches (kind + outcome +
  config identity + detail digest); the row's data and order win, never
  the line's envelope. Unknown, bool, negative, non-integer, foreign-
  kind or content-mismatched claims become EXPLICIT UNTRUSTED evidence:
  never a pass that authorizes, never an ordering advantage, never
  silently lost. A known DB failure cannot be hidden by copies.

  CONTRACT 2 — RECOVERY MUST BE REAL AND USABLE: outage-only failed
  observations are retained immutably, but a NEW committed pass of the
  same kind (current identity, genuine observation — never an old
  classification) supersedes the older order-unprovable failures under
  the same publication/CAS boundary; the decision is derived from
  durable state, so it survives restarts with no ledger edits. What
  auto-supersession must never clear (untrusted or recovery-window
  failures) closes only through the AUDITED ``/safety/reconcile-outage``
  operation — refused while a failure is current, deleting nothing.

  CONTRACT 3 — ROLLBACK HAS NO OWNERSHIP EXCEPTION: forced-activation
  rollback renames the backup back under RENAME_NOREPLACE too; a foreign
  destination that appeared meanwhile keeps its bytes and inode, the
  previous valid release stays RETAINED at its known backup path with a
  durable actionable obligation, and nothing is deleted on the debt.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import subprocess
import time
from contextlib import contextmanager
from pathlib import Path

import pytest

from srplatform.safety import config_identity
from tests.test_plan22_review_round3 import (  # real-boundary helpers
    _Raw, _f1_sup, _qual, _rows, _seed)

REPO = Path(__file__).resolve().parents[1]
_NEED_QEMU = shutil.which("qemu-img") is None


# ------------------------------------------------------------------ utils --
def _sup_records(sup):
    """(state-file ledger path helper)"""
    sf = Path(sup.state_file)
    return sf.parent / (sf.name + ".records")


def _ledger(sup) -> list[dict]:
    p = _sup_records(sup)
    return [json.loads(ln) for ln in p.read_text().splitlines()] \
        if p.exists() else []


def _append(sup, line: dict) -> None:
    with _sup_records(sup).open("a") as f:
        f.write(json.dumps(line) + "\n")


class _StoreDown:
    def __enter__(self):
        raise RuntimeError("injected authoritative-store outage")

    def __exit__(self, *exc):
        return False


@contextmanager
def _store_down():
    """The REAL failure lane: every publication attempt (and every DB
    read) fails exactly like a downed cluster — no stubbing of the
    safety layer itself."""
    import srplatform.db.session as dbs
    real = dbs.db
    dbs.db = lambda *a, **k: _StoreDown()
    try:
        yield
    finally:
        dbs.db = real


def _post_baseline(client, users, ok: bool):
    return client.post("/safety/baseline-check", headers=users["op"],
                       json={"ok": ok})


def _reconcile(client, users, kind="baseline_check",
               reason="reviewed outage window R-6"):
    return client.post("/safety/reconcile-outage", headers=users["op"],
                       json={"kind": kind, "reason": reason})


# ---------------------------------------------------------------- F1 (unit) --
def test_reader_validates_seq_claims_against_the_rows(tmp_path):
    """CONTRACT 1 at the reader: a claimed sequence resolves ONLY to a
    committed row of matching content (which then WINS its data and
    order); every other claim is stripped of ordering, flagged untrusted
    and retained. A failed claim can never be lost, and an audit link
    line is never an observation."""
    sup = _f1_sup(tmp_path, _Raw({"latched": False, "reason": None,
                                  "latched_at": None}))
    ident = config_identity(sup.settings)
    now = time.time()
    row = {"kind": "baseline_check", "ok": True, "config_identity": ident,
           "detail": {"qualification_contract": 1}, "seq": 42,
           "recorded_at": now}
    sup._records_reader = lambda: [dict(row)]
    assert sup._latest_records()["baseline_check"]["seq"] == 42

    # a legitimate delayed duplicate: same seq, matching content, forged
    # envelope clock — it IS that row's copy: reconciled, row time wins.
    _append(sup, {"kind": "baseline_check", "ok": True,
                  "config_identity": ident,
                  "detail": {"qualification_contract": 1},
                  "seq": 42, "recorded_at": now + 9_999})
    recs = sup._latest_records()
    assert recs["baseline_check"]["recorded_at"] == now
    assert not recs.get("__unreconciled__")
    assert sup._qualification("baseline_check")["usable"] is True

    # resolvable sequence, MISMATCHED content -> untrusted (a failed copy
    # claiming a known id can neither flip selection nor be lost)
    _append(sup, {"kind": "baseline_check", "ok": False,
                  "config_identity": ident,
                  "detail": {"qualification_contract": 1},
                  "seq": 42, "recorded_at": now - 5})
    recs = sup._latest_records()
    assert recs["baseline_check"]["ok"] is True  # row still selected
    untr = [x for x in recs["__unreconciled__"] if x.get("untrusted")]
    assert len(untr) == 1 and untr[0]["seq"] is None
    q = sup._qualification("baseline_check")
    assert q["usable"] is False
    assert any("UNTRUSTED FAILED" in p and "reconcile-outage" in p
               for p in q["problems"]), q

    # unresolvable claims: huge, negative, bool, float, string — none
    # authorizes, none orders; and an untrusted line SELECTED for a kind
    # has its own blocking branch.
    for bogus in (999_999_999, -3, True, 4.5, "42"):
        _append(sup, {"kind": "killswitch_test", "ok": True,
                      "config_identity": ident, "detail": {},
                      "seq": bogus, "recorded_at": now})
    recs = sup._latest_records()
    assert recs["killswitch_test"]["untrusted"] is True
    q = sup._qualification("killswitch_test")
    assert q["usable"] is False and q["provenance"] == "untrusted", q

    # an audit link line is skipped entirely — never selection, never a
    # pending entry.
    _append(sup, {"audit": "outage_reconciliation",
                  "kind": "datapath_proof", "via_seq": 42, "ok": False,
                  "recorded_at": now})
    recs = sup._latest_records()
    assert "datapath_proof" not in recs or not recs["datapath_proof"].get(
        "audit")
    assert not any(x.get("audit") for x in recs["__unreconciled__"])


def test_forged_seq_claim_fails_closed_without_any_authority(tmp_path):
    """A sequence claim resolves to nothing at all on a file-only
    install — it is corrupt evidence there too, never honored by the
    legacy timestamp fallback."""
    sup = _f1_sup(tmp_path, _Raw({"latched": False, "reason": None,
                                  "latched_at": None}))
    ident = config_identity(sup.settings)
    _append(sup, {"kind": "baseline_check", "ok": True,
                  "config_identity": ident,
                  "detail": {"qualification_contract": 1},
                  "seq": 999_999_999, "recorded_at": time.time()})
    q = sup._qualification("baseline_check")
    assert q["usable"] is False and q["provenance"] == "untrusted", q


# ------------------------------------------------------------------- F1 --
def test_unresolvable_seq_claims_never_authorize(client, users):
    """THE reviewer counterexample, at the real HTTP/DB/file boundary:
    an authoritative FAILED baseline (current config) plus mirror lines
    claiming PASS under sequences that do not exist — 999999999, bool,
    negative, float, string. Selection stays the DB failure (which can
    never be hidden), the claims stay visible as untrusted, and the
    legitimate delayed duplicate remains the positive control."""
    r = _post_baseline(client, users, False)
    assert r.status_code == 200, r.text
    from srplatform.safety import get_supervisor
    sup = get_supervisor()
    recs = sup._latest_records()
    ident = recs["baseline_check"]["config_identity"]
    now = time.time()
    for i, bogus in enumerate([999_999_999, True, -5, 4.5, "12"]):
        _append(sup, {"kind": "baseline_check", "ok": True,
                      "config_identity": ident,
                      "detail": {"source": f"probe-{i}"}, "seq": bogus,
                      "recorded_at": now - 60 + i})
    recs = sup._latest_records()
    assert recs["baseline_check"]["ok"] is False, \
        "the known DB failure was hidden by a forged copy"
    assert recs["baseline_check"].get("untrusted") is None
    untr = [x for x in recs.get("__unreconciled__") or []
            if x.get("untrusted")]
    assert len(untr) == 5
    assert all(x.get("seq") is None for x in untr)
    q, _ = _qual(client, users, "baseline_check")
    assert q["usable"] is False and q["provenance"] == "current", q
    assert any("FAILED" in p for p in q["problems"])

    # positive control: replaying the committed mirror line (same seq,
    # matching content, fresher clock) is that record's copy — it adds
    # no pending entry and reorders nothing.
    committed = [ln for ln in _ledger(sup)
                 if ln["kind"] == "baseline_check" and ln["ok"] is False
                 and not ln.get("audit")][-1]
    before = len(sup._latest_records().get("__unreconciled__") or [])
    dup = dict(committed)
    dup["recorded_at"] = now + 500
    _append(sup, dup)
    recs = sup._latest_records()
    assert recs["baseline_check"]["seq"] == committed["seq"]
    assert len(recs.get("__unreconciled__") or []) == before


def test_sequence_reference_mismatch_is_untrusted_and_auditable(
        client, users):
    """A valid sequence used by the WRONG content — flipped outcome,
    other config scope, or a foreign kind's real id — is untrusted, and
    a failed such claim keeps blocking even over a genuine pass. The
    audited recovery closes exactly that: it refuses nothing the
    operator can honestly do, vouches for the actual passing record, and
    deletes nothing; a forged line appearing AFTER the audit still
    blocks (no blanket amnesty)."""
    from srplatform.safety import get_supervisor
    sup = get_supervisor()
    sup.datapath.baseline_ok = True  # the scripted positive live fixture
    r = _post_baseline(client, users, True)
    assert r.status_code == 200 and r.json()["ok"] is True, r.text
    recs = sup._latest_records()
    seq_id = recs["baseline_check"]["seq"]
    ident = recs["baseline_check"]["config_identity"]
    good_detail = recs["baseline_check"]["detail"]
    q, _ = _qual(client, users, "baseline_check")
    assert q["usable"] is True, q

    now = time.time()
    _append(sup, {"kind": "baseline_check", "ok": False,
                  "config_identity": ident, "detail": good_detail,
                  "seq": seq_id, "recorded_at": now - 30})
    _append(sup, {"kind": "baseline_check", "ok": True,
                  "config_identity": "other-scope-identity",
                  "detail": good_detail, "seq": seq_id,
                  "recorded_at": now - 29})
    foreign_id = _seed("datapath_proof", age_h=1, returning=True)
    _append(sup, {"kind": "baseline_check", "ok": True,
                  "config_identity": ident, "detail": good_detail,
                  "seq": foreign_id, "recorded_at": now - 28})
    recs = sup._latest_records()
    assert recs["baseline_check"]["ok"] is True  # genuine row selected
    assert len([x for x in recs["__unreconciled__"]
                if x.get("untrusted")]) == 3
    q, _ = _qual(client, users, "baseline_check")
    assert q["usable"] is False, "an untrusted FAILED claim vanished"
    assert any("UNTRUSTED FAILED" in p for p in q["problems"])

    # audited recovery, real endpoint + real DB audit row
    rr = _reconcile(client, users)
    assert rr.status_code == 200, rr.text
    body = rr.json()
    assert body["ok"] is True
    assert body["vouched_record_id"] == seq_id
    q, _ = _qual(client, users, "baseline_check")
    assert q["usable"] is True, q
    arows = _rows("outage_reconciliation")
    assert len(arows) == 1
    adet = arows[0][2]
    if isinstance(adet, str):
        adet = json.loads(adet)
    assert adet["target_kind"] == "baseline_check"
    assert "R-6" in adet["reason"] and adet.get("operator")
    # the forged lines are STILL in the ledger — retained, never deleted
    led = _ledger(sup)
    assert any(ln["kind"] == "baseline_check" and ln["ok"] is False
               and ln.get("seq") == seq_id for ln in led), led
    assert any(ln.get("config_identity") == "other-scope-identity"
               for ln in led)
    assert any(ln.get("seq") == foreign_id for ln in led)

    # a forged FAILED claim appearing AFTER the audit keeps blocking
    _append(sup, {"kind": "baseline_check", "ok": False,
                  "config_identity": ident, "detail": {"late": True},
                  "seq": 888_888_888, "recorded_at": time.time()})
    q, _ = _qual(client, users, "baseline_check")
    assert q["usable"] is False and any("UNTRUSTED FAILED" in p
                                        for p in q["problems"]), q


# ------------------------------------------------------------------- F2 --
def test_outage_recovery_clears_the_block_across_restart(client, users):
    """THE reviewer reproduction: an outage-window FAILED lands in the
    file ledger only; publication is restored; a REAL passing baseline
    is recorded over HTTP. The qualification must recover — and stay
    recovered in a NEW process (fresh Supervisor on the same state
    file), with every old failed line retained and the reconciliation
    linked durably. No restart dance, no ledger edits."""
    from srplatform.safety import Supervisor, get_supervisor
    sup = get_supervisor()
    with _store_down():
        r = _post_baseline(client, users, False)
        assert r.status_code == 200, r.text
    assert any(f.startswith("db record ") for f in sup._record_failures)
    assert sup._qualification("baseline_check")["usable"] is False

    # storage restored — a genuine HTTP pass of the same kind+scope
    sup.datapath.baseline_ok = True
    r = _post_baseline(client, users, True)
    assert r.status_code == 200 and r.json()["ok"] is True, r.text
    assert not [f for f in sup._record_failures
                if f.startswith("db record ")], \
        "the committed pass did not clear the store-outage debts"
    q, full = _qual(client, users, "baseline_check")
    assert q["usable"] is True, q

    # retained + linked, not deleted or forgotten
    lines = _ledger(sup)
    assert any(ln["kind"] == "baseline_check" and ln["ok"] is False
               and ln.get("seq") is None for ln in lines), \
        "the outage-only failure was removed from the ledger"
    audit = [ln for ln in lines if ln.get("audit")
             and ln.get("kind") == "baseline_check"]
    assert audit and audit[-1]["superseded_unreconciled"] >= 1
    assert audit[-1]["via_seq"] == sup._latest_records()[
        "baseline_check"]["seq"]

    # SIMULATED RESTART: a fresh Supervisor over the same state file and
    # the same authoritative store recovers identically.
    from srplatform.safety.datapath import NoopDatapath
    sup2 = Supervisor(datapath=NoopDatapath(),
                      state_file=str(sup.state_file))
    q2 = sup2._qualification("baseline_check")
    assert q2["usable"] is True, q2


def test_newer_and_future_failures_are_never_superseded(client, users):
    """CONTRACT 2's boundary, in order: a failure observed AFTER the
    newest pass blocks with the truthful blocker; a fresh committed pass
    then orders the truth and recovers; a future-clock failure line
    blocks and even the audited reconciliation refuses to forget it."""
    from srplatform.safety import get_supervisor
    sup = get_supervisor()
    sup.datapath.baseline_ok = True
    r = _post_baseline(client, users, True)
    assert r.status_code == 200, r.text
    assert _qual(client, users, "baseline_check")[0]["usable"] is True

    with _store_down():
        r = _post_baseline(client, users, False)
        assert r.status_code == 200
    q, _ = _qual(client, users, "baseline_check")
    assert q["usable"] is False
    assert any("envelope-stamped" in p and "NEWER failure" in p
               for p in q["problems"]), q

    # recovery re-ordered by the SAME mechanism: a newer committed pass
    r = _post_baseline(client, users, True)
    assert r.status_code == 200
    assert _qual(client, users, "baseline_check")[0]["usable"] is True

    # future envelope clock: ambiguous evidence is never superseded —
    # not by the pass, and not by the audited operation.
    _append(sup, {"kind": "baseline_check", "ok": False,
                  "config_identity":
                      sup._latest_records()["baseline_check"]
                      ["config_identity"],
                  "detail": {"future": True}, "seq": None,
                  "recorded_at": time.time() + 7_200})
    q, _ = _qual(client, users, "baseline_check")
    assert q["usable"] is False
    rr = _reconcile(client, users)
    assert rr.status_code == 200, rr.text
    q, _ = _qual(client, users, "baseline_check")
    assert q["usable"] is False, "a future-clock failure was forgotten"


def test_old_classification_never_clears_a_fresh_outage_failure(
        client, users):
    """An OLD classification is not a new observation: a fresh outage
    failure after it keeps blocking; only a genuine fresh pass
    reconciles."""
    _seed("baseline_check", age_h=1)
    r = client.post("/safety/reclassify-qualification",
                    headers=users["op"],
                    json={"kind": "baseline_check",
                          "reason": "commissioning report R-6"})
    assert r.status_code == 200, r.text
    with _store_down():
        assert _post_baseline(client, users, False).status_code == 200
    q, _ = _qual(client, users, "baseline_check")
    assert q["usable"] is False, \
        "an old classification laundered a fresh outage failure"
    assert any("unreconciled FAILED" in p for p in q["problems"]), q
    from srplatform.safety import get_supervisor
    get_supervisor().datapath.baseline_ok = True
    assert _post_baseline(client, users, True).status_code == 200
    assert _qual(client, users, "baseline_check")[0]["usable"] is True


def test_reconcile_outage_refusals_are_truthful(client, users):
    """The audited recovery is a refusal machine: unknown kind 422, no
    record at all 404, store down 503 (nothing unfenced appended), and
    while the newest authoritative record FAILED — the failure is
    current, no laundering — 409; only then 200."""
    rr = _reconcile(client, users, kind="bogus_kind")
    assert rr.status_code == 422, rr.text
    rr = _reconcile(client, users)
    assert rr.status_code == 404, rr.text
    with _store_down():
        rr = _reconcile(client, users)
        assert rr.status_code == 503, rr.text
    assert _post_baseline(client, users, False).status_code == 200
    rr = _reconcile(client, users)
    assert rr.status_code == 409, rr.text
    assert "FAILED" in rr.text
    from srplatform.safety import get_supervisor
    get_supervisor().datapath.baseline_ok = True
    assert _post_baseline(client, users, True).status_code == 200
    rr = _reconcile(client, users)
    assert rr.status_code == 200, rr.text


# ------------------------------------------------------------------- F3 --
bundle_mod = pytest.importorskip("deploy.bundle")
BundleError = bundle_mod.BundleError


def _tiny_image(tmp_path: pathlib.Path, name: str) -> pathlib.Path:
    p = tmp_path / name
    subprocess.run(["qemu-img", "create", "-f", "qcow2", str(p), "8M"],
                   check=True, capture_output=True)
    os.chmod(p, 0o644)
    return p


def _tiny_bundle(tmp_path: pathlib.Path) -> pathlib.Path:
    out = tmp_path / "bundle"
    base = _tiny_image(tmp_path, "appliance-base.qcow2")
    bundle_mod.build(out, base_image=base, role_images={}, app_dir=REPO)
    assert bundle_mod.verify(out)["ok"]
    return out


@pytest.mark.skipif(_NEED_QEMU, reason="qemu-img required")
def test_forced_rollback_never_overwrites_a_foreign_destination(
        tmp_path, monkeypatch):
    """CONTRACT 3: with force, the previous release is moved aside and
    the activation then FAILS while a foreign empty destination has
    appeared. The rollback uses NOREPLACE too: the foreign inode stays
    exactly as found, the previous VALID release is RETAINED at its
    known backup path (and still verifies), the error is a durable
    actionable obligation naming that path, and cleanup kept its hands
    off the debt."""
    out = _tiny_bundle(tmp_path)
    revision = json.loads((out / "MANIFEST.json").read_text())["revision"]
    seen: dict = {}

    def invade_and_fail():
        out.mkdir()  # FOREIGN destination appears in the fault window
        seen["ino"] = out.stat().st_ino
        raise OSError(5, "injected activation fault")

    monkeypatch.setattr(bundle_mod, "_test_fail_activation",
                        invade_and_fail)
    base = tmp_path / "appliance-base.qcow2"
    with pytest.raises(BundleError) as ei:
        bundle_mod.build(out, base_image=base, role_images={},
                         app_dir=REPO, force=True)
    msg = str(ei.value)
    assert "ROLLBACK OBLIGATION" in msg
    retained = [p for p in tmp_path.iterdir() if ".superseded-" in p.name]
    assert len(retained) == 1, retained
    assert str(retained[0]) in msg, "the obligation must name the path"
    # the foreign inode: still there, empty, untouched
    assert out.is_dir() and out.stat().st_ino == seen["ino"]
    assert list(out.iterdir()) == []
    # the previous VALID release is retained and verifies
    v = bundle_mod.verify(retained[0])
    assert v["ok"], v["problems"]
    assert json.loads(
        (retained[0] / "MANIFEST.json").read_text())["revision"] == \
        revision
    # no owned debris beyond the retained backup (the debt itself)
    assert not [p for p in tmp_path.iterdir() if ".staging-" in p.name]
