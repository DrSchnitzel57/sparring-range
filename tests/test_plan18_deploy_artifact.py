"""Plan 18 review — deploy records the artifact identity (db layer).

Cron-pin trust binds to what the deployment ACTUALLY RUNS ON: at clone
time the orchestrator freezes role + template + image SHA-256 from the
installer's own appliance manifest into the immutable deployment
resource, and scoring later injects hashes only for that frozen fact.
These tests drive the REAL deploy path (routes → executor → orchestrator
→ real broker service) against the fake PVE boundary and read the
recorded identity back from persisted state.
"""
from __future__ import annotations

import hashlib
import json
import pathlib

import pytest
from tests.conftest import launch_and_wait

pytestmark = pytest.mark.db


def _manifest(tmp_path: pathlib.Path) -> tuple[pathlib.Path, str]:
    """An installer-shaped manifest whose role image names template 9001
    (the scenario's web template); the sha256 is the deployed-truth value
    the resource must record."""
    from infra.dev import install_sequences as seq
    img = tmp_path / "custom-web.qcow2"
    img.write_bytes(b"deployed-artifact-bytes")
    digest = hashlib.sha256(img.read_bytes()).hexdigest()
    # build_manifest writes real per-role images + digests; override the
    # image map to bind our role to the template this scenario clones.
    path = seq.build_manifest(tmp_path / "materials")
    doc = json.loads(pathlib.Path(path).read_text())
    doc["images"] = {
        "custom-web-role": {
            "template_id": 9001, "path": str(img), "sha256": digest,
            "size_bytes": img.stat().st_size, "disk_gb": 12,
            "memory_mb": 2048, "vcpus": 2,
        }}
    path.write_text(json.dumps(doc))
    return path, digest


def _resources(session_id):
    from srplatform.db.models import Deployment
    from srplatform.db.session import db
    with db() as s:
        dep = (s.query(Deployment)
               .filter(Deployment.session_id == session_id)
               .order_by(Deployment.deployment_id.desc()).first())
        return list(dep.resources or [])


def test_deploy_records_cron_artifact_identity_from_manifest(
        client, users, fake_broker, tmp_path, monkeypatch):
    import srplatform.verification_service as vs
    manifest, digest = _manifest(tmp_path)
    monkeypatch.setattr(vs, "get_settings", lambda: type(
        "S", (), {"appliance_manifest_file": str(manifest)}))

    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    launch_and_wait(client, users["member"], sid)

    web = next(r for r in _resources(sid) if r.get("host") == "web01")
    assert web["cron_artifact"] == {
        "role": "custom-web-role", "template_vmid": 9001,
        "artifact_sha256": digest}
    # the scoring-side dataflow reads exactly this back for its host
    from srplatform.db.session import db as dbf
    with dbf() as s:
        amap = vs.cron_artifact_map(s, sid)
    assert amap["web01"]["artifact_sha256"] == digest
    # unknown templates in the scenario (db01 = 9004) record NOTHING
    # rather than guessing an identity
    db_res = next(r for r in _resources(sid) if r.get("host") == "db01")
    assert "cron_artifact" not in db_res


def test_deploy_without_manifest_records_nothing(
        client, users, fake_broker, monkeypatch):
    """Unset manifest path: honest absence.  Nothing is recorded, the
    map stays empty, and cron checks therefore stay UNKNOWN — deploy
    must NOT invent an identity from pins or scenario YAML."""
    import srplatform.verification_service as vs
    monkeypatch.setattr(vs, "get_settings", lambda: type(
        "S", (), {"appliance_manifest_file": ""}))
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    launch_and_wait(client, users["member"], sid)
    web = next(r for r in _resources(sid) if r.get("host") == "web01")
    assert "cron_artifact" not in web
    from srplatform.db.session import db
    with db() as s:
        assert vs.cron_artifact_map(s, sid) == {}


def test_broken_manifest_records_nothing_never_crashes_deploy(
        client, users, fake_broker, tmp_path, monkeypatch):
    import srplatform.verification_service as vs
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    monkeypatch.setattr(vs, "get_settings", lambda: type(
        "S", (), {"appliance_manifest_file": str(bad)}))
    sid = client.post("/sessions", json={"scenario_id": "web-foothold-01"},
                      headers=users["member"]).json()["session_id"]
    launch_and_wait(client, users["member"], sid)   # deploy still succeeds
    web = next(r for r in _resources(sid) if r.get("host") == "web01")
    assert "cron_artifact" not in web
