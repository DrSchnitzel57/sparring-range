"""seed-profile: a new image role as a pinned base copy (operator path).

Live commissioning 2026-11-03: seeding 10 environment profiles by hand hit
the manifest validator's BOUNDED image sums blind (vcpus, memory, disk) and
required re-editing. The operator path must refuse an invalid manifest
BEFORE writing anything, never overwrite an image, and record the copy's
own digest so the broker clones a pinned artifact.
"""
from __future__ import annotations

import hashlib
import json
import pathlib

import subprocess

import pytest

from deploy.appliance import InstallError, seed_profile
from infra.appliance.manifest import ApplianceManifest
from tests.test_appliance_contract import _manifest

SOURCE_ROLE = "attacker"  # fixture image: 2 vcpu / 2048 MiB / 11 GiB


def _write(tmp_path):
    raw = _manifest(tmp_path)
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(raw))
    return path, raw


def test_seed_profile_copies_pins_and_records_the_copy(tmp_path):
    path, raw = _write(tmp_path)
    out = seed_profile(path, role="ecomm", profile="rocky9-ecomm",
                       template_id=9101, source_role=SOURCE_ROLE,
                       disk_gb=11, memory_mb=2048, vcpus=2)
    src = raw["images"][SOURCE_ROLE]
    dest = tmp_path / "ecomm.qcow2"
    assert out["path"] == str(dest) and not out["dry_run"]
    assert dest.read_bytes() == pathlib.Path(src["path"]).read_bytes()
    # the recorded digest IS the copied bytes, and the manifest validates
    recorded = json.loads(path.read_text())["images"]["ecomm"]
    assert recorded["sha256"] == hashlib.sha256(dest.read_bytes()).hexdigest()
    assert recorded["template_id"] == 9101 and recorded["profile"] == "rocky9-ecomm"
    ApplianceManifest.from_dict(json.loads(path.read_text()),
                                verify_images=True, verify_model_key=False)
    assert "apply" in out["next"]


def test_seed_profile_refuses_duplicate_role_profile_and_template(tmp_path):
    path, _ = _write(tmp_path)
    with pytest.raises(InstallError, match="already exists"):
        seed_profile(path, role=SOURCE_ROLE, profile="x-role", template_id=9199,
                     source_role=SOURCE_ROLE, disk_gb=11)
    with pytest.raises(InstallError, match="invalid"):
        seed_profile(path, role="dup-tid", profile="dup-tid-prof",
                     template_id=9005, source_role=SOURCE_ROLE, disk_gb=11)
    with pytest.raises(InstallError, match="invalid"):
        seed_profile(path, role="dup-prof", profile="attacker",
                     template_id=9199, source_role=SOURCE_ROLE, disk_gb=11)


def test_seed_profile_refuses_budget_overflow_before_any_effect(tmp_path):
    path, _ = _write(tmp_path)
    with pytest.raises(InstallError, match="invalid"):
        seed_profile(path, role="big", profile="big-profile", template_id=9102,
                     source_role=SOURCE_ROLE, vcpus=7, disk_gb=11)
    assert not (tmp_path / "big.qcow2").exists()
    # the fixture's image vcpus total 6; 7 more must never reach disk
    assert "big" not in json.loads(path.read_text())["images"]


def test_seed_profile_never_overwrites(tmp_path):
    path, raw = _write(tmp_path)
    dest = tmp_path / "ecomm.qcow2"
    dest.write_bytes(b"already-here")
    with pytest.raises(InstallError, match="overwrite"):
        seed_profile(path, role="ecomm", profile="rocky9-ecomm",
                     template_id=9101, source_role=SOURCE_ROLE, disk_gb=11)
    assert dest.read_bytes() == b"already-here"


def test_seed_profile_dry_run_touches_nothing(tmp_path):
    path, raw = _write(tmp_path)
    before = path.read_text()
    out = seed_profile(path, role="ecomm", profile="rocky9-ecomm",
                       template_id=9101, source_role=SOURCE_ROLE,
                       disk_gb=11, dry_run=True)
    assert out["dry_run"] and not (tmp_path / "ecomm.qcow2").exists()
    assert path.read_text() == before


def test_seed_profile_refusals_name_the_actual_rule(tmp_path):
    path, _ = _write(tmp_path)
    with pytest.raises(InstallError, match="vcpus"):
        seed_profile(path, role="big-vcpu", profile="big-vcpu-prof",
                     template_id=9102, source_role=SOURCE_ROLE, vcpus=7)
    with pytest.raises(InstallError, match="memory"):
        seed_profile(path, role="big-mem", profile="big-mem-prof",
                     template_id=9103, source_role=SOURCE_ROLE,
                     memory_mb=7000)
    with pytest.raises(InstallError, match="disk"):
        seed_profile(path, role="big-disk", profile="big-disk-prof",
                     template_id=9104, source_role=SOURCE_ROLE, disk_gb=12)


def test_seed_profile_vcpus_defaults_to_one(tmp_path):
    path, raw = _write(tmp_path)
    seed_profile(path, role="defaults", profile="defaults-prof",
                 template_id=9105, source_role=SOURCE_ROLE, disk_gb=11)
    assert json.loads(path.read_text())["images"]["defaults"]["vcpus"] == 1


def test_seed_profile_dest_and_parent_refusals(tmp_path):
    path, _ = _write(tmp_path)
    with pytest.raises(InstallError, match="directory"):
        seed_profile(path, role="elsewhere", profile="elsewhere-prof",
                     template_id=9106, source_role=SOURCE_ROLE, disk_gb=11,
                     dest=tmp_path / "custom" / "any.qcow2")


def test_seed_profile_records_mode_0644(tmp_path):
    path, _ = _write(tmp_path)
    seed_profile(path, role="modes", profile="modes-prof", template_id=9107,
                 source_role=SOURCE_ROLE, disk_gb=11)
    import stat
    assert stat.S_IMODE(path.stat().st_mode) == 0o644


def test_seed_profile_cleans_partial_copy_on_cp_failure(tmp_path, monkeypatch):
    path, _ = _write(tmp_path)
    dest = tmp_path / "partial.qcow2"

    def fake_cp(args, check=True):
        dest.write_bytes(b"partial")
        raise subprocess.CalledProcessError(1, "cp")

    monkeypatch.setattr("deploy.appliance.subprocess.run", fake_cp)
    with pytest.raises(InstallError, match="failed"):
        seed_profile(path, role="partial", profile="partial-prof",
                     template_id=9108, source_role=SOURCE_ROLE, disk_gb=11,
                     dest=dest)
    assert not dest.exists(), "a failed copy must not strand a partial image"


def test_seed_profile_refuses_symlinked_destination(tmp_path):
    path, _ = _write(tmp_path)
    real = tmp_path / "real.qcow2"
    real.write_bytes(b"keep")
    link = tmp_path / "link.qcow2"
    link.symlink_to(real)
    with pytest.raises(InstallError, match="symlink"):
        seed_profile(path, role="linked", profile="linked-prof",
                     template_id=9109, source_role=SOURCE_ROLE, disk_gb=11,
                     dest=link)
    assert link.is_symlink() and real.read_bytes() == b"keep"
