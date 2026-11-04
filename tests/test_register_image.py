"""Registering a built artifact: the manifest edit is pure and digest-true."""
from __future__ import annotations

import json
import pathlib
import shutil
import subprocess

import pytest

from infra.dev.register_image import digest, register

REPO = pathlib.Path(__file__).resolve().parents[1]
EXAMPLE = REPO / "deploy" / "appliance.manifest.example.json"


def _qcow2(path: pathlib.Path, size: str = "8M") -> pathlib.Path:
    if shutil.which("qemu-img") is None:
        pytest.skip("qemu-img is required to make a real image")
    subprocess.run(["qemu-img", "create", "-f", "qcow2", str(path), size],
                   check=True, capture_output=True)
    return path


def test_register_replaces_the_entry_wholesale_never_carries_a_digest():
    raw = json.loads(EXAMPLE.read_text())
    out = register(raw, role="attacker", path="/x/attacker.qcow2",
                   sha256="a" * 64, size_bytes=123, template_id=9005,
                   profile="kali-rolling", disk_gb=16, memory_mb=2048,
                   vcpus=2)
    entry = out["images"]["attacker"]
    assert entry["sha256"] == "a" * 64 and entry["size_bytes"] == 123
    assert entry["vcpus"] == 2 and entry["template_id"] == 9005
    # the shipped example keeps its other roles untouched
    assert set(out["images"]) > {"attacker"}


def test_registered_manifest_satisfies_the_strict_loader(tmp_path):
    from infra.appliance.manifest import ApplianceManifest

    # the shipped example's own images point at appliance paths that do not
    # exist here, so re-point every one at a real file before verification
    raw = json.loads(EXAMPLE.read_text())
    real = _qcow2(tmp_path / "img.qcow2")
    for role in raw["images"]:
        raw["images"][role]["path"] = str(real)
        raw["images"][role]["sha256"], raw["images"][role]["size_bytes"] = \
            digest(real)
    # the example pins operator paths that do not exist here
    pub = tmp_path / "k.pub"
    pub.write_text("ssh-ed25519 AAAA test\n")
    raw["access_keys"] = {k: str(pub) for k in raw.get("access_keys", {})}
    # adding a 64 GiB role to a fixture sized for 44 GiB: widen ITS budgets
    raw["budgets"].update({"max_disk_gb": 2000, "max_vcpus": 128,
                           "max_memory_mb": 120000})
    out = register(raw, role="ws2019-sql", path=str(real),
                   sha256=digest(real)[0], size_bytes=digest(real)[1],
                   template_id=9106, profile="ws2019-sql", disk_gb=64,
                   memory_mb=6144, vcpus=2)
    m = ApplianceManifest.from_dict(out, verify_images=True,
                                    verify_model_key=False)
    spec = m.image_for_template(9106)
    assert spec is not None and spec.role == "ws2019-sql"
    assert spec.vcpus == 2 and spec.memory_mb == 6144 and spec.disk_gb == 64
    cat = {c["profile"]: c for c in m.template_catalog()}
    assert cat["ws2019-sql"]["template_id"] == 9106


def test_a_digest_that_does_not_match_the_bytes_is_refused_by_the_loader(
        tmp_path):
    from infra.appliance.manifest import ApplianceManifest

    raw = json.loads(EXAMPLE.read_text())
    real = _qcow2(tmp_path / "img.qcow2")
    for role in raw["images"]:
        raw["images"][role]["path"] = str(real)
        raw["images"][role]["sha256"], raw["images"][role]["size_bytes"] = \
            digest(real)
    out = register(raw, role="ws2019-sql", path=str(real),
                   sha256="f" * 64, size_bytes=digest(real)[1],
                   template_id=9106, profile="ws2019-sql", disk_gb=64,
                   memory_mb=6144, vcpus=2)
    with pytest.raises(Exception, match="sha256|digest"):
        ApplianceManifest.from_dict(out, verify_images=True,
                                    verify_model_key=False)
