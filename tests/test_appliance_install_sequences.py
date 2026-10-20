"""Real appliance install sequences (fast, no root, no host changes).

The install gate used to accept an environment assertion for the
managed-service half.  These tests execute the ACTUAL sequences in a
sandbox root: clean install, rerun, reboot, populated upgrade, and
drift detection plus repair — with the data, the worker capability and
foreign files observed, not asserted.
"""
from __future__ import annotations

import pathlib

import pytest

from infra.dev.install_sequences import (InstallSequenceError, build_manifest,
                                         run_sequences)


def test_install_sequences_are_real_and_idempotent(tmp_path):
    base = tmp_path / "manifest-input"
    manifest = build_manifest(base)
    root = tmp_path / "sandbox"
    evidence = run_sequences(root, manifest)
    assert evidence["clean"]["changed"] > 0
    assert evidence["clean"]["receipt"] is True
    assert evidence["rerun"]["changed"] == 0
    assert evidence["rerun"]["token"] == "preserved"
    assert evidence["reboot"]["runtime_restored"] is True
    assert evidence["reboot"]["data_preserved"] is True
    assert evidence["upgrade"]["changed"] > 0
    assert evidence["upgrade"]["token"] == "preserved"
    assert evidence["drift"]["detected"] is True
    assert evidence["drift"]["repaired"] is True
    assert evidence["drift"]["foreign_file_untouched"] is True


def test_sandbox_install_never_touches_the_host(tmp_path):
    """The sandbox re-roots the manifest: no host directory is created."""
    import os
    base = tmp_path / "manifest-input"
    manifest = build_manifest(base)
    root = tmp_path / "sandbox"
    run_sequences(root, manifest)
    # The manifest's own state directory is NOT created on the host.
    assert not pathlib.Path(base / "state").exists()
    assert not pathlib.Path(base / "run").exists()
    # ... and everything landed inside the sandbox instead.
    assert (root / "var/lib/sparring-range").is_dir()
    assert (root / "run/sparring-range").is_dir()
    assert (root / "etc/systemd/system/sr-api.service").is_file()


def test_apply_refuses_a_manifest_whose_image_drifted(tmp_path):
    """A changed base image is refused BEFORE any effect (fail closed)."""
    import json
    from infra.appliance.manifest import ApplianceManifest
    base = tmp_path / "manifest-input"
    manifest = build_manifest(base)
    raw = json.loads(manifest.read_text())
    raw["images"]["attacker"]["sha256"] = "0" * 64
    manifest.write_text(json.dumps(raw))
    with pytest.raises(Exception):
        ApplianceManifest.load(manifest, verify_images=True)
    # The installer refuses too, before writing anything.
    from infra.dev.install_sequences import _run
    code, out, err = _run(tmp_path / "sandbox", manifest, "apply",
                          expect_ok=False)
    assert code != 0
    assert not (tmp_path / "sandbox/etc/sparring-range/install-receipt.json").exists()
