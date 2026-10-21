"""The bundle must be a WORKING application, not a file pile.

The scenario loader, the verifiers and the telemetry shipper are separate
top-level packages; a bundle that leaves one of them out installs an
application that cannot load a scenario.  This test builds a bundle and
imports the application FROM THE BUNDLE, with nothing of the repository on
the path.
"""
from __future__ import annotations

import os
import pathlib
import shutil
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from deploy import bundle as bundle_mod  # noqa: E402


def _fake_image(path: pathlib.Path, size: int = 4096) -> pathlib.Path:
    if shutil.which("qemu-img") is None:
        pytest.skip("qemu-img is required to build a release bundle")
    subprocess.run(["qemu-img", "create", "-f", "qcow2", str(path), "8M"],
                   check=True, capture_output=True)
    return path


@pytest.mark.parametrize("module", [
    "srplatform.settings",
    "srplatform.scenario_engine.loader",
    "verifiers",
    "telemetry.shipper",
])
def test_the_bundled_application_imports_without_the_repository(tmp_path,
                                                                module):
    base = _fake_image(tmp_path / "appliance-base.qcow2")
    out = tmp_path / "bundle"
    bundle_mod.build(out, base_image=base, role_images={}, app_dir=REPO)
    env = {k: v for k, v in os.environ.items()
           if k not in ("PYTHONPATH", "PYTHONHOME")}
    # Nothing of the repository may be importable: the bundle must stand alone.
    env["PYTHONPATH"] = str(out)
    r = subprocess.run([sys.executable, "-c",
                        f"import {module}; print({module}.__name__)"],
                       capture_output=True, text=True, cwd=str(tmp_path),
                       env=env, timeout=300)
    assert r.returncode == 0, (module, r.stdout[-2000:], r.stderr[-2000:])
    assert module in r.stdout
