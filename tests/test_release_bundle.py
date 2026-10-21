"""The release bundle must be complete, digest-bound and secret-free."""
from __future__ import annotations

import json
import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from deploy import bundle as bundle_mod  # noqa: E402


def _fake_image(path: pathlib.Path, size: int = 4096) -> pathlib.Path:
    path.write_bytes(b"qcow-image" * (size // 9))
    return path


def _build(tmp_path: pathlib.Path, *, roles: bool = True) -> pathlib.Path:
    """Build a bundle.

    A RELEASE bundle carries the ROLE artifacts: the base image is a bare
    Ubuntu and the practice product is baked into the role images.
    """
    base = _fake_image(tmp_path / "appliance-base.qcow2")
    role_images = {}
    if roles:
        for role in ("attacker", "mojang-web-local", "mojang-web-db"):
            role_images[role] = _fake_image(tmp_path / f"{role}.qcow2", 2048)
    out = tmp_path / "bundle"
    bundle_mod.build(out, base_image=base, role_images=role_images,
                     app_dir=REPO)
    return out


def test_bundle_is_complete_and_verifies(tmp_path):
    out = _build(tmp_path)
    result = bundle_mod.verify(out)
    assert result["ok"], result
    assert result["files"] > 10
    assert "appliance-base" in json.loads(
        (out / bundle_mod.MANIFEST_NAME).read_text())["images"]
    # the application, the lock file and the installer travel with the bundle
    names = set(result and json.loads(
        (out / bundle_mod.MANIFEST_NAME).read_text())["files"])
    assert "requirements.lock" in names
    assert "deploy/appliance.py" in names
    assert "deploy/bundle.py" in names
    assert not any(".venv" in n or "__pycache__" in n for n in names)


def test_verify_refuses_a_tampered_bundle(tmp_path):
    out = _build(tmp_path)
    victim = out / "requirements.lock"
    victim.write_text("tampered\n")
    result = bundle_mod.verify(out)
    assert not result["ok"]
    assert any("digest drift" in p or "size drift" in p for p in result["problems"])


def test_verify_refuses_an_unlisted_file(tmp_path):
    out = _build(tmp_path)
    (out / "sneaked.txt").write_text("not in the manifest\n")
    result = bundle_mod.verify(out)
    assert not result["ok"]
    assert any("unlisted file" in p for p in result["problems"])


def test_bundle_refuses_credential_material(tmp_path):
    out = _build(tmp_path)
    secret = out / "deploy" / "leaked.env"
    secret.write_text('API_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    manifest = json.loads((out / bundle_mod.MANIFEST_NAME).read_text())
    manifest["files"]["deploy/leaked.env"] = {
        "sha256": bundle_mod._sha256(secret),
        "bytes": secret.stat().st_size}
    (out / bundle_mod.MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=True))
    result = bundle_mod.verify(out)
    assert not result["ok"]
    assert any("credential" in p for p in result["problems"])


def _model_key(tmp_path: pathlib.Path) -> pathlib.Path:
    path = tmp_path / "model.key"
    path.write_text("operator-model-key\n")
    return path


def _operator_keys(tmp_path: pathlib.Path) -> dict[str, str]:
    keys = {}
    for role in ("runner", "bastion", "mgmt"):
        priv = tmp_path / f"op-{role}"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                        "-f", str(priv)], check=True, capture_output=True)
        keys[role] = str(priv.with_suffix(".pub"))
    return keys


def test_a_bundle_without_the_role_artifacts_cannot_render_a_manifest(tmp_path):
    """A bundle that carries only the base image would ship bare guests."""
    out = _build(tmp_path, roles=False)
    with pytest.raises(bundle_mod.BundleError) as bad:
        bundle_mod.render_manifest(
            out, tmp_path / "manifest.json",
            installation_id="4f0e7a1c-8a59-4a4e-9b5d-74f0e7a1c999",
            lan_address="10.10.10.50", range_cidr="10.66.0.0/24",
            public_url="https://sr.example.edu",
            internal_url="http://127.0.0.1:8000",
            ingest_url="https://10.66.0.1:8443")
    assert "role image" in str(bad.value)


def test_bundle_renders_a_valid_operator_manifest(tmp_path):
    out = _build(tmp_path)
    out_manifest = tmp_path / "manifest.json"
    info = bundle_mod.render_manifest(
        out, out_manifest,
        installation_id="4f0e7a1c-8a59-4a4e-9b5d-74f0e7a1c999",
        lan_address="10.10.10.50", range_cidr="10.66.0.0/24",
        public_url="https://sr.example.edu",
        internal_url="http://127.0.0.1:8000",
        ingest_url="https://10.66.0.1:8443",
        access_keys=_operator_keys(tmp_path),
        model_api_key_file=str(_model_key(tmp_path)))
    assert info["installation_id"] == "4f0e7a1c-8a59-4a4e-9b5d-74f0e7a1c999"
    raw = json.loads(out_manifest.read_text())
    assert raw["network"]["range_cidr"] == "10.66.0.0/24"
    assert raw["network"]["range_gateway"] == "10.66.0.1"
    assert raw["broker"]["socket"] == "/run/sparring-range/broker.sock"
    # the rendered manifest satisfies the strict appliance schema
    from infra.appliance.manifest import ApplianceManifest

    parsed = ApplianceManifest.from_dict(raw, verify_images=True)
    assert parsed.installation_id == raw["installation_id"]
    assert sorted(parsed.images) == ["attacker", "mojang-web-db",
                                     "mojang-web-local"]
    # every role points at ITS OWN artifact, and the paths are absolute
    for role, image in parsed.images.items():
        assert pathlib.Path(image.path).is_absolute(), (role, image.path)
        assert image.path.endswith(f"{role}.qcow2"), (role, image.path)
    # the role images carry the canonical template ids and budgets
    assert parsed.images["attacker"].template_id == 9005
    assert parsed.images["mojang-web-local"].template_id == 9011
    assert parsed.images["mojang-web-db"].template_id == 9012


def test_bundle_cli_verify_and_manifest(tmp_path):
    out = _build(tmp_path)
    env = {**__import__("os").environ, "PYTHONPATH": str(REPO)}
    r = subprocess.run([sys.executable, str(REPO / "deploy/bundle.py"),
                        "verify", str(out)], capture_output=True, text=True,
                       cwd=REPO, env=env, timeout=300)
    assert r.returncode == 0, (r.stdout + r.stderr)[-800:]
    assert json.loads(r.stdout)["ok"] is True
