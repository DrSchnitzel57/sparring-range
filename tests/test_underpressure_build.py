"""Fast contracts for the Underpressure Linux golden builder.

The slow part (a real cloud-init build boot) runs on the appliance as a
recorded live build; these tests pin the fail-closed input boundary: a
base whose bytes differ from the provider checksum is refused BEFORE any
boot, and the rendered build seed carries exactly the profile's declared
package set, the operator's public key, and a capability report derived
from the same attacker_tools inventory the preflight uses.
"""
from __future__ import annotations

import hashlib
import pathlib

import pytest

from infra.images import underpressure_build as ub


def _key(tmp_path):
    path = tmp_path / "sr.pub"
    path.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOPERATOR operator@sr\n")
    return path


def test_pins_declare_url_and_provider_checksum():
    for name, pin in ub.PINS.items():
        assert pin["url"].startswith("https://"), name
        assert pin.get("sha512") or pin.get("sha256"), name
        if "sha512" in pin:
            assert len(pin["sha512"]) == 128, name
        if "sha256" in pin:
            assert len(pin["sha256"]) == 64, name
        assert pin.get("source_checksum_file"), name


def test_verify_pinned_refuses_foreign_bytes(tmp_path):
    base = tmp_path / "base.qcow2"
    base.write_bytes(b"not the provider image")
    with pytest.raises(RuntimeError, match="pinned"):
        ub.verify_pinned(base, ub.PINS["debian12"])
    ok = {"sha256": hashlib.sha256(base.read_bytes()).hexdigest(),
          "url": "https://example", "source_checksum_file": "https://x"}
    assert ub.verify_pinned(base, ok).startswith("sha256:")


def test_userdata_carries_the_profiles_declared_contract(tmp_path):
    profile = "attacker-debian"
    text = ub.render_userdata(profile=profile, hostname="sr-build-attacker",
                              pubkeys=["ssh-ed25519 AAAKEY operator@sr"])
    for pkg in ub.APT_PACKAGES[profile]:
        assert f"  - {pkg}" in text, pkg
    assert "ssh-ed25519 AAAKEY operator@sr" in text
    # every binary the ATTACKER_TOOLS inventory requires gets a REAL check
    binaries = {b for bins in ub.ATTACKER_PROFILES[profile].values()
                for b in bins}
    for binary in binaries:
        assert f"SR-GUEST-CAP-MISSING:{binary}" in text, binary
    assert "SR-GUEST-DONE rc=0" in text
    assert "shutdown -h now" in text


def test_userdata_for_unknown_profile_is_refused(tmp_path):
    with pytest.raises(RuntimeError, match="no apt package set"):
        ub.build_profile(profile="mystery", base=tmp_path / "x.qcow2",
                         pubkey=_key(tmp_path), run_dir=tmp_path / "run")


def test_build_profile_refuses_a_missing_base(tmp_path):
    with pytest.raises(RuntimeError, match="does not exist"):
        ub.build_profile(profile="scoring-debian",
                         base=tmp_path / "missing.qcow2",
                         pubkey=_key(tmp_path), run_dir=tmp_path / "run2")
