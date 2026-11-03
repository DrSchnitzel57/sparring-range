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


def test_scoring_profile_has_a_nonvacuous_inventory():
    text = ub.render_userdata(profile="scoring-debian",
                              hostname="sr-build-scoring",
                              pubkeys=["ssh-ed25519 AAAKEY k"])
    for binary in ub.SCORING_BINARIES:
        assert f"SR-GUEST-CAP-MISSING:{binary}" in text, binary
    assert "SR-GUEST-CAP-MISSING:ldapsearch" in text


def test_attacker_reports_library_probes_and_records_versions():
    text = ub.render_userdata(profile="attacker-debian",
                              hostname="sr-build-attacker",
                              pubkeys=["ssh-ed25519 AAAKEY k"])
    # impacket's wheel has NO console scripts: the binary checks stay
    # honest MISSING while the library probe is the real evidence.
    assert "SR-GUEST-CAP-MISSING:impacket-library" in text
    assert "SR-GUEST-PKG:" in text and "SR-GUEST-PIP:impacket=" in text


def _fake_harness(monkeypatch, tmp_path, serial_text):
    import hashlib
    from infra.images import underpressure_build as ub

    base = tmp_path / "base.qcow2"
    base.write_bytes(b"fake-provider-bytes")
    pin = {"sha256": hashlib.sha256(base.read_bytes()).hexdigest(),
           "url": "https://example", "source_checksum_file": "https://x"}

    def fake_overlay(_base, run_dir, name, disk_gb):
        assert 4 <= disk_gb <= 16, f"harness bound violated: {disk_gb}"
        path = run_dir / f"{name}.qcow2"
        path.write_bytes(b"overlay")
        return path

    def fake_seed(path, user_data, meta_data, network_config=None):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"seed")
        return path

    def fake_boot(*, disk, seed_iso, **kwargs):
        serial = disk.parent / f"{disk.stem}.serial.log"
        serial.write_text(serial_text)
        return {"ok": True}

    monkeypatch.setitem(ub.PINS, "fake", pin)
    monkeypatch.setattr(ub, "enable_cloud_init",
                        lambda disk: None)  # root-only, proven live instead
    monkeypatch.setattr(ub.qemu_guest, "fresh_role_overlay", fake_overlay)
    monkeypatch.setattr(ub.qemu_guest, "boot_full_guest", fake_boot)
    monkeypatch.setattr(ub, "build_seed_disk", fake_seed)
    return ub, base


def test_build_profile_defaults_are_legal_and_parse_evidence(
        tmp_path, monkeypatch):
    """The defaults must survive the harness's own bounds (disk 4..16 GiB)
    — the first-reviewed version defaulted to 20 and could never build."""
    serial = ("SR-GUEST-CAP-OK:curl\nSR-GUEST-CAP-MISSING:nmap\n"
              "SR-GUEST-PKG:curl=8.5.0-2\nSR-GUEST-DONE rc=0\n")
    ub, base = _fake_harness(monkeypatch, tmp_path, serial)
    pub = tmp_path / "k.pub"
    pub.write_text("ssh-ed25519 AAAKEY k\n")
    out = ub.build_profile(profile="scoring-debian", base=base, pubkey=pub,
                           run_dir=tmp_path / "run8", pin="fake")
    assert out["missing"] == ["nmap"]
    assert out["capabilities"]["curl"] == "ok"
    assert out["packages"]["curl"] == "8.5.0-2"


def test_build_profile_refuses_a_pubkey_that_is_empty(tmp_path, monkeypatch):
    ub, base = _fake_harness(monkeypatch, tmp_path, "SR-GUEST-DONE rc=0\n")
    empty = tmp_path / "empty.pub"
    empty.write_text("\n")
    with pytest.raises(RuntimeError, match="empty"):
        ub.build_profile(profile="scoring-debian", base=base, pubkey=empty,
                         run_dir=tmp_path / "run9", pin="fake")


def test_multi_distro_renders_the_right_package_manager_and_service_gates():
    rocky = ub.render_userdata(profile="rocky9-ecomm", hostname="h",
                               pubkeys=["ssh-ed25519 AAAK k"])
    assert "rpm -q --queryformat" in rocky
    assert "SR-GUEST-SVC-MISSING:httpd" in rocky
    assert "SR-GUEST-SVC-MISSING:php-fpm" in rocky
    assert "  - httpd" in rocky
    mail = ub.render_userdata(profile="ubuntu2204-mail", hostname="h",
                              pubkeys=["ssh-ed25519 AAAK k"])
    assert "dpkg-query" in mail
    assert "SR-GUEST-SVC-MISSING:postfix" in mail
    assert "SR-GUEST-SVC-MISSING:dovecot" in mail


def test_every_profile_builds_from_a_pinned_media_it_declares():
    for profile in ub.APT_PACKAGES:
        media = ub.PROFILE_MEDIA.get(profile)
        assert media, f"{profile} declares no pinned media"
        assert media in ub.PINS, f"{profile} media {media} not pinned"
        assert ub.DISTROS[media] in ("apt", "dnf")
