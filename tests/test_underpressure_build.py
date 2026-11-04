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
        assert (pin["url"].startswith("https://")
                or pin["url"] in ("appliance-local", "operator-extracted-kali")), name
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

    def fake_provision(disk, *, profile, pubkey, distro=None,
                       extra_debs=None):
        return {"versions": {"curl": "8.5.0-2"}}

    def fake_verify(disk, *, profile, timeout_s=600):
        return {"capabilities": {"curl": "ok", "nmap": "missing"},
                "packages": {"curl": "8.5.0-2"},
                "missing": ["nmap"],
                "boot": {"ok": True},
                "serial": str(disk.parent / f"{disk.stem}.serial.log")}

    monkeypatch.setitem(ub.PINS, "fake", pin)
    monkeypatch.setattr(ub, "enable_cloud_init", lambda disk: None)
    monkeypatch.setattr(ub.qemu_guest, "fresh_role_overlay", fake_overlay)
    monkeypatch.setattr(ub, "provision_chroot", fake_provision)
    monkeypatch.setattr(ub, "verify_boot", fake_verify)
    monkeypatch.setattr(ub, "disable_verify_reporter", lambda disk: None)
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


# --------------------------------------------------------------------------- #
# Capability contract: each profile is graded against ITS OWN binaries        #
# --------------------------------------------------------------------------- #

def test_each_profile_gets_its_own_capability_contract():
    """Non-attacker roles were once graded against the scoring vantage's
    toolset; the desktop build reported kinit/ldapsearch 'missing' because of
    it. Every profile now resolves to an explicit contract."""
    caps, bins = ub.capability_contract("attacker-debian")
    assert "nmap" in bins and "ldapsearch" in bins
    assert caps, "attacker profiles keep their per-category capability map"

    _, desktop = ub.capability_contract("ubuntu-desktop")
    assert "kinit" not in desktop and "ldapsearch" not in desktop
    assert "ssh" in desktop and "python3" in desktop

    _, kali = ub.capability_contract("team-kali")
    assert "nmap" in kali and "kinit" not in kali

    _, scoring = ub.capability_contract("scoring-debian")
    assert "ldapsearch" in scoring and "kinit" in scoring

    # Service-only roles: no invented binary contract.
    assert ub.capability_contract("rocky9-ecomm") == ({}, [])
    assert ub.capability_contract("ubuntu2204-mail") == ({}, [])


def test_unknown_profile_fails_closed():
    with pytest.raises(ValueError, match="no capability contract"):
        ub.capability_contract("no-such-role")


def test_seed_checks_named_capabilities_for_a_non_attacker_profile():
    userdata = ub.render_userdata(profile="ubuntu-desktop", hostname="dsk",
                                  pubkeys=["ssh-ed25519 AAAA k"])
    assert "SR-GUEST-CAP-OK:ssh" in userdata
    assert "SR-GUEST-CAP-OK:kinit" not in userdata


# --------------------------------------------------------------------------- #
# Disk sizing never SHRINKS a provider base (Kali cloud is 25 GiB)            #
# --------------------------------------------------------------------------- #

def test_sized_base_copy_never_shrinks_a_larger_base(tmp_path):
    import shutil
    import subprocess

    if shutil.which("qemu-img") is None:
        pytest.skip("qemu-img not installed")
    from infra.dev import qemu_guest

    base = tmp_path / "kali.qcow2"
    subprocess.run(["qemu-img", "create", "-f", "qcow2", str(base), "25G"],
                   check=True, capture_output=True)
    copy = qemu_guest.sized_base_copy(base, tmp_path, "kali", 16)
    out = subprocess.run(["qemu-img", "info", "--output", "json",
                          str(copy)], check=True, capture_output=True,
                         text=True).stdout
    import json
    assert json.loads(out)["virtual-size"] == 25 * (1 << 30)
    assert base.exists(), "provider base must never be modified"


def test_sized_base_copy_grows_a_small_base(tmp_path):
    import shutil
    import subprocess

    if shutil.which("qemu-img") is None:
        pytest.skip("qemu-img not installed")
    from infra.dev import qemu_guest

    base = tmp_path / "small.qcow2"
    subprocess.run(["qemu-img", "create", "-f", "qcow2", str(base), "4G"],
                   check=True, capture_output=True)
    copy = qemu_guest.sized_base_copy(base, tmp_path, "small", 16)
    out = subprocess.run(["qemu-img", "info", "--output", "json",
                          str(copy)], check=True, capture_output=True,
                         text=True).stdout
    import json
    assert json.loads(out)["virtual-size"] == 16 * (1 << 30)


# --------------------------------------------------------------------------- #
# Splunk: not in any apt repo — vendor .deb installed inside the chroot       #
# --------------------------------------------------------------------------- #

def test_splunk_profile_installs_the_vendor_deb_and_enables_boot_start():
    assert ub.PROFILE_MEDIA["debian12-splunk"] == "debian12"
    urls = ub.EXTRA_DEB["debian12-splunk"]
    assert urls and all(u.startswith("https://download.splunk.com/")
                        for u in urls)
    script = ub._provision_script("debian12-splunk")
    assert "dpkg -i" in script and "splunk-*.deb" in script
    assert "enable boot-start" in script and "--accept-license" in script
    assert "systemctl enable Splunkd" in script
    assert ub.ROLE_SERVICES["debian12-splunk"] == ["Splunkd"]
    _, bins = ub.capability_contract("debian12-splunk")
    assert "curl" in bins and "ssh" in bins


def test_fetch_extra_debs_caches_and_hashes_the_bytes(tmp_path, monkeypatch):
    calls = []

    def fake_run(cmd, check, timeout):
        calls.append(cmd)
        pathlib.Path(cmd[-1]).write_bytes(b"deb-bytes")

    monkeypatch.setattr(ub.subprocess, "run", fake_run)
    files = ub.fetch_extra_debs("debian12-splunk", tmp_path)
    assert len(files) == 1
    assert files[0].read_bytes() == b"deb-bytes"
    assert ub.sha256_file(files[0]) == \
        hashlib.sha256(b"deb-bytes").hexdigest()
    ub.fetch_extra_debs("debian12-splunk", tmp_path)  # cached
    assert len(calls) == 1


def test_profiles_without_vendor_debs_fetch_nothing(tmp_path):
    assert ub.fetch_extra_debs("attacker-debian", tmp_path) == []


def test_every_linux_profile_installs_and_ENABLES_the_guest_agent():
    """`systemctl enable` cannot run in a chroot, so it failed silently on
    every build: the unit existed but was never wanted and the agent only
    ran when cloud-init started it. A lagged cloud-init left a silent agent,
    an unpinnable host key and a guest no bastion token could dial. The
    desktop image additionally shipped NO agent at all.

    So: the agent is part of every apt profile's install set, and the wants
    link is created by hand."""
    import infra.images.underpressure_build as ub

    checked = 0
    for profile in ("ubuntu-desktop", "debian12-splunk", "attacker-debian",
                    "scoring-debian", "ubuntu2204-mail"):
        script = ub._provision_script(profile)
        checked += 1
        assert "qemu-guest-agent" in script, profile
        assert "multi-user.target.wants" in script, profile
        assert "SR-GUEST-AGENT-NOT-ENABLED" in script, profile
        assert "systemctl enable ssh qemu-guest-agent" not in script, \
            f"{profile}: chroot systemctl enable does not work"
    assert checked == 5
