"""Fast contracts for the Windows unattended builder (no qemu boot here).

The install itself runs on the appliance as a recorded live build; these
tests pin the answer file, the answer-answer ISO and the driver-free
install-boot command so a broken unattend never reaches a long boot.
"""
from __future__ import annotations

import pathlib

import pycdlib
import pytest

from infra.images import windows_build as wb


def test_autounattend_is_keyless_datacenter_core_with_first_logon():
    xml = wb.render_autounattend(version="2022", computer_name="sr-dc")
    assert "<Value>3</Value>" in xml          # Datacenter CORE, eval media
    assert "sr-dc" in xml
    assert "AdministratorPassword" in xml
    # FirstLogonCommands only fire on a logon; the unattend must AUTOLOGON
    # (the first live attempt sat at the sign-in screen with an idle disk)
    assert "<AutoLogon>" in xml and "<LogonCount>1</LogonCount>" in xml
    assert "FirstLogonCommands" in xml
    # SPECIALIZE is minimal AND logged: VBS/hypervisor off (nested-KVM
    # freezes), no drivers/MSIs there; the stage log proves how far it got.
    assert "Microsoft-Windows-Deployment" in xml
    assert "RunSynchronous" in xml
    assert "EnableVirtualizationBasedSecurity /t REG_DWORD /d 0" in xml
    assert "hypervisorlaunchtype off" in xml
    assert "sr-stage.log" in xml
    assert "pnputil.exe /add-driver" not in xml.split("pass=\"oobeSystem\"")[0]
    assert "qemu-ga-x86_64.msi" not in xml.split("pass=\"oobeSystem\"")[0]
    # first logon: ONE cmd line — QGA, then marker, then ACPI shutdown
    assert "qemu-ga-x86_64.msi" in xml
    # msiexec is a GUI-subsystem exe: plain cmd does NOT wait for it, and
    # the shutdown raced a half-done install (build #9 evidence: marker +
    # stage log, no qemu-ga.exe). `start /wait` is required.
    assert "start /wait msiexec.exe" in xml
    assert "echo build-complete" in xml
    # NO shutdown lives in the answer file: shutting down from inside the
    # first logon, early or ten minutes late, left OOBEInProgress=1 and every
    # clone booted back into OOBE (2026-11-10). The HOST waits for the agent
    # to report OOBEInProgress=0x0 and only then shuts down.
    assert "shutdown.exe" not in xml


def test_autounattend_refuses_unknown_windows_version():
    with pytest.raises(ValueError, match="no eval index"):
        wb.render_autounattend(version="11")


def test_answer_iso_carries_the_root_answer_file(tmp_path):
    iso_path = tmp_path / "answer.iso"
    wb.build_answer_iso(iso_path, "<unattend/>")
    iso = pycdlib.PyCdlib()
    iso.open(str(iso_path))
    try:
        names = {child.rock_ridge.name().decode()
                 if child.rock_ridge else child.file_identifier().decode()
                 for child in iso.list_children(iso_path="/")}
        assert "AUTOUNATTEND.XML" in names
    finally:
        iso.close()


def test_install_command_is_driver_free_and_offline(tmp_path):
    cmd = wb.install_command(
        disk=tmp_path / "d.qcow2", windows_iso=tmp_path / "w.iso",
        virtio_iso=tmp_path / "v.iso", answer_iso=tmp_path / "a.iso",
        serial_log=tmp_path / "s.log", kvm=True)
    joined = " ".join(cmd)
    assert "if=ide" in joined          # SATA: no virtio driver needed to install
    assert joined.count("media=cdrom") == 3
    assert "index=4" not in joined     # pc supports IDE units 0..3 only
    assert "-no-reboot" not in joined  # Setup resets mid-install
    assert "-boot order=d" in joined
    assert "-nic none" in joined       # zero network egress
    assert "-accel kvm" in joined
    tcg = wb.install_command(
        disk=tmp_path / "d.qcow2", windows_iso=tmp_path / "w.iso",
        virtio_iso=tmp_path / "v.iso", answer_iso=tmp_path / "a.iso",
        serial_log=tmp_path / "s.log", kvm=False)
    assert "-accel tcg" in " ".join(tcg)
