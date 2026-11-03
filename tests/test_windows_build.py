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
    assert "<Value>4</Value>" in xml          # Datacenter (Core), eval media
    assert "sr-dc" in xml
    assert "AdministratorPassword" in xml
    assert "FirstLogonCommands" in xml
    assert "pnputil /add-driver" in xml       # virtio drivers installed
    assert "sr-build-complete.txt" in xml     # offline-verifiable marker
    assert "shutdown /s /t 5" in xml          # qemu exits via -no-reboot


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
    assert "-no-reboot" in joined
    assert "-accel kvm" in joined
    assert "-net" not in joined        # zero network egress during install
    tcg = wb.install_command(
        disk=tmp_path / "d.qcow2", windows_iso=tmp_path / "w.iso",
        virtio_iso=tmp_path / "v.iso", answer_iso=tmp_path / "a.iso",
        serial_log=tmp_path / "s.log", kvm=False)
    assert "-accel tcg" in " ".join(tcg)
