"""Windows golden builds — unattended Server installs for the env lane.

Why a separate builder (vs the Linux cloud-image path): Windows ignores
NoCloud/cloud-init, needs an `autounattend.xml` on removable media for a
zero-touch install, and its installer speaks VGA, not serial markers. This
module therefore:

  1. renders `autounattend.xml` for an EVAL Server image (keyless,
     Datacenter Core, BIOS/MBR so the CURRENT appliance domain XML boots it
     — firmware/TPM wiring is a declared blueprint field that the backend
     does not implement yet, stated honestly);
  2. install boot: SATA disk + e1000 NIC (both driver-free) with the
     Windows ISO, the virtio-win driver CD and the unattend-answer CD;
  3. first logon installs the virtio drivers/QGA, drops a completion
     marker file and powers off (qemu exits; -no-reboot);
  4. verification reads the marker back OFFLINE via qemu-nbd + ntfs3 —
     disk content is evidence, not exit-status narration.

Scope: Server evaluation media (2019/2022). Win11 needs UEFI+TPM (later);
SQL/Splunk are installed in-guest during role provisioning, not here.
"""
from __future__ import annotations

import io
import pathlib
import subprocess
import time

import pycdlib

DATACENTER_CORE_INDEX = {
    "2022": 4,   # eval ISO order: Std GUI, Std Core, DC GUI, DC Core
    "2019": 4,
}


def render_autounattend(*, version: str = "2022",
                        computer_name: str = "sr-build") -> str:
    """Zero-touch Server eval install, BIOS/MBR (matches today's domains)."""
    if version not in DATACENTER_CORE_INDEX:
        raise ValueError(f"no eval index for Server {version}; known: "
                         f"{sorted(DATACENTER_CORE_INDEX)}")
    index = DATACENTER_CORE_INDEX[version]
    ps = ("powershell -NoProfile -ExecutionPolicy Bypass -Command "
          "\"$ErrorActionPreference='Continue'; $cd=''; "
          "foreach ($d in (Get-Volume | Where-Object FileSystemLabel -eq "
          "'VirtIO')) { $cd = $d.DriveLetter + ':' }; "
          "if ($cd) { foreach ($inf in Get-ChildItem ($cd + '\\amd64\\"
          "*.inf')) { pnputil /add-driver $inf.FullName /install } }; "
          "$m='C:\\sr-build-complete.txt'; "
          "Set-Content -Path $m -Value ('virtio=' + "
          "[bool](Test-Path 'C:\\Program Files\\qemu-ga\\qemu-ga.exe') "
          "+ ' ver=' + [Environment]::OSVersion.Version); "
          "shutdown /s /t 5\"")
    return _UNATTEND_TEMPLATE.replace("%INDEX%", str(index)) \
                            .replace("%PS%", ps).replace("%NAME%", computer_name)


_UNATTEND_TEMPLATE = r"""<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend"
          xmlns:wcm="http://schemas.microsoft.com/WMIC/winpe/2005/05">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Culture-Setup"
               processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35"
               language="neutral" versionScope="nonSxS">
      <InputLocale>en-US</InputLocale>
      <SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage>
    </component>
    <component name="Microsoft-Windows-Setup"
               processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35"
               language="neutral" versionScope="nonSxS">
      <UserData><AcceptEula>true</AcceptEula></UserData>
      <DiskConfiguration>
        <WillShowUI>OnError</WillShowUI>
        <Disk wcm:action="add">
          <DiskID>0</DiskID>
          <WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <Partition wcm:action="add">
              <Order>1</Order>
              <Type>Primary</Type>
              <Extend>true</Extend>
            </Partition>
          </CreatePartitions>
          <ModifyPartitions>
            <Partition wcm:action="add">
              <Order>1</Order>
              <PartitionID>1</PartitionID>
              <Format>NTFS</Format>
              <Label>Windows</Label>
              <Active>true</Active>
            </Partition>
          </ModifyPartitions>
        </Disk>
      </DiskConfiguration>
      <ImageInstall>
        <OSImage>
          <InstallFrom>
            <MetaData wcm:action="add">
              <Key>/IMAGE/INDEX</Key>
              <Value>%INDEX%</Value>
            </MetaData>
          </InstallFrom>
          <InstallTo>
            <DiskID>0</DiskID>
            <PartitionID>1</PartitionID>
          </InstallTo>
          <WillShowUI>OnError</WillShowUI>
        </OSImage>
      </ImageInstall>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup"
               processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35"
               language="neutral" versionScope="nonSxS">
      <ComputerName>%NAME%</ComputerName>
      <TimeZone>Etc/UTC</TimeZone>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup"
               processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35"
               language="neutral" versionScope="nonSxS">
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <SkipMachineOOBE>true</SkipMachineOOBE>
        <SkipUserOOBE>true</SkipUserOOBE>
      </OOBE>
      <UserAccounts>
        <AdministratorPassword>
          <Value>SrBuild-Only-1!</Value>
          <PlainText>true</PlainText>
        </AdministratorPassword>
      </UserAccounts>
      <FirstLogonCommands>
        <SynchronousCommand wcm:action="add">
          <Order>1</Order>
          <CommandLine>%PS%</CommandLine>
          <RequiresUserInput>false</RequiresUserInput>
        </SynchronousCommand>
      </FirstLogonCommands>
    </component>
  </settings>
</unattend>
"""


def build_answer_iso(path: pathlib.Path, xml: str) -> pathlib.Path:
    """The answer file as a tiny ISO (Windows Setup scans removable media).
    ISO9660 is case-insensitive, so the uppercase root name is enough."""
    answer_xml = pathlib.Path(str(path) + ".xml.src")
    answer_xml.write_text(xml, encoding="utf-8")
    try:
        iso = pycdlib.PyCdlib()
        iso.new(interchange_level=3, sys_ident="LINUX", vol_ident="SRUNATTEND")
        iso.add_file(str(answer_xml), "/AUTOUNATTEND.XML")
        iso.write(str(path))
        iso.close()
    finally:
        answer_xml.unlink(missing_ok=True)
    return path


def install_command(*, disk: pathlib.Path, windows_iso: pathlib.Path,
                    virtio_iso: pathlib.Path, answer_iso: pathlib.Path,
                    serial_log: pathlib.Path, memory_mb: int = 4096,
                    smp: int = 4, kvm: bool = True) -> list[str]:
    """Install boot: driver-free SATA + e1000, then -no-reboot (qemu exits
    on the unattend's shutdown). No network egress: nothing to fetch."""
    accel = ["-accel", "kvm"] if kvm else ["-accel", "tcg"]
    return [
        "qemu-system-x86_64", "-machine", "pc", *accel,
        "-cpu", "host" if kvm else "max",
        "-m", str(memory_mb), "-smp", str(smp),
        "-drive", f"file={disk},format=qcow2,if=ide,index=0",
        "-drive", f"file={windows_iso},media=cdrom,readonly=on,index=2",
        "-drive", f"file={virtio_iso},media=cdrom,readonly=on,index=3",
        "-drive", f"file={answer_iso},media=cdrom,readonly=on,index=4",
        "-boot", "d", "-no-reboot", "-name", "sr-winbuild",
        "-display", "none", "-vga", "std", "-serial", f"file:{serial_log}",
        "-rtc", "base=localtime",
    ]


def read_marker_offline(disk: pathlib.Path,
                        mount_root: pathlib.Path = pathlib.Path("/mnt"),
                        marker: str = "sr-build-complete.txt") -> str | None:
    """Read the marker from the installed system OFFLINE via qemu-nbd +
    ntfs3 — the disk proves the install, not qemu's exit code."""
    dev = "/dev/nbd0"
    subprocess.run(["modprobe", "nbd"], check=False)
    subprocess.run(["qemu-nbd", "-r", "-c", dev, str(disk)], check=True,
                   timeout=120)
    try:
        time.sleep(2)
        parts = sorted(pathlib.Path("/sys/class/block").glob("nbd0p*"))
        for part in parts:
            target = mount_root / part.name
            target.mkdir(parents=True, exist_ok=True)
            r = subprocess.run(["mount", "-t", "ntfs3", "-o", "ro",
                                f"/dev/{part.name}", str(target)],
                               capture_output=True, text=True)
            if r.returncode != 0:
                pathlib.Path(target).rmdir()
                continue
            try:
                marker_path = target / marker
                if marker_path.is_file():
                    return marker_path.read_text(errors="replace").strip()
            finally:
                subprocess.run(["umount", str(target)], check=False)
                pathlib.Path(target).rmdir()
        return None
    finally:
        subprocess.run(["qemu-nbd", "-d", dev], check=False)


def build_windows(*, windows_iso: pathlib.Path, virtio_iso: pathlib.Path,
                  run_dir: pathlib.Path, version: str = "2022",
                  disk_gb: int = 60, memory_mb: int = 4096, smp: int = 4,
                  kvm: bool = True,
                  install_timeout_s: int = 5400) -> dict:
    """One unattended install -> marker-verified qcow2 artifact."""
    run_dir.mkdir(parents=True, exist_ok=True)
    disk = run_dir / f"sr-win{version}.qcow2"
    subprocess.run(["qemu-img", "create", "-f", "qcow2", str(disk),
                    f"{disk_gb}G"], check=True, timeout=120)
    xml = render_autounattend(version=version)
    answer = build_answer_iso(run_dir / "answer.iso", xml)
    serial = run_dir / "install.serial.log"
    cmd = install_command(disk=disk, windows_iso=windows_iso,
                          virtio_iso=virtio_iso, answer_iso=answer,
                          serial_log=serial, memory_mb=memory_mb, smp=smp,
                          kvm=kvm)
    proc = subprocess.run(cmd, timeout=install_timeout_s,
                          capture_output=True, text=True)
    marker = read_marker_offline(disk)
    return {"disk": str(disk), "qemu_rc": proc.returncode,
            "marker": marker, "serial": str(serial),
            "installed": marker is not None}
