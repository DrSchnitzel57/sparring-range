"""Windows golden builds — unattended Server installs for the env lane.

Why a separate builder (vs the Linux cloud-image path): Windows ignores
NoCloud/cloud-init, needs an `autounattend.xml` on removable media for a
zero-touch install, and its installer speaks VGA, not serial markers. This
module therefore:

  1. renders `autounattend.xml` for an EVAL Server image (keyless,
     Datacenter CORE — /IMAGE/INDEX 3 on the 2019/2022 eval media — and
     BIOS/MBR so the CURRENT appliance domain XML boots it; firmware/TPM
     wiring is a declared blueprint field that the backend does not
     implement yet, stated honestly);
  2. install boot is DRIVER-FREE and OFFLINE: SATA disk + PC machine + no
     NIC (`-nic none`), with the Windows ISO, the virtio-win driver CD and
     the unattend-answer CD on IDE cdrom indexes 1..3;
  3. NO `-no-reboot`: Windows Setup resets mid-install; boot order is
     DVD-then-HDD so the reboot continues from the installed disk (the
     DVD's "press any key" is never pressed) and the final ACPI shutdown
     makes qemu exit;
  4. first logon installs the virtio-win drivers (pnputil) AND QGA (its
     MSI — pnputil alone does not install qemu-ga), writes an ASCII marker
     with driver/QGA counts, then shuts down;
  5. verification reads the marker back OFFLINE via qemu-nbd + ntfs3:
     disk content is evidence, never qemu's exit code, and `installed`
     requires qga=1 in the marker.

Scope: Server evaluation media (2019/2022). Win11 needs UEFI+TPM (later);
SQL/Splunk are installed in-guest during role provisioning, not here.
The build Administrator password is a LAB default and must be rotated by
role provisioning.
"""
from __future__ import annotations

import pathlib
import subprocess
import time

import pycdlib

#: /IMAGE/INDEX on Server 2019/2022 EVAL media:
#: 1 Std Core, 2 Std Desktop, 3 Datacenter Core, 4 Datacenter Desktop.
DATACENTER_CORE_INDEX = {"2022": 3, "2019": 3}

#: The first-logon provisioning command (single line; lives in the answer
#: file as plain XML text). Finds the virtio-win CD by looking for its
#: real `amd64\*.inf` payload (the ISO volume label is 'virtio-win-*',
#: never 'VirtIO'), installs every driver, installs QGA from its MSI,
#: and records COUNTS — a false `virtio=True` from pnputil alone is not
#: evidence that the guest agent exists.
FIRST_LOGON_PS = (
    "powershell -NoProfile -ExecutionPolicy Bypass -Command "
    "\"$ErrorActionPreference='Continue'; "
    "$letters=68..90 | ForEach-Object {[char]$_}; $cd=''; "
    "foreach ($l in $letters) { "
    "if (Test-Path ($l.ToString()+':\\viostor')) "
    "{ $cd=$l.ToString(); break } }; "
    "$drivers=0; if ($cd) { "
    "$infs=Get-ChildItem ($cd+':') -Recurse -Filter *.inf "
    "-ErrorAction SilentlyContinue | Where-Object "
    "{ $_.FullName -match '\\\\amd64\\\\' -or "
    "$_.FullName -match '\\\\2k22\\\\' -or "
    "$_.FullName -match '\\\\2k19\\\\' }; "
    "$drivers=@($infs).Count; "
    "foreach ($inf in $infs) "
    "{ pnputil.exe /add-driver $inf.FullName /install | Out-Null } }; "
    "$qga=0; if ($cd) { msiexec.exe /i "
    "($cd+':\\guest-agent\\qemu-ga-x86_64.msi') /qn /norestart; "
    "$qga=[int](Test-Path 'C:\\Program Files\\qemu-ga\\qemu-ga.exe') }; "
    "$m='C:\\sr-build-complete.txt'; "
    "Set-Content -Path $m -Encoding ascii -Value "
    "('cd=' + $cd + ' drivers=' + $drivers + ' qga=' + $qga + "
    "' ver=' + [Environment]::OSVersion.Version); "
    "shutdown.exe /s /t 5 /f\""
)


def render_autounattend(*, version: str = "2022",
                        computer_name: str = "sr-build") -> str:
    """Zero-touch Server CORE eval install, BIOS/MBR (today's domains)."""
    if version not in DATACENTER_CORE_INDEX:
        raise ValueError(f"no eval index for Server {version}; known: "
                         f"{sorted(DATACENTER_CORE_INDEX)}")
    return _UNATTEND_TEMPLATE.replace(
        "%INDEX%", str(DATACENTER_CORE_INDEX[version])).replace(
        "%PS%", FIRST_LOGON_PS).replace("%NAME%", computer_name)


_UNATTEND_TEMPLATE = r"""<?xml version="1.0" encoding="utf-8" standalone="yes"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend"
          xmlns:wcm="http://schemas.microsoft.com/WMIC/winpe/2005/05">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE"
               processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35"
               language="neutral" versionScope="nonSxS">
      <InputLocale>en-US</InputLocale>
      <SystemLocale>en-US</SystemLocale>
      <UILanguage>en-US</UILanguage>
      <SetupUILanguage><UILanguage>en-US</UILanguage></SetupUILanguage>
    </component>
    <component name="Microsoft-Windows-Setup"
               processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35"
               language="neutral" versionScope="nonSxS">
      <DiskConfiguration>
        <WillShowUI>OnError</WillShowUI>
        <Disk wcm:action="add">
          <DiskID>0</DiskID>
          <WillWipeDisk>true</WillWipeDisk>
          <CreatePartitions>
            <CreatePartition wcm:action="add">
              <Order>1</Order>
              <Type>Primary</Type>
              <Extend>true</Extend>
            </CreatePartition>
          </CreatePartitions>
          <ModifyPartitions>
            <ModifyPartition wcm:action="add">
              <Order>1</Order>
              <PartitionID>1</PartitionID>
              <Format>NTFS</Format>
              <Label>Windows</Label>
              <Active>true</Active>
            </ModifyPartition>
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
      <UserData><AcceptEula>true</AcceptEula></UserData>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup"
               processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35"
               language="neutral" versionScope="nonSxS">
      <ComputerName>%NAME%</ComputerName>
      <TimeZone>UTC</TimeZone>
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
      <AutoLogon>
        <Password>
          <Value>SrBuild-Only-1!</Value>
          <PlainText>true</PlainText>
        </Password>
        <Enabled>true</Enabled>
        <LogonCount>1</LogonCount>
        <Username>Administrator</Username>
      </AutoLogon>
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
    """The answer file as a tiny ISO (Windows Setup scans removable media
    roots; ISO9660 is case-insensitive, so the uppercase name suffices)."""
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
                    smp: int = 4, kvm: bool = True,
                    monitor_socket: pathlib.Path | None = None) -> list[str]:
    """Install boot: driver-free SATA + NO NIC (`-nic none` = zero egress),
    answer/virtio/Windows CDs on IDE indexes 1..3 (pc has exactly 4 IDE
    units: the old index 4 cannot attach), DVD-then-HDD boot order so
    Windows Setup's mid-install reset continues from the installed disk.
    No -no-reboot: the unattend's ACPI shutdown is what ends qemu."""
    accel = ["-accel", "kvm"] if kvm else ["-accel", "tcg"]
    return [
        "qemu-system-x86_64", "-machine", "pc", *accel,
        "-cpu", "host" if kvm else "max",
        "-m", str(memory_mb), "-smp", str(smp),
        "-drive", f"file={disk},format=qcow2,if=ide,index=0",
        "-drive", f"file={windows_iso},media=cdrom,readonly=on,index=1",
        "-drive", f"file={virtio_iso},media=cdrom,readonly=on,index=2",
        "-drive", f"file={answer_iso},media=cdrom,readonly=on,index=3",
        "-nic", "none",
        "-boot", "order=d", "-name", "sr-winbuild",
        "-display", "none", "-vga", "std",
        *(["-monitor", f"unix:{monitor_socket},server=on,wait=off"]
          if monitor_socket else []),
        "-serial", f"file:{serial_log}",
        "-rtc", "base=localtime",
    ]


def read_marker_offline(disk: pathlib.Path,
                        mount_root: pathlib.Path = pathlib.Path("/mnt"),
                        marker: str = "sr-build-complete.txt") -> str | None:
    """Read the marker from the installed system OFFLINE via qemu-nbd +
    ntfs3 — the disk proves the install, not qemu's exit code. Needs root
    (qemu-nbd, mount); the appliance build runs as root."""
    dev = "/dev/nbd0"
    subprocess.run(["modprobe", "nbd"], check=False)
    subprocess.run(["qemu-nbd", "-r", "-c", dev, str(disk)], check=True,
                   timeout=120)
    try:
        time.sleep(2)
        for part in sorted(pathlib.Path("/sys/class/block").glob("nbd0p*")):
            target = pathlib.Path(str(mount_root) + part.name)
            target.mkdir(parents=True, exist_ok=True)
            r = subprocess.run(["mount", "-t", "ntfs3", "-o", "ro",
                                f"/dev/nbd0{part.name.replace('nbd0', '')}",
                                str(target)], capture_output=True, text=True)
            if r.returncode != 0:
                target.rmdir()
                continue
            try:
                marker_path = target / marker
                if marker_path.is_file():
                    return marker_path.read_text(errors="replace").strip()
            finally:
                subprocess.run(["umount", str(target)], check=False)
                target.rmdir()
        return None
    finally:
        subprocess.run(["qemu-nbd", "-d", dev], check=False)


def build_windows(*, windows_iso: pathlib.Path, virtio_iso: pathlib.Path,
                  run_dir: pathlib.Path, version: str = "2022",
                  disk_gb: int = 60, memory_mb: int = 4096, smp: int = 4,
                  kvm: bool = True,
                  install_timeout_s: int = 5400) -> dict:
    """One unattended install -> marker-verified qcow2 artifact.

    `installed` requires the marker's qga=1: drivers/QGA are the point of
    the build, and a marker that merely exists proves only the install."""
    run_dir.mkdir(parents=True, exist_ok=True)
    disk = run_dir / f"sr-win{version}.qcow2"
    disk.unlink(missing_ok=True)  # reruns replace the previous attempt
    subprocess.run(["qemu-img", "create", "-f", "qcow2", str(disk),
                    f"{disk_gb}G"], check=True, timeout=120)
    xml = render_autounattend(version=version)
    answer = build_answer_iso(run_dir / "answer.iso", xml)
    serial = run_dir / "install.serial.log"
    cmd = install_command(disk=disk, windows_iso=windows_iso,
                          virtio_iso=virtio_iso, answer_iso=answer,
                          serial_log=serial, memory_mb=memory_mb, smp=smp,
                          kvm=kvm,
                          monitor_socket=run_dir / "monitor.sock")
    error = None
    try:
        proc = subprocess.run(cmd, timeout=install_timeout_s,
                              capture_output=True, text=True)
        qemu_rc, qemu_tail = proc.returncode, (proc.stderr or "")[-800:]
    except subprocess.TimeoutExpired as exc:
        error = f"install boot timed out after {install_timeout_s}s"
        qemu_rc, qemu_tail = None, str(exc)[-400:]
    marker = read_marker_offline(disk)
    installed = bool(marker) and "qga=1" in str(marker)
    return {"disk": str(disk), "installed": installed, "marker": marker,
            "qemu_rc": qemu_rc, "qemu_tail": qemu_tail,
            "error": error, "serial": str(serial)}
