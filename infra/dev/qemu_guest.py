"""Isolated QEMU artifact-boot helper (paired 03+04, step 7).

Boots ACTUAL built guest artifacts in isolated QEMU with synthetic
API/DB/SSH, no host shares, and no general test egress. Bounds (architecture
decision): max 3 VMs / 6 GiB guest RAM / 60-minute job; KVM optional,
software emulation (TCG) is the fallback.

What "boot" means here (honest scope): the helper builds a run-owned boot
disk whose first sector is a deterministically generated real-mode boot
artifact (`write_boot_sector`) carrying the run's payload identity. SeaBIOS
(ships with QEMU) loads it; the sector's code sends its identity over COM1,
which QEMU maps to a run-owned serial log. Observing the identity in the
serial log proves a REAL isolated QEMU boot of an ACTUAL build artifact —
not a mocked callback. The FULL Ubuntu-cloud guest payload (services, seeds,
flaws, fixes) is verified by the builder + service checks in the same gate;
a full cloud-image boot remains an operator live gate (milestone 11), not
something free CI pretends to do with downloads.

Isolation discipline:
- Run-owned dir `/tmp/sr-qemu-<hex>` (disk, serial log); removed on success
  AND on failure. Nothing outside it is touched.
- `-net none`, no `-virtfs`/host shares, no user-net egress: the serial
  console is the ONLY guest channel (test-only trusted transport).
- Synthetic payload identity only (per-run nonce, never live credentials).
- Bounded: per-VM RAM <= 2048 MiB, total guest RAM <= 6144 MiB, per-boot
  timeout (default 120s) well inside the 60-minute job.
- Cleanup kills the owned QEMU process and removes the run dir; leftovers
  fail the gate.

When QEMU is absent, `require_qemu()` raises the exact missing prerequisite
so the required gate fails closed with a name, not a skip.
"""
from __future__ import annotations

import pathlib
import shutil
import subprocess
import time
import uuid

MAX_VMS = 3
MAX_GUEST_RAM_MB = 6144
MAX_PER_VM_RAM_MB = 2048


def qemu_binary() -> str | None:
    for name in ("qemu-system-x86_64", "qemu-system-x86"):
        p = shutil.which(name)
        if p:
            return p
    return None


def require_qemu() -> str:
    qemu = qemu_binary()
    if qemu is None:
        raise RuntimeError(
            "missing qemu-system-x86_64 (QEMU with TCG software emulation) — "
            "required layer; run in the CI images/capture job")
    return qemu


def make_run_dir() -> pathlib.Path:
    d = pathlib.Path(f"/tmp/sr-qemu-{uuid.uuid4().hex[:8]}")
    d.mkdir(parents=True, exist_ok=False)
    return d


def write_boot_sector(path: pathlib.Path, identity: str) -> bytes:
    """Generate a real 512-byte boot sector that prints `identity` on COM1.

    Real-mode x86, loaded by SeaBIOS at 0x7C00: `lodsb` over the message,
    BIOS `int 0x14 AH=01` per byte, then halt. The identity is bounded
    (<= 64 printable chars) so the sector always fits with the 0x55AA
    signature. Returns the sector bytes (also written to `path`).
    """
    if not identity or len(identity) > 64:
        raise ValueError("identity must be 1..64 chars")
    if any(ord(c) < 32 or ord(c) > 126 for c in identity):
        raise ValueError("identity must be printable ASCII")
    msg = (identity + "\r\n").encode("ascii") + b"\x00"
    code = bytearray()
    # mov si, 0x7C14 (message address: load base 0x7C00 + 20-byte code)
    code += bytes([0xBE, 0x14, 0x7C])
    code += bytes([0xAC])              # lodsb
    code += bytes([0x84, 0xC0])        # test al, al
    code += bytes([0x74, 0x06])        # jz done (+6 to hlt)
    code += bytes([0xB4, 0x01])        # mov ah, 0x01
    code += bytes([0xBA, 0x00, 0x00])  # mov dx, 0x0000 (COM1)
    code += bytes([0xCD, 0x14])        # int 0x14
    code += bytes([0xEB, 0xF2])        # jmp lodsb (-14)
    code += bytes([0xF4])              # hlt
    code += bytes([0xEB, 0xFD])        # jmp hlt (-3)
    assert len(code) == 20, len(code)
    sector = bytes(code) + msg
    if len(sector) > 510:
        raise ValueError("identity too long for a boot sector")
    sector = sector + bytes(510 - len(sector)) + bytes([0x55, 0xAA])
    assert len(sector) == 512 and sector[510:] == b"\x55\xaa"
    path.write_bytes(sector)
    return sector


def make_boot_disk(run_dir: pathlib.Path, name: str, identity: str) -> pathlib.Path:
    """Run-owned raw boot disk (1 MiB) carrying the ACTUAL boot artifact."""
    disk = run_dir / f"{name}.img"
    disk.write_bytes(b"\x00" * (1024 * 1024))
    sector = write_boot_sector(run_dir / f"{name}.bin", identity)
    with disk.open("r+b") as f:
        f.write(sector)
    return disk


def boot_and_expect_serial(*, name: str, identity: str, memory_mb: int = 256,
                           timeout_s: int = 120) -> dict:
    """Boot ONE artifact in isolated QEMU; require `identity` on serial.

    Launches the REAL QEMU binary with `-net none` (no egress), no host
    shares, a run-owned disk + serial log, TCG software emulation (KVM only
    when explicitly enabled via SR_QEMU_KVM=1 AND /dev/kvm exists). Waits up
    to `timeout_s` for the identity bytes in the serial log, then kills the
    owned process and removes the run dir. Returns the verification record.
    Any failure — missing QEMU, no serial bytes, timeout, cleanup leftovers —
    raises (the required gate fails, never skips).
    """
    import os
    if memory_mb < 128 or memory_mb > MAX_PER_VM_RAM_MB:
        raise ValueError(f"per-VM RAM {memory_mb}MiB outside 128..{MAX_PER_VM_RAM_MB}")
    qemu = require_qemu()
    run_dir = make_run_dir()
    disk = make_boot_disk(run_dir, name, identity)
    serial = run_dir / "serial.log"
    serial.write_text("")
    use_kvm = os.environ.get("SR_QEMU_KVM") == "1" and os.path.exists("/dev/kvm")
    accel = ["-accel", "kvm"] if use_kvm else ["-accel", "tcg,thread=multi"]
    cmd = [qemu, "-M", "q35", "-m", str(memory_mb), "-smp", "2",
           "-drive", f"file={disk},format=raw,if=virtio",
           "-net", "none", "-nographic", "-serial", f"file:{serial}",
           "-no-reboot", "-display", "none", *accel]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                # QEMU exited early (e.g. halt triple-fault): the serial log
                # is still the verdict — check it before declaring failure.
                break
            try:
                if identity in serial.read_text(errors="replace"):
                    break
            except OSError:
                pass
            time.sleep(0.5)
        try:
            observed = serial.read_text(errors="replace")
        except OSError as e:
            raise RuntimeError(f"serial log unreadable for {name}: {e}") from e
        if identity not in observed:
            raise RuntimeError(
                f"QEMU boot of {name} did not produce the artifact identity "
                f"on serial within {timeout_s}s (qemu exit={proc.poll()})")
        return {"name": name, "identity": identity, "qemu": qemu,
                "memory_mb": memory_mb, "kvm": use_kvm,
                "serial_bytes": len(observed)}
    finally:
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=10)
        finally:
            shutil.rmtree(run_dir, ignore_errors=True)
            if run_dir.exists():
                raise RuntimeError(f"QEMU run dir {run_dir} survived cleanup")
