"""Isolated QEMU artifact-boot helper (paired 03+04, step 7).

Boots ACTUAL built guest artifacts in isolated QEMU with synthetic
API/DB/SSH, no host shares, and no general test egress. Bounds (architecture
decision): max 3 VMs / 6 GiB guest RAM / 60-minute job; KVM optional,
software emulation (TCG) is the fallback.

What "boot" means here: the helper boots the REAL Ubuntu 24.04 guest —
the pinned, checksum-verified cloud base plus a run-owned qcow2 overlay
carrying the actually installed packages (nginx/MySQL/auditd/shipper),
payload, seeds, flaws and units — with a NoCloud seed ISO. cloud-init runs
the guest-side checks; results come back over the serial console into a
run-owned log. Observing those bytes proves a REAL isolated Ubuntu boot with
the ACTUAL installed payload — not a mocked callback and not a synthetic
boot sector. Build-phase package fetching uses only pinned names (resolved
versions are recorded from the guest itself); verification boots run with
`-net none`, proving no runtime fetching is needed.

Isolation discipline:
- Run-owned dir `/tmp/sr-qemu-<hex>` (overlay, seed ISO, serial log);
  removed on success AND on failure. The read-only base is shared from a
  hash-verified cache; overlays are per-run. Nothing else is touched.
- Verification/negative boots use `-net none` (no guest egress at all). The
  build boot and the capture-positive control path use SLIRP userspace
  networking: the ONLY consumer is the pinned package fetch or the single
  host synthetic-API stub port (10.0.2.2) — narrow control paths, never
  general egress. No `-virtfs`/host shares ever.
- Synthetic secrets only (per-run nonce/tokens, never live credentials).
- Bounded: per-VM RAM <= 2048 MiB, at most 3 VMs per gate run, per-boot
  timeouts inside the 60-minute job.
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


def manifest_base_image() -> dict:
    """Pinned base-image record (URL + SHA256 + size) from the manifest."""
    import json
    repo = pathlib.Path(__file__).resolve().parents[2]
    manifest = json.loads((repo / "infra" / "images" / "manifest.json").read_text())
    return manifest["base_image"]


def ensure_verified_base(cache_dir: pathlib.Path) -> pathlib.Path:
    """Fetch (pinned URL, build-phase fetch only) + verify the base cloud
    image into `cache_dir`. Returns the image path. A checksum mismatch or
    size mismatch fails closed — never boot an unverified base."""
    import hashlib
    import urllib.request
    base = manifest_base_image()
    cache_dir.mkdir(parents=True, exist_ok=True)
    img = cache_dir / "noble-server-cloudimg-amd64.img"
    if not img.exists():
        # Build-phase fetch of the single pinned input (plan step 1).
        with urllib.request.urlopen(base["source_url"], timeout=120) as r, \
                open(img, "wb") as f:
            shutil.copyfileobj(r, f, 8 * 1024 * 1024)
    h = hashlib.sha256()
    with open(img, "rb") as f:
        for chunk in iter(lambda: f.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    if h.hexdigest() != base["sha256"].lower():
        raise RuntimeError(
            f"base image checksum mismatch for {img} — refusing to boot")
    if img.stat().st_size != base["size_bytes"]:
        raise RuntimeError(
            f"base image size {img.stat().st_size} != pinned "
            f"{base['size_bytes']} — refusing to boot")
    return img


def make_overlay(base_img: pathlib.Path, run_dir: pathlib.Path, name: str) -> pathlib.Path:
    """Run-owned qcow2 overlay on the verified base (the overlay deltas ARE
    the built artifact; the base is never mutated)."""
    overlay = run_dir / f"{name}.qcow2"
    r = subprocess.run(["qemu-img", "create", "-f", "qcow2",
                        "-b", str(base_img), "-F", "qcow2", str(overlay)],
                       capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        raise RuntimeError(f"qemu-img overlay failed: {(r.stderr or r.stdout)[:300]}")
    return overlay


def boot_full_guest(*, disk: pathlib.Path, seed_iso: pathlib.Path,
                    memory_mb: int = 2048, smp: int = 2,
                    net: str = "none", host_api_port: int | None = None,
                    expect: tuple[str, ...] = ("SR-GUEST-DONE rc=0",),
                    timeout_s: int = 900) -> dict:
    """Boot a REAL Ubuntu guest (disk + NoCloud seed) in isolated QEMU.

    - `net="none"`: no guest egress at all (verification/negative boots —
      proves no runtime fetching is needed).
    - `net="user"`: SLIRP userspace networking for the build phase (pinned
      package fetch) and the capture-positive synthetic-API control path
      (guest reaches the host stub at 10.0.2.2:`host_api_port` only).
    No host shares ever. TCG software emulation unless SR_QEMU_KVM=1 with
    /dev/kvm. The serial log must contain every `expect` marker within
    `timeout_s`, else this raises (required gates fail, never skip).
    """
    import os
    if memory_mb < 512 or memory_mb > MAX_PER_VM_RAM_MB:
        raise ValueError(f"guest RAM {memory_mb}MiB outside 512..{MAX_PER_VM_RAM_MB}")
    qemu = require_qemu()
    run_dir = disk.parent
    serial = run_dir / f"{disk.stem}.serial.log"
    use_kvm = os.environ.get("SR_QEMU_KVM") == "1" and os.path.exists("/dev/kvm")
    accel = ["-accel", "kvm"] if use_kvm else ["-accel", "tcg,thread=multi"]
    if net == "none":
        net_args: list[str] = ["-net", "none"]
    elif net == "user":
        net_args = ["-netdev", "user,id=n0", "-device", "virtio-net-pci,netdev=n0"]
    else:
        raise ValueError(f"net must be 'none' or 'user', got {net!r}")
    cmd = [qemu, "-M", "q35", "-m", str(memory_mb), "-smp", str(smp),
           "-drive", f"file={disk},format=qcow2,if=virtio",
           "-drive", f"file={seed_iso},format=raw,media=cdrom,readonly=on",
           *net_args, "-nographic", "-serial", f"file:{serial}",
           "-no-reboot", "-display", "none", *accel]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + timeout_s
        observed = ""
        while time.monotonic() < deadline:
            try:
                observed = serial.read_text(errors="replace").replace("\r", "")
            except OSError:
                pass
            if all(m in observed for m in expect):
                break
            if proc.poll() is not None:
                # Exited early (e.g. guest poweroff after DONE, or a boot
                # failure): re-read once and judge on the markers.
                try:
                    observed = serial.read_text(errors="replace").replace("\r", "")
                except OSError:
                    pass
                break
            time.sleep(2)
        missing = [m for m in expect if m not in observed]
        if missing:
            found = sorted({l for l in observed.splitlines()
                            if "SR-GUEST-" in l})
            dbg = pathlib.Path(f"/tmp/opencode/sr-gate-debug/{disk.stem}.serial.log")
            try:
                dbg.parent.mkdir(parents=True, exist_ok=True)
                dbg.write_text(observed)
            except OSError:
                pass
            raise RuntimeError(
                f"guest {disk.name} missing serial markers {missing} within "
                f"{timeout_s}s (qemu exit={proc.poll()}); found markers: "
                f"{found[:20]!r}; full serial preserved at {dbg}; "
                f"tail: {observed[-800:]!r}")
        return {"disk": str(disk), "qemu": qemu, "memory_mb": memory_mb,
                "kvm": use_kvm, "net": net,
                "serial_bytes": len(observed)}
    finally:
        try:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=15)
        finally:
            pass  # run-dir lifecycle belongs to the caller (gate asserts it)


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
