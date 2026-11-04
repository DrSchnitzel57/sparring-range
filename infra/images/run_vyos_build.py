#!/usr/bin/env python3
"""Build the VyOS edge golden from the vendor ISO, driven over the serial console.

Why serial and not VGA: the installer is a deterministic prompt sequence, and
a serial socket lets the host read/write exact bytes. Why not answer files:
VyOS has none — but it DOES install the CURRENT live configuration if asked,
so the plan is:

  1. attach the vendor ISO + a tiny ISO carrying `/config/config.boot`
     (rendered by `environment_specs/router_config.render_vyos`);
  2. boot the live image, log in, copy the config into `/config/`;
  3. `install image`, choose that config, install to the target disk;
  4. shut down; the disk now boots as the replica's edge with its REAL
     routes/DNAT/syslog already in config.boot.

Every prompt is matched, never guessed by position: a changed installer
prints its transcript and fails closed. `installed` evidence is the disk's
own grub menu entry read back offline (qemu-nbd), not qemu's exit code.

Run on the appliance as root, ALONE (one heavy build at a time).
"""
from __future__ import annotations

import argparse
import json
import pathlib
import select
import socket
import subprocess
import sys
import tempfile
import time

import pycdlib

MEDIA = pathlib.Path("/var/lib/sparring-range/media")
BUILDS = pathlib.Path("/var/lib/sparring-range/builds")
#: Synthetic lab password; the edge is a guest, not a platform account.
DEFAULT_PASSWORD = "Vyos-Only-1!"


class SerialTimeout(RuntimeError):
    pass


class Console:
    """A QEMU serial socket as an expect-like channel."""

    def __init__(self, path: pathlib.Path, timeout_s: float = 240.0):
        self.path = path
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(str(path))
        self.sock.setblocking(False)
        self.buf = b""
        self.timeout_s = timeout_s
        self.transcript = []

    def send(self, text: str, *, newline: bool = True) -> None:
        data = text.encode() + (b"\r" if newline else b"")
        self.sock.sendall(data)
        self.transcript.append(f"> {text}")

    def expect(self, needles: tuple[str, ...], timeout: float | None = None,
               ) -> str:
        """Wait until ANY needle appears; return the matched needle."""
        deadline = time.monotonic() + (timeout or self.timeout_s)
        while time.monotonic() < deadline:
            for needle in needles:
                pos = self.buf.find(needle.encode())
                if pos >= 0:
                    # CONSUME through the match: a stale prompt left in the
                    # buffer would satisfy the NEXT expect falsely
                    self.buf = self.buf[pos + len(needle):]
                    return needle
            r, _, _ = select.select([self.sock], [], [], 0.5)
            if r:
                try:
                    chunk = self.sock.recv(65536)
                except OSError:
                    chunk = b""
                if chunk:
                    self.buf += chunk
                    self.transcript.append(chunk.decode(errors="replace"))
                    # keep the buffer bounded: prompts are near the tail
                    if len(self.buf) > 1 << 20:
                        self.buf = self.buf[-4096:]
                else:
                    time.sleep(0.2)
            else:
                time.sleep(0.2)
        raise SerialTimeout(f"none of {needles} within {timeout or self.timeout_s}s; "
                            f"tail={self.buf[-600:]!r}")

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


def build_config_iso(config_text: str, path: pathlib.Path) -> pathlib.Path:
    """A tiny ISO carrying the rendered `config.boot`.

    ISO9660 stores names upper-case; Linux's isofs maps them back to lowercase,
    so the live VyOS sees `/mnt/config.boot` (the same trick the Windows
    answer ISO uses for AUTOUNATTEND.XML).
    """
    src = pathlib.Path(str(path) + ".src")
    src.write_text(config_text)
    try:
        iso = pycdlib.PyCdlib()
        iso.new(interchange_level=3, sys_ident="LINUX",
                vol_ident="SRVYOSCONF")
        iso.add_file(str(src), "/CONFIG.BOOT")
        iso.write(str(path))
        iso.close()
    finally:
        src.unlink(missing_ok=True)
    return path


def run_installer(*, iso: pathlib.Path, config_iso: pathlib.Path,
                  disk: pathlib.Path, password: str,
                  password_cmd: str = "install image",
                  monitor: pathlib.Path, serial_log: pathlib.Path,
                  timeout_s: float = 2400.0) -> dict:
    """Boot the live ISO, seed /config, run `install image`, shut down."""
    cmd = [
        "qemu-system-x86_64", "-machine", "pc", "-accel", "kvm",
        "-cpu", "host", "-m", "2048", "-smp", "2",
        "-drive", f"file={disk},format=qcow2,if=virtio",
        "-drive", f"file={iso},media=cdrom,readonly=on,index=0",
        "-drive", f"file={config_iso},media=cdrom,readonly=on,index=1",
        "-nic", "none", "-boot", "order=d",
        "-display", "none", "-vga", "std",
        "-monitor", f"unix:{monitor},server=on,wait=off",
        "-serial", f"unix:{serial_log},server=on,wait=off",
        "-rtc", "base=localtime",
    ]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.STDOUT)
    try:
        # the socket file appears once qemu starts listening
        for _ in range(200):
            try:
                con = Console(serial_log)
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("serial socket never appeared")
        con.expect(("login:"), timeout=300)
        con.send("vyos")
        con.expect(("Password:",), timeout=60)
        con.send("vyos")                     # live-image default
        con.expect(("$", "#"), timeout=60)
        con.send("timedatectl set-timezone UTC >/dev/null 2>&1; echo READY")
        con.expect(("READY",), timeout=60)
        # seed the live configuration with the replica's rendered config
        con.send("sudo mkdir -p /config && "
                 "sudo mount -o ro /dev/sr1 /mnt 2>/dev/null; "
                 "sudo cp /mnt/config.boot /config/config.boot && "
                 "sudo chmod 600 /config/config.boot && echo SEEDED")
        con.expect(("SEEDED",), timeout=120)
        con.send(password_cmd)
        con.expect(("continue?", "y/N"), timeout=120)
        con.send("y")
        con.expect(("name this image",), timeout=60)
        con.send("vyos-replica")
        con.expect(("password",), timeout=60)
        con.send(password)
        matched = con.expect(("again", "console"), timeout=90)
        if matched == "again":
            con.send(password)
            con.expect(("console",), timeout=60)
        con.send("S")                        # serial console
        con.expect(("RAID",), timeout=60)
        con.send("n")
        con.expect(("disk",), timeout=120)
        con.send("")                          # default: the only disk
        con.expect(("config",), timeout=120)
        con.send("1")                         # /config/config.boot (the seed)
        con.expect(("continue", "OK", "sure"), timeout=120)
        con.send("y")
        con.expect(("successful", "complete", "installed", "$"), timeout=1800)
        con.send("poweroff")
        try:
            con.expect(("poweroff", "Power down"), timeout=120)
        except SerialTimeout:
            pass
        con.close()
        proc.wait(timeout=120)
        return {"installed_prompt": True, "rc": proc.returncode}
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()


def disk_boots_linux(disk: pathlib.Path) -> dict:
    """Offline evidence: the disk's own grub entry names a VyOS kernel."""
    found: dict = {"grub_entry": None}
    with tempfile.TemporaryDirectory() as tmp:
        mnt = pathlib.Path(tmp)
        subprocess.run(["modprobe", "nbd"], check=False)
        subprocess.run(["qemu-nbd", "-d", "/dev/nbd0"], check=False,
                       capture_output=True)
        subprocess.run(["qemu-nbd", "-r", "-c", "/dev/nbd0", str(disk)],
                       check=True)
        time.sleep(1)
        try:
            parts = sorted(pathlib.Path("/sys/class/block")
                           .glob("nbd0p*"))
            for part in parts:
                name = "/dev/nbd0" + part.name.replace("nbd0", "")
                subprocess.run(["mount", "-o", "ro", name, str(mnt)],
                               check=False, capture_output=True)
                grub = mnt / "boot" / "grub" / "grub.cfg"
                if not grub.is_file():
                    grub = mnt / "boot" / "grub2" / "grub.cfg"
                if grub.is_file():
                    text = grub.read_text(errors="replace")
                    for line in text.splitlines():
                        if "menuentry" in line:
                            found["grub_entry"] = line.strip()[:200]
                            break
                subprocess.run(["umount", str(mnt)], check=False,
                               capture_output=True)
                if found["grub_entry"]:
                    break
        finally:
            subprocess.run(["qemu-nbd", "-d", "/dev/nbd0"], check=False,
                           capture_output=True)
    return found


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="run_vyos_build")
    ap.add_argument("--iso", default=str(MEDIA / "vyos.iso"))
    ap.add_argument("--config", default=None,
                    help="rendered config.boot (default: render from the "
                         "underpressure blueprint)")
    ap.add_argument("--out-dir", default=str(BUILDS / "vyos"))
    ap.add_argument("--disk-gb", type=int, default=8)
    ap.add_argument("--password", default=DEFAULT_PASSWORD)
    ap.add_argument("--timeout-s", type=float, default=2400.0)
    args = ap.parse_args(argv)

    if args.config:
        config_text = pathlib.Path(args.config).read_text()
    else:
        from srplatform.environment_specs import load_environment
        from srplatform.environment_specs.router_config import render_vyos
        bp = load_environment("underpressure-range").blueprint
        config_text = render_vyos(bp)

    from infra.images.windows_build import qemu_alone_preflight
    qemu_alone_preflight(2048)
    out = pathlib.Path(args.out_dir)
    out.mkdir(parents=True, exist_ok=True)
    disk = out / "vyos.qcow2"
    subprocess.run(["qemu-img", "create", "-f", "qcow2", str(disk),
                    f"{args.disk_gb}G"], check=True)
    config_iso = build_config_iso(config_text, out / "config.iso")
    result = run_installer(
        iso=pathlib.Path(args.iso), config_iso=config_iso, disk=disk,
        password=args.password, monitor=out / "monitor.sock",
        serial_log=out / "serial.sock", timeout_s=args.timeout_s)
    evidence = disk_boots_linux(disk)
    installed = bool(evidence["grub_entry"])
    print(json.dumps({"disk": str(disk), "installed": installed,
                      "evidence": evidence, **result},
                     indent=2, sort_keys=True))
    return 0 if installed else 1


if __name__ == "__main__":
    sys.exit(main())
