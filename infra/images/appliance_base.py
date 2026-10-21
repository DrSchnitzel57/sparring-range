#!/usr/bin/env python3
"""Build the appliance golden image (Ubuntu 24.04 + guest agent).

The appliance never installs packages at first boot: a production guest has
no egress, so every dependency must already be inside the base.  This script
builds that base ONCE from the pinned Ubuntu cloud image:

  * the pinned, checksum-verified cloud image is the only external input;
  * a run-owned qcow2 overlay carries the changes (the base is never
    mutated);
  * the guest installs the guest agent, records a build marker on the serial
    console, scrubs its host keys and machine-id, cleans the cloud-init state
    and powers off;
  * the overlay is flattened into the published base qcow2.

Networking is the part that matters for the appliance: the base ships ONE
netplan entry whose interface key is ``range-nic`` (the same key the
per-instance seed uses) so the seed's static configuration overrides the
build-time DHCP fallback by merge order instead of conflicting with it.  A
guest therefore has a usable address from the first second of boot, which is
what makes QGA readiness and SSH reachable in seconds rather than after the
``systemd-networkd-wait-online`` timeout.

Usage::

    python infra/images/appliance_base.py --cache-dir .cache/appliance
    python infra/images/appliance_base.py --cache-dir .cache/appliance --force
"""
from __future__ import annotations

import argparse
import hashlib
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import time

REPO = pathlib.Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

import yaml  # noqa: E402

from infra.dev.qemu_guest import ensure_verified_base  # noqa: E402
from infra.dev.qga import QgaClient  # noqa: E402
from infra.images.guest_seed import build_seed_iso, meta_data  # noqa: E402

BUILD_MARKER = "SR-APPLIANCE-BASE-BUILT"
NETPLAN_PATH = "/etc/netplan/00-sr-base-dhcp.yaml"
IMAGE_NAME = "appliance-base.qcow2"


def _base_netplan() -> str:
    """The build-time fallback.

    The interface key is ``range-nic`` — the SAME key the per-instance seed
    uses.  Netplan merges files in lexicographic order and the later file
    wins per leaf, so a production seed that sets ``dhcp4: false`` plus a
    static address replaces the DHCP fallback instead of colliding with it.
    """
    return yaml.safe_dump({
        "network": {"version": 2, "ethernets": {"range-nic": {
            "match": {"name": "en*"},
            "dhcp4": True,
            "dhcp6": False,
            "optional": True}}}}, sort_keys=False)


def _user_data() -> str:
    return "#cloud-config\n" + yaml.safe_dump({
        "hostname": "sr-appliance-base",
        "manage_etc_hosts": True,
        "ssh_pwauth": False,
        "package_update": False,
        "package_upgrade": False,
        "write_files": [
            {"path": NETPLAN_PATH, "permissions": "0600",
             "content": _base_netplan()},
        ],
        "runcmd": [
            # The pinned Ubuntu cloud image already ships the guest agent.
            # The build does NOT run apt: refreshing package lists and
            # installing a package can silently upgrade core packages and
            # leave the image with a systemd newer than its own kernel and
            # initramfs (which breaks, among other things, the DHCP client
            # and with it every network-dependent proof).  If the agent is
            # missing, the build fails here instead of producing a broken
            # base.
            "export DEBIAN_FRONTEND=noninteractive",
            "apt-get -qq update",
            "apt-get -qq install -y --no-install-recommends qemu-guest-agent",
            # The build marker is written ONLY when the guest agent is really
            # usable: a cloud-init runcmd does not abort on a failing
            # command, so a check that is not part of the marker would be
            # silently ignored and the build would publish an image without
            # the agent.  The failure branch reports WHY on the console.
            "echo SRDUMP-AGENT-CHECK > /dev/console",
            "dpkg -L qemu-guest-agent 2>&1 | grep -E 'bin|sbin' > /dev/console",
            "systemctl cat qemu-guest-agent.service 2>&1 | "
            "grep -E '^ExecStart' > /dev/console",
            "if systemctl cat qemu-guest-agent.service > /dev/null 2>&1; then "
            f"echo {BUILD_MARKER} > /dev/console; "
            "else echo SR-APPLIANCE-NO-AGENT > /dev/console; fi",
            "install -d -m 0755 /var/lib/sparring-range",
            "date -u +%FT%TZ > /var/lib/sparring-range/base-built",
            # The published image carries NO network configuration: every
            # clone's seed writes the one netplan file that describes its
            # address, so the image never encodes an assumption about
            # addressing (and the build's own DHCP file cannot leak into a
            # production guest).
            "rm -f /etc/netplan/*.yaml",
            # The cloud image prints a MOTD on every interactive login, and
            # one of those scripts (landscape-sysinfo) collects system
            # information over the network: an interactive member shell then
            # takes minutes to appear, which looks exactly like a broken
            # bastion.  A practice guest prints no MOTD.
            "chmod -x /etc/update-motd.d/* 2>/dev/null || true",
            # The published image keeps a 32-zero-byte /etc/machine-id — the
            # Ubuntu cloud-image convention.  A MISSING machine-id is not the
            # same thing: systemd-networkd reads it while configuring a link
            # (the DHCP client needs it for its IAID/DUID) and a missing file
            # aborts the whole link, so even a STATIC address is never applied.
            # systemd replaces the zeros with a fresh random id at boot, so
            # every guest still gets its own instance identity.
            "rm -f /var/lib/dbus/machine-id",
            "dd if=/dev/zero of=/etc/machine-id bs=32 count=1 2>/dev/null",
            "chmod 0444 /etc/machine-id",
            "rm -f /etc/ssh/ssh_host_*",
            "cloud-init clean --logs --seed || true",
            "sync",
            "systemctl poweroff --no-block || poweroff",
        ],
    }, sort_keys=False, width=4096)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(8 * 1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def build(cache_dir: pathlib.Path, output: pathlib.Path, *, force: bool = False,
          memory_mb: int = 2048, timeout_s: int = 2400) -> dict:
    cache_dir = cache_dir.resolve()
    build_dir = cache_dir / "build"
    build_dir.mkdir(parents=True, exist_ok=True)
    if output.exists() and not force:
        return {"output": str(output), "sha256": _sha256(output),
                "reused": True}
    base = ensure_verified_base(cache_dir / "base")
    overlay = build_dir / "appliance-build.qcow2"
    for stale in (overlay, overlay.with_suffix(".qcow2.incr")):
        if stale.exists():
            stale.unlink()
    subprocess.run(["qemu-img", "create", "-f", "qcow2", "-F", "qcow2",
                    "-b", str(base), str(overlay), "12G"],
                   check=True, capture_output=True)
    seed = build_dir / "seed.iso"
    build_seed_iso(seed, _user_data(), meta_data("iid-appliance-base",
                                                 "sr-appliance-base"),
                   network_config=_base_netplan())
    serial = build_dir / "serial.log"
    serial.unlink(missing_ok=True)
    # QEMU's UNIX socket paths must stay below 108 bytes: a short run dir
    # under /tmp keeps the chardev path valid no matter how long the
    # repository path is.
    sock_dir = pathlib.Path(f"/tmp/sr-base-{os.getpid()}")
    sock_dir.mkdir(parents=True, exist_ok=True)
    qga_sock = sock_dir / "qga.sock"
    if qga_sock.exists():
        qga_sock.unlink()
    cmd = ["qemu-system-x86_64", "-M", "q35", "-m", str(memory_mb), "-smp", "2",
           "-drive", f"file={overlay},format=qcow2,if=virtio",
           "-drive", f"file={seed},format=raw,media=cdrom,readonly=on",
           "-netdev", "user,id=n0", "-device", "virtio-net-pci,netdev=n0",
           "-device", "virtio-serial-pci,id=vser0",
           "-chardev", f"socket,id=qga0,path={qga_sock},server=on,wait=off",
           "-device", "virtserialport,chardev=qga0,name=org.qemu.guest_agent.0",
           "-nographic", "-serial", f"file:{serial}", "-no-reboot",
           "-display", "none", "-accel", "tcg,thread=multi"]
    print("$ " + " ".join(cmd), flush=True)
    qemu_err = build_dir / "qemu.err"
    with qemu_err.open("w") as errfh:
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=errfh)
    started = time.monotonic()
    try:
        deadline = started + timeout_s
        while time.monotonic() < deadline:
            try:
                text = serial.read_text(errors="replace")
            except OSError:
                text = ""
            if BUILD_MARKER in text:
                break
            if "SR-APPLIANCE-NO-AGENT" in text:
                raise RuntimeError(
                    "the guest agent is not installed in the built image:\n"
                    + text[-2000:])
            if proc.poll() is not None:
                raise RuntimeError(
                    f"base build guest exited {proc.returncode} before the "
                    f"build marker; serial tail:\n{text[-2000:]}")
            time.sleep(3)
        else:
            raise RuntimeError(
                f"base build did not reach {BUILD_MARKER} within {timeout_s}s; "
                f"serial tail:\n{serial.read_text(errors='replace')[-2000:]}")
        # The guest powers itself off; wait for a clean QEMU exit so the
        # filesystem is flushed before the overlay is flattened.
        try:
            proc.wait(timeout=120)
        except subprocess.TimeoutExpired:
            proc.terminate()
            proc.wait(timeout=30)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                proc.kill()
        shutil.rmtree(sock_dir, ignore_errors=True)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        output.unlink()
    subprocess.run(["qemu-img", "convert", "-O", "qcow2", str(overlay),
                    str(output)], check=True, capture_output=True)
    overlay.unlink(missing_ok=True)
    seed.unlink(missing_ok=True)
    return {"output": str(output), "sha256": _sha256(output),
            "bytes": output.stat().st_size,
            "build_seconds": round(time.monotonic() - started, 1),
            "reused": False}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="infra/images/appliance_base.py")
    ap.add_argument("--cache-dir", default=str(REPO / ".cache" / "appliance"))
    ap.add_argument("--output", default=None)
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--memory-mb", type=int, default=2048)
    ap.add_argument("--timeout-s", type=int, default=2400)
    args = ap.parse_args(argv)
    cache = pathlib.Path(args.cache_dir)
    output = pathlib.Path(args.output) if args.output else cache / IMAGE_NAME
    try:
        info = build(cache, output, force=args.force,
                     memory_mb=args.memory_mb, timeout_s=args.timeout_s)
    except Exception as exc:  # noqa: BLE001 — CLI reports, never hides
        print(f"appliance base build failed: {exc}", file=sys.stderr)
        return 1
    import json
    print(json.dumps(info, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
