#!/usr/bin/env python3
"""Live Windows Server golden build (appliance runner, parameterised).

Runs as root on the appliance (qemu needs /dev/kvm, qemu-nbd needs
/dev/nbd0). Exits nonzero when the artifact is not proven installed
(stage log + marker + qemu-ga.exe on disk).

Examples:
    run_win_build.py --version 2022 --iso win2022.iso --disk-gb 64
    run_win_build.py --version 2019 --iso win2019.iso --disk-gb 80
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

from infra.images.windows_build import build_windows

MEDIA = pathlib.Path("/var/lib/sparring-range/media")
BUILDS = pathlib.Path("/var/lib/sparring-range/builds")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="run_win_build")
    ap.add_argument("--version", required=True, choices=["2019", "2022"])
    ap.add_argument("--iso", required=True)
    ap.add_argument("--disk-gb", type=int, required=True)
    ap.add_argument("--memory-mb", type=int, default=4096)
    ap.add_argument("--smp", type=int, default=2)
    ap.add_argument("--run-dir", default=None)
    ap.add_argument("--timeout-s", type=int, default=5400)
    args = ap.parse_args(argv)
    run_dir = pathlib.Path(args.run_dir) if args.run_dir \
        else BUILDS / f"win{args.version}"
    out = build_windows(
        windows_iso=MEDIA / args.iso,
        virtio_iso=MEDIA / "virtio-win.iso",
        run_dir=run_dir, version=args.version,
        disk_gb=args.disk_gb, memory_mb=args.memory_mb, smp=args.smp,
        kvm=True, install_timeout_s=args.timeout_s)
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0 if out["installed"] else 1


if __name__ == "__main__":
    sys.exit(main())
