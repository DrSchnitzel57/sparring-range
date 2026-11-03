#!/usr/bin/env python3
"""Live Windows Server 2022 golden build (appliance runner).

Versioned so a rebuild is reproducible instead of an ad-hoc /opt script.
Runs as root on the appliance: qemu + qemu-nbd need /dev/kvm and /dev/nbd0.
Exits nonzero when the artifact is not proven installed (marker + qemu-ga).
"""
from __future__ import annotations

import json
import pathlib
import sys

from infra.images.windows_build import build_windows


def main() -> int:
    media = pathlib.Path("/var/lib/sparring-range/media")
    out = build_windows(
        windows_iso=media / "win2022.iso",
        virtio_iso=media / "virtio-win.iso",
        run_dir=pathlib.Path("/var/lib/sparring-range/builds/win2022"),
        version="2022",
        # Blueprint ad-dns resources: 2 vcpu / 4096 MB / 64 GiB.
        disk_gb=64, memory_mb=4096, smp=2, kvm=True,
        install_timeout_s=5400)
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0 if out["installed"] else 1


if __name__ == "__main__":
    sys.exit(main())
