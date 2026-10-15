#!/usr/bin/env python3
"""Broker policy-file generator (pilot step 7 — operator handoff).

The broker refuses to start without a valid, closed policy (fail-closed).
This generator turns the operator's OWN network facts (PVE node, bridge,
VLAN, range CIDR, template VMIDs, storage, VMID range, aggregate limits)
into that file and VALIDATES it through the broker's own policy loader
before writing — an invalid policy never reaches the broker.

Usage (on the broker VM):
    python deploy/gen_broker_policy.py \\
        --node pve-node-1 --bridge vmbr-range --vlan 66 \\
        --cidr 10.66.0.0/24 --gateway 10.66.0.1 \\
        --templates 9005,9011 --vmid-range 9100-9199 --storage local-zfs \\
        --out /etc/sparring-range/broker-policy.json

Nothing here chooses the operator's network — it only encodes and checks
what the operator provides. The generated file contains no credentials.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from infra.broker.policy import BrokerPolicy  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--node", required=True, help="exact PVE node name")
    ap.add_argument("--bridge", required=True, help="range bridge name (e.g. vmbr-range)")
    ap.add_argument("--vlan", required=True, type=int)
    ap.add_argument("--cidr", required=True, help="range network CIDR, e.g. 10.66.0.0/24")
    ap.add_argument("--gateway", required=True, help="range gateway IP inside the CIDR")
    ap.add_argument("--templates", required=True,
                    help="comma-separated TEMPLATE vmids the broker may clone (e.g. 9005,9011)")
    ap.add_argument("--vmid-range", required=True, help="allocatable range, e.g. 9100-9199")
    ap.add_argument("--storage", required=True, help="comma-separated storage ids")
    ap.add_argument("--clone-mode", default="full", choices=("linked", "full"))
    ap.add_argument("--max-vms", type=int, default=3)
    ap.add_argument("--cores-per-vm", type=int, default=2)
    ap.add_argument("--memory-mb-per-vm", type=int, default=2048)
    ap.add_argument("--disk-gb-per-vm", type=int, default=16)
    # Exact aggregate ceilings override the multiplied defaults: the
    # manifest's approved budgets are authoritative — the generator must
    # never silently raise them (e.g. 3x16=48 over an approved 44).
    ap.add_argument("--max-total-cores", type=int, default=None)
    ap.add_argument("--max-total-memory-mb", type=int, default=None)
    ap.add_argument("--max-total-disk-gb", type=int, default=None)
    ap.add_argument("--name-prefix", default="sr-")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    lo, _, hi = args.vmid_range.partition("-")
    policy = {
        "node": args.node,
        "templates": [int(t) for t in args.templates.split(",") if t.strip()],
        "vmid_range": [int(lo), int(hi)],
        "storage": [s for s in args.storage.split(",") if s.strip()],
        "clone_mode": args.clone_mode,
        "nic": {"bridge": args.bridge, "vlan": args.vlan},
        "provision": {"cidr": args.cidr, "gateway": args.gateway},
        "limits": {
            "max_vms": args.max_vms,
            "cores_per_vm": args.cores_per_vm,
            "memory_mb_per_vm": args.memory_mb_per_vm,
            "disk_gb_per_vm": args.disk_gb_per_vm,
            "max_total_cores": (args.max_total_cores
                                  if args.max_total_cores is not None
                                  else args.max_vms * args.cores_per_vm),
            "max_total_memory_mb": (args.max_total_memory_mb
                                    if args.max_total_memory_mb is not None
                                    else args.max_vms * args.memory_mb_per_vm),
            "max_total_disk_gb": (args.max_total_disk_gb
                                  if args.max_total_disk_gb is not None
                                  else args.max_vms * args.disk_gb_per_vm),
        },
        "name_prefix": args.name_prefix,
    }
    # THE broker's own loader is the only judge: validate before writing.
    BrokerPolicy.from_dict(policy, source="generated")
    out = pathlib.Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n")
    out.chmod(0o640)
    print(f"broker policy validated and written: {out}")
    print("  templates:", policy["templates"], "vmids:", policy["vmid_range"],
          "network:", args.cidr, "vlan:", args.vlan)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
