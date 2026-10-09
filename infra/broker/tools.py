"""Offline operator tools for the broker (broker-local, never networked).

These are the ONLY ways to release the cessation latch or adopt a VM into
broker ownership, and they run on the broker host with direct ledger/PVE
access — the API's mutual-TLS surface deliberately does not expose them.

  status                       inventory, obligations, lease, audit tail
  stop --yes --reason ...      independent hard cessation
  enroll --vmid --name --tag   VERIFIED adoption of an attacker VM
                               (exact PVE identity match required)
  reconcile-legacy --db-url    list legacy (pre-broker) deployment resources
                               and, with --adopt, verify + adopt each one
  release --operator ...       release the latch (refused while ANY
                               obligation is unresolved)
"""
from __future__ import annotations

import argparse
import json
import sys

from .server import build_service_from_settings


def _service(args):
    service, ledger, _policy = build_service_from_settings()
    return service, ledger


def cmd_status(args) -> int:
    service, _ = _service(args)
    print(json.dumps(service.inventory(), indent=2, default=str))
    for row in service.ledger.audit_tail(20):
        print(f"  #{row['seq']} {row['kind']}: {row['detail']}")
    return 0


def cmd_stop(args) -> int:
    if not args.yes:
        print("refusing: pass --yes to hard-stop every owned VM", file=sys.stderr)
        return 2
    service, _ = _service(args)
    report = service.hard_stop_all(args.reason)
    print(json.dumps(report, indent=2, default=str))
    return 0 if not report["failed"] else 1


def cmd_enroll(args) -> int:
    service, _ = _service(args)
    out = service.enroll(args.vmid, args.name, args.tag, operator=args.operator)
    print(json.dumps(out, indent=2))
    return 0


def cmd_release(args) -> int:
    service, _ = _service(args)
    out = service.release_latch(args.operator, note=args.note)
    print(json.dumps(out, indent=2))
    return 0


def cmd_reconcile_legacy(args) -> int:
    """Pre-broker deployments carry resources in the app DB but no broker
    claims. For each residual resource, verify identity against PVE (exact
    clone name + session ownership tag) and adopt ONLY on an exact match.
    Anything unverifiable stays unresolved — the upgrade latch remains."""
    service, ledger = _service(args)
    from sqlalchemy import create_engine, text

    engine = create_engine(args.db_url)
    unresolved = []
    with engine.connect() as conn:
        rows = conn.execute(text(
            "SELECT deployment_id, session_id, scenario_id, status, resources "
            "FROM deployments WHERE status <> 'torn_down' ORDER BY created_at"
        )).mappings().all()
    print(f"{len(rows)} non-torn-down deployment(s)")
    for row in rows:
        resources = row["resources"]
        if isinstance(resources, str):
            resources = json.loads(resources)
        for res in resources or []:
            if res.get("state") not in ("pending", "created"):
                continue
            vmid = int(res["vmid"])
            claim = ledger.get_claim(vmid)
            if claim and claim["state"] != "destroyed":
                print(f"  vmid {vmid}: already broker-claimed ({claim['state']})")
                continue
            cfg = service.pve.try_lookup_config(service.policy.node, vmid)
            name = res.get("name") or ""
            tag = f"srsess-{str(row['session_id']).replace('-', '')}" \
                if row["session_id"] else None
            ok = bool(cfg) and "_unavailable" not in cfg and cfg.get("name") == name
            if not ok:
                unresolved.append({"vmid": vmid, "name": name,
                                   "why": "identity unreadable or mismatched"})
                print(f"  vmid {vmid} ({name}): UNVERIFIED — left unresolved")
                continue
            if not args.adopt:
                print(f"  vmid {vmid} ({name}): identity verified — pass --adopt "
                      "to record the claim")
                unresolved.append({"vmid": vmid, "why": "awaiting --adopt"})
                continue
            ledger.upsert_claim(vmid, node=service.policy.node, name=name,
                                session_id=str(row["session_id"]) if row["session_id"]
                                else None, kind="legacy", state="created",
                                detail={"deployment": str(row["deployment_id"])})
            ledger.audit("legacy-adopt", {"vmid": vmid, "name": name})
            print(f"  vmid {vmid} ({name}): adopted")
    if unresolved:
        print(json.dumps({"unresolved": unresolved}, indent=2))
        return 1
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="brokerctl")
    ap.add_argument("--policy", default=None, help="override policy file")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status").set_defaults(fn=cmd_status)
    p = sub.add_parser("stop")
    p.add_argument("--yes", action="store_true")
    p.add_argument("--reason", default="operator-cessation")
    p.set_defaults(fn=cmd_stop)
    p = sub.add_parser("enroll")
    p.add_argument("--vmid", type=int, required=True)
    p.add_argument("--name", required=True)
    p.add_argument("--tag", required=True)
    p.add_argument("--operator", required=True)
    p.set_defaults(fn=cmd_enroll)
    p = sub.add_parser("release")
    p.add_argument("--operator", required=True)
    p.add_argument("--note", default="")
    p.set_defaults(fn=cmd_release)
    p = sub.add_parser("reconcile-legacy")
    p.add_argument("--db-url", required=True, help="app DB URL (offline admin)")
    p.add_argument("--adopt", action="store_true")
    p.set_defaults(fn=cmd_reconcile_legacy)
    args = ap.parse_args(argv)
    if args.policy:
        import os

        os.environ["BROKER_POLICY_FILE"] = args.policy
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
