"""Appliance broker daemon entrypoint.

Runs as the separate ``sr-broker`` service account, owns the only libvirt
connection, and serves typed operations over the peer-UID Unix socket. It
loads two independent operator files (manifest + policy), cross-checks them,
and refuses to start rather than serving a half-configured appliance.
"""
from __future__ import annotations

import argparse
import os
import signal
import sys
import threading

from infra.appliance.backend import BackendConfig, LibvirtBackend
from infra.appliance.manifest import ApplianceManifest
from infra.appliance.policy import AppliancePolicy
from infra.appliance.server import make_unix_server
from infra.broker.ledger import Ledger
from infra.broker.service import BrokerService


def build(manifest_path: str, policy_path: str, *, uri: str,
          allow_tcg: bool, fixture: bool):
    manifest = ApplianceManifest.load(manifest_path, verify_images=True,
                                      verify_model_key=False)
    policy = AppliancePolicy.load(policy_path)
    policy.validate_manifest(manifest)
    manifest.ensure_state_dirs()
    os.makedirs(os.path.dirname(manifest.broker_ledger) or ".", exist_ok=True)
    ledger = Ledger(manifest.broker_ledger)
    backend = LibvirtBackend(manifest, policy,
                             BackendConfig(uri=uri, allow_tcg=allow_tcg,
                                           fixture_mode=fixture))
    # Fail before serving if KVM/TCG policy is impossible. The backend also
    # refuses at clone time; this makes the startup failure obvious.
    backend._domain_type()
    service = BrokerService(policy, backend, ledger,
                            agent_ready_timeout_s=180,
                            agent_ready_poll_s=2)
    return manifest, policy, ledger, backend, service


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="sr-appliance-broker")
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--policy", required=True)
    ap.add_argument("--uri", default="qemu:///system",
                    help="libvirt URI (production: qemu:///system; local "
                         "software fixture: qemu:///session)")
    ap.add_argument("--allow-tcg", action="store_true",
                    help="EXPLICIT software-fixture only: permit TCG when KVM "
                         "is absent. Never use for a production acceptance.")
    ap.add_argument("--fixture", action="store_true",
                    help="EXPLICIT software-fixture only: libvirt user-mode "
                         "NIC instead of the isolated bridge")
    ap.add_argument("--allowed-uid", action="append", default=[],
                    help="service account name or numeric UID permitted to "
                         "call the broker (repeatable; production: sr-api only)")
    args = ap.parse_args(argv)

    manifest, policy, ledger, backend, service = build(
        args.manifest, args.policy, uri=args.uri,
        allow_tcg=args.allow_tcg, fixture=args.fixture)
    report = service.startup_reconcile()
    print(f"appliance broker startup reconciliation: {report}", flush=True)
    service.start_watchdog()
    allowed = args.allowed_uid or [os.environ.get("SR_BROKER_ALLOWED_UID", "sr-api")]
    srv = make_unix_server(service, manifest.broker_socket, allowed)
    print(f"appliance broker listening on {manifest.broker_socket} "
          f"(uids {sorted(srv.allowed_uids)})", flush=True)

    def _term(_signum, _frame):
        # shutdown() waits for serve_forever() to return, so it must not run
        # on the serving thread itself.
        threading.Thread(target=srv.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, _term)
    signal.signal(signal.SIGINT, _term)
    try:
        srv.serve_forever()
    finally:
        service.stop_watchdog()
        # A daemon exit must not orphan live guests: if any VM is still
        # claimed, drain it with the latched cessation path before closing
        # the only libvirt connection. (The netrules unit keeps range
        # isolation across stops, so the firewall is not the safety net.)
        drain = service.drain_on_shutdown("broker-daemon-exit")
        if drain is not None:
            print(f"broker shutdown drain: {drain}", flush=True)
        backend.close()
        srv.server_close()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
