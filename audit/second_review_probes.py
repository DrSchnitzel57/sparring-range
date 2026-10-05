"""Safe, stdlib-only probes for review of 18377c6.

No signals, network requests, nft changes, VM operations, or real credentials.
AST extraction runs checked-in functions with explicit boundary doubles.
Spool tests use only disposable temporary directories.
"""
from __future__ import annotations

import ast
import hashlib
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def extract(path, names, namespace):
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
    body = [ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0)]
    body += [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in names]
    exec(compile(ast.fix_missing_locations(ast.Module(body=body, type_ignores=[])), path, "exec"), namespace)


results = {}

# A config-read timeout is incorrectly positive authorization to delete.
# (Stage 1 update: exercised through the REAL adapter boundary so the probe
# remains meaningful against the typed-lookup contract; historical pre-fix
# output is preserved in audit/second-review-results.json and
# audit/second-review-results-before-fix.json.)
from infra.proxmox_client import ProxmoxClient as _PC

ns = {"get_settings": lambda: SimpleNamespace(proxmox_node="test")}
extract("srplatform/scenario_engine/orchestrator.py", {"_ownership_tag", "_verify_ownership"}, ns)


def unavailable(*args, **kwargs):
    raise TimeoutError("simulated management outage")


_pve_ro = object.__new__(_PC)
_pve_ro.api = SimpleNamespace(get=unavailable)
_pve_ro.task_timeout = 1
try:
    results["ownership_on_read_timeout"] = list(ns["_verify_ownership"](
        _pve_ro, {"vmid": 200, "node": "test", "name": "owned"}, "session"))
except Exception as exc:  # post-fix: uncertain reads RAISE, never authorize
    results["ownership_on_read_timeout"] = f"raised {type(exc).__name__}: {exc}"

# Actual adapter treats an outage as successful no-op destruction.
pve = object.__new__(_PC)
pve.api = SimpleNamespace(get=unavailable)
pve.task_timeout = 1
try:
    results["destroy_on_status_timeout"] = {"returned": pve.destroy_and_wait("test", 200),
                                            "raised": False}
except Exception as exc:  # post-fix: raises instead of silently returning
    results["destroy_on_status_timeout"] = {"returned": None,
                                            "raised": f"{type(exc).__name__}: {exc}"}

# Direct stdlib shipper import; interleave two real-format event groups.
from telemetry.shipper import Spooler, build_command_event, group_event_records

lines = [
    'type=SYSCALL msg=audit(1700000000.1:1): uid=1000 comm="id" exe="/usr/bin/id"',
    'type=SYSCALL msg=audit(1700000000.2:2): uid=1001 comm="whoami" exe="/usr/bin/whoami"',
    'type=EXECVE msg=audit(1700000000.1:1): argc=1 a0="id"',
    'type=EXECVE msg=audit(1700000000.2:2): argc=1 a0="whoami"',
    'type=EOE msg=audit(1700000000.1:1):',
    'type=EOE msg=audit(1700000000.2:2):',
]
events = [build_command_event("host", g, "machine", "boot") for g in group_event_records(lines)]
results["interleaved_audit_commands"] = [e for e in events if e]

with tempfile.TemporaryDirectory(prefix="sr-review-") as td:
    spool = Spooler(td, max_bytes=100)
    spool.append({"pad": "x" * 500})
    results["oversize_first_spool_record"] = {"limit": 100, "actual": Path(spool.path).stat().st_size,
                                               "dropped": spool.dropped}

with tempfile.TemporaryDirectory(prefix="sr-review-") as td:
    spool = Spooler(td)
    spool.append({"id": "acknowledged-old-event"})
    write = spool._atomic_write_lines

    def append_between_read_and_replace(lines):
        # Deterministic scheduling of main-thread append after delivery's read
        # and before its replace. This is a valid production interleaving.
        spool.append({"id": "new-event-not-sent"})
        write(lines)

    spool._atomic_write_lines = append_between_read_and_replace
    spool.remove({0})
    results["append_during_delivery_remove"] = {"pending": spool.pending(), "dropped": spool.dropped,
                                                 "unsent_new_event_lost": not spool.pending()}

# Missing file is treated as a healthy fresh store even if DB is unreadable.
ns = {}
extract("srplatform/safety/__init__.py", {"Supervisor"}, ns)
sup = object.__new__(ns["Supervisor"])
sup._read_state = lambda: ({}, None)
sup._db_read_state = lambda: (None, "simulated DB outage")
results["missing_file_and_unreadable_db"] = sup.latch_status()

ns = {"hashlib": hashlib, "json": json, "BASELINE_TABLE": "sr_range_baseline",
      "EMERGENCY_TABLE": "sr_emergency"}
extract("srplatform/safety/datapath.py", {"config_identity", "NftDatapath"}, ns)
settings = SimpleNamespace(range_bridge="vmbr1", range_vlan=66, range_cidr="10.66.0.0/24",
                           management_cidr="10.0.0.0/24", bastion_address="10.66.0.2",
                           proxmox_node="test", range_bridge_ports="tap1", api_base_url="http://10.0.0.1:8000")
before = ns["config_identity"](settings)
settings.range_bridge_ports = "tap2"
settings.api_base_url = "http://10.0.0.2:9999"
results["network_change_keeps_proof_identity"] = before == ns["config_identity"](settings)
nft = object.__new__(ns["NftDatapath"])
nft.s = settings
# No forward hook: rules in an ordinary unreferenced chain do not filter.
nft.list_table = lambda table: '''table inet sr_range_baseline {
 chain range_forward {
  meta nfproto ipv4 drop
  meta nfproto ipv6 drop
  ip saddr @range_hosts ip daddr @range_hosts accept
 }
}'''
results["unhooked_baseline_accepted"] = nft.baseline_status()
settings.range_bridge_ports = ""
nft.table_exists = lambda table: False
nft.render_emergency = lambda **kwargs: "stubbed nft transaction"
nft._run_nft_stdin = lambda ruleset: (0, "")
results["missing_bridge_ports_apply"] = nft.apply_emergency()

# Production worker gets runner settings, but the shared validator demands
# the controller-only settings that _worker_env intentionally strips.
ns = {}
extract("srplatform/settings.py", {"validate_production"}, ns)
worker_settings = SimpleNamespace(
    proxmox_token_id="", proxmox_token_secret="", proxmox_insecure_lab_override=False,
    proxmox_tls_ca_file="", runner_transport="ssh", runner_ssh_target="runner@test",
    runner_ssh_known_hosts="test-known-hosts", postgres_url="default-app-url",
    postgres_url_owner="default-owner-url", bastion_targets_known_hosts="")
try:
    ns["validate_production"](worker_settings)
    results["production_worker_validation"] = "accepted"
except RuntimeError as exc:
    results["production_worker_validation"] = str(exc)

print(json.dumps(results, indent=2))
