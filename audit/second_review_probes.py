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
    r = spool.append({"pad": "x" * 500})
    results["oversize_first_spool_record"] = {"limit": 100, "accepted": r is not None,
                                              "actual": Path(spool.path).stat().st_size
                                              if Path(spool.path).exists() else 0,
                                              "dropped_visible": spool.dropped}

with tempfile.TemporaryDirectory(prefix="sr-review-") as td:
    spool = Spooler(td)
    a = spool.append({"id": "acknowledged-old-event"})
    spool.append({"id": "new-event-sent"})
    pend = spool.pending()               # delivery reads...
    c = spool.append({"id": "new-event-not-sent"})   # ...append in flight
    spool.ack({i for i, _ in pend})      # ack exactly the sent ids (stable ids)
    ids = [e["id"] for _, e in spool.pending()]
    results["append_during_delivery_remove"] = {"pending": ids, "dropped": spool.dropped,
                                                "unsent_new_event_lost": "new-event-not-sent" not in ids}

# --- safety state reconciliation (N07) — REAL Supervisor boundary -----------
from srplatform.safety import Supervisor
from tests.helpers import FakeDatapath  # non-noop mechanism double

with tempfile.TemporaryDirectory(prefix="sr-review-") as td:
    sup = Supervisor(datapath=FakeDatapath(), state_file=f"{td}/s.json")
    sup._db_read_state = lambda: (None, "simulated DB outage")
    # Missing file + unreadable DB: post-fix this is LOST state -> latched.
    results["missing_file_and_unreadable_db"] = sup.latch_status()

    # No evidence anywhere -> latched until documented initialization.
    sup2 = Supervisor(datapath=FakeDatapath(), state_file=f"{td}/s2.json")
    sup2._db_read_state = lambda: (None, None)
    results["no_evidence_anywhere"] = sup2.latch_status()["latched"]
    sup2.initialize_state(reason="probe")
    results["no_evidence_after_init"] = sup2.latch_status()["latched"]

    # Stale DB cannot outrank a newer file-mirror record.
    import time as _t
    from srplatform.safety.datapath import config_identity as _ci
    sup3 = Supervisor(datapath=FakeDatapath(), state_file=f"{td}/s3.json")
    now = _t.time()
    ident = _ci(sup3.settings)
    sup3._records_reader = lambda: [{"kind": "engage", "ok": True,
                                     "config_identity": ident, "recorded_at": now - 100}]
    Path(f"{td}/s3.json.records").write_text(json.dumps(
        {"kind": "release", "ok": True, "config_identity": ident,
         "recorded_at": now}) + "\n")
    results["stale_db_outranks_file"] = sup3._latest_records()["release"]["recorded_at"] == now

    # Record persistence failure is retained and denies starts.
    sup4 = Supervisor(datapath=FakeDatapath(), state_file=f"{td}/nodir/s4.json")
    sup4._db_read_state = lambda: ({"latched": False, "latched_at": None, "reason": None}, None)
    import srplatform.db.session as _dbs

    class _Boom:
        def __enter__(self):
            raise RuntimeError("db down")

        def __exit__(self, *a):
            return False

    _orig_db = _dbs.db
    _dbs.db = lambda: _Boom()
    try:
        sup4.record("baseline_check", True, {})
    finally:
        _dbs.db = _orig_db
    results["record_persistence_failure_retained"] = bool(sup4._record_failures)

# --- datapath verification (N06) — REAL NftDatapath boundary -----------------
from srplatform.safety import datapath as _dp
from srplatform.safety import firewall as _fw
from srplatform.settings import Settings as _S

settings = _S(sr_env="dev", range_bridge="vmbr1", range_bridge_ports="tap1",
              api_base_url="http://10.0.0.1:8000")
before = _dp.config_identity(settings)
alt = settings.model_copy(update={"range_bridge_ports": "tap2",
                                  "api_base_url": "http://10.0.0.2:9999"})
results["network_change_keeps_proof_identity"] = before == _dp.config_identity(alt)

# No forward hook: rules in an ordinary unreferenced chain do not filter.
nft = _dp.NftDatapath(settings)
_unhooked = {"nftables": [{"table": {"family": "inet", "name": "sr_range_baseline"}},
                          {"chain": {"family": "inet", "table": "sr_range_baseline",
                                     "name": "range_forward", "handle": 2}}]}
nft._run_nft = lambda args: (0, json.dumps(_unhooked)) if "-j" in args else (0, "x")
results["unhooked_baseline_accepted"] = nft.baseline_status()["ok"]

# Missing port declarations: post-fix apply REFUSES full success.
nft2 = _dp.NftDatapath(settings.model_copy(update={"range_bridge_ports": ""}))
nft2._run_nft_stdin = lambda ruleset: (0, "")
nft2._run_nft = lambda args: (0, "")
results["missing_bridge_ports_apply"] = {"ok": nft2.apply_emergency()["ok"]}

# Blanket established accept / wrong reply direction (N06 item 4):
base_rules = _fw.render_baseline_ruleset(settings)
results["reply_rules_destination_scoped"] = (
    'ct state established,related ip daddr 10.0.0.0/24 iifname "vmbr1" accept' in base_rules
    and "ip saddr { 10.0.0.0/24 } ct state established" not in base_rules
    and "ip protocol ip" not in base_rules)

# Production worker (N04): role-scoped validation — the worker starts with
# ONLY api/model/runner config; controller secrets stay controller-side.
from srplatform.settings import Settings as _PS, validate_production as _vp
worker_settings = _PS(sr_env="production", runner_transport="ssh",
                      runner_ssh_target="runner@test",
                      runner_ssh_known_hosts="test-known-hosts",
                      llm_base_url="http://llm:8001/v1", llm_model_red="m",
                      api_base_url="http://api:8000")
try:
    _vp(worker_settings, role="worker")
    results["production_worker_validation"] = "accepted (worker role, least privilege)"
except RuntimeError as exc:
    results["production_worker_validation"] = str(exc)
try:
    _vp(worker_settings, role="controller")
    results["production_controller_still_gated"] = "accepted (WRONG: controller ungated)"
except RuntimeError:
    results["production_controller_still_gated"] = "rejected controller secrets absent (correct)"

# --- runner supervision (N05) — REAL runner boundary -------------------------
from srplatform.red_agent import runner as _rn

_op = _rn._new_op_id()


class _DeadRemote:
    def cancel_remote(self, op_id, timeout_s=10):
        return False


_rn._register(_op, {"kind": "remote", "state": "running", "remote": True,
                    "runner": _DeadRemote(), "proc": None})
_cancel = _rn.cancel_active()
results["cancel_unconfirmed_never_silent"] = {
    "reported_ok": _cancel["ok"], "cancelled": _cancel["ops"][0]["cancelled"],
    "still_tracked": _op in _rn._ACTIVE}
_rn._finish_op(_op)

# Bounded streaming: the reader caps output at the configured maximum.
import inspect as _inspect
results["runner_output_bound_streamed"] = (
    "_bounded_reader" in _inspect.getsource(_rn)
    and "communicate" not in _inspect.getsource(_rn.LocalDevRunner.run))

print(json.dumps(results, indent=2))
