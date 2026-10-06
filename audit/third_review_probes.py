"""Safe Windows-compatible reproductions for 0b0d726.

AST-extracted production functions, explicit substitutes at unavailable Linux
boundaries, temporary spool files, and one harmless short Python subprocess.
No infrastructure, signals, real secrets, or firewall mutations.
"""
from __future__ import annotations
import ast
import contextlib
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def extract(path, names, ns):
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
    body = [ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0)]
    body += [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in names]
    exec(compile(ast.fix_missing_locations(ast.Module(body=body, type_ignores=[])), path, "exec"), ns)


results = {}
# Run this checked-in test's exact body; it needs no third-party runtime.
ns = {"REPO": ROOT}
extract("tests/test_stage3_telemetry.py", {"test_unit_and_installer_agree_on_service_identity"}, ns)
try:
    ns["test_unit_and_installer_agree_on_service_identity"]()
    results["checked_in_unit_identity_test"] = "passed"
except AssertionError:
    results["checked_in_unit_identity_test"] = {
        "status": "FAILED", "reason": "unit comment contains DynamicUser, forbidden by exact test assertion"}

# Serial crash-recovery probes: flock is irrelevant to these single-threaded
# scenarios; replace only the Linux lock with a no-op context manager.
ns = {"os": os, "json": json, "re": re, "time": time}
extract("telemetry/shipper.py", {"Spooler"}, ns)
Spooler = ns["Spooler"]
Spooler._lock = lambda self: contextlib.nullcontext()
with tempfile.TemporaryDirectory(prefix="sr-third-review-") as td:
    spool = Spooler(td)
    old_id = spool.append({"event": "already-in-flight"})
    Path(spool.seq_path).write_text("")  # crash after counter truncate, before replacement write
    new_id = spool.append({"event": "never-sent"})
    spool.ack({old_id})
    results["truncated_counter_reuses_id"] = {"old_id": old_id, "new_id": new_id,
        "pending_after_old_ack": spool.pending(), "drops": spool.dropped}
with tempfile.TemporaryDirectory(prefix="sr-third-review-") as td:
    spool = Spooler(td)
    Path(spool.path).write_text('{"interrupted":')
    spool.append({"event": "valid-new-event"})
    results["append_after_torn_tail"] = {"pending": spool.pending(),
        "valid_event_physically_present": "valid-new-event" in Path(spool.path).read_text(),
        "drops": spool.dropped}

# Actual nft validator/normalizer; replace only settings, inventory discovery
# and nft's JSON table response. The rules are otherwise the expected policy.
firewall = types.ModuleType("srplatform.safety.firewall")
firewall._ctrl_addr = lambda s: "10.0.0.1"
firewall._api_port = lambda s: 8000
firewall.validate_port_coverage = lambda s: (True, "explicit inventory substitute")
sys.modules["srplatform.safety.firewall"] = firewall
ns = {"BASELINE_TABLE": "sr_range_baseline"}
extract("srplatform/safety/datapath.py", {"NftDatapath", "_rules_equivalent"}, ns)
nft = object.__new__(ns["NftDatapath"])
nft.s = types.SimpleNamespace(range_cidr="10.66.0.0/24", range_bridge="vmbr1", management_cidr="10.0.0.0/24")
def meta(k): return {"meta": {"key": k}}
def ip(k): return {"payload": {"protocol": "ip", "field": k}}
def match(left, right, op="=="): return {"match": {"left": left, "right": right, "op": op}}
def rule(*expr): return {"expr": list(expr)}
ct = {"ct": {"key": "state"}}
mgmt = {"prefix": {"addr": "10.0.0.0", "len": 24}}
rules = [
    rule(match(meta("iifname"), "vmbr1", "!="), {"return": None}),
    rule(match(ct, [2, 4]), match(ip("daddr"), mgmt), match(meta("iifname"), "vmbr1"), {"accept": None}),
    rule(match(ct, [2, 4]), match(ip("daddr"), "10.0.0.1"), match(meta("iifname"), "vmbr1"), {"accept": None}),
    rule(match(ip("saddr"), "@range_hosts"), match(ip("daddr"), "@range_hosts"), {"accept": None}),
    rule(match(ip("protocol"), 6), match(ip("daddr"), "10.0.0.1"), match({"payload": {"protocol": "tcp", "field": "dport"}}, 8000), match(ct, 8), {"accept": None}),
    rule(match(ip("protocol"), 6), match(ip("saddr"), mgmt), match(ip("daddr"), "@range_hosts"), match({"payload": {"protocol": "tcp", "field": "dport"}}, 22), match(ct, 8), {"accept": None}),
    rule(match(meta("nfproto"), 2), {"drop": None}),
    rule(match(meta("nfproto"), 10), {"drop": None}),
]
table = {"family": "inet", "name": "sr_range_baseline", "chains": [{"name": "range_forward",
    "hooks": [{"hook": "forward", "family": "inet", "prio": 0, "policy": "accept"}], "rule": rules}],
    "sets": [{"name": "range_hosts", "type": "ipv4_addr", "flags": ["interval"],
              "elem": [{"prefix": {"addr": "10.66.0.0", "len": 24}}]}]}
nft._json_table = lambda name: table
results["expected_baseline_control"] = nft.baseline_status()
rules.insert(0, rule(match(meta("nfproto"), 2), {"accept": None}))
results["extra_ipv4_allow_accepted"] = nft.baseline_status()
rules.pop(0)
table["sets"][0]["elem"].append({"prefix": {"addr": "0.0.0.0", "len": 1}})
results["widened_range_set_accepted"] = nft.baseline_status()

# Production readiness still takes the purported dev relaxation branch.
loader = types.ModuleType("srplatform.scenario_engine.loader")
loader.SUPPORTED_SERVICES = {"http": "apache2"}
sys.modules["srplatform.scenario_engine.loader"] = loader
ns = {"scenario_spec": lambda db, sid: {"topology": {"hosts": [{"name": "web01", "services": ["http"]}]}},
      "host_map_for": lambda db, sid: {"web01": "10.66.0.10"}, "_exec_override": None,
      "_ssh_exec": lambda *args: None,
      "get_settings": lambda: types.SimpleNamespace(sr_env="production", verifier_ssh_key_path="", verifier_ssh_known_hosts="configured-but-missing")}
extract("srplatform/verification_service.py", {"readiness_checks"}, ns)
results["production_readiness_without_management_key"] = ns["readiness_checks"](None, "session")

# select() on Windows cannot poll pipe handles. Substitute readiness only;
# keep the REAL Popen text pipe and production .read(4096) behavior. The child
# writes one byte then holds the pipe open briefly, with no further output.
ns = {}
extract("srplatform/red_agent/runner.py", {"_bounded_reader"}, ns)
select_original = sys.modules.get("select")
select_adapter = types.ModuleType("select")
select_adapter.select = lambda read, write, err, timeout: (read, [], [])
sys.modules["select"] = select_adapter
proc = subprocess.Popen([sys.executable, "-c", "import sys,time; sys.stdout.write('x'); sys.stdout.flush(); time.sleep(0.5)"], stdout=subprocess.PIPE, text=True)
started = time.monotonic()
try:
    try:
        ns["_bounded_reader"](proc, 100, deadline=started + 0.05)
    except TimeoutError:
        pass
    results["reader_deadline_overrun"] = {"deadline_seconds": 0.05,
        "elapsed_seconds": round(time.monotonic() - started, 3),
        "readiness_boundary": "adapter for Windows pipe; actual blocking TextIOWrapper read"}
finally:
    proc.wait(timeout=3)
    proc.stdout.close()
    if select_original is not None:
        sys.modules["select"] = select_original
    else:
        del sys.modules["select"]

print(json.dumps(results, indent=2))
