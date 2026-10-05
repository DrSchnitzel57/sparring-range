"""Safe, dependency-light regression probes for bd93f0d. No network or signals.

AST extraction runs selected checked-in functions with explicit test doubles;
this is not a replacement for production-path integration tests.
"""
import ast
import json
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True
results = {}


def extract(path, names, namespace):
    tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
    nodes = [n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.ClassDef)) and n.name in names]
    unit = ast.Module(body=[ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0)] + nodes, type_ignores=[])
    exec(compile(ast.fix_missing_locations(unit), path, "exec"), namespace)


# Auth lookup: POST-FIX, _principal_from_token resolves the run-scoped
# credential (sha256 on Run) as a session-bound runner capability, and revokes
# it once the run is inactive. Probe both states with explicit stubs.
class HTTPError(Exception):
    def __init__(self, status, detail):
        self.status, self.detail = status, detail


import hashlib as _hashlib


class _Scalars:
    def __init__(self, row):
        self._row = row

    def first(self):
        return self._row


class _Result:
    def __init__(self, row):
        self._row = row

    def scalars(self):
        return _Scalars(self._row)


def _make_auth_db(run_row):
    return SimpleNamespace(get=lambda table, token: None,
                           execute=lambda q: _Result(run_row))


class _SelectStub:
    def __init__(self, model):
        pass

    def where(self, *a):
        return self


class _AnyAttr:
    def __getattr__(self, _name):
        return _AnyAttr()

    def __eq__(self, _other):
        return self

    def __hash__(self):
        return 0


auth_ns = {"HTTPException": HTTPError, "WebToken": object(), "ServiceToken": object(),
           "User": object(), "Principal": SimpleNamespace, "Run": _AnyAttr(),
           "hashlib": _hashlib, "select": _SelectStub}
extract("srplatform/api/auth.py", {"_principal_from_token"}, auth_ns)
TOKEN = "run-scoped-token"
ACTIVE_RUN = SimpleNamespace(status="running", session_id="sess-1",
                             worker_token=_hashlib.sha256(TOKEN.encode()).hexdigest())
CANCELLED_RUN = SimpleNamespace(status="cancelled", session_id="sess-1",
                                worker_token=ACTIVE_RUN.worker_token)
try:
    p = auth_ns["_principal_from_token"](_make_auth_db(ACTIVE_RUN), TOKEN)
    results["worker_bearer_auth"] = {"status": "accepted", "scope": p.scope,
                                     "session_bound": p.session_id}
except HTTPError as exc:
    results["worker_bearer_auth"] = {"status": exc.status, "detail": exc.detail}
try:
    auth_ns["_principal_from_token"](_make_auth_db(CANCELLED_RUN), TOKEN)
    results["worker_credential_revoked_when_run_inactive"] = "accepted (WRONG)"
except HTTPError as exc:
    results["worker_credential_revoked_when_run_inactive"] = {
        "status": exc.status, "detail": exc.detail}

# Real scorecard function, fake database and verifier, captures arguments received.
received = []


def evaluate(ctx, **args):
    received.append(args)
    return SimpleNamespace(status="passed", expected=args.get("expect", "true"),
                           args_digest="probe", evidence={}, error=None)


score_ns = {"_session_scenario": lambda *a: "test", "scenario_spec": lambda *a: {
    "scoring": {"blue_checks": [{"verifier": "persistence", "host": "h", "points": 5, "expect": "absent"}]}},
    "_exec_override": None, "_ssh_exec": None, "host_map_for": lambda *a: {},
    "Context": lambda **kw: None, "_resolve": lambda *a: None,
    "registry": SimpleNamespace(get=lambda vid: SimpleNamespace(evaluate=evaluate, version="1")),
    "Event": lambda **kw: SimpleNamespace(event_id=1, **kw), "datetime": datetime, "timezone": timezone}
extract("srplatform/verification_service.py", {"build_scorecard"}, score_ns)
card = score_ns["build_scorecard"](SimpleNamespace(add=lambda e: None, flush=lambda: None), "sid")
results["blue_expect_absent"] = {"arguments_received_by_verifier": received, "recorded_expected": card["items"][0]["expected"]}

# Standard SYSCALL then EXECVE then PROCTITLE order loses uid/comm/exe.
from telemetry.shipper import group_event_records, build_command_event
lines = [
    'type=SYSCALL msg=audit(1791120000.1:101): uid=1000 comm="id" exe="/usr/bin/id" key="sparring_cmd"',
    'type=EXECVE msg=audit(1791120000.1:101): argc=1 a0="id"',
    'type=PROCTITLE msg=audit(1791120000.1:101): proctitle=6964',
    'type=SYSCALL msg=audit(1791120001.1:102): uid=1000 comm="pwd" exe="/usr/bin/pwd" key="sparring_cmd"',
]
groups = list(group_event_records(lines))
results["syscall_first_audit_record"] = [e for g in groups if (e := build_command_event("h", g, "m", "b"))]
results["last_group_flushed_at_eof"] = list(group_event_records([lines[1], lines[2]]))

# Exact gateway timeout path: cancel a running Future, then finish the function.
from srplatform.model_gateway import ModelGateway
started, release, thread_died = threading.Event(), threading.Event(), threading.Event()
original_hook = threading.excepthook
threading.excepthook = lambda args: thread_died.set()
gateway = ModelGateway()


def blocked():
    started.set()
    release.wait(2)
    return "finished"


future = gateway.submit(0, "probe", blocked)
started.wait(1)
try:
    gateway.wait(future, timeout=0.01)
except TimeoutError:
    pass
next_future = gateway.submit(0, "next", lambda: "next-finished")
release.set()
thread_died.wait(1)
results["gateway_timeout"] = {"worker_alive": gateway._worker.is_alive(),
                              "next_request_completed": next_future.done()}
threading.excepthook = original_hook

# Exact release/record-fresh/start_gate functions with no filesystem or
# database — but with a MODELLED record store: release() appends a `release`
# record, and the fixed _record_fresh must treat it as the invalidation cutoff
# (the old code appended the record and ignored it).
import time
safety_ns = {"time": time, "config_identity": lambda settings: "current"}
extract("srplatform/safety/__init__.py", {"Supervisor"}, safety_ns)
sup = object.__new__(safety_ns["Supervisor"])
sup.settings = SimpleNamespace(sr_env="production", safety_evidence_max_age_h=24)
sup.datapath = SimpleNamespace(mechanism="nft", remove_emergency=lambda: {"ok": True})
sup._write_state = lambda state: (None, None)
sup.latch_status = lambda: {"latched": False}
sup.runner_available = lambda: (True, "stubbed configured runner")
_store = [{"kind": k, "ok": True, "config_identity": "current",
           "recorded_at": time.time() - 3600} for k in ("baseline_check", "datapath_proof")]


def _record(kind, ok, detail=None):
    _store.append({"kind": kind, "ok": ok, "config_identity": "current",
                   "recorded_at": time.time()})


def _latest():
    out = {}
    for r in _store:
        out[r["kind"]] = r
    return out


sup.record = _record
sup._latest_records = _latest
sup.release()
results["gate_after_release_with_preexisting_evidence"] = sup.start_gate()

print(json.dumps(results, indent=2))
