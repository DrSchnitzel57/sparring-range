"""Read-only audit probes; no network, database, shell commands, or process signals.

Run from the repository root with Python 3.12+ and pydantic 2 installed.
These reproduce current defects, not acceptance tests for the repaired product.
"""
import ast
import json
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.dont_write_bytecode = True
results = []


def record(name, value):
    results.append({"probe": name, "observed": value})


files = [p for folder in ("srplatform", "rangectl", "infra", "verifiers", "telemetry", "tests")
         for p in (ROOT / folder).rglob("*.py")]
errors = []
tests = 0
for p in files:
    try:
        tree = ast.parse(p.read_text(encoding="utf-8"), filename=str(p))
        tests += sum(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                     and n.name.startswith("test_") for n in ast.walk(tree))
    except SyntaxError as exc:
        errors.append(str(exc))
record("Python 3.12 source parse", {"files": len(files), "errors": errors, "test_functions": tests})
try:
    ast.parse((ROOT / "tests/conftest.py").read_text(), feature_version=(3, 11))
    record("Python 3.11 conftest syntax", "accepted")
except SyntaxError as exc:
    record("Python 3.11 conftest syntax", str(exc))

from srplatform.coach.aar import build_aar
from srplatform.coach.timeline import compress_timeline
from srplatform.red_agent.schema import parse_tool_call
from verifiers.base import Context
from verifiers.library.ccdc import FirewallEnabled, AvEnabled, UnpatchedService
from verifiers.library.flag_file import CronPersistencePresent

event = {"event_id": 1, "ts": "2026-10-04T10:00:00+00:00", "actor": "system",
         "action_type": "verifier", "payload": {"objective": "one-of-two", "passed": True}}
blue = {"event_id": 2, "ts": "2026-10-04T10:01:00+00:00", "actor": "blue:token",
        "action_type": "bastion_session_end", "payload": {}}
record("Unrelated SSH disconnect erases miss", {
    "before": len(compress_timeline([event])[1]["misses"]),
    "after": len(compress_timeline([event, blue])[1]["misses"])})
record("Missing scorecard grade", build_aar([], {"id": "x"}, None)["grade"])
record("One objective discounts perfect score", build_aar([event], {"id": "x"},
       {"earned": 10, "total": 10})["grade"])
for verifier, output, kwargs in (
    (FirewallEnabled(), "active", {}), (AvEnabled(), "true", {}),
    (UnpatchedService(), "version 1.0", {"version_cmd": "version", "min_version": "2.0"}),
):
    record(f"{verifier.id} accepts failed command", verifier.check(
        Context(exec=lambda host, cmd: (1, output)), host="test", **kwargs).passed)
record("Baseline cron file confirms persistence", CronPersistencePresent().check(
    Context(exec=lambda host, cmd: (0, "e2scrub_all\n")), host="test").passed)
record("Empty tool args accepted", parse_tool_call('{"tool":"shell","args":{}}').command)
record("Non-string command coerced", parse_tool_call('{"tool":"shell","args":{"command":42}}').command)

# Stub only external configuration/I/O dependencies; load actual safety and loop code.
settings = types.ModuleType("srplatform.settings")
settings.Settings = object
settings.get_settings = lambda: types.SimpleNamespace(api_base_url="http://unused.invalid")
sys.modules["srplatform.settings"] = settings
from srplatform.safety import Supervisor
record("Unwired killswitch", Supervisor().killswitch())  # empty PID set: no signals
record("Release without state or firewall operation", Supervisor().release())

from infra.proxmox_client import ProxmoxClient
pve = object.__new__(ProxmoxClient)
calls = []
pve.post = lambda path, **kwargs: calls.append({"path": path, "args": kwargs})
pve.clone_template(9001, 210, "test")
pve.destroy("r740", 210)
record("Production adapter request paths (intercepted)", calls)

loader = types.ModuleType("srplatform.scenario_engine.loader")
loader.load_scenario = lambda _: {"id": "test", "name": "test", "red": {"objectives": [
    {"id": "first", "verifier": "flag_file_present", "args": {"host": "h", "path": "/first"}},
    {"id": "second", "verifier": "flag_file_present", "args": {"host": "h", "path": "/second"}},
]}}
sys.modules["srplatform.scenario_engine.loader"] = loader
httpx = types.ModuleType("httpx")
httpx.post = lambda *a, **kw: None
sys.modules["httpx"] = httpx
from srplatform.red_agent import loop as loop_module
loop_module.get_supervisor = lambda: types.SimpleNamespace(register_red_agent=lambda pid: None)


class MemoryTransport:
    def __init__(self):
        self.rows = []

    def get_agent_state(self, sid):
        return {}

    def events_since(self, sid, after):
        return [e for e in self.rows if e["event_id"] > after]

    def log_event(self, e):
        self.rows.append(dict(e, event_id=len(self.rows) + 1))

    def save_agent_state(self, *args):
        pass


class Model:
    def __init__(self):
        self.calls = 0

    def complete(self, *args):
        self.calls += 1
        return '{"tool":"shell","args":{"command":"DONE"}}'


model = Model()
sandbox = types.SimpleNamespace(verifier_exec=lambda host, cmd: (0, "flag") if cmd == "cat /first" else (1, ""))
result = loop_module.RedAgentLoop("sid", "test", MemoryTransport(), model, sandbox, max_steps=5).run()
record("DONE stops after only one of two objectives passes", {"model_calls": model.calls, "result": result})

print(json.dumps(results, indent=2))
