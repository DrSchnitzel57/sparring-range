"""Safe call-path probe for normal SSH completion at 213246e.

Runs the actual AST-extracted SshRunner.run with a successful SSH process
double. No shell command, signal, network connection or infrastructure call.
This establishes which supervisor calls the adapter makes, not live Linux
descendant behavior.
"""
import ast
import dataclasses
import json
import shlex
import threading
from pathlib import Path
from types import SimpleNamespace

root = Path(__file__).resolve().parents[1]
tree = ast.parse((root / "srplatform/red_agent/runner.py").read_text(encoding="utf-8"))
names = {"RunResult", "Runner", "SshRunner"}
nodes = [ast.ImportFrom(module="__future__", names=[ast.alias(name="annotations")], level=0)]
nodes += [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name in names]
active = {}
calls = []
proc = SimpleNamespace(returncode=0, wait=lambda timeout: 0)
ns = {"dataclass": dataclasses.dataclass, "shlex": shlex,
      "subprocess": SimpleNamespace(Popen=lambda *args, **kwargs: proc, PIPE=-1, STDOUT=-2,
                                    TimeoutExpired=TimeoutError),
      "_ACTIVE": active, "_ACTIVE_LOCK": threading.Lock(),
      "_register": lambda op, entry: active.update({op: entry}),
      "_attach_proc": lambda op, proc: None,
      "_bounded_reader": lambda *args, **kwargs: (b"", False)}
exec(compile(ast.fix_missing_locations(ast.Module(body=nodes, type_ignores=[])),
             "srplatform/red_agent/runner.py", "exec"), ns)
runner = object.__new__(ns["SshRunner"])
runner.s = SimpleNamespace(runner_command_timeout_s=5, runner_max_output_bytes=100,
                          runner_supervisor_bin="runner-supervisor")
runner._base_cmd = lambda: ["unused-ssh-double"]
runner._control = lambda *a, **k: (calls.append(a) or (0, "running"))
runner.cancel_remote = lambda *a, **k: (calls.append(("cancel", *a)) or False)
result = runner.run("harmless command placeholder", op_id="reviewoperation")
out = {"ssh_exit_code": result.exit_code, "cancel_state": result.cancel_state,
       "supervisor_control_calls": calls, "operation_still_in_local_inventory": bool(active),
       "loop_maps_result_to": "cancel-unknown" if result.cancel_state == "unknown" else "completed"}
print(json.dumps(out, indent=2))
