"""Shared test helpers (moved out of test_m3 so other test modules don't import
across test files — a globally installed unrelated `tests` package must never
shadow this repo's tests, audit F22)."""
from __future__ import annotations

import json


def api_json(method: str, url: str, *, body=None, headers=None,
             expect: tuple = (200, 201)):
    """HTTP call with a SELF-EXPLANATORY failure (M01-R3/M01-R4 lesson): a bare
    .json()["key"] on an error response raises a contentless KeyError and
    leaves CI unclassifiable — the status + body name the branch (auth vs
    5xx vs validation) the moment it happens."""
    import httpx
    r = httpx.request(method, url, json=body, headers=headers, timeout=30)
    if r.status_code not in expect:
        raise AssertionError(f"{method} {url} -> {r.status_code} {r.text[:400]}")
    return r.json()


# --------------------------------------------------------------------------- #
# Containment observation: REAL HOST identities across the PID namespace       #
# --------------------------------------------------------------------------- #
# Commands execute inside a user+mount+cgroup+pid namespace (audit F1/F5): the
# pids THEY print are namespace-local and meaningless on the host. A test that
# asserts on process identity must observe the host view of the delegated
# cgroup tree — the kernel's own bookkeeping — never a number the command
# chose to write.

def cgroup_tree_members(cg_root: str, op: str) -> list[int]:
    """RECURSIVE host-PID membership of the operation's containment tree
    (nested cgroups included; the host sees the real hierarchy even though
    the command's own cgroup namespace cannot)."""
    import os
    out: list[int] = []
    base = os.path.join(cg_root, f"sr-{op}")
    for dirpath, _dirs, files in os.walk(base):
        if "cgroup.procs" not in files:
            continue
        try:
            with open(os.path.join(dirpath, "cgroup.procs")) as f:
                out.extend(int(x) for x in f.read().split())
        except (OSError, ValueError):
            pass
    return out


def find_tree_member(cg_root: str, op: str, argv: tuple) -> int | None:
    """Host PID of the containment-tree member whose /proc cmdline is exactly
    argv — identity by observed executable, never by a number the command
    itself reported."""
    import os
    for pid in cgroup_tree_members(cg_root, op):
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmd = tuple(a.decode("utf-8", "replace")
                            for a in f.read().split(b"\0") if a)
        except OSError:
            continue
        if cmd == tuple(argv):
            return pid
    return None


def wait_value(fn, timeout: float = 10.0):
    """Poll fn() until it returns a truthy value; return that value (or None).
    Use with find_tree_member so a move into a nested cgroup is observed."""
    import time
    deadline = time.time() + timeout
    while time.time() < deadline:
        value = fn()
        if value:
            return value
        time.sleep(0.05)
    return None


def alive(pid: int) -> bool:
    """Host-identity liveness probe (kill-0): PermissionError means alive."""
    import os
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def require_sql_handoff_prereq() -> None:
    """Gate for installer tests that drive the REAL secret-provisioning
    handoff: os.chown to the postgres user + su postgres are root-only.
    Hosts without a postgres OS user exercise the documented no-handoff
    branch honestly and run; a privileged box runs the real path. An
    unprivileged box that HAS the user (CI runners) cannot, so it SKIPs
    with the reason; required jobs (SR_REQUIRE_SECRETS=1) FAIL instead."""
    import os
    import pwd

    import pytest
    try:
        pwd.getpwnam("postgres")
    except KeyError:
        return  # no handoff branch — the test covers the documented path
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        return
    reason = "secret provisioning needs root to chown/su as postgres"
    if os.environ.get("SR_REQUIRE_SECRETS") == "1":
        pytest.fail(f"SR_REQUIRE_SECRETS=1 — {reason}", pytrace=False)
    pytest.skip(reason)


def require_packet_prereq() -> None:
    """Gate for the privileged PACKET layer (real nft + netns packet flows,
    disposable namespaces only). Ordinary hosts SKIP with the exact missing
    prerequisites; required jobs (SR_REQUIRE_PACKET=1) FAIL instead — a
    missing prerequisite is never a green job (audit F8)."""
    import os
    import shutil

    import pytest
    missing = []
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        missing.append("root")
    if not shutil.which("nft"):
        missing.append("nft")
    if not shutil.which("ip"):
        missing.append("iproute2")
    if not missing:
        return
    reason = f"packet layer needs {' + '.join(missing)}"
    if os.environ.get("SR_REQUIRE_PACKET") == "1":
        pytest.fail(f"SR_REQUIRE_PACKET=1 — {reason}", pytrace=False)
    pytest.skip(reason)


def tool(thought: str, command: str) -> str:
    return json.dumps({"thought": thought, "propose_phase": None, "tool": "shell",
                       "args": {"command": command}})


class FakeLLM:
    """Scripted model. Summarization requests (recognizable system prompt) always
    get a canned compressed report."""

    def __init__(self, script: list):
        self.script = list(script)
        self.calls: list[tuple[str, str]] = []
        self.turns: list[tuple[str, str, dict | None]] = []

    def complete(self, system: str, user: str) -> str:
        self.calls.append((system, user))
        if "situation report" in system:
            return "SUMMARY: web01 discovered; exploit pending."
        if not self.script:
            raise AssertionError("FakeLLM script exhausted")
        item = self.script.pop(0)
        if isinstance(item, BaseException):  # KeyboardInterrupt is BaseException
            raise item
        return item

    def turn(self, *, system: str, user: str, tool_result: dict | None = None) -> dict:
        """Structured-turn surface (plan 19): the scripted legacy JSON — the
        exact same scripts every loop test already writes — becomes a TYPED
        native tool call when it matches the schema, plain text otherwise.
        The loop's strict-parse/retry semantics are preserved either way,
        so behavior tests stay meaningful on the new protocol."""
        self.calls.append((system, user))
        self.turns.append((system, user, tool_result))
        if not self.script:
            raise AssertionError("FakeLLM script exhausted")
        item = self.script.pop(0)
        if isinstance(item, BaseException):
            raise item
        import json as _json
        text = str(item)
        stripped = text.strip().strip("`")
        if stripped.startswith("json"):
            stripped = stripped[4:]
        try:
            obj = _json.loads(stripped)
        except ValueError:
            obj = None
        if (isinstance(obj, dict) and obj.get("tool", "shell") == "shell"
                and isinstance(obj.get("args"), dict)
                and "command" in obj["args"]):
            return {"kind": "tool_call", "text": None,
                    "tool_call": {"call_id": f"fake-{len(self.turns)}",
                                  "command": str(obj["args"]["command"]),
                                  "thought": str(obj.get("thought") or "")}}
        return {"kind": "text", "text": text, "tool_call": None}


class FakeDatapath:
    """DatapathController double with a NON-noop mechanism so the evidence gate
    is exercised; every call is recorded for assertions."""
    mechanism = "test-fake"

    def __init__(self, ok: bool = True):
        self.ok = ok
        self.calls: list[str] = []

    def baseline_status(self) -> dict:
        self.calls.append("baseline_status")
        return {"ok": self.ok, "detail": "fake baseline table present" if self.ok
                else "fake baseline missing"}

    def apply_emergency(self) -> dict:
        self.calls.append("apply_emergency")
        return {"ok": self.ok, "detail": "fake emergency ruleset applied",
                "mechanism": self.mechanism}

    def remove_emergency(self) -> dict:
        self.calls.append("remove_emergency")
        return {"ok": self.ok, "detail": "fake emergency ruleset removed",
                "mechanism": self.mechanism}


class ScriptedHostExec:
    """Verifier exec-channel double: per-host scripted command responses.
    responses: {host: [(command_substring, (code, output)), ...]}; the first
    matching substring wins; unmatched -> (127, 'no route') meaning unreachable."""

    def __init__(self, responses: dict | None = None, default=(127, "unreachable")):
        self.responses = responses or {}
        self.default = default
        self.calls: list[tuple[str, str]] = []

    def __call__(self, host: str, command: str) -> tuple[int, str]:
        self.calls.append((host, command))
        for frag, resp in self.responses.get(host, []):
            if frag in command:
                return resp if isinstance(resp, tuple) else (0, str(resp))
        return self.default


def make_runner_token(session_id: str, scenario_id: str = "test") -> str:
    """Issue a REAL run-scoped worker credential for the session — the exact
    format `start_run` issues (sha256 stored on a Run row), NOT a test-only
    ServiceToken stand-in (audit R01: tests must not inject a credential
    format production never creates)."""
    import hashlib
    import secrets
    import uuid as _uuid

    from srplatform.db.models import Run
    from srplatform.db.session import db as db_ctx
    tok = secrets.token_urlsafe(32)
    with db_ctx() as s:
        s.add(Run(session_id=_uuid.UUID(session_id), scenario_id=scenario_id,
                  status="running",
                  worker_token=hashlib.sha256(tok.encode()).hexdigest()))
        s.commit()
    return tok


def cgroup_containment_root() -> str:
    """Resolve AND probe a delegated cgroup v2 directory for the runner
    supervisor's authoritative containment (audit T-04, F8). The supervisor
    REFUSES to start work without it (unsupported execution mode), so tests
    that need real containment SKIP with an explicit reason when the host
    does not delegate one; the refusal itself is tested separately.

    The probe is not just mkdir: a child process must actually be movable
    into a fresh child cgroup — that is the containment guarantee.

    AUDIT F8: in required CI/acceptance jobs set SR_REQUIRE_CONTAINMENT=1 —
    a missing or unusable containment hierarchy is then a FAILURE, never a
    silent green-job skip. Ordinary developer hosts keep the explicit skip."""
    import os
    import subprocess
    import sys
    import uuid as _u

    import pytest
    required = os.environ.get("SR_REQUIRE_CONTAINMENT") == "1"

    def _skip_or_fail(reason):
        if required:
            pytest.fail(f"SR_REQUIRE_CONTAINMENT=1 — {reason}", pytrace=False)
        pytest.skip(f"{reason} — the supervisor refuses uncontained starts by design")

    root = os.environ.get("RUNNER_CGROUP_ROOT")
    if not root:
        try:
            with open("/proc/self/cgroup") as f:
                path = next(l.split("::", 1)[1].strip()
                            for l in f if l.startswith("0::"))
            root = "/sys/fs/cgroup" + path
        except (OSError, StopIteration):
            _skip_or_fail("no cgroup v2 unified self-path — containment untestable here")
    if not os.path.isdir(root) or not os.access(root, os.W_OK):
        _skip_or_fail(f"no writable delegated cgroup v2 root at {root!r}")
    probe = os.path.join(root, f"srprobe-{_u.uuid4().hex[:8]}")
    try:
        os.mkdir(probe)
        proc = subprocess.Popen(["sleep", "30"], start_new_session=True)
        try:
            with open(os.path.join(probe, "cgroup.procs"), "w") as f:
                f.write(str(proc.pid))
            with open(f"/proc/{proc.pid}/cgroup") as f:
                if "srprobe-" not in f.read():
                    _skip_or_fail(f"cgroup {root!r} does not accept process moves")
        except OSError:
            _skip_or_fail(f"cgroup {root!r} rejects process moves")
        finally:
            proc.kill()
            proc.wait()
    except OSError as e:
        _skip_or_fail(f"cgroup {root!r} unusable: {e}")
    finally:
        try:
            os.rmdir(probe)
        except OSError:
            pass
    return root
