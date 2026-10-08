"""Shared test helpers (moved out of test_m3 so other test modules don't import
across test files — a globally installed unrelated `tests` package must never
shadow this repo's tests, audit F22)."""
from __future__ import annotations

import json


def tool(thought: str, command: str) -> str:
    return json.dumps({"thought": thought, "propose_phase": None, "tool": "shell",
                       "args": {"command": command}})


class FakeLLM:
    """Scripted model. Summarization requests (recognizable system prompt) always
    get a canned compressed report."""

    def __init__(self, script: list):
        self.script = list(script)
        self.calls: list[tuple[str, str]] = []

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
