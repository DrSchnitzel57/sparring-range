"""Command sandbox (M3): red commands execute INSIDE the Kali container,
constrained to the range VLAN (hard constraint #1 is what makes "constrained"
true — the range simply has no other routes).

Prod: subprocess on the Kali host/container the agent service runs on
(Drew's deployment places it; `pct exec` on Proxmox is one way).
Tests: scripted fake so the loop is testable without a Kali box.
"""
from __future__ import annotations

import subprocess
from typing import Callable, Protocol


class Sandbox(Protocol):
    def run(self, command: str) -> tuple[int, str]: ...


class KaliSandbox:
    """Run the command in the Kali environment via subprocess (the agent process
    itself runs inside/next-to the container; commands inherit the range-only
    network).

    `verifier_exec` is the management bridge used by verifiers to check REAL
    host state: Drew's golden images accept the platform's management key, so
    verifiers run `ssh root@<host>` straight from the control plane (the range's
    egress-deny rules permit control-plane management traffic; nothing leaves
    the range)."""

    def __init__(self, shell: str = "/bin/bash", timeout: int = 120):
        self.shell = shell
        self.timeout = timeout

    def run(self, command: str) -> tuple[int, str]:
        try:
            p = subprocess.run([self.shell, "-lc", command], capture_output=True, text=True,
                               timeout=self.timeout)
            return p.returncode, (p.stdout + p.stderr)[:8000]
        except subprocess.TimeoutExpired:
            return 124, "[sandbox] command timed out"

    def verifier_exec(self, host: str, command: str) -> tuple[int, str]:
        """Management exec channel for verifiers (see class docstring)."""
        try:
            p = subprocess.run(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5",
                                f"root@{host}", command], capture_output=True, text=True, timeout=30)
            return p.returncode, (p.stdout + p.stderr)[:8000]
        except (subprocess.TimeoutExpired, OSError) as e:
            return 124, f"[verifier-exec] {e}"


class FakeSandbox:
    """Scripted responses + a tiny in-memory 'range filesystem' for verifiers.

    script: dict command-substring -> (exit, output). Unmatched commands get
    `default`. Also records every command (tests assert what the agent ran).
    """

    def __init__(self, script: dict[str, tuple[int, str]] | None = None, default: tuple[int, str] = (0, "")):
        self.script = script or {}
        self.default = default
        self.history: list[str] = []
        # host -> path -> content; shared with the verifier Context
        self.fs: dict[str, dict[str, str]] = {}

    def run(self, command: str) -> tuple[int, str]:
        self.history.append(command)
        for pattern, resp in self.script.items():
            if pattern in command:
                # a scripted response is (code, out) or a callable(command)->(code,out)
                code, out = resp(command) if callable(resp) else resp
                return code, out
        # emulate `cat host:path`-style exec used by verifier transports
        return self.default

    # ---- verifier exec bridge: exec(host, command) -> (code, out) ------------
    def verifier_exec(self, host: str, command: str) -> tuple[int, str]:
        if command.startswith("cat "):
            path = command[4:].strip()
            fs = self.fs.get(host, {})
            if path in fs:
                return 0, fs[path]
            return 1, ""
        if command.startswith("crontab"):
            fs = self.fs.get(host, {})
            cron = [p for p in fs if p.startswith("/etc/cron")]
            if cron:
                return 0, "\n".join(fs[p] for p in cron)
            return 1, ""
        return 1, ""
