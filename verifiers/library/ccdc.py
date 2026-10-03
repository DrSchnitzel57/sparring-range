"""CCDC-staple verifiers (M4). Each can serve as BOTH a red objective check and a
blue scorecard item — the same deterministic code judges both sides; semantics
are 'the named condition holds' and the scenario YAML decides who wants it."""
from __future__ import annotations

from verifiers.base import Context, Verifier, VerifierResult


def _out(ctx: Context, host: str, cmd: str) -> tuple[int, str]:
    return ctx.exec(host, cmd)


class NoRogueAdmin(Verifier):
    id = "no_rogue_admin"
    description = "No unexpected UID-0 account besides root"
    mitre = ["T1136.001"]

    def check(self, ctx: Context, host: str) -> VerifierResult:
        code, out = _out(ctx, host, "awk -F: '($3==0 && $1!=\"root\"){print $1}' /etc/passwd")
        rogue = [l.strip() for l in out.splitlines() if l.strip()]
        return VerifierResult(passed=code == 0 and not rogue, evidence={"host": host, "uid0_accounts": rogue})


class RogueAccount(Verifier):
    id = "rogue_account"
    description = "Accounts present beyond the known baseline (args: known_users)"
    mitre = ["T1136"]

    def check(self, ctx: Context, host: str, known_users: list[str] | None = None) -> VerifierResult:
        code, out = _out(ctx, host, "cut -d: -f1 /etc/passwd")
        users = {l.strip() for l in out.splitlines() if l.strip()}
        extra = sorted(users - set(known_users or []))
        return VerifierResult(passed=code == 0 and not extra, evidence={"host": host, "unknown_accounts": extra})


class FirewallEnabled(Verifier):
    id = "firewall_enabled"
    description = "Host firewall is active"
    mitre = ["T1562.004"]

    def check(self, ctx: Context, host: str) -> VerifierResult:
        code, out = _out(ctx, host, "systemctl is-active firewalld")
        active = out.strip() == "active"
        return VerifierResult(passed=active, evidence={"host": host, "firewalld": out.strip()})


class AvEnabled(Verifier):
    id = "av_enabled"
    description = "Windows Defender real-time protection on (blue scorecard item)"
    mitre = ["T1562.001"]

    def check(self, ctx: Context, host: str) -> VerifierResult:
        code, out = _out(ctx, host,
                         "powershell -c (Get-MpComputerStatus).RealTimeProtectionEnabled")
        on = out.strip().lower() == "true"
        return VerifierResult(passed=on, evidence={"host": host, "realtime": out.strip()})


class ServicePresent(Verifier):
    id = "service_present"
    description = "A service with the given name exists (red persistence objective)"
    mitre = ["T1543.002"]

    def check(self, ctx: Context, host: str, service: str) -> VerifierResult:
        code, out = _out(ctx, host, f"systemctl list-unit-files {service}.service --no-legend")
        present = code == 0 and service in out
        return VerifierResult(passed=present, evidence={"host": host, "service": service})


class ScheduledTaskPresent(Verifier):
    id = "scheduled_task_present"
    description = "Windows scheduled task exists (red persistence / blue detection)"
    mitre = ["T1053.005"]

    def check(self, ctx: Context, host: str, task: str) -> VerifierResult:
        code, out = _out(ctx, host, f"schtasks /query /fo LIST /tn {task}")
        present = code == 0 and task in out
        return VerifierResult(passed=present, evidence={"host": host, "task": task})


class PersistenceRunKey(Verifier):
    id = "persistence_run_key"
    description = "Unexpected value in the Windows Run key beyond baseline (args: baseline)"
    mitre = ["T1547.001"]

    def check(self, ctx: Context, host: str, baseline: list[str] | None = None) -> VerifierResult:
        code, out = _out(ctx, host,
                         "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
        keys = {l.strip().split()[0] for l in out.splitlines() if l.strip() and not l.startswith("HKEY")}
        extra = sorted(keys - set(baseline or []))
        return VerifierResult(passed=code == 0 and bool(extra),
                              evidence={"host": host, "new_run_keys": extra})


class UnpatchedService(Verifier):
    id = "unpatched_service"
    description = "Service version is below the patched minimum (args: version_cmd, min_version)"
    mitre = ["T1190"]

    @staticmethod
    def _vt(s: str) -> tuple[int, ...]:
        import re
        m = re.search(r"(\d+(?:\.\d+)+)", s)
        return tuple(int(x) for x in m.group(1).split(".")) if m else ()

    def check(self, ctx: Context, host: str, version_cmd: str, min_version: str) -> VerifierResult:
        code, out = _out(ctx, host, version_cmd)
        cur, want = self._vt(out), self._vt(min_version)
        unpatched = bool(cur) and bool(want) and cur < want
        return VerifierResult(passed=unpatched, evidence={"host": host, "version": out.strip()[:80],
                                                          "min": min_version})


class DataIntegrity(Verifier):
    id = "data_integrity"
    description = "File hash matches the golden baseline (passed == intact)"
    mitre = ["T1565"]

    def check(self, ctx: Context, host: str, path: str, expected_sha256: str) -> VerifierResult:
        code, out = _out(ctx, host, f"sha256sum {path}")
        actual = out.split()[0] if out.split() else ""
        return VerifierResult(passed=code == 0 and actual == expected_sha256,
                              evidence={"host": host, "path": path, "actual": actual[:16]})


class ExfilFlag(Verifier):
    id = "exfil_flag"
    description = "An exfiltrated flag artifact landed on the staging host (args: host, path)"
    mitre = ["T1041", "T1567"]

    def check(self, ctx: Context, host: str, path: str = "/tmp/exfil/loot") -> VerifierResult:
        code, out = _out(ctx, host, f"cat {path}")
        return VerifierResult(passed=code == 0 and bool(out.strip()),
                              evidence={"host": host, "path": path, "bytes": len(out)})
