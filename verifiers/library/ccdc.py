"""CCDC-staple verifiers (M4, F10 rewrite).

Each verifier OBSERVES one deterministic condition and the scenario declares
per-use polarity (`expect`), so the same predicate can be a red objective and a
blue check without rewarding the wrong side. All command parameters are quoted
(shlex). Probe failures/timeouts/unparsable output are UNKNOWN — never passes.
"""
from __future__ import annotations

import re
import shlex

from pydantic import BaseModel, Field, field_validator

from verifiers.base import Context, Verifier, VerifierOutcome  # noqa: F401


# ------------------------------------------------------------ arg models -----
class HostArg(BaseModel):
    host: str = Field(min_length=1, max_length=253)

    @field_validator("host")
    @classmethod
    def _safe_host(cls, v: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9._:-]+", v):
            raise ValueError("host must be a bare hostname/IP")
        return v


class PathArg(HostArg):
    path: str

    @field_validator("path")
    @classmethod
    def _abs_path(cls, v: str) -> str:
        if not v.startswith("/") or ".." in v.split("/") or len(v) > 512:
            raise ValueError("path must be absolute and traversal-free")
        return v


class ServiceArg(HostArg):
    service: str

    @field_validator("service")
    @classmethod
    def _unit_name(cls, v: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9@._+-]{1,128}", v):
            raise ValueError("service must be a bare systemd unit name")
        return v


class UsersArg(HostArg):
    known_users: list[str] = Field(min_length=1)  # baseline REQUIRED (F10)


class TaskArg(HostArg):
    task: str = Field(min_length=1, max_length=256)

    @field_validator("task")
    @classmethod
    def _task_name(cls, v: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9 ._\\\\-]+", v):
            raise ValueError("task must be a bare Windows task path")
        return v


class RunKeyArg(HostArg):
    baseline: list[str] = Field(min_length=1)  # no baseline => cannot judge


class VersionArg(HostArg):
    version_cmd: str
    min_version: str

    @field_validator("version_cmd")
    @classmethod
    def _cmd_charset(cls, v: str) -> str:
        # operator-authored scenario data; still constrained (no shell
        # metacharacters, no substitution, no redirection)
        if not re.fullmatch(r"[A-Za-z0-9_./ -]{1,128}", v):
            raise ValueError("version_cmd may only contain a plain command and simple flags")
        return v

    @field_validator("min_version")
    @classmethod
    def _ver(cls, v: str) -> str:
        if not re.fullmatch(r"\d+(\.\d+){0,4}", v):
            raise ValueError("min_version must be dotted digits")
        return v


class IntegrityArg(PathArg):
    expected_sha256: str

    @field_validator("expected_sha256")
    @classmethod
    def _hex64(cls, v: str) -> str:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", v):
            raise ValueError("expected_sha256 must be 64 hex chars")
        return v


class ExfilArg(PathArg):
    expected_content: str | None = None  # scenario flag identity (F10 proof)


class CronArg(HostArg):
    baseline_files: list[str] = Field(default_factory=list)  # golden /etc/cron.d names
    baseline_crontab: list[str] = Field(default_factory=list)  # golden user crontab lines


# ---------------------------------------------------------------- verifiers --
def _run(ctx: Context, host: str, cmd: str) -> tuple[int | None, str]:
    try:
        code, out = ctx.exec(host, cmd)
        return code, out or ""
    except Exception as e:  # noqa: BLE001
        return None, f"exec failed: {e}"


class NoRogueAdmin(Verifier):
    id = "no_rogue_admin"
    description = "No unexpected UID-0 account besides root"
    observed_condition = "only root has UID 0"
    mitre = ["T1136.001"]
    version = "2"
    args_model = HostArg

    def observe(self, ctx: Context, host: str):
        code, out = _run(ctx, host,
                         "awk -F: '($3==0 && $1!=\"root\"){print $1}' /etc/passwd")
        if code is None or code != 0:
            return None, {"host": host}, f"probe failed (exit {code})"
        rogue = [l.strip() for l in out.splitlines() if l.strip()]
        return (not rogue), {"host": host, "uid0_accounts": rogue}, None


class RogueAccount(Verifier):
    id = "rogue_account"
    description = "Accounts match the known baseline exactly (baseline REQUIRED)"
    observed_condition = "no accounts beyond the baseline"
    mitre = ["T1136"]
    version = "2"
    args_model = UsersArg

    def observe(self, ctx: Context, host: str, known_users: list[str]):
        code, out = _run(ctx, host, "cut -d: -f1 /etc/passwd")
        if code is None or code != 0 or not out.strip():
            return None, {"host": host}, f"probe failed (exit {code})"
        users = {l.strip() for l in out.splitlines() if l.strip()}
        extra = sorted(users - set(known_users))
        return (not extra), {"host": host, "unknown_accounts": extra}, None


class FirewallEnabled(Verifier):
    id = "firewall_enabled"
    description = "Host firewall is active"
    observed_condition = "firewalld reports active"
    mitre = ["T1562.004"]
    version = "2"
    args_model = HostArg

    def observe(self, ctx: Context, host: str):
        code, out = _run(ctx, host, "systemctl is-active firewalld")
        state = out.strip().lower()
        if state == "active":
            return True, {"host": host, "firewalld": state}, None
        if state in ("inactive", "failed", "unknown"):
            return False, {"host": host, "firewalld": state}, None
        return None, {"host": host, "raw": out.strip()[:120]}, f"unrecognized state (exit {code})"


class AvEnabled(Verifier):
    id = "av_enabled"
    description = "Windows Defender real-time protection on (blue scorecard item)"
    observed_condition = "RealTimeProtectionEnabled is True"
    mitre = ["T1562.001"]
    version = "2"
    args_model = HostArg

    def observe(self, ctx: Context, host: str):
        code, out = _run(ctx, host,
                         "powershell -NoProfile -c (Get-MpComputerStatus).RealTimeProtectionEnabled")
        state = out.strip().lower()
        if code is None:
            return None, {"host": host}, f"exec failed: {out[:120]}"
        if state == "true":
            return True, {"host": host, "realtime": state}, None
        if state == "false":
            return False, {"host": host, "realtime": state}, None
        return None, {"host": host, "raw": out.strip()[:120]}, f"unparsable answer (exit {code})"


class ServicePresent(Verifier):
    id = "service_present"
    description = "A systemd unit with the EXACT name exists"
    observed_condition = "unit exists"
    mitre = ["T1543.002"]
    version = "2"
    args_model = ServiceArg

    def observe(self, ctx: Context, host: str, service: str):
        unit = f"{service}.service" if not service.endswith(".service") else service
        code, out = _run(ctx, host,
                         f"systemctl list-unit-files {shlex.quote(unit)} --no-legend")
        if code is None or code != 0:
            return None, {"host": host, "service": service}, f"probe failed (exit {code})"
        names = {line.split()[0] for line in out.splitlines() if line.split()}
        present = unit in names  # exact match, not substring (F10)
        return present, {"host": host, "service": unit}, None


class ScheduledTaskPresent(Verifier):
    id = "scheduled_task_present"
    description = "Windows scheduled task exists (red persistence / blue detection)"
    observed_condition = "task exists"
    mitre = ["T1053.005"]
    version = "2"
    args_model = TaskArg

    def observe(self, ctx: Context, host: str, task: str):
        code, out = _run(ctx, host, f"schtasks /query /fo LIST /tn {shlex.quote(task)}")
        if code is None:
            return None, {"host": host, "task": task}, f"exec failed: {out[:120]}"
        if code == 0:
            return True, {"host": host, "task": task}, None
        if "ERROR" in out.upper():  # task not found is a definitive answer
            return False, {"host": host, "task": task}, None
        return None, {"host": host, "raw": out[:120]}, f"ambiguous answer (exit {code})"


class PersistenceRunKey(Verifier):
    id = "persistence_run_key"
    description = "Unexpected value in the Windows Run key beyond baseline (baseline REQUIRED)"
    observed_condition = "extra Run-key values beyond the baseline exist"
    mitre = ["T1547.001"]
    version = "2"
    args_model = RunKeyArg

    def observe(self, ctx: Context, host: str, baseline: list[str]):
        code, out = _run(ctx, host,
                         "reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
        if code is None or code != 0:
            return None, {"host": host}, f"probe failed (exit {code})"
        keys = {l.strip().split()[0] for l in out.splitlines()
                if l.strip() and not l.startswith("HKEY")}
        extra = sorted(keys - set(baseline))
        return bool(extra), {"host": host, "new_run_keys": extra}, None


class UnpatchedService(Verifier):
    id = "unpatched_service"
    description = "Service version below the patched minimum"
    observed_condition = "detected version < min_version"
    mitre = ["T1190"]
    version = "2"
    args_model = VersionArg

    @staticmethod
    def _vt(s: str) -> tuple[int, ...] | None:
        m = re.search(r"(\d+(?:\.\d+){1,4})", s)
        return tuple(int(x) for x in m.group(1).split(".")) if m else None

    def observe(self, ctx: Context, host: str, version_cmd: str, min_version: str):
        code, out = _run(ctx, host, version_cmd)
        if code is None or code != 0:
            return None, {"host": host, "raw": out.strip()[:120]}, f"probe failed (exit {code})"
        cur, want = self._vt(out), self._vt(min_version)
        if not cur or not want:
            return None, {"host": host, "version": out.strip()[:120], "min": min_version}, \
                "version string unparsable"
        n = max(len(cur), len(want))
        cur_n, want_n = cur + (0,) * (n - len(cur)), want + (0,) * (n - len(want))
        return (cur_n < want_n), {"host": host, "version": ".".join(map(str, cur)),
                                  "min": min_version}, None


class DataIntegrity(Verifier):
    id = "data_integrity"
    description = ("File hash matches the golden baseline hash. The baseline hash MUST be "
                   "produced by the documented golden-image capture (see scenario comments); "
                   "hosts that legitimately write to the file are not integrity-scored.")
    observed_condition = "sha256(file) == expected_sha256"
    mitre = ["T1565"]
    version = "2"
    args_model = IntegrityArg

    def observe(self, ctx: Context, host: str, path: str, expected_sha256: str):
        code, out = _run(ctx, host, f"sha256sum {shlex.quote(path)}")
        if code is None or code != 0:
            return None, {"host": host, "path": path}, f"probe failed (exit {code})"
        actual = out.split()[0] if out.split() else ""
        if not re.fullmatch(r"[0-9a-fA-F]{64}", actual):
            return None, {"host": host, "path": path}, "hash output unparsable"
        return (actual.lower() == expected_sha256.lower()), \
            {"host": host, "path": path, "actual": actual[:16]}, None


class ExfilFlag(Verifier):
    id = "exfil_flag"
    description = ("Exfiltrated artifact on the staging host. With expected_content, PROVES "
                   "scenario-specific data movement; without it the check is WEAK (any "
                   "nonempty file) and the evidence says so.")
    observed_condition = "artifact exists (and matches expected content when provided)"
    mitre = ["T1041", "T1567"]
    version = "2"
    args_model = ExfilArg

    def observe(self, ctx: Context, host: str, path: str, expected_content: str | None = None):
        code, out = _run(ctx, host, f"cat {shlex.quote(path)}")
        if code is None:
            return None, {"host": host, "path": path}, f"exec failed: {out[:120]}"
        if code != 0:
            return False, {"host": host, "path": path, "exit_code": code}, None
        if expected_content is not None:
            ok = expected_content in out
            return ok, {"host": host, "path": path, "matches_flag": ok}, None
        return bool(out.strip()), {"host": host, "path": path, "bytes": len(out),
                                   "weak": True,
                                   "note": "no expected_content — presence only, not provenance"}, None
