"""Execute availability plans FROM THE VANTAGE and hand back evidence.

`availability_plan` renders each registered check into a vetted transaction;
`availability` decides what one sample MEANS. This module is the missing
middle: it runs those plans on the TRUSTED SCORING VANTAGE and reports
observations, without ever deciding for itself.

The exit-code contract is the whole interface between a plan and this
runner (documented in the plan templates):

    0                 the transaction COMPLETED and its expectation held  -> ok
    3                 it completed and the expectation FAILED            -> failed
    anything else     the SCORER failed (timeout, auth, client, DB)      -> error
    timeout/transport the vantage could not finish                      -> error

`error` is never downtime and never a deduction (`availability.py`): only a
completed, un-met expectation counts against a defender. Credentials are
resolved at run time and passed to the vantage as environment variables;
their VALUES never appear in a plan, an observation, an event or a log.
"""
from __future__ import annotations

import shlex
import subprocess
import time
from dataclasses import dataclass
from typing import Callable, Protocol

from .availability import Observation, evaluate_registry
from .availability_plan import plan_transactions
from .environment_specs.blueprint import EnvironmentBlueprint
from .environment_specs.checks import ServiceCheckRegistry

#: A plan completed and its expectation held.
EXIT_OK = 0
#: A plan completed and its expectation did NOT hold (real target failure).
EXIT_EXPECTATION_FAILED = 3


@dataclass(frozen=True)
class VantageSample:
    """What the vantage itself reported — raw, before any interpretation."""
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    latency_ms: int = 0
    timed_out: bool = False


class VantageTransport(Protocol):
    def run(self, plan: dict, *, env: dict[str, str]) -> VantageSample: ...


#: Resolves a credential ENV NAME (`SR_CRED_…`) to its value, or None when
#: the material is missing. Missing material is a SCORER error: the check was
#: never really attempted, so it cannot be downtime.
CredentialResolver = Callable[[str], "str | None"]


def observe(plan: dict, sample: VantageSample) -> Observation:
    """Map one raw sample to an observation. Never raises: an unexplained
    exit is a scorer error, because the vantage could not tell us what
    happened to the target."""
    detail = (sample.stderr or sample.stdout or "").strip()[-300:]
    if sample.timed_out:
        return Observation("error", latency_ms=sample.latency_ms,
                           detail=f"vantage timeout after {plan['timeout_s']}s")
    if sample.returncode == EXIT_OK:
        return Observation("ok", latency_ms=sample.latency_ms,
                           detail=(sample.stdout or "").strip()[-200:])
    if sample.returncode == EXIT_EXPECTATION_FAILED:
        return Observation("failed", latency_ms=sample.latency_ms,
                           detail=detail or "expectation not met")
    return Observation("error", latency_ms=sample.latency_ms,
                       detail=f"scorer exit {sample.returncode}: "
                              f"{detail or 'no output'}")


def _env_for(plan: dict, credentials: CredentialResolver) -> tuple[
        dict[str, str], list[str]]:
    env: dict[str, str] = {}
    missing: list[str] = []
    for name in plan["credential_env"]:
        value = credentials(name)
        if value is None:
            missing.append(name)
        else:
            env[name] = value
    return env, missing


def sample_window(registry: ServiceCheckRegistry, blueprint: EnvironmentBlueprint,
                  *, transport: VantageTransport,
                  credentials: CredentialResolver,
                  guest_states: dict[str, str]) -> dict:
    """Run one sampling window over the whole registry.

    Sequential by design: the caller (a scheduler) decides cadence and may
    overlap windows; a single window must not have one check outlive another's
    classification. Every check is sampled or honestly reported unknown:
    a missing credential or an unreachable target is an observation, never a
    silent pass.
    """
    observations: dict[str, Observation] = {}
    for plan in plan_transactions(registry, blueprint):
        env, missing = _env_for(plan, credentials)
        if missing:
            observations[plan["check"]] = Observation(
                "error", detail=f"credential unavailable: {', '.join(missing)}")
            continue
        try:
            sample = transport.run(plan, env=env)
        except Exception as exc:  # noqa: BLE001 — scorer-side, never downtime
            observations[plan["check"]] = Observation(
                "error", detail=f"transport failed: {type(exc).__name__}: "
                                f"{str(exc)[:200]}")
            continue
        observations[plan["check"]] = observe(plan, sample)
    return evaluate_registry(registry, observations=observations,
                             guest_states=guest_states)


@dataclass(frozen=True)
class SshVantage:
    """The vantage channel: run a plan's script ON the scoring guest.

    The appliance holds the vantage's own deploy key; the plan travels over
    the (encrypted) stdin channel together with `export NAME=value` lines, so
    a credential never becomes argv (visible in `ps`) and never reaches a
    log. Strict host keys are required: the vantage is pinned by its
    deployment generation, exactly like a bastion dial.
    """
    host: str
    user: str = "sr"
    key_path: str = "/etc/sparring-range/keys/runner"
    known_hosts: str | None = None
    ssh: str = "ssh"
    #: The replica CA (PUBLIC anchor only). When supplied, the very first
    #: transaction writes it to the vantage and exports SSL_CERT_FILE, so
    #: `verify_tls_against_lab_ca` verifies against the lab CA on the SAME
    #: default trust path Python uses — never by switching verification off.
    trust_pem: bytes | None = None
    trust_path: str = "/etc/sr-lab/lab-ca.crt"

    def run(self, plan: dict, *, env: dict[str, str]) -> VantageSample:
        exports = "".join(f"export {k}={shlex.quote(str(v))}\n"
                          for k, v in sorted(env.items()))
        if self.trust_pem:
            import base64
            blob = base64.b64encode(self.trust_pem).decode()
            exports += (
                "install -d -m 755 $(dirname " + shlex.quote(self.trust_path) + ")\n"
                "printf '%s' '" + blob + "' | base64 -d > "
                + shlex.quote(self.trust_path) + "\n"
                "chmod 644 " + shlex.quote(self.trust_path) + "\n"
                "export SSL_CERT_FILE=" + shlex.quote(self.trust_path) + "\n")
        cmd = [self.ssh, "-o", "BatchMode=yes",
               "-o", "StrictHostKeyChecking=yes",
               "-o", f"ConnectTimeout=10"]
        if self.known_hosts:
            cmd += ["-o", f"UserKnownHostsFile={self.known_hosts}"]
        cmd += ["-i", self.key_path, f"{self.user}@{self.host}", "bash", "-s"]
        started = time.monotonic()
        try:
            proc = subprocess.run(cmd, input=(exports + plan["script"]).encode(),
                                  capture_output=True, timeout=plan["timeout_s"])
        except subprocess.TimeoutExpired as exc:
            return VantageSample(
                returncode=124, latency_ms=int((time.monotonic() - started) * 1000),
                stdout=(exc.stdout or b"").decode(errors="replace"),
                stderr="vantage transaction timed out", timed_out=True)
        return VantageSample(
            returncode=proc.returncode,
            latency_ms=int((time.monotonic() - started) * 1000),
            stdout=proc.stdout.decode(errors="replace"),
            stderr=proc.stderr.decode(errors="replace"))
