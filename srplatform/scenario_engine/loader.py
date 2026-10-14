"""YAML scenario loader + typed schema validator (M4 — F19 rewrite).

Scenarios are PURE DATA validated with nested pydantic models: IDs, uniqueness,
IPs, positive limits, per-verifier REQUIRED args, host references, phases, OS,
polarity — all checked at load time with actionable messages. Unknown fields
are rejected. Library listing VALIDATES each entry (broken files are reported,
not silently skipped). Scenario IDs are constrained so file resolution can
never escape the scenarios directory.

Session history integrity: sessions snapshot the scenario bytes at creation
(`load_scenario_for_session`); editing the YAML afterwards cannot change what
historical scores mean.
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, ValidationError, field_validator

from verifiers import registry

PHASES = ["recon", "initial-access", "priv-esc", "lateral", "persistence", "objectives"]
SCENARIO_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")

# Provisioning contract (audit N10 item 4): scenario host `services` are a
# VERSIONED PREBUILT-TEMPLATE REQUIREMENT — the golden template for the host
# must provide these units, and launch VERIFIES readiness (service_present
# against the owned inventory) before a session reaches `ready`. Names are
# validated against this registry: listing a service name no longer silently
# ignores it.
SUPPORTED_SERVICES: dict[str, str] = {
    "http": "nginx",     # golden linux template serves HTTP via nginx
    "mysql": "mysql",
    "ssh": "sshd",
    # Mojang catalogue app (paired 03+04): a local Python service fronted by
    # nginx. Web-local reads its fictional data from a local file; web+DB
    # reads MySQL through PyMySQL with a read-only application role
    # (SELECT-only; the verifier enforces the same direction).
    "mojang-web": "mojang-web",
}


class ScenarioError(ValueError):
    def __init__(self, issues: list[str]):
        self.issues = issues
        super().__init__("; ".join(issues))


# ------------------------------------------------------------------ schema ---
class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Host(Strict):
    name: str = Field(min_length=1, max_length=63)
    template_vmid: int = Field(gt=0, lt=1_000_000)
    ip: IPvAnyAddress
    services: list[str] = []
    os: Literal["linux", "windows"] | None = None
    # plan 13 phase 3: the DB-tier host this web tier's application is wired
    # to at deploy time (guest_config provisions grants/listeners/firewall
    # for exactly this owned host). Validated against the topology.
    db_ref: str | None = None

    @field_validator("name")
    @classmethod
    def _hostname(cls, v: str) -> str:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", v):
            raise ValueError("host name must be a bare hostname")
        return v

    @field_validator("services")
    @classmethod
    def _services(cls, v: list[str]) -> list[str]:
        unknown = sorted(set(v) - set(SUPPORTED_SERVICES))
        if unknown:
            raise ValueError(
                f"unsupported service(s) {unknown} — the provisioning contract supports "
                f"{sorted(SUPPORTED_SERVICES)} (extend SUPPORTED_SERVICES and the golden "
                "template together; readiness is enforced at launch)")
        return v


class Topology(Strict):
    hosts: list[Host] = Field(min_length=1)


class Objective(Strict):
    id: str = Field(min_length=1, max_length=64)
    verifier: str
    args: dict[str, Any] = {}
    phase: Literal["recon", "initial-access", "priv-esc", "lateral", "persistence", "objectives"] | None = None
    description: str | None = None


class Red(Strict):
    start_phase: str = "recon"
    objectives: list[Objective] = Field(min_length=1)

    @field_validator("start_phase")
    @classmethod
    def _phase(cls, v: str) -> str:
        if v not in PHASES:
            raise ValueError(f"start_phase must be one of {PHASES}")
        return v


class BlueCheck(Strict):
    verifier: str
    points: int = Field(gt=0)          # positive points (F19)
    host: str | None = None
    domain: str = "general"            # CCDC scoring domain (F20)
    expect: Literal["true", "false", "present", "absent"] = "true"
    description: str | None = None
    model_config = ConfigDict(extra="allow")  # verifier args pass through


class Scoring(Strict):
    blue_checks: list[BlueCheck] = Field(min_length=1)


class ScenarioSpec(Strict):
    id: str
    name: str = Field(min_length=1)
    difficulty: int = Field(ge=1, le=5)
    focus: list[str] = []
    est_minutes: int = Field(gt=0)
    techniques: list[str] = []
    version: int = 1
    rubric_version: int | None = None
    # Paired 03+04: versioned seed/image/user/cron/static baselines. Legacy
    # scenarios without manifests are NOT release-ready (their checks run,
    # but readiness requires the manifest on mojang presets).
    seed_version: int | None = None
    image_version: str | None = None
    topology: Topology
    red: Red
    scoring: Scoring | None = None

    @field_validator("id")
    @classmethod
    def _sid(cls, v: str) -> str:
        if not SCENARIO_ID_RE.match(v):
            raise ValueError(f"id must match {SCENARIO_ID_RE.pattern} (safe path identifier)")
        return v

    @field_validator("techniques")
    @classmethod
    def _tech(cls, v: list[str]) -> list[str]:
        bad = [t for t in v if not TECHNIQUE_RE.match(t)]
        if bad:
            raise ValueError(f"invalid MITRE technique ids: {bad}")
        return v


# ------------------------------------------------------------------- load ----
def scenarios_dir() -> Path:
    # checkout-based deployment (documented): scenarios ship with the checkout,
    # not as wheel data (see docs/ARCHITECTURE_NOTES.md)
    return Path(__file__).resolve().parents[2] / "scenarios"


def load_scenario(scenario_id: str) -> dict:
    if not SCENARIO_ID_RE.match(scenario_id or ""):
        raise ScenarioError([f"scenario id '{scenario_id}' is not a safe identifier"])
    root = scenarios_dir().resolve()
    path = (root / f"{scenario_id}.yaml").resolve()
    if not path.is_relative_to(root):
        raise ScenarioError([f"scenario id '{scenario_id}' escapes the scenarios root"])
    if not path.exists():
        raise FileNotFoundError(f"scenario '{scenario_id}' not found at {path}")
    return parse_scenario(path.read_text(), where=path.name)


def parse_scenario(text: str, where: str = "<string>") -> dict:
    spec = yaml.safe_load(text)
    return validate_scenario(spec, where=where)


def validate_scenario(spec: Any, where: str = "<spec>") -> dict:
    """Return the normalized scenario dict; raise ScenarioError with ALL issues."""
    issues: list[str] = []
    try:
        model = ScenarioSpec.model_validate(spec)
    except ValidationError as e:
        for err in e.errors():
            loc = ".".join(str(p) for p in err["loc"]) or "<root>"
            issues.append(f"{where}: {loc}: {err['msg']}")
        raise ScenarioError(issues)

    data = model.model_dump(mode="json")
    hostnames = {h["name"] for h in data["topology"]["hosts"]}
    for h in data["topology"]["hosts"]:
        if h.get("db_ref"):
            if h["db_ref"] not in hostnames:
                issues.append(f"{where}: host '{h['name']}': db_ref "
                              f"'{h['db_ref']}' not in topology")

    def check(prefix: str, verifier_id: str, args: dict, needs_host: bool = True) -> None:
        if verifier_id not in registry.REGISTRY:
            issues.append(f"{where}: {prefix}: unknown verifier '{verifier_id}' "
                          "(add it to verifiers/ or fix the name)")
            return
        v = registry.get(verifier_id)
        issue = v.validate_static(args)
        if issue:
            issues.append(f"{where}: {prefix}: {issue}")
        if needs_host and not args.get("host"):
            issues.append(f"{where}: {prefix}: args must include 'host'")
        elif needs_host and args.get("host") not in hostnames:
            issues.append(f"{where}: {prefix}: host '{args['host']}' not in topology")

    for obj in data["red"]["objectives"]:
        check(f"red.objectives.{obj['id']}", obj["verifier"], obj.get("args") or {})
    if data["scoring"]:
        for i, chk in enumerate(data["scoring"]["blue_checks"]):
            args = {k: v for k, v in chk.items()
                    if k not in ("verifier", "points", "domain", "expect", "description")}
            if chk.get("host") and chk["host"] not in hostnames:
                issues.append(f"{where}: scoring.blue_checks[{i}]: references unknown host "
                              f"'{chk['host']}'")
            check(f"scoring.blue_checks[{i}]", chk["verifier"], args)

    if issues:
        raise ScenarioError(issues)
    return data


def list_scenarios(directory: Path | None = None) -> list[dict]:
    """Library listing — every entry validated; broken entries are REPORTED
    (F19: no silent bypass)."""
    out = []
    for p in sorted((directory or scenarios_dir()).glob("*.yaml")):
        try:
            spec = parse_scenario(p.read_text(), where=p.name)
            spec["_valid"] = True
            out.append(spec)
        except ScenarioError as e:
            out.append({"id": p.stem, "_valid": False, "_issues": e.issues,
                        "name": p.stem, "difficulty": None, "focus": [],
                        "est_minutes": None, "techniques": []})
        except FileNotFoundError:
            continue
    return out
