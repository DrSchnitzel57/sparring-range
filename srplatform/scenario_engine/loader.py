"""YAML scenario loader + schema validator (M4).

The contract (plan Part 5): scenarios are PURE DATA. New capability = a new field
+ a verifier, not new machinery. The validator catches a broken scenario at load
time with a full issue list, including references to unknown verifier ids (which
would silently make an objective un-checkable).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from verifiers import registry

PHASES = ["recon", "initial-access", "priv-esc", "lateral", "persistence", "objectives"]


class ScenarioError(ValueError):
    def __init__(self, issues: list[str]):
        self.issues = issues
        super().__init__("; ".join(issues))


def scenarios_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "scenarios"


def load_scenario(scenario_id: str) -> dict:
    path = scenarios_dir() / f"{scenario_id}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"scenario '{scenario_id}' not found at {path}")
    return parse_scenario(path.read_text(), where=path.name)


def parse_scenario(text: str, where: str = "<string>") -> dict:
    spec = yaml.safe_load(text)
    validate_scenario(spec, where=where)
    return spec


def validate_scenario(spec: Any, where: str = "<spec>") -> list[str]:
    """Return [] when valid; raise ScenarioError with every issue otherwise."""
    issues: list[str] = []

    def bad(msg: str) -> None:
        issues.append(f"{where}: {msg}")

    if not isinstance(spec, dict):
        bad("scenario must be a mapping")
        raise ScenarioError(issues)

    for field in ("id", "name", "topology"):
        if field not in spec:
            bad(f"missing required field '{field}'")
    # library metadata (M7 launcher filters on these)
    for field, typ in (("difficulty", int), ("focus", list), ("est_minutes", int), ("techniques", list)):
        if field in spec and not isinstance(spec[field], typ):
            bad(f"'{field}' must be {typ.__name__}")

    if "id" in spec and where not in ("<string>", "<spec>") and Path(where).stem != spec["id"]:
        bad(f"id '{spec['id']}' != filename '{Path(where).stem}'")

    topo = spec.get("topology") or {}
    hosts = topo.get("hosts") or []
    if not hosts:
        bad("topology.hosts is empty")
    hostnames = set()
    for i, h in enumerate(hosts):
        for field in ("name", "template_vmid", "ip"):
            if field not in h:
                bad(f"topology.hosts[{i}] missing '{field}'")
        hostnames.add(h.get("name"))

    def check_verifier_use(prefix: str, entry: dict) -> None:
        vid = entry.get("verifier")
        if not vid:
            bad(f"{prefix}: missing 'verifier'")
            return
        if vid not in registry.REGISTRY:
            bad(f"{prefix}: unknown verifier '{vid}' (add it to verifiers/ or fix the name)")

    red = spec.get("red") or {}
    if red.get("start_phase") and red["start_phase"] not in PHASES:
        bad(f"red.start_phase '{red['start_phase']}' not in {PHASES}")
    for obj in red.get("objectives", []):
        if "id" not in obj:
            bad("red.objectives entry missing 'id'")
        check_verifier_use(f"red.objectives.{obj.get('id', '?')}", obj)

    scoring = spec.get("scoring") or {}
    for i, chk in enumerate(scoring.get("blue_checks", [])):
        if not isinstance(chk.get("points"), int):
            bad(f"scoring.blue_checks[{i}] needs integer 'points'")
        if chk.get("host") and hostnames and chk["host"] not in hostnames:
            bad(f"scoring.blue_checks[{i}] references unknown host '{chk['host']}'")
        check_verifier_use(f"scoring.blue_checks[{i}]", chk)

    if issues:
        raise ScenarioError(issues)
    return issues


def list_scenarios() -> list[dict]:
    out = []
    for p in sorted(scenarios_dir().glob("*.yaml")):
        try:
            out.append(yaml.safe_load(p.read_text()))
        except yaml.YAMLError:
            continue  # library listing skips unreadable files; load/validate reports them
    return out
