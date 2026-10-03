"""Minimal YAML scenario loader (full schema validation lands in M4).

The loader is the only thing that reads scenarios/*.yaml; the orchestrator and
API consume its output. Field contract is the plan's target shape (Part 5/M4).
"""
from __future__ import annotations

from pathlib import Path

import yaml

from srplatform.settings import get_settings


def scenarios_dir() -> Path:
    # repo root = parents of srplatform/
    return Path(__file__).resolve().parents[2] / "scenarios"


def load_scenario(scenario_id: str) -> dict:
    path = scenarios_dir() / f"{scenario_id}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"scenario '{scenario_id}' not found at {path}")
    spec = yaml.safe_load(path.read_text())
    # Minimum the orchestrator needs; M4's validator enforces the full contract.
    for field in ("id", "topology"):
        if field not in spec:
            raise ValueError(f"scenario {scenario_id}: missing required field '{field}'")
    if spec["id"] != scenario_id:
        raise ValueError(f"scenario file {path.name}: id '{spec['id']}' != filename")
    hosts = spec["topology"].get("hosts") or []
    if not hosts:
        raise ValueError(f"scenario {scenario_id}: topology.hosts is empty")
    for h in hosts:
        for field in ("name", "template_vmid", "ip"):
            if field not in h:
                raise ValueError(f"scenario {scenario_id}: host entry missing '{field}'")
    return spec


def list_scenarios() -> list[dict]:
    out = []
    for p in sorted(scenarios_dir().glob("*.yaml")):
        try:
            out.append(load_scenario(p.stem))
        except ValueError:
            continue  # skip malformed for the library listing (validator reports them)
    return out
