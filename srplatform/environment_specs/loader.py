"""Environment directory loader — closed file set, cross-file validation.

Layout (all repository-owned, non-secret):

    environments/<id>/blueprint.yaml   the typed blueprint (segments/guests)
    environments/<id>/fidelity.yaml    deviation ledger
    environments/<id>/checks.yaml      service-check registry + practice rubric
    environments/<id>/defender.md      public defender description (markdown)
    environments/<id>/attack.yaml      private attack scope + tactic guide

IDs are path-safe (mirrors the scenario loader rule). Every file is scanned
for credential-shaped values before parsing; the attack guide must never
contain scorer credentials; checks' guest references must resolve against
the blueprint; fidelity entries (except `excluded`) must resolve inside the
blueprint document. A half-wired environment FAILS to load — there is no
partial success path.
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from .attack import AttackGuide
from .blueprint import EnvironmentBlueprint, EnvironmentError
from .checks import ServiceCheckRegistry, load_checks
from .fidelity import FidelityClass, FidelityLedger

_SECRETY_VALUE = re.compile(
    r"(?i)\b(password|passwd|token|secret|api[_-]?key|private[_-]?key)\s*[:=]\s*\S")
_PEM = "BEGIN "

DEFENDER_MAX_BYTES = 32_000


def environments_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "environments"


def environment_ids(directory: Path | None = None) -> list[str]:
    root = directory or environments_dir()
    if not root.is_dir():
        return []
    return sorted(p.name for p in root.iterdir()
                  if p.is_dir() and (p / "blueprint.yaml").is_file())


@dataclass(frozen=True)
class LoadedEnvironment:
    blueprint: EnvironmentBlueprint
    fidelity: FidelityLedger
    checks: ServiceCheckRegistry
    attack: AttackGuide
    defender_description: str

    @property
    def id(self) -> str:
        return self.blueprint.id

    # ----------------------------------------------------------- versions --
    def pins(self) -> dict:
        """Version pins a session freezes when it binds this environment."""
        return {
            "environment": self.blueprint.id,
            "blueprint_schema": self.blueprint.schema_version,
            "blueprint_version": self.blueprint.version,
            "fidelity_version": self.fidelity.version,
            "checks_version": self.checks.version,
            "attack_version": self.attack.version,
        }

    # --------------------------------------------------------- visibility --
    def defender_view(self) -> dict:
        """Centralized environment authorization applies THIS plus membership
        checks in the API layer; nothing red or scorer-internal is reachable
        through any visibility view by construction."""
        return {
            "pins": self.pins(),
            "name": self.blueprint.name,
            "domain": self.blueprint.domain,
            "description": self.blueprint.description,
            "guests": [
                {"name": g.name, "display_name": g.display_name,
                 "role": g.role.value, "os": g.os.value,
                 "segments": [i.segment for i in g.interfaces],
                 "services": [s.value for s in g.services]}
                for g in self.blueprint.guests],
            "segments": [{"name": s.name, "purpose": s.purpose.value,
                          "cidr": s.cidr} for s in self.blueprint.segments],
            "description_md": self.defender_description,
        }

    def attack_view(self) -> dict:
        """The authorized-scope projection handed to the offensive AI:
        scope + service context + tactics only."""
        return {
            "pins": self.pins(),
            "domain": self.blueprint.domain,
            "scope": self.attack.scope.model_dump(mode="json"),
            "service_context": self.attack.service_context,
            "tactics": [t.model_dump(mode="json") for t in self.attack.tactics],
        }

    def scoring_view(self) -> dict:
        """Trusted scoring vantage input: availability transactions and the
        practice rubric. Includes credential REFS (names, never values)."""
        return {
            "pins": self.pins(),
            "practice_only": self.checks.practice_only,
            "checks": [c.model_dump(mode="json") for c in self.checks.checks],
            "tasks": [t.model_dump(mode="json") for t in self.checks.tasks],
        }


# ------------------------------------------------------------------ load ----
def _secret_scan(text: str, where: str) -> None:
    if _PEM in text and "PRIVATE KEY" in text:
        raise EnvironmentError([f"{where}: private key material is forbidden"])
    m = _SECRETY_VALUE.search(text)
    if m:
        raise EnvironmentError(
            [f"{where}: credential-shaped value near {m.group(0)!r} — "
             f"environment documents are non-secret; use credential:<ref> "
             f"names resolved by the protected verifier path"])


def _read_yaml(path: Path) -> dict:
    text = path.read_text()
    _secret_scan(text, path.name)
    data = yaml.safe_load(text)
    if not isinstance(data, dict):
        raise EnvironmentError([f"{path.name}: top level must be a mapping"])
    return data


def _resolve_path(doc: dict, tokens: list[str]) -> bool:
    node = doc
    for tok in tokens:
        if isinstance(node, list):
            if not tok.isdigit() or int(tok) >= len(node):
                return False
            node = node[int(tok)]
        elif isinstance(node, dict) and tok in node:
            node = node[tok]
        else:
            return False
    return True


def _validate_fidelity_paths(fidelity: FidelityLedger, blueprint_doc: dict) -> list[str]:
    issues: list[str] = []
    for e in fidelity.entries:
        if e.classification == FidelityClass.EXCLUDED:
            continue  # describes what was intentionally NOT built
        if not _resolve_path(blueprint_doc, e.path.lstrip("/").split("/")):
            issues.append(f"fidelity: path {e.path} does not resolve inside "
                          f"blueprint.yaml (classification "
                          f"{e.classification.value} requires a real path; use "
                          f"'excluded' only for intentional non-reproduction)")
    return issues


def _validate_check_bindings(env_id: str, blueprint: EnvironmentBlueprint,
                             checks: ServiceCheckRegistry) -> list[str]:
    issues: list[str] = []
    if checks.environment != env_id:
        issues.append(f"checks: environment {checks.environment!r} != {env_id!r}")
    guest_names = {g.name for g in blueprint.guests}
    for c in checks.checks:
        if c.guest not in guest_names:
            issues.append(f"checks: check {c.id}: guest {c.guest!r} not in blueprint")
        for dep in c.depends_on_guests:
            if dep not in guest_names:
                issues.append(f"checks: check {c.id}: dependency guest {dep!r} "
                              f"not in blueprint")
    return issues


def _validate_attack(env_id: str, blueprint: EnvironmentBlueprint,
                     attack: AttackGuide) -> list[str]:
    issues: list[str] = []
    if attack.environment != env_id:
        issues.append(f"attack: environment {attack.environment!r} != {env_id!r}")
    guest_names = {g.name for g in blueprint.guests}
    segment_names = {s.name for s in blueprint.segments}
    scope = attack.scope
    if scope.entry_guest not in guest_names:
        issues.append(f"attack: entry_guest {scope.entry_guest!r} not in blueprint")
    for t in scope.target_guests:
        if t not in guest_names:
            issues.append(f"attack: target guest {t!r} not in blueprint")
    for s in scope.allowed_segments:
        if s not in segment_names:
            issues.append(f"attack: allowed segment {s!r} not in blueprint")
    from .blueprint import GuestRole
    entry = blueprint.guest(scope.entry_guest) if scope.entry_guest in guest_names else None
    if entry is not None and entry.role != GuestRole.RED_ENTRY:
        issues.append("attack: entry_guest must carry role red-entry — external "
                      "entry is proven through the replica's routed/NAT path, "
                      "never a foothold handed to the AI")
    if entry is not None:
        allowed = set(scope.allowed_segments)
        for iface in entry.interfaces:
            if iface.segment not in allowed:
                issues.append(
                    f"attack: entry_guest {entry.name} attaches to segment "
                    f"{iface.segment!r}, which scope.allowed_segments does "
                    f"not cover — the attacker's own position must be inside "
                    f"its declared scope")
    for i, t in enumerate(attack.tactics):
        for c in t.concerns:
            if c not in guest_names and c not in segment_names:
                issues.append(f"attack: tactics[{i}] concern {c!r} names neither "
                              f"a guest nor a segment")
    return issues


def load_environment(env_id: str, directory: Path | None = None
                     ) -> LoadedEnvironment:
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", env_id or ""):
        raise EnvironmentError([f"environment id {env_id!r} is not a safe identifier"])
    root = (directory or environments_dir()).resolve()
    env_dir = (root / env_id).resolve()
    if not env_dir.is_relative_to(root):
        raise EnvironmentError([f"environment id {env_id!r} escapes the environments root"])
    missing = [name for name in
               ("blueprint.yaml", "fidelity.yaml", "checks.yaml", "defender.md",
                "attack.yaml")
               if not (env_dir / name).is_file()]
    if missing:
        raise EnvironmentError([f"environment {env_id}: missing {', '.join(missing)}"])

    blueprint_doc = _read_yaml(env_dir / "blueprint.yaml")
    try:
        blueprint = EnvironmentBlueprint.model_validate(blueprint_doc)
    except Exception as exc:  # pydantic ValidationError
        raise EnvironmentError([f"blueprint.yaml: {exc}"]) from exc
    if blueprint.id != env_id:
        raise EnvironmentError([f"blueprint.yaml: id {blueprint.id!r} != directory {env_id!r}"])

    try:
        fidelity = FidelityLedger.model_validate(_read_yaml(env_dir / "fidelity.yaml"))
    except Exception as exc:
        raise EnvironmentError([f"fidelity.yaml: {exc}"]) from exc
    try:
        checks = load_checks(_read_yaml(env_dir / "checks.yaml"))
    except Exception as exc:
        raise EnvironmentError([f"checks.yaml: {exc}"]) from exc
    try:
        attack = AttackGuide.model_validate(_read_yaml(env_dir / "attack.yaml"))
    except Exception as exc:
        raise EnvironmentError([f"attack.yaml: {exc}"]) from exc

    defender = (env_dir / "defender.md").read_text()
    _secret_scan(defender, "defender.md")
    if len(defender.encode()) > DEFENDER_MAX_BYTES:
        raise EnvironmentError(["defender.md exceeds the 32 KB public description budget"])

    issues = []
    issues += _validate_fidelity_paths(fidelity, blueprint_doc)
    issues += _validate_check_bindings(env_id, blueprint, checks)
    issues += _validate_attack(env_id, blueprint, attack)
    if fidelity.environment != env_id:
        issues.append(f"fidelity: environment {fidelity.environment!r} != {env_id!r}")
    if issues:
        raise EnvironmentError([f"environment {env_id}: {i}" for i in issues])
    return LoadedEnvironment(blueprint=blueprint, fidelity=fidelity, checks=checks,
                             attack=attack, defender_description=defender)


def environment_summary(env_id: str, directory: Path | None = None) -> dict:
    """Library listing entry (validated; broken environments REPORTED, never
    silently skipped — mirrors list_scenarios)."""
    try:
        env = load_environment(env_id, directory=directory)
        return {"id": env.id, "_valid": True, "pins": env.pins(),
                "name": env.blueprint.name,
                "reservation": env.blueprint.reservation()}
    except EnvironmentError as exc:
        return {"id": env_id, "_valid": False, "_issues": exc.issues,
                "name": env_id}


def _json_default(o):  # pragma: no cover - helper
    if isinstance(o, (ipaddress.IPv4Address, ipaddress.IPv4Network)):
        return str(o)
    raise TypeError(type(o))


def dump_json(data) -> str:  # used by CLI/reporting
    return json.dumps(data, default=_json_default, sort_keys=True)
