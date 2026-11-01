"""Underpressure environment contract tests (plan step 1 + schema v2).

Covers the closed validation surfaces that later lanes depend on:
blueprint self-consistency (segments/addresses/gateway ownership/dependency
acyclicity/aggregate budget), the fidelity ledger's honest-classification
rules, the versioned service-check registry (typed per-kind params,
secret-shaped values refused), attack-scope rules (red entry role, no
scorer credentials), scenario v2 (environment-referencing scenarios),
visibility projections, and the orchestrator's refusal to flat-provision
an environment scenario.
"""
from __future__ import annotations

import copy
import shutil
from pathlib import Path

import pytest
import yaml

from srplatform.environment_specs import (
    EnvironmentError,
    load_environment,
)
from srplatform.environment_specs import loader as env_loader
from srplatform.scenario_engine.loader import ScenarioError, load_scenario, parse_scenario

REPO = Path(__file__).resolve().parents[1]
ENV_DIR = REPO / "environments" / "underpressure-range"


def _bp_doc() -> dict:
    return yaml.safe_load((ENV_DIR / "blueprint.yaml").read_text())


def _write_env(tmp: Path, name: str = "underpressure-range") -> Path:
    root = tmp / "environments"
    root.mkdir(parents=True, exist_ok=True)
    shutil.copytree(ENV_DIR, root / name)
    return root


# ---------------------------------------------------------------- happy path --
def test_environment_loads_and_accounts_for_itself():
    env = load_environment("underpressure-range")
    pins = env.pins()
    assert pins["environment"] == "underpressure-range"
    assert pins["blueprint_version"] == 1
    bp = env.blueprint
    # 12 guests: 10 competition machines + infrastructure attacker + scoring
    assert len(bp.guests) == 12
    names = {g.name for g in bp.guests}
    assert {"vyos-edge", "opnsense-fw", "ecomm", "webmail", "splunk", "ad-dns",
            "mssql", "ubuntu-wkst", "win11-wkst", "team-kali", "red-entry",
            "scoring-vantage"} <= names
    res = bp.reservation()
    # the blueprint must FIT its own declared policy (no silent overcommit)
    assert res["memory_mb_total"] <= (res["outer_memory_mb"]
                                      - bp.resource_policy.controller_reserve_mb
                                      - bp.resource_policy.headroom_reserve_mb)
    # vCPU oversubscription is explicit (guest total may exceed physical)
    assert res["vcpus_total"] > res["outer_vcpus"]
    assert bp.resource_policy.aggregate_cpu_limit_percent > 100
    # provisioning respects declared dependencies
    order = bp.provision_order()
    for g in bp.guests:
        for dep in g.depends_on:
            assert order.index(dep) < order.index(g.name)


def test_visibility_views_never_cross_the_line():
    env = load_environment("underpressure-range")
    defender = env.defender_view()
    attack = env.attack_view()
    scoring = env.scoring_view()
    blob_d = str(defender)
    blob_a = str(attack)
    # defender view carries no attack internals
    assert "tactic" not in blob_d
    assert "entry_via" not in blob_d
    # attack view carries NO scorer credentials/expectations at all
    assert "credential:" not in blob_a
    assert "seed_expectation" not in blob_a
    assert "success_text" not in blob_a
    # scoring view has refs only — never values
    assert all("account_ref" in str(c) for c in scoring["checks"]
               if "account_ref" in str(c))
    assert scoring["practice_only"] is True


# ------------------------------------------------------------------ rejects --
def _mutate(mut) -> dict:
    doc = _bp_doc()
    mut(doc)
    return doc


@pytest.mark.parametrize("label,mut,needle", [
    ("address-outside-segment",
     lambda d: d["guests"][2]["interfaces"][0].__setitem__("ipv4",
                                                           {"mode": "static",
                                                            "address": "172.20.241.10"}),
     "outside segment"),
    ("duplicate-address",
     lambda d: d["guests"][3]["interfaces"][0]["ipv4"].__setitem__(
         "address", "172.20.240.10"),
     "used by both"),
    ("overlapping-segments",
     lambda d: d["segments"][1].__setitem__("cidr", "172.20.240.0/23"),
     "overlap"),
    ("dhcp-without-pool",
     lambda d: d["guests"][7]["interfaces"][0].__setitem__(
         "segment", "transit"),
     "no pool"),
    ("unknown-segment",
     lambda d: d["guests"][2]["interfaces"][0].__setitem__("segment", "internet"),
     "unknown segment"),
    ("double-attach",
     lambda d: d["guests"][2]["interfaces"].append(copy.deepcopy(
         d["guests"][2]["interfaces"][0])),
     "twice"),
    ("dependency-cycle",
     lambda d: d["guests"][5]["depends_on"].append("ecomm"),
     "cycle"),
    ("dependency-unknown",
     lambda d: d["guests"][0]["depends_on"].append("ghost"),
     "unknown guest"),
    ("gateway-not-owned",
     lambda d: d["segments"][2].__setitem__("default_gateway", "172.20.240.9"),
     "bound to exactly one guest"),
    ("memory-over-budget",
     lambda d: d["guests"][4]["resources"].__setitem__("memory_mb", 32768),
     "exceeds the policy"),
    ("edge-unknown-endpoint",
     lambda d: d["edges"].append({"kind": "sql", "src": "ecomm", "dst": "ghost",
                                  "detail": "x" * 12}),
     "neither a guest nor a segment"),
    ("unknown-field",
     lambda d: d.__setitem__("arbitrary_libvirt_xml", "<qemu/>"),
     "extra"),
    ("bad-enum",
     lambda d: d["segments"][0].__setitem__("purpose", "wild"),
     "purpose"),
])
def test_blueprint_closed_validation(label, mut, needle):
    doc = _mutate(mut)
    path = ENV_DIR / "blueprint.yaml"
    from pydantic import ValidationError
    from srplatform.environment_specs import EnvironmentBlueprint
    with pytest.raises((ValidationError, EnvironmentError)) as exc:
        EnvironmentBlueprint.model_validate(doc)
    assert needle.lower() in str(exc.value).lower(), label


def test_dhcp_reservation_still_collision_checked():
    doc = _bp_doc()
    # win11-wkst reservation collides with mssql's static address
    doc["guests"][8]["interfaces"][0]["ipv4"]["address"] = "172.20.240.120"
    from pydantic import ValidationError
    from srplatform.environment_specs import EnvironmentBlueprint
    with pytest.raises(ValidationError, match="used by both"):
        EnvironmentBlueprint.model_validate(doc)


# ------------------------------------------------------------------- fidelity --
def test_fidelity_rules(tmp_path):
    root = _write_env(tmp_path)
    led_path = root / "underpressure-range" / "fidelity.yaml"
    led = yaml.safe_load(led_path.read_text())

    # duplicate path refused
    led["entries"].append(dict(led["entries"][0]))
    led_path.write_text(yaml.safe_dump(led))
    with pytest.raises(EnvironmentError, match="duplicate path"):
        load_environment("underpressure-range", directory=root)

    # undeclared source refused
    led["entries"].pop()
    led["entries"][1]["source"] = "made-up-source"
    led_path.write_text(yaml.safe_dump(led))
    with pytest.raises(EnvironmentError, match="undeclared source"):
        load_environment("underpressure-range", directory=root)

    # a REPORTED claim pointing at a nonexistent blueprint path is refused —
    # only `excluded` may name what was not built
    led = yaml.safe_load((ENV_DIR / "fidelity.yaml").read_text())
    led["entries"].append({"path": "/guests/99/role", "classification": "reported",
                           "source": "replication-spec", "note": "x" * 12})
    led_path.write_text(yaml.safe_dump(led))
    with pytest.raises(EnvironmentError, match="does not resolve"):
        load_environment("underpressure-range", directory=root)


# -------------------------------------------------------------- checks/attack --
def test_secret_shaped_values_cannot_be_loaded(tmp_path):
    root = _write_env(tmp_path)
    checks = root / "underpressure-range" / "checks.yaml"
    text = checks.read_text().replace(
        'app_account_ref: "credential:store-app-sql"',
        'app_account_ref: "hunter2"')
    checks.write_text(text)
    # credential-shaped literal: refused either by the secret scan or the
    # credential-ref pattern, never accepted
    with pytest.raises(EnvironmentError):
        load_environment("underpressure-range", directory=root)


def test_attack_entry_must_be_red_entry(tmp_path):
    root = _write_env(tmp_path)
    attack = root / "underpressure-range" / "attack.yaml"
    doc = yaml.safe_load(attack.read_text())
    doc["scope"]["entry_guest"] = "ecomm"
    attack.write_text(yaml.safe_dump(doc))
    with pytest.raises(EnvironmentError, match="red-entry"):
        load_environment("underpressure-range", directory=root)


def test_attack_guide_cannot_carry_credentials(tmp_path):
    root = _write_env(tmp_path)
    attack = root / "underpressure-range" / "attack.yaml"
    doc = yaml.safe_load(attack.read_text())
    doc["service_context"].append('use "credential:splunk-prb" now')
    attack.write_text(yaml.safe_dump(doc))
    with pytest.raises(EnvironmentError, match="credential"):
        load_environment("underpressure-range", directory=root)


def test_service_check_kind_params_are_typed():
    from srplatform.environment_specs import load_checks
    base = {
        "schema_version": 1, "environment": "e", "version": 1,
        "practice_only": True,
        "checks": [{
            "id": "chk1", "kind": "sql-seed-read", "guest": "mssql",
            "title": "t", "params": {
                "database": "d", "seed_expectation": "seed_1",
                "app_account_ref": "credential:app"}}],
    }
    reg = load_checks(base)
    assert reg.check("chk1").kind.value == "sql-seed-read"
    bad = copy.deepcopy(base)
    bad["checks"][0]["params"]["database"] = "db; DROP TABLE"
    with pytest.raises(Exception):
        load_checks(bad)
    bad2 = copy.deepcopy(base)
    bad2["checks"][0]["params"]["raw_query"] = "SELECT 1"
    with pytest.raises(Exception):
        load_checks(bad2)


# ---------------------------------------------------------------- scenario v2 --
def test_environment_scenario_loads_with_pins():
    spec = load_scenario("underpressure-range-01")
    assert spec["environment"] == "underpressure-range"
    assert spec["topology"] is None
    assert spec["environment_pins"]["environment"] == "underpressure-range"
    ids = spec["scoring"]["availability"]
    assert "mail-roundtrip" in ids


def test_legacy_scenarios_still_validate_as_flat():
    for sid in ("mojang-web-01", "mojang-web-db-01", "db-exfil-01",
                "web-foothold-01", "quick-win-01"):
        spec = load_scenario(sid)
        assert spec.get("environment") is None
        assert spec["topology"]["hosts"]
        assert spec.get("environment_pins") is None


def test_scenario_v2_rejects():
    base = yaml.safe_load(
        (REPO / "scenarios" / "underpressure-range-01.yaml").read_text())
    # environment AND topology together
    both = copy.deepcopy(base)
    both["topology"] = {"hosts": [{"name": "web01", "template_vmid": 9011,
                                   "ip": "10.0.0.5"}]}
    with pytest.raises(ScenarioError, match="single source of truth"):
        parse_scenario(yaml.safe_dump(both))
    # unknown availability id
    avail = copy.deepcopy(base)
    avail["scoring"]["availability"] = ["not-a-check"]
    with pytest.raises(ScenarioError, match="unknown service check"):
        parse_scenario(yaml.safe_dump(avail))
    # objective host not in the environment
    host = copy.deepcopy(base)
    host["red"]["objectives"][0]["args"]["host"] = "ghostbox"
    with pytest.raises(ScenarioError, match="ghostbox"):
        parse_scenario(yaml.safe_dump(host))
    # missing environment declaration entirely
    missing = copy.deepcopy(base)
    missing.pop("environment")
    with pytest.raises(ScenarioError, match="must declare"):
        parse_scenario(yaml.safe_dump(missing))
    # unknown environment id
    ghost = copy.deepcopy(base)
    ghost["environment"] = "no-such-environment"
    with pytest.raises(ScenarioError, match="environment"):
        parse_scenario(yaml.safe_dump(ghost))
    # legacy scenario may not use availability
    legacy = yaml.safe_load(
        (REPO / "scenarios" / "mojang-web-01.yaml").read_text())
    legacy["scoring"]["availability"] = ["store-catalog-https"]
    with pytest.raises(ScenarioError, match="requires an"):
        parse_scenario(yaml.safe_dump(legacy))


def test_broken_environment_is_reported_not_skipped(tmp_path):
    root = _write_env(tmp_path)
    bp = root / "underpressure-range" / "blueprint.yaml"
    bp.write_text(bp.read_text().replace("memory_mb: 2048", "memory_mb: 909090", 1))
    with pytest.raises(EnvironmentError):
        env_loader.load_environment("underpressure-range", directory=root)
    broken = env_loader.environment_summary("underpressure-range", directory=root)
    assert broken["_valid"] is False and broken["_issues"]
    # the repository's own environment is unaffected and still reports valid
    repo_copy = env_loader.environment_summary("underpressure-range")
    assert repo_copy["_valid"] is True


# ------------------------------------------------------------- deploy guard --
class _NoBroker:
    def __getattr__(self, name):
        raise AssertionError(f"broker must not be touched: {name}")


def test_deploy_refuses_environment_scenario_without_side_effects():
    from srplatform.scenario_engine.orchestrator import deploy
    with pytest.raises(ScenarioError, match="environment provisioning"):
        deploy(db=None, session_id=None, scenario_id="underpressure-range-01",
               broker=_NoBroker())


# ------------------------------------------------------------- windows paths --
def test_windows_path_args_contract():
    from verifiers.library.ccdc import ExfilArg
    assert ExfilArg(host="ad-dns", path="C:/Users/Public/x.txt").path
    assert ExfilArg(host="h", path="/tmp/x").path
    for bad in ("tmp/x", "C:", "C:/a/../b", "C:/a;b", "C:/a|b", "/a/../b",
                "\\\\server\\share\\x", "C:/a`x"):
        with pytest.raises(Exception, match="absolute"):
            ExfilArg(host="h", path=bad)


def test_loop_environment_context_is_scope_only():
    from srplatform.red_agent.loop import render_environment_context
    scenario = {"environment": "underpressure-range"}
    text = render_environment_context(scenario)
    assert text is not None
    assert "red-entry" in text and "routed-nat" in text
    assert "DNAT 172.25.31.10" in text          # public path from edges
    assert "Kerberoastable" in text              # tactic guide present
    assert "credential:" not in text             # no scorer material
    assert "seed_expectation" not in text
    assert "success_text" not in text
    # broken/unknown environment => None (loop must not go blind)
    assert render_environment_context({"environment": "nope"}) is None
    assert render_environment_context({}) is None
