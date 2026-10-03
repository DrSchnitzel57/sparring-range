"""M4 acceptance tests — Part 5/M4 'Accept when':

  * a scenario defined ENTIRELY in YAML (no code changes) deploys, runs, and
    produces a score
  * adding a new objective is a YAML edit reusing an existing verifier
Plus the M4 deliverables themselves: metadata the M7 launcher filters on, the
validator, and verifiers that serve red AND blue.
"""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from infra.proxmox_client import FakeProxmox
from srplatform.api import deps
from srplatform.api.app import app
from srplatform.red_agent.loop import RedAgentLoop
from srplatform.red_agent.sandbox import FakeSandbox
from srplatform.red_agent.transport import TestClientTransport
from srplatform.scenario_engine.loader import ScenarioError, load_scenario, parse_scenario
from srplatform.scenario_engine.scoring import compute_blue_score
from tests.test_m3_acceptance import FakeLLM, tool


def test_m4_scenario_metadata_for_the_library():
    spec = load_scenario("db-exfil-01")
    assert spec["focus"] and spec["est_minutes"] and spec["techniques"]
    assert spec["difficulty"] == 2


def test_m4_validator_catches_broken_scenarios():
    base = {
        "id": "x", "name": "x", "difficulty": 1, "focus": [], "est_minutes": 1,
        "techniques": [], "topology": {"hosts": [{"name": "h", "template_vmid": 9001, "ip": "10.0.0.1"}]},
    }
    import yaml
    # unknown verifier id — an objective nobody could ever confirm
    bad = dict(base, red={"objectives": [{"id": "o", "verifier": "not_a_verifier", "args": {}}]})
    with pytest.raises(ScenarioError) as e:
        parse_scenario(yaml.safe_dump(bad))
    assert "not_a_verifier" in str(e.value)
    # non-integer points
    bad2 = dict(base, scoring={"blue_checks": [{"verifier": "firewall_enabled", "host": "h", "points": "lots"}]})
    with pytest.raises(ScenarioError):
        parse_scenario(yaml.safe_dump(bad2))
    # blue check on an unknown host
    bad3 = dict(base, scoring={"blue_checks": [{"verifier": "firewall_enabled", "host": "ghost", "points": 5}]})
    with pytest.raises(ScenarioError):
        parse_scenario(yaml.safe_dump(bad3))
    # a valid scenario passes
    parse_scenario(yaml.safe_dump(dict(base, red={"objectives": []})))


def test_m4_pure_yaml_scenario_deploys_runs_and_scores(migrated_db):
    fake = FakeProxmox()
    deps.set_proxmox(fake)
    try:
        c = TestClient(app)

        # DEPLOY: two hosts cloned from their golden templates
        r = c.post("/deploy/db-exfil-01")
        assert r.status_code == 200
        assert {h["host"] for h in r.json()["hosts"]} == {"web01", "db01"}
        assert any(call[1] == 9004 for call in fake.calls if call[0] == "CLONE")

        # RUN: scripted model; verifiers (not the model) confirm three objectives
        sid = c.post("/sessions", json={"scenario_id": "db-exfil-01"}).json()["session_id"]
        sb = FakeSandbox(script={
            "nmap": (0, "Nmap: 10.66.0.10 web01, 10.66.0.11 db01"),
            "exploit.py": lambda cmd: _plant(sb, "/root/flag_foothold.txt", "FLAG{fh}") or (0, "pwned"),
            "dump": lambda cmd: _plant(sb, "/tmp/exfil/loot", "user,ssn,ssn") or (0, "looted"),
            "router.sh": lambda cmd: (sb.set_state("db01", "systemctl list-unit-files mysql-router",
                                                   (0, "mysql-router.service enabled static")) or (0, "installed")),
        })
        res = RedAgentLoop(sid, "db-exfil-01", TestClientTransport(c), FakeLLM([
            tool("scan", "nmap -sn 10.66.0.0/24"),
            tool("exploit web", "python3 exploit.py --target web01"),
            tool("loot", "python3 dump.py --db db01 > /tmp/exfil/loot"),
            tool("persist db", "bash router.sh"),
        ]), sb, max_steps=10, compress_after=20, keep_recent=4).run()
        assert res["complete"] and set(res["achieved"]) == {"foothold", "loot", "persistence"}

        # SCORE: blue checks on the same hosts, same verifier code
        sb.set_state("web01", "awk -F:", (0, ""))                       # no rogue admin
        sb.set_state("web01", "systemctl is-active firewalld", (0, "active\n"))
        sb.set_state("db01", "cut -d:", (0, "root\nmysql\n"))           # no unknown accounts
        sb.set_state("db01", "sha256sum", (0, "7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d6772842dd42728a0f1383e  ibdata1\n"))
        sc = compute_blue_score("db-exfil-01", _ctx(sb))
        assert sc["total"] == 40 and sc["earned"] == 40, sc["items"]

        # blue misses one check -> score reflects truth
        sb.set_state("web01", "systemctl is-active firewalld", (0, "inactive\n"))
        sc2 = compute_blue_score("db-exfil-01", _ctx(sb))
        assert sc2["earned"] == 35
    finally:
        deps.set_proxmox(None)


def test_m4_adding_an_objective_is_a_yaml_edit_only(migrated_db, tmp_path):
    """Drop a new objective into a scenario (reusing the flag_file_present
    verifier with new args) — zero code changes — and the loop honors it."""
    import yaml

    spec = dict(load_scenario("web-foothold-01"))
    spec["id"] = "web-foothold-01b"
    spec["red"] = dict(spec["red"])
    spec["red"]["objectives"] = list(spec["red"]["objectives"]) + [
        {"id": "second_flag", "verifier": "flag_file_present",
         "args": {"host": "web01", "path": "/root/flag_second.txt"}}]
    scen = tmp_path / "web-foothold-01b.yaml"
    scen.write_text(yaml.safe_dump(spec))

    import srplatform.scenario_engine.loader as L
    orig_dir = L.scenarios_dir
    L.scenarios_dir = lambda: tmp_path
    try:
        c = TestClient(app)
        sid = c.post("/sessions", json={"scenario_id": "web-foothold-01b"}).json()["session_id"]
        sb = FakeSandbox(script={
            "exploit.py": lambda cmd: _plant(sb, "/root/flag_foothold.txt", "FLAG{a}") or (0, "ok"),
            "deploy2.sh": lambda cmd: _plant(sb, "/root/flag_second.txt", "FLAG{b}") or (0, "ok"),
            "persist.sh": lambda cmd: (sb.fs.setdefault("web01", {}).__setitem__("/etc/cron.d/x", "cron entry") or (0, "ok")),
        })
        res = RedAgentLoop(sid, "web-foothold-01b", TestClientTransport(c), FakeLLM([
            tool("pwn", "python3 exploit.py --target 10.66.0.10"),
            tool("second", "bash deploy2.sh"),
            tool("cron", "bash persist.sh"),
        ]), sb, max_steps=10, compress_after=20, keep_recent=4).run()
        assert res["complete"], res
        assert "second_flag" in res["achieved"], "YAML-added objective must be honored and verified"
    finally:
        L.scenarios_dir = orig_dir


# ---------------------------------------------------------------- helpers
def _plant(sb, path, content):
    sb.fs.setdefault("web01", {})[path] = content
    return None  # so `callable() or (code, out)` yields (0, ...)


def _ctx(sb):
    from verifiers.base import Context
    return Context(exec=sb.verifier_exec)
