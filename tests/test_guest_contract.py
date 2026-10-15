"""Plan 13 phase 3 — guest/template contract (fast layer).

Source/config-level proofs for the role-key policy, attacker capture +
runner boundary, web/DB tier separation, reproducible base pin and the
deploy-time DB provisioning plan. Booting the real artifacts stays with
the images gate; these tests fail fast when the GENERATED contracts drift.
"""
from __future__ import annotations

import json
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------- #
# role key policy
# --------------------------------------------------------------------------- #

def _keys(*, emergency=True):
    keys = {
        "runner": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIRunner runner@lab",
        "bastion": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBastion bastion@lab",
        "mgmt": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMgmt mgmt@lab",
    }
    if emergency:
        keys["emergency"] = ("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEmerg "
                             "emergency@lab")
    return keys


def test_runner_key_only_on_attacker_bastion_only_on_defenders():
    from infra.images.role_keys import resolve_role_keys
    keys = _keys(emergency=False)
    atk = resolve_role_keys("attacker", keys)
    assert atk["attacker"].startswith("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIRunner")
    assert "Bastion" not in atk.get("attacker", "")  # bastion never lands here
    assert "defender" not in atk                     # no defender user on attacker
    web = resolve_role_keys("mojang-web-local", keys)
    assert "Bastion" in web["defender"]
    assert "Runner" not in json.dumps(web)  # runner key NEVER on defenders


def test_emergency_requires_explicit_flag_and_unknown_principals_refused():
    from infra.images.role_keys import KeyPolicyError, resolve_role_keys
    with pytest.raises(KeyPolicyError, match="emergency"):
        resolve_role_keys("attacker", _keys())  # manifest includes emergency
    ok = resolve_role_keys("attacker", _keys(), include_emergency=True)
    assert "Emerg" in ok["emergency"]
    with pytest.raises(KeyPolicyError, match="unknown key principal"):
        resolve_role_keys("attacker", {"operator": "ssh-ed25519 AAAA x"})


def test_private_key_and_placeholder_refused_deduplicated():
    from infra.images.role_keys import (KeyPolicyError, bake_script,
                                        resolve_role_keys)
    with pytest.raises(KeyPolicyError, match="PRIVATE"):
        resolve_role_keys("attacker", {
            "runner": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n"})
    with pytest.raises(KeyPolicyError, match="placeholder"):
        resolve_role_keys("attacker", {"runner": "ssh-ed25519 CHANGE_ME"})
    dup = {"runner": "ssh-ed25519 AAAASAMEKEY runner@lab",
           "mgmt": "ssh-ed25519 AAAASAMEKEY mgmt@lab"}  # same key, two principals
    out = resolve_role_keys("attacker", dup)
    # both principals place onto DIFFERENT users; identical key line per user
    # appears exactly once (dedup happens per user in bake_script)
    script = bake_script("attacker", dup)
    assert script.count("ssh-ed25519 AAAASAMEKEY") >= 2  # per placed user
    assert "awk '!seen[$0]++'" in script                 # dedupe guard present
    assert set(out) == {"attacker", "root"}
    # the management channel dials root: the mgmt principal MUST resolve to
    # the admin account on every role, or provisioning/verification cannot
    # authenticate (fail-closed mapping, not an unprivileged account).
    for role in ("attacker", "mojang-web-local", "mojang-web-db"):
        assert resolve_role_keys(role, {"mgmt": _keys()["mgmt"]}) == {
            "root": _keys()["mgmt"] + "\n"}


def test_bake_script_atomic_and_role_scoped():
    from infra.images.role_keys import bake_script
    script = bake_script("attacker", _keys(), include_emergency=True)
    assert "install -m 0600 -o attacker -g attacker" in script
    assert "mv" in script or "install" in script  # atomic write
    assert "Bastion" not in script  # bastion never baked on attacker


# --------------------------------------------------------------------------- #
# generated user-data contracts
# --------------------------------------------------------------------------- #

def test_attacker_build_carries_capture_and_boundary():
    from infra.images import guest_build, guest_userdata
    payload = {"/etc/sparring-range/role": "attacker\n"}
    pins = ["auditd=1", "openssh-server=1", "curl=1", "qemu-guest-agent=1",
            "ufw=1"]
    ud = guest_userdata.attacker_build_user_data(payload, pins, _keys())
    # capture path identical to defender guests
    assert "sparring-shipper.service" in ud and "auditd.rules" in ud
    assert "systemctl enable --now auditd sparring-shipper" in ud
    # runner boundary: cgroup delegation + scoped AppArmor, reboot-persistent
    assert "sr-runner-cgroup.service" in ud
    assert "apparmor.d/usr.bin.unshare" in ud
    assert "RUNNER_CGROUP_ROOT=/sys/fs/cgroup/sr-runner" in ud
    assert "apparmor_parser" in ud
    # role keys via policy, never one key everywhere
    assert "sr-bake-keys.sh" in ud
    assert "Runner" in ud and "Bastion" not in ud
    # pinned attacker packages include auditd
    assert "auditd" in guest_build.ATTACKER_PACKAGES


def test_setup_script_separates_web_and_db_tiers():
    from infra.images.guest_userdata import _setup_script
    db = _setup_script("mojang-web-db", ["mysql-server", "auditd"])
    web = _setup_script("mojang-web-local", ["nginx", "auditd"])
    # DB tier: database only — never enables the web app
    assert "enable --now auditd sparring-shipper ssh mysql" in db
    assert "nginx" not in db.split("enable --now")[1].split("\n")[0]
    assert "ufw allow 3306/tcp" in db
    # Web tier: app enabled, mysql disabled
    assert "enable --now auditd sparring-shipper nginx mojang-web ssh" in web
    assert "disable --now mysql" in web
    assert "ufw allow 80/tcp" in web


def test_verify_checks_are_role_separated():
    from infra.images.guest_userdata import _verify_checks
    db = _verify_checks("mojang-web-db")
    web = _verify_checks("mojang-web-local")
    assert "NO-WEB-APP" in db and "CATALOGUE" not in db
    assert "MYSQL-COUNT" in db
    assert "CATALOGUE" in web and "NO-MYSQL-ENABLED" in web
    assert "MYSQL-COUNT" not in web


def test_finalize_is_role_aware_and_refuses_private_material():
    from infra.images import guest_userdata
    from infra.images.role_keys import KeyPolicyError
    ud = guest_userdata.finalize_user_data("mojang-web-local", _keys())
    assert "Bastion" in ud          # bastion -> defender on web roles
    assert "Runner" not in ud       # runner key NEVER baked on web roles
    assert "SCRUB" in ud and "ssh_host_*" in ud
    with pytest.raises(KeyPolicyError):
        guest_userdata.finalize_user_data(
            "attacker", {"runner": "-----BEGIN OPENSSH PRIVATE KEY-----"})


def test_payload_trees_separate_db_from_web_app():
    db = REPO / "infra/images/payloads/mojang-web-db"
    web = REPO / "infra/images/payloads/mojang-web-local"
    assert not (db / "srv/mojang-web/app.py").exists()
    assert not (db / "etc/nginx").exists()
    assert (db / "etc/mysql/mojang/schema.sql").exists()
    assert (web / "srv/mojang-web/app.py").exists()


def test_base_image_pin_is_immutable_retained_not_moving_current():
    manifest = json.loads((REPO / "infra/images/manifest.json").read_text())
    base = manifest["base_image"]
    assert "/current/" not in base["source_url"]
    assert base["sha256"] and base["size_bytes"] > 0
    # dated retained directory: .../noble/<YYYYMMDD>/...
    parts = base["source_url"].split("/")
    assert parts[-2].isdigit() and len(parts[-2]) == 8


# --------------------------------------------------------------------------- #
# deploy-time DB provisioning plan
# --------------------------------------------------------------------------- #

def _spec():
    return {
        "topology": {"hosts": [
            {"name": "attacker", "ip": "10.66.0.9"},
            {"name": "web01", "ip": "10.66.0.10", "db_ref": "db01"},
            {"name": "db01", "ip": "10.66.0.11"},
        ]}
    }


def test_db_plan_orders_db_before_web_and_validates():
    from srplatform.scenario_engine.guest_config import plan_db_provisioning
    plan = plan_db_provisioning(_spec())
    assert [p["kind"] for p in plan] == ["db", "web"]
    assert plan[0]["web_sources"] == [("web01", "10.66.0.10")]
    assert plan[1]["db_ip"] == "10.66.0.11"
    bad = {"topology": {"hosts": [{"name": "w", "ip": "999.1.1.1",
                                   "db_ref": "nope"}]}}
    with pytest.raises(ValueError):
        plan_db_provisioning(bad)


def test_db_provision_command_restricts_listener_grants_firewall():
    from srplatform.scenario_engine import guest_config as gc
    plan = gc.plan_db_provisioning(_spec())[0]
    cmd = gc.db_provision_command(plan, "deadbeef" * 4)
    # listener: loopback probe + OWNED range address only
    assert "bind-address = 127.0.0.1,10.66.0.11" in cmd
    # grants ONLY for the owned web source + loopback, SELECT only
    assert "CREATE USER IF NOT EXISTS 'mojang_reader'@'10.66.0.10'" in cmd
    assert "GRANT SELECT ON mojang.* TO 'mojang_reader'@'10.66.0.10'" in cmd
    assert "GRANT ALL" not in cmd
    # firewall narrowed to the owned source; broad template rule removed
    assert "ufw delete allow 3306/tcp" in cmd
    assert "ufw allow from 10.66.0.10 to any port 3306 proto tcp" in cmd
    # read-back proves the credential and the grant rows
    assert "--host=127.0.0.1" in cmd and "SELECT 1" in cmd
    assert "mysql.user" in cmd and "grep -q 10.66.0.10" in cmd


def test_web_provision_command_targets_owned_db_ip_atomically():
    from srplatform.scenario_engine import guest_config as gc
    plan = gc.plan_db_provisioning(_spec())[1]
    cmd = gc.web_provision_command(plan, "cafe" * 8)
    assert "MOJANG_MYSQL_HOST=10.66.0.11" in cmd
    assert "MOJANG_DATA_BACKEND=mysql" in cmd
    assert ".tmp" in cmd and "mv" in cmd          # atomic replace
    assert "systemctl restart mojang-web" in cmd
    assert "grep -q 'MOJANG_MYSQL_HOST=10.66.0.11'" in cmd  # read-back


def test_reader_password_is_fresh_and_reused_on_resume():
    from srplatform.scenario_engine.guest_config import reader_password
    pw1 = reader_password([], "db01")
    assert len(pw1) == 32 and pw1 != reader_password([], "db01")
    stored = [{"host": "db01", "db_reader_password": pw1}]
    assert reader_password(stored, "db01") == pw1  # resume reuses generation


def test_real_scenario_declares_db_ref_and_plan_resolves():
    import yaml
    from srplatform.scenario_engine.guest_config import plan_db_provisioning
    spec = yaml.safe_load(
        (REPO / "scenarios/mojang-web-db-01.yaml").read_text())
    plan = plan_db_provisioning(spec)
    assert [p["kind"] for p in plan] == ["db", "web"]
    web_local = yaml.safe_load(
        (REPO / "scenarios/mojang-web-01.yaml").read_text())
    assert plan_db_provisioning(web_local) == []  # no DB tier -> no plan


def test_orchestrator_wires_provisioning_pass():
    src = (REPO / "srplatform/scenario_engine/orchestrator.py").read_text()
    assert "_provision_guest_configs(db, dep, spec, resources, session_id)" in src
    # and it runs BEFORE readiness/ready, after the host loop
    assert src.index("_provision_guest_configs") < src.index('dep.status = "ready"')
    # no management channel: VISIBLE skip (event), never silent — same
    # contract as telemetry enrollment; enforced readiness refuses it later
    assert "guest_config_skipped" in src
    # a channel that ANSWERS with a nonzero exit still fails the deployment
    assert "guest config provisioning failed" in src


def test_template_build_defaults_cover_all_three_roles():
    from infra.images import pve_template_build as ptb
    import inspect
    src = inspect.getsource(ptb.main)
    assert "mojang-web-db" in src
    assert "--runner-key" in src and "--bastion-key" in src and "--mgmt-key" in src
    assert "ROLE_VMID" in src and set(ptb.ROLE_VMID.values()) >= {9005, 9011, 9012}
