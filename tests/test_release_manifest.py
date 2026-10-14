"""Plan 13 phase 1: release manifest schema, inventory classification and
source-of-truth renderings. Infrastructure-free fast tests."""
from __future__ import annotations

import copy
import json
import pathlib

import pytest

from infra.release_manifest import (
    ABSENT,
    CONFLICTING,
    MATCHING,
    UNREADABLE,
    ManifestError,
    assess_capacity,
    classify_resource,
    inventory_report,
    load_manifest,
    render_broker_policy,
    render_env,
    validate_manifest,
)

EXAMPLE = pathlib.Path(__file__).resolve().parents[1] / "deploy" / "manifest.example.json"


def _raw() -> dict:
    return json.loads(EXAMPLE.read_text())


def _mutate(raw: dict, path: list, value) -> dict:
    node = raw
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return raw


# ---------------------------------------------------------------- loading --

def test_example_manifest_validates():
    manifest = load_manifest(EXAMPLE)
    assert manifest.version == 1
    assert manifest.clone_mode in ("full", "linked")
    assert {p.role for p in manifest.templates} == {
        "attacker", "mojang-web-local", "mojang-web-db"}
    assert manifest.range_gateway in manifest.range_network


def test_secret_material_is_rejected_not_stripped():
    raw = _mutate(_raw(), ["network", "bridge_password"], "hunter2")
    with pytest.raises(ManifestError, match="secret material is forbidden"):
        validate_manifest(raw)


def test_secret_key_nested_anywhere_is_rejected():
    raw = _raw()
    raw["trust"]["api_key"] = "abc"
    with pytest.raises(ManifestError, match="secret material is forbidden"):
        validate_manifest(raw)


def test_secret_inputs_may_only_reference_protected_paths():
    raw = _mutate(_raw(), ["secret_inputs", "owner_db_url"],
                  "postgres://owner:pw@db/app")
    with pytest.raises(ManifestError, match="absolute path"):
        validate_manifest(raw)


def test_placeholders_are_rejected():
    raw = _mutate(_raw(), ["pve", "node"], "CHANGE_ME")
    with pytest.raises(ManifestError, match="placeholder"):
        validate_manifest(raw)


def test_unsupported_manifest_version_refuses():
    raw = _mutate(_raw(), ["manifest_version"], 99)
    with pytest.raises(ManifestError, match="unsupported manifest_version"):
        validate_manifest(raw)


def test_gateway_outside_cidr_refuses():
    raw = _mutate(_raw(), ["network", "gateway"], "192.168.9.1")
    with pytest.raises(ManifestError, match="gateway"):
        validate_manifest(raw)


def test_overlapping_service_and_clone_vmid_refuses():
    raw = _mutate(_raw(), ["service_vms", "broker", "vmid"], 9100)
    with pytest.raises(ManifestError, match="clone VMID window overlaps"):
        validate_manifest(raw)


def test_overlapping_service_and_template_vmid_refuses():
    raw = _mutate(_raw(), ["service_vms", "broker", "vmid"], 9005)
    with pytest.raises(ManifestError, match="overlap template VMIDs"):
        validate_manifest(raw)


def test_unbounded_clone_window_refuses():
    raw = _mutate(_raw(), ["pve", "clone_vmid_range"], [100, 99999])
    with pytest.raises(ManifestError, match="bounded"):
        validate_manifest(raw)


def test_missing_template_checksum_refuses():
    raw = _raw()
    raw["templates"]["attacker"]["sha256"] = "not-a-digest"
    with pytest.raises(ManifestError, match="sha256"):
        validate_manifest(raw)


def test_relative_state_path_refuses():
    raw = _mutate(_raw(), ["state_paths", "safety_state_file"],
                  "./.safety_state")
    with pytest.raises(ManifestError, match="absolute writable path"):
        validate_manifest(raw)


def test_backup_must_be_explicit_and_consistent():
    raw = _raw()
    del raw["backup"]["enabled"]
    with pytest.raises(ManifestError, match="explicit"):
        validate_manifest(raw)
    raw = _mutate(_raw(), ["backup", "enabled"], True)
    with pytest.raises(ManifestError, match="destination"):
        validate_manifest(raw)
    raw = _raw()
    raw["backup"] = {"enabled": False, "destination": "/nas/protected"}
    with pytest.raises(ManifestError, match="backup.enabled is false"):
        validate_manifest(raw)


def test_urls_must_be_three_distinct_listeners():
    raw = _mutate(_raw(), ["urls", "ingest"], _raw()["urls"]["public_https"])
    with pytest.raises(ManifestError, match="distinct"):
        validate_manifest(raw)


def test_public_and_ingest_urls_must_be_https():
    raw = _mutate(_raw(), ["urls", "public_https"], "http://10.60.0.11:8080")
    with pytest.raises(ManifestError, match="https"):
        validate_manifest(raw)


# ------------------------------------------------------------- inventory --

def test_classify_resource_states():
    expected = {"name": "sr-service-01", "vmid": 9001}
    assert classify_resource(expected, None) == ABSENT
    assert classify_resource(expected, {"error": "connection reset"}) == UNREADABLE
    assert classify_resource(expected, {"name": "sr-service-01",
                                        "vmid": 9001, "extra": 1}) == MATCHING
    assert classify_resource(expected, {"name": "someone-elses-vm",
                                        "vmid": 9001}) == CONFLICTING


def test_read_error_is_never_absence():
    # A failed read must never be treated as "resource absent" (plan phase 2
    # invariant, enforced already at the inventory layer).
    assert classify_resource({"name": "x"}, {"error": "timeout"}) == UNREADABLE
    assert classify_resource({"name": "x"}, "garbage") == UNREADABLE


def test_capacity_uses_measured_numbers_not_labels():
    headroom = {"min_free_gb": 60, "min_reserve_gb": 40}
    assert assess_capacity(None, 44, headroom)["safe"] is False
    assert assess_capacity(100, 44, headroom)["safe"] is False  # 100 < 144
    assert assess_capacity(200, 44, headroom)["safe"] is True


def _observed_all_matching(manifest) -> dict:
    observed: dict = {}
    for pin in manifest.templates:
        observed[f"vm:{pin.vmid}"] = {"name": f"tpl-{pin.role}", "template": 1}
    for role, svc in manifest.service_vms.items():
        observed[f"vm:{svc.vmid}"] = {"name": svc.name}
    observed[f"bridge:{manifest.bridge}"] = {"vlan": manifest.vlan}
    return observed


def test_inventory_safe_only_when_everything_matches():
    manifest = load_manifest(EXAMPLE)
    observed = _observed_all_matching(manifest)
    report = inventory_report(manifest, observed, "9.2.0", 500)
    assert report["safe_to_apply"], report["refusal_reasons"]

    conflicting = copy.deepcopy(observed)
    conflicting["vm:9001"] = {"name": "foreign-vm"}
    report = inventory_report(manifest, conflicting, "9.2.0", 500)
    assert not report["safe_to_apply"]
    assert any("conflicting" in r for r in report["refusal_reasons"])

    unreadable = copy.deepcopy(observed)
    unreadable["vm:9002"] = {"error": "permission denied"}
    report = inventory_report(manifest, unreadable, "9.2.0", 500)
    assert not report["safe_to_apply"]
    assert any("unreadable" in r for r in report["refusal_reasons"])

    report = inventory_report(manifest, observed, None, 500)
    assert not report["safe_to_apply"]  # version unreadable

    report = inventory_report(manifest, observed, "9.2.0", None)
    assert not report["safe_to_apply"]  # capacity unreadable

    report = inventory_report(manifest, observed, "9.2.0", 10)
    assert not report["safe_to_apply"]  # capacity unsafe


def test_inventory_absent_is_applyable_but_visible():
    # Absent resources are the fresh-install case: allowed, but each one is
    # explicitly classified so the installer plans a create, not a reuse.
    manifest = load_manifest(EXAMPLE)
    report = inventory_report(manifest, {}, "9.2.0", 500)
    assert report["safe_to_apply"]
    assert all(state == ABSENT
               for state in report["classifications"].values())


# ------------------------------------------------------------- rendering --

def test_render_broker_policy_matches_broker_loader():
    from infra.broker.policy import BrokerPolicy
    manifest = load_manifest(EXAMPLE)
    policy = BrokerPolicy.from_dict(render_broker_policy(manifest))
    assert policy.node == manifest.pve_node
    assert policy.storage == (manifest.storage,)
    assert (policy.vmid_min, policy.vmid_max) == manifest.vmid_range
    assert sorted(policy.templates) == sorted(p.vmid for p in manifest.templates)
    assert policy.bridge == manifest.bridge and policy.vlan == manifest.vlan
    assert policy.network == manifest.range_network
    assert policy.limits["max_total_disk_gb"] == manifest.budgets["disk_gb_total"]


def test_render_env_role_separation():
    manifest = load_manifest(EXAMPLE)
    controller = render_env(manifest, "controller")
    worker = render_env(manifest, "worker")
    broker = render_env(manifest, "broker")
    migration = render_env(manifest, "migration")

    # Worker is minimal: no PVE, no DB, no secrets.
    assert set(worker) == {"SR_PROCESS_ROLE", "API_BASE_URL"}
    for fragment in (controller, worker, broker):
        joined = json.dumps(fragment).lower()
        for banned in ("token", "password", "secret", "private_key"):
            assert banned not in joined
    # PVE credentials never appear in any rendered env (broker reads the
    # protected secret_inputs file directly).
    assert not any("PROXMOX" in k for frag in (controller, worker, broker)
                   for k in frag)
    assert controller["SR_SAFETY_STATE_FILE"].startswith("/")
    assert broker["SR_PROCESS_ROLE"] == "broker"
    assert migration["SR_PROCESS_ROLE"] == "migration"
    with pytest.raises(ManifestError):
        render_env(manifest, "browser")  # unknown role refuses
