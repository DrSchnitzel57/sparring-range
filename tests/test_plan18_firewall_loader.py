"""Plan 18 — own-table firewall loader (fast layer).

Live find: the operator applied the range isolation rules once in the
maintenance window and a reboot silently lost them. The repair is a loader
service that re-loads EXACTLY the installer's own rendered file, plus a
render-time scope parser that makes it impossible for the installed
ruleset to touch anything but ``inet sr_appliance``: no flush ruleset, no
foreign table, no include, and a first-run-idempotent add/delete order.
"""
from __future__ import annotations

import pytest

from deploy import appliance as ap
from infra.appliance.manifest import ApplianceManifest
from infra.appliance.netrules import nft_scope_problems, render_nftables
from infra.dev import install_sequences as seq


def _manifest(tmp_path):
    return ApplianceManifest.load(seq.build_manifest(tmp_path / "fire"))


def test_rendered_ruleset_is_own_table_only(tmp_path):
    text = render_nftables(_manifest(tmp_path))
    assert nft_scope_problems(text) == []
    assert "flush" not in text.lower()


def test_scope_parser_refuses_every_escape():
    bad = {
        "flush ruleset": "flush ruleset",
        "foreign table": "table inet filter { }",
        "include": 'include "/etc/nftables.conf"',
        "bare flush": "flush chain inet sr_appliance input",
    }
    for label, text in bad.items():
        problems = nft_scope_problems("add table inet sr_appliance\n" + text)
        assert problems, f"scope parser accepted {label}"


def test_scope_parser_flags_delete_before_add_ordering():
    bad = ("delete table inet sr_appliance\n"
           "add table inet sr_appliance\ntable inet sr_appliance {\n}\n")
    problems = nft_scope_problems(bad)
    assert any("follow add table" in p for p in problems), problems


def test_loader_unit_and_broker_order(tmp_path):
    m = _manifest(tmp_path)
    lay = ap.default_layout(root=tmp_path / "root")
    plan = ap.render_files(m, layout=lay)
    by_name = {f.path.name: f for f in plan.files}
    loader = by_name[ap.NETRULES_UNIT].content
    assert "Type=oneshot" in loader and "RemainAfterExit=yes" in loader
    assert "ExecStart=/usr/sbin/nft -f " in loader
    assert str(lay.nftables_dir / "sr-appliance.nft") in loader
    assert "/usr/sbin/nft -c -f" in loader, "validate-before-load missing"
    assert "flush ruleset" not in loader.lower()
    # broker is fail-closed ordered on the loader: no guest may exist
    # before the range isolation table is loaded.
    broker = by_name["sr-appliance-broker.service"].content
    assert f"Requires=libvirtd.service {ap.NETRULES_UNIT}" in broker
    assert f"After=network-online.target libvirtd.service {ap.NETRULES_UNIT}" \
        in broker
    # and it is part of what apply enables
    assert any(ap.NETRULES_UNIT in a for a in plan.actions)


def test_render_files_refuses_out_of_scope_ruleset(tmp_path, monkeypatch):
    m = _manifest(tmp_path)
    monkeypatch.setattr(ap, "render_nftables", lambda _m: "flush ruleset\n")
    with pytest.raises(ap.InstallError, match="own-table scope"):
        ap.render_files(m, layout=ap.default_layout(root=tmp_path / "r2"))


def test_storage_headroom_preflight_is_explicit():
    gib = 1024**3
    assert ap.storage_headroom_problem(100 * gib, 30 * gib, 20) is None
    problem = ap.storage_headroom_problem(40 * gib, 30 * gib, 20)
    assert problem and "40.0 GiB free" in problem and "50.0 GiB" in problem
    # exactly enough is enough; the check never refuses a fitting box
    assert ap.storage_headroom_problem(50 * gib, 30 * gib, 20) is None
