"""PVE broker ACL scope (review finding): the bootstrap plan must never
contain a bare `/vms` grant — runtime privileges are enumerated per
approved VMID (templates + bounded clone window), storage privileges live
on the named storage only. Pure dry-run output inspection (no PVE)."""
from __future__ import annotations

import re
import subprocess

REPO = __import__("pathlib").Path(__file__).resolve().parents[1]


def _plan(*extra: str) -> str:
    r = subprocess.run(
        ["bash", str(REPO / "deploy/pve_broker_acl.sh"),
         "--node", "pve", "--bridge", "srrange",
         "--templates", "9005,9011", "--vmid-range", "9100-9102",
         "--storage", "local-zfs", *extra],
        capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-800:]
    return r.stdout


def test_acl_plan_has_no_bare_vms_grant():
    out = _plan()
    bare = [l for l in out.splitlines()
            if re.search(r"acl\s+modify\s+/vms(\s|$)", l)]
    assert not bare, f"bare /vms grants would cover unrelated VMs: {bare}"


def test_acl_plan_enumerates_window_and_templates():
    out = _plan()
    for vmid in ("9005", "9011", "9100", "9101", "9102"):
        assert re.search(rf"acl\s+modify\s+/vms/{vmid}\b", out), vmid
    # outside the window: never granted
    assert "/vms/9099" not in out and "/vms/9103" not in out
    assert "/storage/local-zfs" in out


def test_acl_plan_splits_storage_role():
    out = _plan()
    assert "SRBrokerStorage" in out
    assert "Datastore.Allocate" in out
    # datastore privileges must not ride VM paths
    for l in out.splitlines():
        if "/vms/" in l and "role" in l.lower():
            assert "Datastore" not in l, l
