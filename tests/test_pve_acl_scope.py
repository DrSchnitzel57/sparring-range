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


def _acl_json(entries):
    import json
    return json.dumps([
        {"path": p, "propagate": 1, "roleid": r, "type": "user", "ugid": u}
        for p, u, r in entries])


def _check(extra_env_json):
    import json
    import os
    import stat
    import tempfile
    stubdir = tempfile.mkdtemp(prefix="sr-pveum-stub-")
    stub = os.path.join(stubdir, "pveum")
    with open(stub, "w") as f:
        f.write("#!/bin/bash\n"
                "if [ \"$1 $2\" = \"acl list\" ]; then\n"
                f"  printf '%s' '{extra_env_json}'; exit 0\n"
                "fi\n"
                "echo \"unexpected pveum call: $*\" >&2; exit 3\n")
    os.chmod(stub, os.stat(stub).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    env = {**os.environ, "PATH": f"{stubdir}:{os.environ['PATH']}"}
    r = subprocess.run(
        ["bash", str(REPO / "deploy/pve_broker_acl.sh"),
         "--node", "pve", "--bridge", "srrange",
         "--templates", "9005,9011", "--vmid-range", "9100-9101",
         "--storage", "local-zfs", "--check"],
        capture_output=True, text=True, timeout=60, env=env)
    return r


def _full_set():
    U = "sr-broker@pve"
    return [
        ("/nodes/pve", U, "SRBrokerAudit"),
        ("/sdn/zones/localnetwork/srrange", U, "SRBrokerSdn"),
        ("/vms/9005", U, "SRBrokerTemplate"),
        ("/vms/9011", U, "SRBrokerTemplate"),
        ("/vms/9100", U, "SRBrokerBase"),
        ("/vms/9101", U, "SRBrokerBase"),
        ("/storage/local-zfs", U, "SRBrokerStorage"),
    ]


def test_acl_check_passes_on_complete_grants():
    import json
    r = _check(_acl_json(_full_set()))
    assert r.returncode == 0, r.stdout[-800:] + r.stderr[-400:]
    assert "7/7" in r.stdout


def test_acl_check_names_missing_window_grant():
    # a destroyed clone's grant vanishes from the live table (the PVE rot):
    # --check must name exactly that path for --apply to restore.
    missing = [e for e in _full_set() if e[0] != "/vms/9100"]
    r = _check(_acl_json(missing))
    assert r.returncode == 1, r.stdout[-800:]
    assert "MISSING /vms/9100 sr-broker@pve SRBrokerBase" in r.stdout
    assert "6/7" in r.stdout
    # nothing else executes in check mode: no role/user/acl writes
    assert "pveum acl modify" not in r.stdout
    assert "pveum role add" not in r.stdout
    assert "pveum user add" not in r.stdout
