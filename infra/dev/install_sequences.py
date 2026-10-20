"""Real appliance install sequences (plan 14, step 5).

The installer gate used to accept an environment assertion
(``SR_INSTALL_VM_EVIDENCE=1``) for the managed-service half.  This module
replaces that with the ACTUAL sequences, executed against the real
installer in a SANDBOX root: no root, no system identities, and nothing
outside the sandbox root is touched.

Sequences (each one is an observation, not a claim):

  clean          a first installation writes the configuration, the units,
                 the network artifacts and the worker capability, and leaves
                 a digest-only receipt.
  rerun          a second installation changes NOTHING and preserves the
                 capability byte for byte.
  reboot         the runtime state that does not survive a reboot is gone;
                 re-installing restores it while the DATA and the keys stay.
  upgrade        a populated installation is upgraded to a changed manifest;
                 the changed configuration is rewritten, the unchanged data
                 and the capability are preserved.
  drift+repair  a corrupted file is detected by ``verify`` and repaired by
                 ``apply``; a foreign file is never touched.
"""
from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
INSTALLER = REPO / "deploy" / "appliance.py"


class InstallSequenceError(RuntimeError):
    pass


def build_manifest(base: pathlib.Path) -> pathlib.Path:
    """Write a self-consistent manifest for the sandbox sequences.

    The paths are absolute and real, exactly like an operator's manifest;
    the installer re-roots them into the sandbox root, so the sandbox never
    touches the host.
    """
    import hashlib
    base = pathlib.Path(base)
    base.mkdir(parents=True, exist_ok=True)
    images = {}
    for role, tid, size in (("attacker", 9005, 11),
                            ("mojang-web-local", 9011, 12),
                            ("mojang-web-db", 9012, 10)):
        img = base / f"{role}.qcow2"
        img.write_bytes((role + "-image").encode())
        images[role] = {
            "template_id": tid, "path": str(img),
            "sha256": hashlib.sha256(img.read_bytes()).hexdigest(),
            "size_bytes": img.stat().st_size, "disk_gb": size,
            "memory_mb": 2048, "vcpus": 2,
        }
    keys = {}
    for name in ("runner", "bastion", "mgmt"):
        key = base / name
        if not key.exists():
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "",
                            "-f", str(key)], check=True, capture_output=True)
        keys[name] = str(base / f"{name}.pub")
    (base / "model.key").write_text("sandbox-model-key\n")
    raw = {
        "schema_version": 1,
        "installation_id": "4f0e7a1c-8a59-4a4e-9b5d-74f0e7a1c333",
        "appliance": {"hostname": "sr-appliance", "timezone": "UTC"},
        "network": {
            "lan_cidr": "10.10.10.0/24", "lan_address": "10.10.10.50",
            "range_cidr": "10.66.0.0/24", "range_bridge": "srlab0",
            "range_gateway": "10.66.0.1", "controller_range_ip": "10.66.0.1",
            "bastion_address": "10.66.0.2", "ingest_address": "10.66.0.1",
            "ingest_port": 8443, "management_cidr": "10.0.0.0/24",
        },
        "urls": {"public": "https://sr.example.edu",
                 "internal": "http://127.0.0.1:8000",
                 "ingest": "https://10.66.0.1:8443"},
        "broker": {
            "socket": "/run/sparring-range/broker.sock",
            "ledger": "/var/lib/sparring-range/broker-ledger.sqlite3",
            "state_dir": "/var/lib/sparring-range",
        },
        # Canonical appliance locations: the installer re-roots them into the
        # sandbox, exactly as it would into a real appliance.
        "paths": {"images": "/var/lib/sparring-range/images",
                  "recordings": "/var/lib/sparring-range/recordings",
                  "secrets": "/etc/sparring-range/secrets"},
        "images": images,
        "access_keys": keys,
        "model": {"base_url": "http://127.0.0.1:8001/v1",
                  "alias": "sr-test-model",
                  "api_key_file": str(base / "model.key")},
        "budgets": {"max_guests": 6, "max_vcpus": 12, "max_memory_mb": 12288,
                    "max_disk_gb": 44, "min_free_gb": 20},
        "backup": {"enabled": False, "destination": ""},
    }
    path = base / "appliance-manifest.json"
    path.write_text(json.dumps(raw, indent=2, sort_keys=True))
    return path


def _run(root: pathlib.Path, manifest: pathlib.Path, *args: str,
         expect_ok: bool = True) -> tuple[int, str, str]:
    cmd = [sys.executable, str(INSTALLER), *args, "--manifest", str(manifest),
           "--system-root", str(root)]
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=REPO,
                          timeout=600)
    if expect_ok and proc.returncode != 0:
        raise InstallSequenceError(
            f"{' '.join(args)} failed ({proc.returncode}): "
            f"{(proc.stdout + proc.stderr)[-1200:]}")
    return proc.returncode, proc.stdout, proc.stderr


def _apply(root: pathlib.Path, manifest: pathlib.Path):
    code, out, err = _run(root, manifest, "apply")
    try:
        return json.loads(out)
    except ValueError as exc:
        raise InstallSequenceError(
            f"apply did not return JSON: {(out + err)[-600:]}") from exc


def _verify(root: pathlib.Path, manifest: pathlib.Path) -> dict:
    code, out, err = _run(root, manifest, "verify", "--json",
                          expect_ok=False)
    try:
        return json.loads(out)
    except ValueError as exc:
        raise InstallSequenceError(
            f"verify did not return JSON: {(out + err)[-600:]}") from exc


def _manifest_paths(root: pathlib.Path) -> dict:
    """The absolute paths the sandboxed manifest resolves to."""
    return {
        "etc": root / "etc/sparring-range",
        "receipt": root / "etc/sparring-range/install-receipt.json",
        "token": root / "etc/sparring-range/secrets/worker-supervisor.token",
        "env": root / "etc/sparring-range/control-plane.derived.env",
        "units": root / "etc/systemd/system",
        "network": root / "etc/systemd/network",
        "nft": root / "etc/nftables.d/sr-appliance.nft",
        "run": root / "run/sparring-range",
        "state": root / "var/lib/sparring-range",
    }


def run_sequences(root: pathlib.Path, manifest: pathlib.Path) -> dict:
    """Run every sequence and return the observed evidence."""
    root = pathlib.Path(root)
    paths = _manifest_paths(root)
    evidence: dict = {"root": str(root)}

    # --- clean ---------------------------------------------------------------
    first = _apply(root, manifest)
    evidence["clean"] = {
        "changed": len(first["changed"]),
        "token": first["supervisor_token"],
        "receipt": paths["receipt"].is_file(),
    }
    if not paths["receipt"].is_file():
        raise InstallSequenceError("clean install wrote no receipt")
    for required in (paths["env"], paths["units"] / "sr-api.service",
                      paths["network"] / "10-srlab.netdev", paths["nft"],
                      paths["token"]):
        if not required.exists():
            raise InstallSequenceError(f"clean install missed {required}")
    if paths["token"].stat().st_mode & 0o077:
        raise InstallSequenceError("worker capability is group/world readable")
    token_bytes = paths["token"].read_bytes()
    receipt = json.loads(paths["receipt"].read_text())
    if "supervisor_token_sha256" not in receipt:
        raise InstallSequenceError("receipt does not record the capability digest")
    if any("token" in str(k) and "sha256" not in str(k) for k in receipt):
        raise InstallSequenceError("receipt contains something that is not a digest")

    # --- rerun ---------------------------------------------------------------
    second = _apply(root, manifest)
    if second["changed"]:
        raise InstallSequenceError(
            f"rerun changed {len(second['changed'])} file(s): "
            f"{second['changed'][:5]}")
    if second["supervisor_token"] != "preserved":
        raise InstallSequenceError("rerun did not preserve the capability")
    if paths["token"].read_bytes() != token_bytes:
        raise InstallSequenceError("rerun rewrote the worker capability")
    evidence["rerun"] = {"changed": 0, "token": second["supervisor_token"]}

    # --- reboot --------------------------------------------------------------
    data_file = paths["state"] / "sentinel.db"
    data_file.parent.mkdir(parents=True, exist_ok=True)
    data_file.write_text("history-and-data\n")
    shutil.rmtree(paths["run"], ignore_errors=True)
    if paths["run"].exists():
        raise InstallSequenceError("runtime directory survived the reboot")
    third = _apply(root, manifest)
    if not paths["run"].is_dir():
        raise InstallSequenceError("re-install did not restore the runtime dir")
    if data_file.read_text() != "history-and-data\n":
        raise InstallSequenceError("re-install did not preserve the data")
    if paths["token"].read_bytes() != token_bytes:
        raise InstallSequenceError("re-install rewrote the worker capability")
    evidence["reboot"] = {"runtime_restored": True, "data_preserved": True,
                          "token_preserved": True,
                          "changed": len(third["changed"])}

    # --- populated upgrade ---------------------------------------------------
    upgraded = json.loads(manifest.read_text())
    upgraded["appliance"] = dict(upgraded["appliance"])
    upgraded["appliance"]["timezone"] = "Europe/Berlin"
    upgraded["network"] = dict(upgraded["network"])
    upgraded_manifest = manifest.with_name("manifest-upgraded.json")
    upgraded_manifest.write_text(json.dumps(upgraded, indent=2, sort_keys=True))
    fourth = _apply(root, upgraded_manifest)
    if not fourth["changed"]:
        raise InstallSequenceError("upgrade changed nothing")
    if fourth["supervisor_token"] != "preserved":
        raise InstallSequenceError("upgrade did not preserve the capability")
    if data_file.read_text() != "history-and-data\n":
        raise InstallSequenceError("upgrade did not preserve the data")
    new_receipt = json.loads(paths["receipt"].read_text())
    if new_receipt["manifest_sha256"] == receipt["manifest_sha256"]:
        raise InstallSequenceError("upgrade did not change the receipt digest")
    evidence["upgrade"] = {"changed": len(fourth["changed"]),
                           "token": fourth["supervisor_token"],
                           "data_preserved": True}

    # --- drift and repair ----------------------------------------------------
    victim = paths["env"]
    original = victim.read_text()
    victim.write_text("tampered\n")
    victim.chmod(0o600)
    drift = _verify(root, upgraded_manifest)
    if drift.get("ok") or not any(d["path"] == str(victim)
                                  for d in drift.get("drift", [])):
        raise InstallSequenceError("verify did not detect the tampered file")
    foreign = paths["etc"] / "operator-note.txt"
    foreign.write_text("not ours\n")
    _apply(root, upgraded_manifest)
    if victim.read_text() != original:
        raise InstallSequenceError("apply did not repair the tampered file")
    if foreign.read_text() != "not ours\n":
        raise InstallSequenceError("apply touched a file it does not own")
    clean = _verify(root, upgraded_manifest)
    if not clean.get("ok"):
        raise InstallSequenceError(f"verify still reports drift: {clean}")
    evidence["drift"] = {"detected": True, "repaired": True,
                         "foreign_file_untouched": True}
    return evidence
