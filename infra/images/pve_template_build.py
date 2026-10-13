#!/usr/bin/env python3
"""PVE template build (pilot plan step 2): import-ready qcow2 templates.

Produces standalone (flattened) qcow2 templates for the pilot presets —
9005 attacker and 9011 mojang-web-local — from the pinned, checksum-verified
noble base plus the payload, using the SAME QEMU overlay machinery as the
images gate (`infra/images/guest_build.py`). Every artifact is built by
booting a real guest: build boot (packages + payload), then a finalize boot
that scrubs per-clone identity (SSH host keys, machine-id, cloud-init state)
so every PVE clone regenerates fresh identity — the contract the broker's
guest-agent host-key pinning depends on.

Only the operator PUBLIC access key is baked (refuses private material).
The output directory carries SHA256SUMS, TEMPLATE-INFO.json (inputs hash,
guest-resolved package versions, QEMU record) and IMPORT-STEPS.md with the
documented `qm importdisk` → template-convert procedure the operator runs.

Usage:
    python infra/images/pve_template_build.py --out /tmp/sr-templates \
        --pubkey /secure/operator_access.pub [--roles attacker,mojang-web-local]

This never contacts Proxmox; importing is the operator's documented step.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import shutil
import subprocess
import sys
import uuid

REPO = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from infra.dev import qemu_guest  # noqa: E402
from infra.images import build as image_build, guest_build, guest_seed, guest_userdata  # noqa: E402
from infra.images import specs  # noqa: E402

ROLE_VMID = {"attacker": 9005, "mojang-web-local": 9011, "mojang-web-db": 9012}

IMPORT_STEPS = """# Operator import steps (run on the Proxmox node as root)

For each template file below (example: 9011 / mojang-web-local; repeat for
9005 / attacker with its file and budget):

    # 0. Verify the artifact BEFORE import:
    sha256sum -c SHA256SUMS

    # 1. Create the placeholder VM with the role's budget (no disk yet):
    qm create 9011 --name tpl-mojang-web-local --ostype l26 \\
        --cores 2 --sockets 1 --memory 2048 \\
        --net0 virtio,bridge=<BRIDGE> \\
        --agent enabled=1 \\
        --scsihw virtio-scsi-single

    # 2. Import the flattened qcow2 and attach it as the boot disk:
    qm importdisk 9011 template-mojang-web-local.qcow2 <STORAGE>
    qm set 9011 --scsi0 <STORAGE>:vm-9011-disk-0,discard=on
    qm set 9011 --boot order=scsi0

    # 3. Cloud-Init (drives per-clone identity regeneration: fresh SSH host
    #    keys + machine-id on every clone; the broker pins the fresh ed25519
    #    host key via the guest-agent FileRead channel — that requires the
    #    VM.AgentFileRead ACL privilege on the CLONE path /vms, it is NOT a
    #    VM creation flag):
    qm set 9011 --ide2 <STORAGE>:cloudinit --ciuser attacker \\
        --ipconfig0 ip=dhcp
    # (range guests get static IPs from the broker's ipconfig0 at clone time;
    #  the template itself only needs Cloud-Init enabled)

    # 4. Convert to a template (irreversible; broker clones only from
    #    templates listed in its operator policy):
    qm template 9011

Never boot these templates directly — they are clone sources. The broker
policy must allowlist exactly these VMIDs; nothing else may be cloned.

Attacker guest note: the runner-supervisor's kernel-enforced command boundary
needs unprivileged user namespaces. On the ATTACKER guest only, either load
the scoped AppArmor profile used by CI or set
`kernel.apparmor_restrict_unprivileged_userns=0` (a disposable guest, never
the control plane or the host).
"""


def sha256_file(p: pathlib.Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def finalize(overlay: pathlib.Path, run_dir: pathlib.Path, role: str,
             pubkey: str | None = None) -> None:
    """Offline boot that bakes the operator PUBLIC key (root/defender/
    attacker) and scrubs per-clone identity from the built overlay."""
    seed = guest_seed.build_seed_iso(
        run_dir / f"finalize-{role}-seed.iso",
        guest_userdata.finalize_user_data(pubkey),
        guest_seed.meta_data(f"sr-finalize-{uuid.uuid4().hex[:8]}",
                             f"sr-finalize-{role}"))
    qemu_guest.boot_full_guest(disk=overlay, seed_iso=seed, memory_mb=1024,
                               net="none", expect=("SR-GUEST-DONE rc=0",),
                               timeout_s=600)


def flatten(overlay: pathlib.Path, out_qcow2: pathlib.Path,
            expect_virtual_gb: int) -> dict:
    """Flatten overlay+backing chain into one standalone qcow2 and prove it
    is importable (qcow2, NO backing file, budgeted virtual size)."""
    r = subprocess.run(["qemu-img", "convert", "-O", "qcow2",
                        str(overlay), str(out_qcow2)],
                       capture_output=True, text=True, timeout=1800)
    if r.returncode != 0:
        raise RuntimeError(f"qemu-img convert failed: {(r.stderr or r.stdout)[:300]}")
    info = subprocess.run(["qemu-img", "info", "--output=json", str(out_qcow2)],
                          capture_output=True, text=True, timeout=120)
    if info.returncode != 0:
        raise RuntimeError("qemu-img info failed on the built template")
    meta = json.loads(info.stdout)
    if meta.get("format") != "qcow2":
        raise RuntimeError(f"template is not qcow2: {meta.get('format')}")
    if "backing-filename" in meta:
        raise RuntimeError("template still has a backing file (not standalone)")
    vsize_gb = int(meta["virtual-size"]) // (1024 ** 3)
    if vsize_gb != expect_virtual_gb:
        raise RuntimeError(
            f"template virtual size {vsize_gb}G != budget {expect_virtual_gb}G")
    # plain `check` is repair-free (`-r` only accepts leaks|all here)
    check = subprocess.run(["qemu-img", "check", str(out_qcow2)],
                           capture_output=True, text=True, timeout=600)
    if check.returncode != 0:
        raise RuntimeError(f"qemu-img check failed: "
                           f"{(check.stdout or check.stderr)[:300]}")
    return meta


def build_role(role: str, out: pathlib.Path, cache_dir: pathlib.Path,
               pubkey: str) -> dict:
    from infra.images.build import check_pubkey  # reuse the public-key gate
    check_pubkey(pathlib.Path(pubkey))
    pub = pathlib.Path(pubkey).read_text().strip()
    run = qemu_guest.make_run_dir()
    try:
        if role == "attacker":
            rec = guest_build.build_attacker_overlay(
                repo_root=REPO, run_dir=run, cache_dir=cache_dir / role,
                pubkey=pub, memory_mb=1024, base_dir=cache_dir)
        else:
            budget = specs.check_guest_budget(role)
            rec = guest_build.build_overlay(
                repo_root=REPO, run_dir=run, cache_dir=cache_dir / role,
                role=role, memory_mb=2048, disk_gb=budget["disk_gb"],
                base_dir=cache_dir)
        overlay = pathlib.Path(rec["overlay"])
        finalize(overlay, run, role, pub)
        out_qcow2 = out / f"template-{role}.qcow2"
        meta = flatten(overlay, out_qcow2,
                       specs.check_guest_budget(role)["disk_gb"])
        return {"role": role, "template_vmid": ROLE_VMID[role],
                "file": out_qcow2.name,
                "sha256": sha256_file(out_qcow2),
                "bytes": out_qcow2.stat().st_size,
                "virtual_bytes": meta["virtual-size"],
                "inputs_hash": rec.get("inputs_hash"),
                "packages": rec.get("packages", {}),
                "build_cached": rec.get("cached", False)}
    finally:
        shutil.rmtree(run, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--pubkey", required=True,
                    help="Operator PUBLIC access key (bare key file)")
    ap.add_argument("--cache-dir", default="/tmp/sr-guest-cache")
    ap.add_argument("--roles", default="attacker,mojang-web-local")
    args = ap.parse_args(argv)
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    cache = pathlib.Path(args.cache_dir)
    manifest = image_build.load_manifest()
    built = []
    for role in [r.strip() for r in args.roles.split(",") if r.strip()]:
        if role not in ROLE_VMID:
            print(f"template-build: unknown role {role!r}", file=sys.stderr)
            return 2
        print(f"template-build: building {role} (QEMU boots; TCG is slow)...")
        built.append(build_role(role, out, cache, args.pubkey))
    sums = "".join(f"{b['sha256']}  {b['file']}\n" for b in built)
    (out / "SHA256SUMS").write_text(sums)
    info = {"built_by": "infra/images/pve_template_build.py",
            "base_image": manifest["base_image"],
            "image_version": manifest["base_image"]["image_version"],
            "templates": built}
    (out / "TEMPLATE-INFO.json").write_text(json.dumps(info, indent=2,
                                                       sort_keys=True) + "\n")
    (out / "IMPORT-STEPS.md").write_text(IMPORT_STEPS)
    for b in built:
        print(f"template-build: {b['file']} vmid={b['template_vmid']} "
              f"sha256={b['sha256'][:16]}... cached={b['build_cached']}")
    print(f"template-build: ok — {len(built)} import-ready templates under {out} "
          f"(verify with: cd {out} && sha256sum -c SHA256SUMS)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
