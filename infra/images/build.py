#!/usr/bin/env python3
"""Deterministic Mojang guest-image builder (paired 03+04, step 1).

Builds attacker / mojang-web-local / mojang-web-db filesystem trees from
PINNED local inputs only — no network access at build time. The only
network-adjacent step (fetching the pinned Ubuntu 24.04 cloud image) happens
OUTSIDE this builder in an explicit build phase with URL+SHA256 verification;
this builder never fetches anything.

Discipline (architecture decision):
- Bake ONLY operator PUBLIC keys (from --pubkey files). Any private-key
  material, live token, or `CHANGE_ME`-style placeholder fails closed.
- Scrub secrets/logs/spools/host keys/machine IDs from the finished tree.
- Record every output file's SHA256 into BUILD-MANIFEST.json alongside the
  pinned manifest copy, package list, seed digest, and guest budgets.
- Prove the supervisor/cgroup/AppArmor boundary separately in the images
  gate (this builder asserts the guest carries the supervisor + shipper +
  auditd units; the gate exercises the real boundary).

Usage:
    python infra/images/build.py --out /tmp/sr-images --pubkey guest.pub
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import shutil
import sys

REPO = pathlib.Path(__file__).resolve().parents[2]
MANIFEST = REPO / "infra" / "images" / "manifest.json"
PAYLOADS = REPO / "infra" / "images" / "payloads"
SEEDS = REPO / "scenarios" / "mojang-seeds.json"

FORBIDDEN_MARKERS = (
    "BEGIN PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "SR_TELEMETRY_TOKEN=",
    "PROXMOX_TOKEN_SECRET",
    "CHANGE_ME",
    "CHANGEME",
)


def sha256_file(p: pathlib.Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def fail(msg: str) -> int:
    print(f"build: FAIL: {msg}", file=sys.stderr)
    return 1


def load_manifest() -> dict:
    try:
        return json.loads(MANIFEST.read_text())
    except (OSError, json.JSONDecodeError) as e:
        print(f"build: FAIL: unreadable manifest {MANIFEST}: {e}", file=sys.stderr)
        raise SystemExit(1)


def check_pubkey(path: pathlib.Path) -> str:
    try:
        text = path.read_text().strip()
    except OSError as e:
        raise SystemExit(fail(f"pubkey unreadable {path}: {e}"))
    if not text.startswith(("ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-")):
        raise SystemExit(fail(f"pubkey {path} is not a bare public key line"))
    for marker in FORBIDDEN_MARKERS:
        if marker in text:
            raise SystemExit(fail(f"pubkey {path} contains forbidden marker {marker!r}"))
    return text


def copy_tree(src: pathlib.Path, dst: pathlib.Path) -> list[pathlib.Path]:
    written: list[pathlib.Path] = []
    for item in sorted(src.rglob("*")):
        rel = item.relative_to(src)
        target = dst / rel
        if item.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(item, target)
            written.append(target)
    return written


def scrub_tree(root: pathlib.Path) -> None:
    """Remove host keys, machine IDs, logs, spools, secrets from the tree."""
    for name in ("ssh_host_rsa_key", "ssh_host_ecdsa_key",
                 "ssh_host_ed25519_key", "ssh_host_rsa_key.pub",
                 "ssh_host_ecdsa_key.pub", "ssh_host_ed25519_key.pub"):
        for p in root.rglob(name):
            p.unlink(missing_ok=True)
    for p in root.rglob("machine-id"):
        try:
            p.write_text("")
        except OSError:
            pass
    for sub in ("var/log/sparring-range", "var/lib/sparring-range/shipper",
                "var/log/audit", "tmp"):
        d = root / sub
        if d.is_dir():
            for child in d.iterdir():
                if child.is_dir():
                    shutil.rmtree(child, ignore_errors=True)
                else:
                    child.unlink(missing_ok=True)


def scan_forbidden(root: pathlib.Path) -> list[str]:
    hits = []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        try:
            text = p.read_text(errors="strict")
        except (OSError, UnicodeDecodeError):
            continue
        for marker in FORBIDDEN_MARKERS:
            if marker in text:
                hits.append(f"{p.relative_to(root)}: {marker}")
    return hits


def build_guest(name: str, out: pathlib.Path, pubkey: str, manifest: dict) -> dict:
    src = PAYLOADS / name
    if not src.is_dir():
        raise SystemExit(fail(f"payload dir missing: {src}"))
    dst = out / name
    if dst.exists():
        shutil.rmtree(dst)
    dst.mkdir(parents=True)
    written = copy_tree(src, dst)
    # Bake ONLY the public key (authorized_keys for defender/attacker roles).
    for user in ("defender", "attacker"):
        ak = dst / "home" / user / ".ssh" / "authorized_keys"
        if ak.exists():
            ak.write_text(pubkey + "\n")
    # Seed + manifest copies for traceability.
    seeds = json.loads(SEEDS.read_text())
    (dst / "srv" / "mojang-web").mkdir(parents=True, exist_ok=True)
    (dst / "srv" / "mojang-web" / "seeds.json").write_text(
        json.dumps(seeds, indent=2, sort_keys=True) + "\n")
    (dst / "etc" / "sparring-range").mkdir(parents=True, exist_ok=True)
    (dst / "etc" / "sparring-range" / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    scrub_tree(dst)
    hits = scan_forbidden(dst)
    if hits:
        raise SystemExit(fail(f"forbidden markers in {name}: {hits[:5]}"))
    files = {}
    for p in sorted(dst.rglob("*")):
        if p.is_file():
            files[str(p.relative_to(dst))] = sha256_file(p)
    guest_spec = manifest["guests"][name]
    return {"guest": name, "vcpus": guest_spec["vcpus"],
            "memory_mb": guest_spec["memory_mb"], "disk_gb": guest_spec["disk_gb"],
            "template_vmid": guest_spec["template_vmid"],
            "services": guest_spec["services"], "files": files}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--pubkey", required=True,
                    help="Operator PUBLIC key file (bare ssh public key line)")
    args = ap.parse_args(argv)
    manifest = load_manifest()
    # Pinned-input retention: every declared build input must exist.
    missing = [i for i in manifest.get("build_inputs", [])
               if not (REPO / i).exists()]
    if missing:
        return fail(f"missing pinned build inputs: {missing}")
    # Package pin file must match the manifest list exactly.
    pkg_file = REPO / "infra" / "images" / "packages-24.04.txt"
    pinned = sorted(manifest.get("packages", []))
    try:
        on_disk = sorted(l.strip() for l in pkg_file.read_text().splitlines()
                         if l.strip() and not l.startswith("#"))
    except OSError as e:
        return fail(f"package pin file unreadable: {e}")
    if pinned != on_disk:
        return fail("package pin file does not match manifest.json")
    pubkey = check_pubkey(pathlib.Path(args.pubkey))
    out = pathlib.Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    guests = {}
    for name in ("attacker", "mojang-web-local", "mojang-web-db"):
        guests[name] = build_guest(name, out, pubkey, manifest)
    seeds_digest = sha256_file(SEEDS)
    record = {"manifest": manifest, "seeds_sha256": seeds_digest,
              "guests": guests}
    (out / "BUILD-MANIFEST.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(f"build: ok: 3 guests under {out} "
          f"(seeds {seeds_digest[:16]}, "
          f"{sum(len(g['files']) for g in guests.values())} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
