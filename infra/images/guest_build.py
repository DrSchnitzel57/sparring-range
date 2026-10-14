#!/usr/bin/env python3
"""Superset guest-overlay builder for real-Ubuntu gates (03+04 rework).

Assembles ONE bootable guest overlay per run: the pinned, checksum-verified
Ubuntu 24.04 base + build-phase package fetch (pinned NAMES; resolved
versions RECORDED from the guest over serial) + local payload (services,
seeds, flaws, shipper install inputs) + NoCloud build seed. The overlay
deltas ARE the built artifact: hashed, recorded, bounded, run-owned.

Role differentiation (web-local vs web-db) is config-level (data backend +
checks), exercised by separate VERIFY seeds on the same overlay family — the
overlay is a documented superset build so the 60-minute gate budget holds on
TCG software emulation. Per-role template VMIDs in `infra/images/specs.py`
remain the operator-build contract and are unchanged.

Overlay cache: `cache_dir/overlay-<inputs-hash>.qcow2` skips the build boot
when every input (base SHA, manifest, packages, payload trees, seeds,
user-data generator, shipper inputs) is byte-identical to a previous build.
The cache key covers all of them — a changed input always rebuilds. The gate
records BUILD vs BUILD-CACHED honestly; CI starts cold and always builds.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import shutil
import subprocess

from infra.dev import qemu_guest
from infra.images import guest_seed, guest_userdata

SUPERSET_PACKAGES = ["nginx", "mysql-server", "auditd", "openssh-server",
                     "python3-pymysql", "ufw", "curl", "qemu-guest-agent"]

#: Pinned subset the attacker template installs. Plan 13 phase 3: the
#: attacker ALSO carries the capture path (auditd; shipper is installed from
#: the canonical telemetry inputs) and the runner boundary; no target
#: services, no MySQL. AppArmor userspace ships with the Ubuntu cloud image
#: (the build fails loudly if `apparmor_parser` is somehow absent).
ATTACKER_PACKAGES = ["openssh-server", "curl", "qemu-guest-agent", "ufw",
                     "auditd"]


def manifest_packages(repo_root: pathlib.Path) -> list[str]:
    """Exact pinned `name=version` install set from the manifest (single
    source of truth; resolved from a real guest boot, re-pinned explicitly
    when the archive drifts — never floated)."""
    manifest = json.loads((pathlib.Path(repo_root) / "infra/images/manifest.json"
                           ).read_text())
    pins = manifest["packages"]
    assert all("=" in p for p in pins), f"pins must be exact: {pins}"
    return list(pins)


def inputs_hash(repo_root: pathlib.Path, role: str = "mojang-web-db") -> str:
    """Per-role cache key: base SHA + the ROLE's payload subtree + seeds +
    generators. Plan 13 phase 3: web and DB tiers are separate artifacts,
    so they cache separately and each boots its own production shape."""
    h = hashlib.sha256()
    repo = pathlib.Path(repo_root)
    h.update(f"role={role}\n".encode())
    manifest = json.loads((repo / "infra/images/manifest.json").read_text())
    h.update(manifest["base_image"]["sha256"].encode())
    h.update((repo / "infra/images/packages-24.04.txt").read_bytes())
    for rel in sorted((repo / "infra/images/payloads").rglob("*")):
        if rel.is_file():
            h.update(str(rel.relative_to(repo)).encode())
            h.update(rel.read_bytes())
    h.update((repo / "scenarios/mojang-seeds.json").read_bytes())
    for mod in ("infra/images/guest_userdata.py", "infra/images/guest_seed.py",
                "telemetry/shipper.py", "telemetry/sparring-shipper.service",
                "telemetry/auditd.rules"):
        h.update((repo / mod).read_bytes())
    return h.hexdigest()[:16]


def serial_markers(serial: pathlib.Path) -> list[str]:
    try:
        text = serial.read_text(errors="replace").replace("\r", "")
    except OSError:
        return []
    return [l for l in text.splitlines() if l.startswith("SR-GUEST-")]


def recorded_packages(serial: pathlib.Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in serial_markers(serial):
        if line.startswith("SR-GUEST-PKG:"):
            pkg = line[len("SR-GUEST-PKG:"):]
            if "=" in pkg:
                name, ver = pkg.split("=", 1)
                out[name.strip()] = ver.strip()
    return out


def build_overlay(*, repo_root: pathlib.Path, run_dir: pathlib.Path,
                  cache_dir: pathlib.Path, role: str = "mojang-web-db",
                  memory_mb: int = 2048, timeout_s: int = 1500,
                  disk_gb: int = 16,
                  base_dir: pathlib.Path | None = None) -> dict:
    """Build (or reuse) the superset overlay. Returns the build record with
    resolved package versions parsed from the guest's own serial report."""
    key = inputs_hash(repo_root, role)
    cache_dir.mkdir(parents=True, exist_ok=True)
    cached = cache_dir / f"overlay-{role}-{key}.qcow2"
    cached_meta = cache_dir / f"overlay-{role}-{key}.json"
    base = qemu_guest.ensure_verified_base((base_dir or cache_dir) / "base")
    if cached.exists() and cached_meta.exists():
        meta = json.loads(cached_meta.read_text())
        # Recreate the sized base (deterministic) and rebase the copied
        # overlay onto it: backing paths are absolute per-run, so a raw copy
        # would dangle at the deleted original run dir.
        qemu_guest.sized_base_copy(base, run_dir, "guest", disk_gb)
        overlay = run_dir / "guest.qcow2"
        shutil.copyfile(cached, overlay)
        r = subprocess.run(["qemu-img", "rebase", "-u", "-F", "qcow2",
                            "-b", str(run_dir / "guest-base.qcow2"),
                            str(overlay)],
                           capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            raise RuntimeError(f"qemu-img rebase failed: {(r.stderr or r.stdout)[:200]}")
        return {"overlay": str(overlay), "cached": True,
                "inputs_hash": key, **meta}
    # Production-sized test disk (superset serves the 16 GiB web-db role;
    # template builds pass their role budget).
    overlay = qemu_guest.fresh_role_overlay(base, run_dir, "guest", disk_gb)
    seeds = json.loads((pathlib.Path(repo_root) / "scenarios/mojang-seeds.json"
                        ).read_text())
    payload = guest_userdata.payload_from_repo(str(repo_root), role, seeds)
    user_data = guest_userdata.build_user_data(
        role, payload, manifest_packages(repo_root))
    seed_iso = guest_seed.build_seed_iso(
        run_dir / "build-seed.iso", user_data,
        guest_seed.meta_data(f"sr-build-{key[:8]}", f"sr-build-{role}"))
    rec = qemu_guest.boot_full_guest(disk=overlay, seed_iso=seed_iso,
                                     memory_mb=memory_mb, net="user",
                                     expect=("SR-GUEST-BUILD-PASS",),
                                     timeout_s=timeout_s)
    serial = run_dir / "guest.serial.log"
    pkgs = recorded_packages(serial)
    missing = [p for p in ("nginx", "mysql-server", "auditd")
               if not any(n == p or n.startswith(p + "-") or n.startswith(p + ":")
                          for n in pkgs)]
    # dpkg-query names for meta-packages resolve to real binary packages
    # (e.g. mysql-server -> mysql-server-8.0); require the families present.
    families = {"nginx": ("nginx",), "mysql": ("mysql-server", "mysql-client",
                "mysql-common"), "audit": ("auditd", "audit")}
    absent = [fam for fam, names in families.items()
              if not any(any(n == want or n.startswith(want + "-")
                             for want in names) for n in pkgs)]
    if absent:
        raise RuntimeError(f"build overlay missing package families {absent}: "
                           f"recorded {sorted(pkgs)}")
    meta = {"packages": pkgs, "inputs_hash": key,
            "qemu": rec["qemu"], "kvm": rec["kvm"]}
    (run_dir / "build-meta.json").write_text(json.dumps(meta, indent=2,
                                                        sort_keys=True))
    shutil.copyfile(overlay, cached)
    (cached_meta).write_text(json.dumps(meta, indent=2, sort_keys=True))
    # Bound the cache: only the current key's overlay survives (plus the
    # verified base); stale overlays are removed, never accumulated.
    for stale in cache_dir.glob(f"overlay-{role}-*.qcow2"):
        if stale != cached:
            stale.unlink(missing_ok=True)
    for stale in cache_dir.glob(f"overlay-{role}-*.json"):
        if stale != cached_meta:
            stale.unlink(missing_ok=True)
    return {"overlay": str(overlay), "cached": False, **meta}


def attacker_inputs_hash(repo_root: pathlib.Path,
                         key_manifest: dict[str, str]) -> str:
    """Cache key for the attacker overlay: base SHA + attacker payload +
    supervisor script + cgroup delegation unit + AppArmor profile + capture
    inputs + pinned subset + the role key manifest (public keys only)."""
    h = hashlib.sha256()
    repo = pathlib.Path(repo_root)
    manifest = json.loads((repo / "infra/images/manifest.json").read_text())
    h.update(manifest["base_image"]["sha256"].encode())
    h.update(json.dumps(key_manifest, sort_keys=True).encode())
    for rel in sorted((repo / "infra/images/payloads/attacker").rglob("*")):
        if rel.is_file() and ".ssh" not in rel.parts:
            h.update(str(rel.relative_to(repo)).encode())
            h.update(rel.read_bytes())
    for mod in ("infra/runner/runner_supervise.sh",
                "infra/runner/sr-runner-cgroup.service",
                "infra/runner/apparmor/usr.bin.unshare",
                "infra/images/guest_userdata.py",
                "telemetry/shipper.py",
                "telemetry/sparring-shipper.service",
                "telemetry/auditd.rules"):
        h.update((repo / mod).read_bytes())
    pins = {p.split("=")[0]: p for p in manifest_packages(repo)}
    for name in ATTACKER_PACKAGES:
        h.update(pins[name].encode())
    return h.hexdigest()[:16]


def build_attacker_overlay(*, repo_root: pathlib.Path, run_dir: pathlib.Path,
                           cache_dir: pathlib.Path,
                           key_manifest: dict[str, str],
                           memory_mb: int = 1024,
                           timeout_s: int = 1500,
                           base_dir: pathlib.Path | None = None) -> dict:
    """Build (or reuse) the attacker template overlay (plan 13 phase 3):
    pinned base + attacker role + runner-supervisor + capture path + runner
    boundary + role-appropriate public keys. Fresh per-input, cached by
    every build input, same discipline as the target overlay; resolved
    package versions are RECORDED like every other artifact."""
    key = attacker_inputs_hash(repo_root, key_manifest)
    cache_dir.mkdir(parents=True, exist_ok=True)
    cached = cache_dir / f"attacker-{key}.qcow2"
    cached_meta = cache_dir / f"attacker-{key}.json"
    if cached.exists() and cached_meta.exists():
        base = qemu_guest.ensure_verified_base((base_dir or cache_dir) / "base")
        qemu_guest.sized_base_copy(base, run_dir, "attacker", 16)
        overlay = run_dir / "attacker.qcow2"
        shutil.copyfile(cached, overlay)
        r = subprocess.run(["qemu-img", "rebase", "-u", "-F", "qcow2",
                            "-b", str(run_dir / "attacker-base.qcow2"),
                            str(overlay)],
                           capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            raise RuntimeError(f"qemu-img rebase failed: {(r.stderr or r.stdout)[:200]}")
        return {"overlay": str(overlay), "cached": True, "inputs_hash": key,
                **json.loads(cached_meta.read_text())}
    base = qemu_guest.ensure_verified_base((base_dir or cache_dir) / "base")
    overlay = qemu_guest.fresh_role_overlay(base, run_dir, "attacker", 16)
    from infra.images import guest_userdata
    manifest = json.loads((pathlib.Path(repo_root)
                           / "infra/images/manifest.json").read_text())
    pins = {p.split("=")[0]: p for p in manifest["packages"]}
    packages = [pins[n] for n in ATTACKER_PACKAGES]
    # The attacker payload is just the role marker (keys arrive per the
    # role_keys policy below; `payload_from_repo` deliberately ships nothing
    # else for the attacker role).
    payload = {"/etc/sparring-range/role":
               (pathlib.Path(repo_root)
                / "infra/images/payloads/attacker/etc/sparring-range/role")
               .read_text()}
    user_data = guest_userdata.attacker_build_user_data(payload, packages,
                                                        key_manifest)
    seed_iso = guest_seed.build_seed_iso(
        run_dir / "attacker-build-seed.iso", user_data,
        guest_seed.meta_data(f"sr-atk-build-{key[:8]}", "sr-build-attacker"))
    rec = qemu_guest.boot_full_guest(disk=overlay, seed_iso=seed_iso,
                                     memory_mb=memory_mb, net="user",
                                     expect=("SR-GUEST-BUILD-APT-OK",
                                             "SR-GUEST-BUILD-SETUP-OK"),
                                     timeout_s=timeout_s)
    serial = run_dir / "attacker.serial.log"
    meta = {"packages": recorded_packages(serial), "inputs_hash": key,
            "qemu": rec["qemu"], "kvm": rec["kvm"]}
    (run_dir / "attacker-build-meta.json").write_text(
        json.dumps(meta, indent=2, sort_keys=True))
    shutil.copyfile(overlay, cached)
    cached_meta.write_text(json.dumps(meta, indent=2, sort_keys=True))
    for stale in cache_dir.glob("attacker-*.qcow2"):
        if stale != cached:
            stale.unlink(missing_ok=True)
    for stale in cache_dir.glob("attacker-*.json"):
        if stale != cached_meta:
            stale.unlink(missing_ok=True)
    return {"overlay": str(overlay), "cached": False, **meta}


def verify_overlay(*, overlay: pathlib.Path, run_dir: pathlib.Path, name: str,
                   user_data: str, instance_id: str, hostname: str,
                   memory_mb: int = 2048, net: str = "none",
                   timeout_s: int = 600) -> dict:
    """Boot `overlay` with a VERIFY seed (offline unless net=user); require
    the guest's DONE rc=0 marker and return the full serial marker list."""
    seed_iso = guest_seed.build_seed_iso(
        run_dir / f"{name}-seed.iso", user_data,
        guest_seed.meta_data(instance_id, hostname))
    serial_name = f"verify-{name}"
    rec = qemu_guest.boot_full_guest(disk=overlay, seed_iso=seed_iso,
                                     memory_mb=memory_mb, net=net,
                                     expect=("SR-GUEST-DONE rc=0",),
                                     timeout_s=timeout_s,
                                     serial_name=serial_name)
    serial = run_dir / f"{serial_name}.serial.log"
    markers = serial_markers(serial)
    # ALWAYS preserve the serial for the run: a lost marker (no PASS, no
    # FAIL, DONE rc=0) is an evidence-level anomaly and must never be
    # deleted by fixture cleanup (pilot: serial-loss flake root-cause).
    dbg = pathlib.Path(f"/tmp/opencode/sr-gate-debug/{name}.serial.log")
    try:
        dbg.parent.mkdir(parents=True, exist_ok=True)
        dbg.write_text(serial.read_text(errors="replace"))
    except OSError:
        pass
    failures = [m for m in markers if "-FAIL:" in m]
    if failures or "SR-GUEST-DONE rc=0" not in markers:
        raise RuntimeError(
            f"guest {name} reported check failures: {failures[:8]} "
            f"(serial preserved at {dbg})")
    return {"name": name, "markers": markers, "packages": {}, **rec}
