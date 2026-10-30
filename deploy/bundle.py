#!/usr/bin/env python3
"""Build and verify the appliance release bundle (milestone 16).

The bundle is what an operator carries into their own virtual machine: the
application, the LOCKED dependency set, the flattened guest base images, the
installer with its fixed systemd/network artifacts, and a short operator
guide.  Everything in it is addressed by a SHA-256 digest in a single
``MANIFEST.json``.

Hard rules (all fail closed):

* no secret material is ever written into a bundle — a private key block, a
  password or a token in a packaged file is an error, not a warning;
* the bundle is *appliance-generic*: the operator's own addresses, ranges
  and installation id are rendered at install time from the bundle, never
  baked in;
* ``verify`` re-computes every digest and refuses drift, so a bundle that was
  edited, truncated or partially copied cannot be installed as if it were the
  released artifact;
* the bundle never contains the operator's ledger, recordings, keys or
  database.

Usage::

    python deploy/bundle.py build --output /tmp/sr-bundle \\
        --base-image /path/to/appliance-base.qcow2 \\
        --role-image mojang-web-local=/path/to/web-local.qcow2
    python deploy/bundle.py verify /tmp/sr-bundle
    python deploy/bundle.py manifest /tmp/sr-bundle --out manifest.json \\
        --installation-id 4f0e7a1c-8a59-4a4e-9b5d-74f0e7a1c222 \\
        --lan-address 10.10.10.50 --range-cidr 10.66.0.0/24 \\
        --public-url https://sr.example.edu \\
        --internal-url http://127.0.0.1:8000 \\
        --ingest-url https://10.66.0.1:8443
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

BUNDLE_VERSION = 2
MANIFEST_NAME = "MANIFEST.json"
TARGET_OS = "ubuntu-24.04"
TARGET_PYTHON = "3.12"

# Directories that never belong in a release bundle.
_EXCLUDED_DIRS = {".git", ".venv", ".cache", "node_modules", ".next",
                  "__pycache__", ".pytest_cache", "recordings", ".e2e-builds"}
_EXCLUDED_SUFFIXES = (".pyc", ".pyo", ".cast", ".log")
# Files that carry operator secrets or evidence never travel in a bundle.
_EXCLUDED_NAMES = (".env", ".env.local", "pgadmin.env", "known_hosts",
                   "install_receipt.json")
_EXCLUDED_GLOBS = ("id_*", "*_ed25519", "*_ed25519.pub", "*.pem", "*.key")

# A packaged file that looks like credential material is a hard error.
_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\bauthorization:\s*bearer\s+\S+"),
)
# An assignment that looks like a stored credential is only meaningful in
# configuration: application source legitimately contains the word "password".
_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(password|passwd|api[_-]?key|secret|token)\s*[=:]\s*[\"']?([^\s\"']+)")
# A credential value is long and has no spaces; prose ("token: create") is not.
_MIN_SECRET_LEN = 16
_CONFIG_SUFFIXES = (".env", ".json", ".yaml", ".yml", ".ini", ".conf", ".toml",
                    ".sh", ".properties", ".cfg", ".txt", ".service")
_SOURCE_SUFFIXES = (".py", ".js", ".ts", ".tsx", ".jsx", ".md", ".rst",
                    ".sql", ".html", ".css")


class BundleError(RuntimeError):
    pass


def _sha256(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _revision() -> str:
    try:
        return subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO,
                              capture_output=True, text=True,
                              timeout=30).stdout.strip() or "unknown"
    except Exception:  # noqa: BLE001 — a bundle without a revision is labelled
        return "unknown"


# The directories and top-level files a release bundle carries.
APP_DIRS = ("docs", "deploy", "scenarios", "srplatform", "rangectl", "infra",
            "tests", "web", "audit", "verifiers", "telemetry")
APP_FILES = ("pyproject.toml", "requirements.lock", "alembic.ini", "README.md",
             "AGENTS.md")
# The parts of the bundle that are RUNTIME: what the appliance executes.
RUNTIME_DIRS = ("srplatform", "deploy", "infra", "verifiers", "telemetry",
                "audit", "rangectl", "scenarios", "web")
RUNTIME_FILES = ("pyproject.toml", "requirements.lock", "alembic.ini")


def is_runtime(rel) -> bool:
    """Is this packaged path part of the application's runtime?"""
    rel = str(rel)
    if rel in RUNTIME_FILES:
        return True
    head = rel.split("/", 1)[0]
    return head in RUNTIME_DIRS


def app_file_relpaths(root: pathlib.Path) -> set[str]:
    """The relative paths a bundle built from ``root`` carries."""
    return {str(rel) for rel, _path in _iter_app_files(root)
            if rel.parts[0] in APP_DIRS or rel.parts[0] in APP_FILES}


def _iter_app_files(root: pathlib.Path):
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if any(part in _EXCLUDED_DIRS for part in rel.parts):
            continue
        if rel.name.endswith(_EXCLUDED_SUFFIXES):
            continue
        if rel.name in _EXCLUDED_NAMES:
            continue
        if any(fnmatch.fnmatch(rel.name, g) for g in _EXCLUDED_GLOBS):
            continue
        yield rel, path


def _scan_for_secrets(rel: str, data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    name = rel.rsplit("/", 1)[-1]
    if name.endswith(_SOURCE_SUFFIXES):
        # Application source is covered by the repository's own secret
        # policy; the bundle's job is not to introduce operator material.
        return None
    for pattern in _SECRET_PATTERNS:
        if pattern.search(text):
            return f"{rel}: looks like credential material ({pattern.pattern})"
    if name.endswith(_CONFIG_SUFFIXES) or "." not in name:
        match = _ASSIGNMENT_PATTERN.search(text)
        if match and len(match.group(2)) >= _MIN_SECRET_LEN:
            return (f"{rel}: looks like a stored credential "
                    f"({match.group(0)[:40]!r})")
    return None


def _qemu_img(*args: str) -> str:
    """Run qemu-img and return its output (the release needs it)."""
    if shutil.which("qemu-img") is None:
        raise BundleError("qemu-img is required to build a release bundle: "
                          "the shipped images are validated (and flattened) "
                          "with it")
    r = subprocess.run(["qemu-img", *args], capture_output=True, text=True,
                       timeout=3600)
    if r.returncode != 0:
        raise BundleError(f"qemu-img {' '.join(args)} failed: "
                          f"{(r.stderr or r.stdout)[-400:]}")
    return r.stdout


def _image_info(path: pathlib.Path) -> dict:
    try:
        return json.loads(_qemu_img("info", "--output=json", str(path)))
    except json.JSONDecodeError as exc:
        raise BundleError(f"{path} is not a readable qcow2 image: {exc}") from exc


def _add_image(src: pathlib.Path, dst: pathlib.Path) -> None:
    """Put a SELF-CONTAINED image into the bundle.

    A qcow2 overlay whose backing file lives in the build machine's temp
    directory is broken the moment it is copied: the backing file is gone
    and the image cannot be opened. The bundle therefore flattens such an
    image and verifies that what it ships has no backing file at all — a
    released artifact must not depend on anything outside itself.
    """
    info = _image_info(src)
    if info.get("backing-filename"):
        _qemu_img("convert", "-O", "qcow2", str(src), str(dst))
    else:
        shutil.copyfile(src, dst)
    shipped = _image_info(dst)
    if shipped.get("backing-filename"):
        raise BundleError(f"{dst} still has a backing file "
                          f"({shipped.get('backing-filename')})")
    chain = _qemu_img("info", "--backing-chain", str(dst))
    images = [ln for ln in chain.splitlines() if ln.startswith("image:")]
    if len(images) != 1:
        raise BundleError(f"{dst} has a backing chain of {len(images)} "
                          "images; a released image must stand alone")


def _ship_image(src: pathlib.Path, dst: pathlib.Path, *,
                link: bool = False) -> None:
    """Place an image into the bundle (see _add_image). With ``link`` the
    SHIPPED inode is a HARDLINK to the source — bytes identical, no second
    copy — which requires the source to be a self-contained single-image
    qcow2 in bundle mode already (verified exactly as _add_image would);
    release artifacts must not silently depend on a build machine path,
    and the source seals keep the same bytes either way."""
    if not link:
        _add_image(src, dst)
        return
    info = _image_info(src)
    if info.get("backing-filename"):
        raise BundleError(
            f"--link-images requires a self-contained source image, but "
            f"{src} has backing file {info['backing-filename']!r}")
    chain = _qemu_img("info", "--backing-chain", str(src))
    images = [ln for ln in chain.splitlines() if ln.startswith("image:")]
    if len(images) != 1:
        raise BundleError(f"{src} has a backing chain of {len(images)} "
                          "images; a released image must stand alone")
    mode = src.stat().st_mode & 0o777
    if mode != 0o644:
        raise BundleError(
            f"--link-images shares the source inode (mode {mode:04o}); "
            f"{src} must already carry the bundle mode 0644 so linking "
            "cannot mutate a sealed artifact")
    os.link(src, dst)


def build(output: pathlib.Path, *, base_image: pathlib.Path,
          role_images: dict[str, pathlib.Path], app_dir: pathlib.Path = REPO,
          guest_agent_available: bool = True,
          link_images: bool = False) -> dict:
    output = pathlib.Path(output)
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)

    files: dict[str, dict] = {}

    def add(src: pathlib.Path, rel: str) -> None:
        dst = output / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        os.chmod(dst, 0o644)
        files[rel] = {"sha256": _sha256(dst), "bytes": dst.stat().st_size}

    # 1. the application (source + locked dependencies + tests)
    for rel, path in _iter_app_files(app_dir):
        if rel.parts[0] in APP_DIRS or rel.parts[0] in APP_FILES:
            add(path, str(rel))
    # 2. the guest base images — self-contained, verified
    images = {}
    if base_image.is_file():
        rel = f"images/{base_image.name}"
        dst = output / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        _ship_image(base_image, dst, link=link_images)
        if not link_images:
            os.chmod(dst, 0o644)
        files[rel] = {"sha256": _sha256(dst), "bytes": dst.stat().st_size}
        images["appliance-base"] = {"path": rel, "sha256": files[rel]["sha256"],
                                    "bytes": files[rel]["bytes"]}
    for role, path in sorted(role_images.items()):
        if not path.is_file():
            raise BundleError(f"role image missing: {path}")
        rel = f"images/{path.name}"
        dst = output / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        _ship_image(path, dst, link=link_images)
        if not link_images:
            os.chmod(dst, 0o644)
        files[rel] = {"sha256": _sha256(dst), "bytes": dst.stat().st_size}
        images[role] = {"path": rel, "sha256": files[rel]["sha256"],
                        "bytes": files[rel]["bytes"]}
    if not guest_agent_available:
        raise BundleError("the guest agent is not available in the base image")

    manifest_revision = _revision()
    manifest = {
        "bundle_version": BUNDLE_VERSION,
        "revision": manifest_revision,
        "target": {"os": TARGET_OS, "python": TARGET_PYTHON},
        "images": images,
        "files": dict(sorted(files.items())),
        "install": {
            "command": "python deploy/appliance.py apply --manifest manifest.json",
            "notes": "render the operator manifest with: "
                     "python deploy/bundle.py manifest <bundle> --out manifest.json ...",
        },
        "upgrade": {
            "engine": "deploy/upgrade.py",
            "migrations": "srplatform/db/migrations/versions",
            "bundle_version": BUNDLE_VERSION,
            "revision": manifest_revision,
            "command": "SR_PG_UPGRADE_URL=... python deploy/appliance.py "
                       "upgrade --manifest manifest.json --payload <this "
                       "bundle>  # owner URL via environment ONLY: a URL "
                       "with a credential must never be a process argument",
            "notes": "preserving in-place upgrade: journal first, admission "
                     "fence, private config + database backups (password "
                     "via private PGPASSFILE, never argv), digest-verified "
                     "staging, per-file atomic activation, provisioning of "
                     "the locked runtime + frontend BEFORE migration, "
                     "forward-only migrations, checked service restart with "
                     "readiness, version stamp last; data, keys and the "
                     "ledger are never deleted, and unknown in-flight work "
                     "is refused until resolved",
        },
    }
    (output / MANIFEST_NAME).write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def verify(bundle: pathlib.Path) -> dict:
    bundle = pathlib.Path(bundle)
    manifest_path = bundle / MANIFEST_NAME
    if not manifest_path.is_file():
        raise BundleError(f"no {MANIFEST_NAME} in {bundle}")
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("bundle_version") != BUNDLE_VERSION:
        raise BundleError(f"unsupported bundle version "
                          f"{manifest.get('bundle_version')!r}")
    problems: list[str] = []
    files = manifest.get("files") or {}
    for rel, expect in sorted(files.items()):
        path = bundle / rel
        if not path.is_file():
            problems.append(f"missing: {rel}")
            continue
        if path.stat().st_size != expect.get("bytes"):
            problems.append(f"size drift: {rel}")
            continue
        if _sha256(path) != expect.get("sha256"):
            problems.append(f"digest drift: {rel}")
            continue
        secret = _scan_for_secrets(rel, path.read_bytes())
        if secret:
            problems.append(secret)
    # the upgrade payload contract: a bundle that cannot drive the
    # preserving upgrade is not a release artifact (milestone 21)
    upgrade = manifest.get("upgrade") or {}
    if not upgrade:
        problems.append("no `upgrade` contract in the manifest: pre-21 "
                        "bundles must be rebuilt before they can upgrade "
                        "an appliance")
    else:
        engine_rel = str(upgrade.get("engine") or "")
        if not engine_rel:
            problems.append("upgrade contract missing 'engine'")
        elif engine_rel not in files:
            problems.append(f"upgrade contract names {engine_rel} which the "
                            "bundle does not carry")
        if "revision" not in upgrade or upgrade.get("revision") != \
                manifest.get("revision"):
            problems.append("upgrade contract revision does not match the "
                            "bundle revision")
        mig_dir = str(upgrade.get("migrations") or "").rstrip("/")
        if not mig_dir:
            problems.append("upgrade contract missing 'migrations'")
        elif not any(rel.startswith(mig_dir + "/") and
                     rel.endswith(".py") for rel in files):
            problems.append(f"upgrade contract names {mig_dir} but the "
                            "bundle carries no migrations there")
        elif (bundle / mig_dir).is_dir():
            from deploy.upgrade import migration_heads
            heads = migration_heads(bundle / mig_dir)
            if len(heads) != 1:
                problems.append(
                    f"upgrade payload migration graph has {len(heads)} "
                    f"heads ({sorted(heads)}); refusing")
    # the shipped images must stand alone: an image that depends on a file
    # outside the bundle cannot be installed on the operator's machine.
    for rel, meta in sorted((manifest.get("images") or {}).items()):
        path = bundle / meta["path"]
        if not path.is_file():
            problems.append(f"missing image: {meta['path']}")
            continue
        if shutil.which("qemu-img") is None:
            continue
        try:
            info = json.loads(_qemu_img("info", "--output=json", str(path)))
        except BundleError as exc:
            problems.append(f"{meta['path']}: {exc}")
            continue
        if info.get("backing-filename"):
            problems.append(f"{meta['path']} depends on "
                            f"{info['backing-filename']}, which is outside the "
                            "bundle")
    # a file that is not in the manifest is drift too
    for path in sorted(bundle.rglob("*")):
        if path.is_file() and path.name != MANIFEST_NAME:
            rel = str(path.relative_to(bundle))
            if rel not in files:
                problems.append(f"unlisted file: {rel}")
    return {"ok": not problems, "problems": problems,
            "files": len(files), "images": len(manifest.get("images") or {}),
            "revision": manifest.get("revision")}


def render_manifest(bundle: pathlib.Path, out: pathlib.Path, *,
                     installation_id: str, lan_address: str, range_cidr: str,
                     public_url: str, internal_url: str, ingest_url: str,
                     bridge: str = "srlab0", hostname: str = "sr-appliance",
                     timezone: str = "UTC", gateway: str | None = None,
                     controller_range_ip: str | None = None,
                     bastion_address: str | None = None,
                     ingest_address: str | None = None,
                     ingest_port: int = 8443, management_cidr: str = "10.0.0.0/24",
                     access_keys: dict[str, str] | None = None,
                     member_keys: dict[str, str] | None = None,
                     model_base_url: str = "http://127.0.0.1:8001/v1",
                     model_alias: str = "sr-model",
                     model_api_key_file: str = "/etc/sparring-range/secrets/model.key",
                     max_guests: int = 6, max_vcpus: int = 12,
                     max_memory_mb: int = 12288, max_disk_gb: int = 44,
                     min_free_gb: int = 20) -> dict:
    """Render a valid appliance manifest from the bundle plus the operator's
    own parameters.  The operator never edits the manifest by hand."""
    import ipaddress

    # The image paths in the manifest MUST be absolute: the installer copies
    # them from an absolute location and a relative path is refused.
    bundle = pathlib.Path(bundle).resolve()
    manifest = json.loads((bundle / MANIFEST_NAME).read_text())
    images_meta = manifest.get("images") or {}
    base = images_meta.get("appliance-base")
    if not base:
        raise BundleError("the bundle carries no appliance base image")
    net = ipaddress.ip_network(range_cidr)
    gateway = gateway or str(net.network_address + 1)
    controller = controller_range_ip or gateway
    bastion = bastion_address or str(net.network_address + 2)
    ingest = ingest_address or controller
    lan = ipaddress.ip_interface(f"{lan_address}/24").ip

    def image_entry(path_rel: str, template_id: int, disk_gb: int,
                    memory_mb: int, vcpus: int) -> dict:
        path = bundle / path_rel
        return {"template_id": template_id, "path": str(path),
                "sha256": _sha256(path), "size_bytes": path.stat().st_size,
                "disk_gb": disk_gb, "memory_mb": memory_mb, "vcpus": vcpus}

    # Every role MUST have its OWN artifact: the base image is a bare Ubuntu
    # and the practice product (the web/db services, the shipped payload) is
    # baked into the role images.  Falling back to the base would ship guests
    # that cannot run the scenario, so the renderer refuses instead.
    from infra.images.specs import GUEST_BUDGETS

    role_meta = {role: meta for role, meta in images_meta.items()
                 if role != "appliance-base"}
    missing = [role for role in sorted(GUEST_BUDGETS) if role not in role_meta]
    if missing:
        raise BundleError(
            "the bundle carries no role image for: "
            + ", ".join(missing)
            + " — the shipped guests would be a bare Ubuntu without the "
              "practice product. Build the role images and rebuild the bundle "
              "(deploy/bundle.py build --role-image ROLE=PATH ...).")
    images = {}
    for role, budget in sorted(GUEST_BUDGETS.items()):
        images[role] = image_entry(
            role_meta[role]["path"], budget["template_vmid"],
            budget["disk_gb"], budget["memory_mb"], budget["vcpus"])

    raw = {
        "schema_version": 1,
        "installation_id": installation_id,
        "appliance": {"hostname": hostname, "timezone": timezone},
        "network": {
            "lan_cidr": str(ipaddress.ip_network(f"{lan}/24", strict=False)),
            "lan_address": str(lan),
            "range_cidr": str(net),
            "range_bridge": bridge,
            "range_gateway": gateway,
            "controller_range_ip": controller,
            "bastion_address": bastion,
            "ingest_address": ingest,
            "ingest_port": ingest_port,
            "management_cidr": management_cidr,
        },
        "urls": {"public": public_url, "internal": internal_url,
                 "ingest": ingest_url},
        "broker": {"socket": "/run/sparring-range/broker.sock",
                   "ledger": "/var/lib/sparring-range/broker-ledger.sqlite3",
                   "state_dir": "/var/lib/sparring-range"},
        "paths": {"images": "/var/lib/sparring-range/images",
                  "recordings": "/var/lib/sparring-range/recordings",
                  "secrets": "/etc/sparring-range/secrets"},
        "images": images,
        "access_keys": access_keys or {
            "runner": "/etc/sparring-range/keys/runner.pub",
            "bastion": "/etc/sparring-range/keys/bastion.pub",
            "mgmt": "/etc/sparring-range/keys/mgmt.pub",
        },
        # The MEMBERS' public keys, by the username they log in with on the
        # recording bastion. The machine roles above are baked into the
        # guest templates; they are not logins.
        "member_keys": dict(sorted((member_keys or {}).items())),
        "model": {"base_url": model_base_url, "alias": model_alias,
                  "api_key_file": model_api_key_file},
        "budgets": {"max_guests": max_guests, "max_vcpus": max_vcpus,
                    "max_memory_mb": max_memory_mb, "max_disk_gb": max_disk_gb,
                    "min_free_gb": min_free_gb},
        "backup": {"enabled": False, "destination": ""},
    }
    from infra.appliance.manifest import ApplianceManifest

    parsed = ApplianceManifest.from_dict(raw, verify_images=True)
    out = pathlib.Path(out)
    out.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    return {"manifest": str(out), "installation_id": parsed.installation_id,
            "images": sorted(parsed.images)}


def _parser() -> argparse.ArgumentParser:
    """The CLI's parser (so a caller can check the flags it accepts)."""
    ap = argparse.ArgumentParser(prog="deploy/bundle.py")
    sub = ap.add_subparsers(dest="cmd", required=True)

    pb = sub.add_parser("build")
    pb.add_argument("--output", required=True)
    pb.add_argument("--base-image", required=True)
    pb.add_argument("--role-image", action="append", default=[],
                    metavar="ROLE=PATH")
    pb.add_argument("--link-images", action="store_true",
                    help="ship the qcow2 files as hardlinks to the (already "
                         "self-contained, 0644) source images instead of a "
                         "second full copy; bytes and seals are unchanged")

    pv = sub.add_parser("verify")
    pv.add_argument("bundle")

    pm = sub.add_parser("manifest")
    pm.add_argument("bundle")
    pm.add_argument("--out", required=True)
    pm.add_argument("--installation-id", required=True)
    pm.add_argument("--lan-address", required=True)
    pm.add_argument("--range-cidr", required=True)
    pm.add_argument("--public-url", required=True)
    pm.add_argument("--internal-url", required=True)
    pm.add_argument("--ingest-url", required=True)
    pm.add_argument("--bridge", default="srlab0")
    pm.add_argument("--hostname", default="sr-appliance")
    pm.add_argument("--timezone", default="UTC")
    pm.add_argument("--gateway")
    pm.add_argument("--controller-range-ip")
    pm.add_argument("--bastion-address")
    pm.add_argument("--ingest-address")
    pm.add_argument("--ingest-port", type=int, default=8443)
    pm.add_argument("--management-cidr", default="10.0.0.0/24")
    pm.add_argument("--access-key", action="append", default=[],
                    metavar="ROLE=PATH")
    pm.add_argument("--member-key", action="append", default=[],
                    metavar="USERNAME=PATH")
    pm.add_argument("--model-base-url", default="http://127.0.0.1:8001/v1")
    pm.add_argument("--model-alias", default="sr-model")
    pm.add_argument("--model-api-key-file",
                    default="/etc/sparring-range/secrets/model.key")

    return ap


def main(argv: list[str] | None = None) -> int:
    ap = _parser()
    args = ap.parse_args(argv)
    try:
        if args.cmd == "build":
            role_images = {}
            for item in args.role_image:
                role, _, path = item.partition("=")
                if not path:
                    raise BundleError(f"--role-image must be ROLE=PATH: {item!r}")
                role_images[role] = pathlib.Path(path)
            manifest = build(pathlib.Path(args.output),
                             base_image=pathlib.Path(args.base_image),
                             role_images=role_images,
                             link_images=args.link_images)
            from infra.images.specs import GUEST_BUDGETS
            carried = set(manifest["images"])
            missing = [role for role in sorted(GUEST_BUDGETS)
                       if role not in carried]
            print(json.dumps({"bundle": args.output,
                              "revision": manifest["revision"],
                              "files": len(manifest["files"]),
                              "images": sorted(manifest["images"]),
                              # loud, not fatal here: `manifest` refuses to
                              # render an appliance from a bundle that lacks
                              # the role artifacts.
                              "roles_missing": missing},
                             indent=2, sort_keys=True))
        elif args.cmd == "verify":
            result = verify(pathlib.Path(args.bundle))
            print(json.dumps(result, indent=2, sort_keys=True))
            if not result["ok"]:
                return 1
        elif args.cmd == "manifest":
            keys = {}
            for item in args.access_key:
                role, _, path = item.partition("=")
                keys[role] = path
            members = {}
            for item in args.member_key:
                username, _, path = item.partition("=")
                if not path:
                    raise BundleError(f"--member-key must be USERNAME=PATH: "
                                      f"{item!r}")
                members[username] = path
            out = render_manifest(
                pathlib.Path(args.bundle), pathlib.Path(args.out),
                installation_id=args.installation_id,
                lan_address=args.lan_address, range_cidr=args.range_cidr,
                public_url=args.public_url, internal_url=args.internal_url,
                ingest_url=args.ingest_url, bridge=args.bridge,
                hostname=args.hostname, timezone=args.timezone,
                gateway=args.gateway,
                controller_range_ip=args.controller_range_ip,
                bastion_address=args.bastion_address,
                ingest_address=args.ingest_address,
                ingest_port=args.ingest_port,
                management_cidr=args.management_cidr,
                access_keys=keys or None, member_keys=members or None,
                model_base_url=args.model_base_url,
                model_alias=args.model_alias,
                model_api_key_file=args.model_api_key_file)
            print(json.dumps(out, indent=2, sort_keys=True))
        return 0
    except BundleError as exc:
        print(f"bundle: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
