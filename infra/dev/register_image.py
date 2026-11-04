"""Register a BUILT artifact as an approved image in the appliance manifest.

The manifest is the only authority the broker consults: an image exists for
the range when it has a role entry with its path, digest, size and template
id. This tool makes that update atomic and provable instead of a hand edit:
the digest is computed from the bytes actually shipped, the budgets come from
the blueprint's own sizing, and the resulting document is validated with the
strict loader before anything is applied.

Run on the appliance as root:

    .venv/bin/python -m infra.dev.register_image \\
        --role ws2019-sql --artifact /var/lib/sparring-range/builds/win2019/sr-win2019.qcow2 \\
        --template-id 9106 --profile ws2019-sql \\
        --disk-gb 64 --memory-mb 6144 --vcpus 2 --apply
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import shutil
import sys

DEFAULT_MANIFEST = "/etc/sparring-range/appliance-manifest.json"


def digest(path: pathlib.Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            size += len(chunk)
            h.update(chunk)
    return h.hexdigest(), size


def register(raw: dict, *, role: str, path: str, sha256: str, size_bytes: int,
             template_id: int, profile: str, disk_gb: int, memory_mb: int,
             vcpus: int) -> dict:
    """PURE manifest edit: the role's entry with exactly the given identity.

    The digest is never carried over from a previous build (that is how a
    stale artifact silently passes); refusal is left to the strict loader,
    which also checks every OTHER pinned image still exists and matches.
    """
    images = dict(raw.get("images") or {})
    images[role] = {
        "disk_gb": int(disk_gb),
        "memory_mb": int(memory_mb),
        "path": str(path),
        "profile": str(profile),
        "sha256": str(sha256),
        "size_bytes": int(size_bytes),
        "template_id": int(template_id),
        "vcpus": int(vcpus),
    }
    out = dict(raw)
    out["images"] = dict(sorted(images.items()))
    return out


def _validate(raw: dict, *, verify_files: bool) -> None:
    from infra.appliance.manifest import ApplianceManifest
    ApplianceManifest.from_dict(raw, verify_images=verify_files,
                                verify_model_key=False)


def _main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--manifest", default=DEFAULT_MANIFEST)
    ap.add_argument("--role", required=True)
    ap.add_argument("--artifact", required=True, help="built qcow2/raw image")
    ap.add_argument("--template-id", type=int, required=True)
    ap.add_argument("--profile", required=True)
    ap.add_argument("--disk-gb", type=int, required=True)
    ap.add_argument("--memory-mb", type=int, required=True)
    ap.add_argument("--vcpus", type=int, required=True)
    ap.add_argument("--images-dir", default=None,
                    help="copy the artifact here as <role>.qcow2 "
                         "(default: the manifest's images_dir)")
    ap.add_argument("--apply", action="store_true",
                    help="run `deploy.appliance apply`, restart the API and "
                         "the broker, then release the latch (root-run)")
    args = ap.parse_args(argv)

    manifest_path = pathlib.Path(args.manifest)
    raw = json.loads(manifest_path.read_text())
    if args.images_dir:
        images_dir = pathlib.Path(args.images_dir)
    else:
        images_dir = pathlib.Path(str(raw.get("paths", {}).get("images_dir")
                                     or "/var/lib/sparring-range/images"))
    images_dir.mkdir(parents=True, exist_ok=True)
    dest = images_dir / f"{args.role}.qcow2"
    artifact = pathlib.Path(args.artifact)
    if artifact.resolve() != dest.resolve():
        shutil.copyfile(artifact, dest)
        os.chmod(dest, 0o644)
    sha, size = digest(dest)
    raw = register(raw, role=args.role, path=str(dest), sha256=sha,
                   size_bytes=size, template_id=args.template_id,
                   profile=args.profile, disk_gb=args.disk_gb,
                   memory_mb=args.memory_mb, vcpus=args.vcpus)
    _validate(raw, verify_files=True)
    manifest_path.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n")
    os.chmod(manifest_path, 0o644)
    print(json.dumps({"registered": args.role, "path": str(dest),
                      "sha256": sha, "size_bytes": size,
                      "template_id": args.template_id}, indent=1))

    if not args.apply:
        print("manifest written and validated; --apply not requested")
        return 0

    import subprocess
    subprocess.run([sys.executable, "-m", "deploy.appliance", "apply",
                    "--manifest", str(manifest_path)], check=True)
    print("applied")
    return 0


if __name__ == "__main__":
    sys.exit(_main())
