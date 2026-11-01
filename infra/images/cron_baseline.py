#!/usr/bin/env python3
"""Trusted cron baselines bound to built-artifact digests (plan 18).

Why this exists: the cron verifier (v3) refuses to call a clean-looking
``/etc/cron.d`` clean on FILENAME alone — filenames are exactly what
persistence malware reuses, and a compromised guest must never be able to
"teach" the platform what clean looks like. Before this module there was
NOWHERE legitimate for the trusted content hashes to come from, so those
checks could only ever answer UNKNOWN.

The honest source is the CLEAN BUILT ARTIFACT: capture the bytes of every
``etc/cron.d`` file (and the root crontab) from the build output tree at
release-build time, bind them to the artifact's SHA-256 and version, and
distribute that pin file with the release. At verification time the API
injects the hashes ONLY while the artifact digest still matches the pin's;
a changed artifact, a missing pin or a corrupt pin degrades to UNKNOWN —
never to a pass and never to a guess.

This module is pure: it never SSHes, never reads a guest, never runs at
verification time beyond ``load_pins``/``trusted_hashes_for``.

Capture CLI (release build):

    python3 -m infra.images.cron_baseline capture \
        --tree mojang-web-local=/build/out/mojang-web-local \
        --tree mojang-web-db=/build/out/mojang-web-db \
        --manifest infra/images/manifest.json --out cron-baselines.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys

SCHEMA = 1
_NAME = re.compile(r"[A-Za-z0-9_.-]{1,255}")
_HEX = re.compile(r"[0-9a-f]{64}")


def _sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def capture_from_tree(root: pathlib.Path) -> dict:
    """Inventory the clean artifact tree's cron state.

    Only regular files directly in ``etc/cron.d`` and the single root
    crontab are captured. Symlinks and nested paths are NOT pinned — the
    verifier independently refuses to trust anything with unsafe
    metadata, and pinning it here would launder it."""
    root = pathlib.Path(root)
    cron_d = root / "etc" / "cron.d"
    files: dict[str, str] = {}
    if cron_d.is_dir():
        for entry in sorted(cron_d.iterdir()):
            if entry.is_symlink() or not entry.is_file():
                continue
            files[entry.name] = _sha256(entry)
    root_tab = root / "var" / "spool" / "cron" / "crontabs" / "root"
    crontab_sha = _sha256(root_tab) if root_tab.is_file() else None
    return {"files": files, "root_crontab_sha256": crontab_sha}


def capture_from_verify_markers(markers: list[str]) -> dict:
    """Extract the cron inventory emitted by the CLEAN verify boot of the
    BUILT artifact (marker ``SR-GUEST-CRON-PIN {json}``). This is the only
    sanctioned runtime-side capture source: the boot is offline, before
    any lab use, and the same harness that proves the artifact also proves
    its cron state. Absent or malformed markers raise — never a guess."""
    last_error: Exception | None = None
    for line in markers:
        if not line.startswith("SR-GUEST-CRON-PIN "):
            continue
        payload = line[len("SR-GUEST-CRON-PIN "):].strip()
        try:
            inv = json.loads(payload)
            files = inv.get("files")
            if not isinstance(files, dict):
                raise ValueError("no files object")
            for name, sha in files.items():
                if not isinstance(name, str) or not isinstance(sha, str) \
                        or not _NAME.fullmatch(name) or not _HEX.fullmatch(sha):
                    raise ValueError("invalid entry")
            tab = inv.get("root_crontab_sha256")
            if tab is not None and (not isinstance(tab, str)
                                    or not _HEX.fullmatch(tab)):
                raise ValueError("invalid root crontab hash")
        except (ValueError, AttributeError) as exc:
            # the harness emits every marker TWICE because serial noise can
            # corrupt one line: a corrupt emission is RETRIED, never trusted;
            # if none parse, the refusal is loud
            last_error = exc
            continue
        return {"files": dict(files), "root_crontab_sha256": tab}
    if last_error is not None:
        raise ValueError(f"cron pin marker invalid: {last_error}")
    raise ValueError("no SR-GUEST-CRON-PIN marker in the verify boot")


def _validate_pin(role: str, pin: dict) -> None:
    def bad(msg: str) -> None:
        raise ValueError(f"cron pin {role!r}: {msg}")

    if not isinstance(pin, dict):
        bad("must be an object")
    # explicit integer schema: Python equality would otherwise accept
    # ``true`` and ``1.0`` as version 1 (review finding)
    schema = pin.get("schema")
    if isinstance(schema, bool) or not isinstance(schema, int) \
            or schema != SCHEMA:
        bad(f"unsupported schema {schema!r}")
    # TYPE checks before any regex: a hostile or truncated pin must
    # DEGRADE TO UNKNOWN through ValueError, never crash the loader with a
    # TypeError the callers do not expect (review finding).
    digest = pin.get("artifact_sha256")
    if not isinstance(digest, str) or not _HEX.fullmatch(digest):
        bad("artifact_sha256 must be a SHA-256 hex digest string")
    version = pin.get("artifact_version")
    if not isinstance(version, str) or not version:
        bad("artifact_version must be a non-empty string")
    if not isinstance(pin.get("template_id"), int) or isinstance(
            pin.get("template_id"), bool):
        bad("template_id must be the integer template VMID this artifact "
            "was installed as (the runtime refuses pins for other templates)")
    files = pin.get("files")
    if not isinstance(files, dict):
        bad("files must be an object")
    for name, sha in files.items():
        if (not isinstance(name, str) or not isinstance(sha, str)
                or not _NAME.fullmatch(name) or name in {".", ".."}
                or not _HEX.fullmatch(sha)):
            bad("files entries must be bare names with SHA-256 hashes")
    tab = pin.get("root_crontab_sha256")
    if tab is not None and (not isinstance(tab, str)
                            or not _HEX.fullmatch(tab)):
        bad("root_crontab_sha256 must be null or a SHA-256 hex digest")
    src = pin.get("captured_from")
    if src != "clean-built-artifact":
        bad("captured_from must be 'clean-built-artifact' (pins may never "
            "be learned from a running guest)")


def build_pin(role: str, *, artifact_sha256: str, artifact_version: str,
              template_id: int, capture: dict) -> dict:
    pin = {"schema": SCHEMA, "role": role,
           "artifact_sha256": artifact_sha256.lower(),
           "artifact_version": artifact_version,
           "template_id": int(template_id),
           "captured_from": "clean-built-artifact",
           "files": dict(capture["files"]),
           "root_crontab_sha256": capture["root_crontab_sha256"]}
    _validate_pin(role, pin)
    return pin


def load_pins(path: pathlib.Path) -> dict[str, dict]:
    """Load and VALIDATE a pin document; a corrupt pin behaves exactly
    like an absent one (the caller falls back to UNKNOWN)."""
    try:
        raw = json.loads(pathlib.Path(path).read_text())
    except (OSError, ValueError):
        return {}
    if not isinstance(raw, dict):
        return {}
    top = raw.get("schema")
    if isinstance(top, bool) or not isinstance(top, int) or top != SCHEMA:
        return {}
    pins = raw.get("pins")
    if not isinstance(pins, dict):
        return {}
    out: dict[str, dict] = {}
    for role, pin in pins.items():
        try:
            if not isinstance(role, str):
                raise ValueError("role keys must be strings")
            _validate_pin(role, pin)
        except (ValueError, TypeError):
            # one bad pin invalidates the WHOLE document, and no malformed
            # value — int digests, null digests, nested junk — may ever
            # escape this loader as a crash or a half-trusted pin
            return {}
        out[role] = pin
    return out


def dump_pins(path: pathlib.Path, pins: dict[str, dict]) -> None:
    for role, pin in pins.items():
        _validate_pin(role, pin)
    doc = {"schema": SCHEMA, "pins": dict(pins)}
    pathlib.Path(path).write_text(json.dumps(doc, indent=2, sort_keys=True)
                                  + "\n")


def trusted_hashes(pins: dict[str, dict], role: str | None,
                   artifact_sha256: str | None) -> dict[str, str]:
    """The hashes to inject for ROLE — ONLY while the artifact digest the
    deployment actually runs on matches the pin's bound digest. Anything
    else (unknown role, absent pin, version/digest drift, tampered pin)
    returns {} and the verifier stays honestly UNKNOWN."""
    if not pins or not role or not artifact_sha256:
        return {}
    pin = pins.get(role)
    if pin is None:
        return {}
    if pin["artifact_sha256"] != str(artifact_sha256).lower():
        return {}
    return dict(pin["files"])


def trusted_hashes_for_deployment(pins: dict[str, dict], role: str | None, *,
                                  artifact_sha256: str | None,
                                  template_vmid: int | None) -> dict[str, str]:
    """Runtime lookup bound to the DEPLOYED artifact (review finding):
    template identity alone is stable across rebuilds, so honouring a pin
    on template ID trusted hashes for bytes the deployment never ran.  A
    pin is honoured only when the deployment resource positively records
    ALL of: the exact role, the exact template ID, AND the artifact digest
    the appliance manifest named when this session's host was cloned.
    A rebuilt artifact (new digest, new pin), an artifact the pins never
    covered, or a scenario on an unexpected template yields {} — the cron
    check reports UNKNOWN, never a pass.  Replacing the pin file can only
    ever REVOKE trust for a running session (digest stops matching),
    never forge it."""
    if not pins or not role or template_vmid is None \
            or not artifact_sha256:
        return {}
    pin = pins.get(role)
    if pin is None:
        return {}
    if pin["template_id"] != int(template_vmid):
        return {}
    if pin["artifact_sha256"] != str(artifact_sha256).lower():
        return {}
    if not isinstance(pin.get("artifact_version"), str) \
            or not pin["artifact_version"]:
        return {}
    return dict(pin["files"])


# --------------------------------------------------------------------------- #
# FROZEN baselines (second review, finding 1)                                    #
#                                                                               #
# ``trusted_hashes_for_deployment`` freezes the ARTIFACT identity but still      #
# reads the pin's FILE HASHES from the current file at scoring time: editing     #
# pins[role]["files"] in place (role/template/digest untouched) rewrote what     #
# "clean" meant for a session ALREADY RUNNING and re-scores its stored bytes.   #
# A root-controlled mutable file is not a session snapshot.  The accepted        #
# baseline must therefore be frozen INTO the immutable per-deployment evidence   #
# before it is ever used, and scoring may only ever read THAT version.  A        #
# post-launch pin replacement can then only REVOKE the artifact (identity        #
# stops binding -> UNKNOWN); it can never adopt new hashes for that session.     #
# --------------------------------------------------------------------------- #


def artifact_binding_ok(pins: dict[str, dict], role: str | None, *,
                        artifact_sha256: str | None,
                        template_vmid: int | None) -> bool:
    """Whether the CURRENT pins still positively bind the deployment's
    frozen artifact identity (role + template + digest + version).  This
    is the REVOCATION channel only: it never returns hashes.  A pin edited
    in place keeps binding (which is exactly why hashes must be frozen);
    a pin whose identity drifts (rebuilt digest, moved template) revokes
    trust for the session."""
    if not pins or not role or template_vmid is None \
            or not artifact_sha256:
        return False
    pin = pins.get(role)
    if pin is None:
        return False
    if pin.get("template_id") != int(template_vmid):
        return False
    if pin.get("artifact_sha256") != str(artifact_sha256).lower():
        return False
    return bool(isinstance(pin.get("artifact_version"), str)
                and pin["artifact_version"])


def baseline_digest(files: dict, root_crontab_sha256: str | None) -> str:
    """Integrity reference of one frozen baseline (canonical JSON)."""
    blob = json.dumps({"files": dict(files),
                       "root_crontab_sha256": root_crontab_sha256},
                      sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(blob).hexdigest()


def freeze_baseline(pins: dict[str, dict], role: str | None, *,
                    artifact_sha256: str | None,
                    template_vmid: int | None) -> dict:
    """Freeze the CLEAN baseline this artifact's pin currently vouches for
    — called at CLONE/DEPLOY time, BEFORE any scoring uses it.  Returns
    {} when no pin binds this exact identity (the session then stays
    honestly UNKNOWN forever; a pin appearing later is a NEW deployment's
    business, never this session's)."""
    if not artifact_binding_ok(pins, role,
                               artifact_sha256=artifact_sha256,
                               template_vmid=template_vmid):
        return {}
    pin = pins[role]
    files = dict(pin["files"])
    tab = pin.get("root_crontab_sha256")
    return {"files": files, "root_crontab_sha256": tab,
            "artifact_version": pin["artifact_version"],
            "baseline_sha256": baseline_digest(files, tab)}


def frozen_hashes(baseline: dict) -> dict[str, str]:
    """The hashes to inject for a session — from its FROZEN baseline only.
    A missing or corrupt (digest-mismatched) baseline yields {} — the cron
    check stays UNKNOWN; frozen evidence is never partially trusted."""
    if not isinstance(baseline, dict) or not baseline:
        return {}
    files = baseline.get("files")
    if not isinstance(files, dict) or not files:
        return {}
    tab = baseline.get("root_crontab_sha256")
    if tab is not None and (not isinstance(tab, str)
                            or not _HEX.fullmatch(tab)):
        return {}
    if baseline.get("baseline_sha256") != baseline_digest(files, tab):
        return {}
    for name, sha in files.items():
        if not isinstance(name, str) or not isinstance(sha, str) \
                or not _NAME.fullmatch(name) or not _HEX.fullmatch(sha):
            return {}
    return dict(files)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="cron_baseline")
    sub = ap.add_subparsers(dest="cmd", required=True)
    cap = sub.add_parser("capture",
                         help="pin cron state from ONE clean built role "
                              "(run per rebuilt role; unchanged roles keep "
                              "their existing pin — artifacts are never "
                              "re-pinned wholesale)")
    cap.add_argument("--role", required=True)
    cap.add_argument("--tree", required=True,
                     help="built artifact rootfs tree")
    cap.add_argument("--image", required=True,
                     help="the built role image (qcow2) whose SHA-256 the "
                          "pin binds to")
    cap.add_argument("--template-id", required=True, type=int)
    cap.add_argument("--version", default=None,
                     help="artifact version (default: the image digest)")
    cap.add_argument("--out", required=True)
    ver = sub.add_parser("verify", help="re-verify a pin against a tree")
    ver.add_argument("--pin", required=True)
    ver.add_argument("--role", required=True)
    ver.add_argument("--tree", required=True)
    args = ap.parse_args(argv)

    if args.cmd == "capture":
        out = pathlib.Path(args.out)
        tree = pathlib.Path(args.tree)
        image = pathlib.Path(args.image)
        if not tree.is_dir() or not image.is_file():
            print("tree or image missing", file=sys.stderr)
            return 2
        digest = _sha256(image)
        pins = load_pins(out)
        pins[args.role] = build_pin(
            args.role, artifact_sha256=digest,
            artifact_version=args.version or digest,
            template_id=args.template_id, capture=capture_from_tree(tree))
        dump_pins(out, pins)
        print(f"pinned {args.role} to sha256:{digest[:12]} -> {out}")
        return 0

    if args.cmd == "verify":
        pins = load_pins(pathlib.Path(args.pin))
        if args.role not in pins:
            print(f"{args.role}: pin absent or document invalid",
                  file=sys.stderr)
            return 1
        current = capture_from_tree(pathlib.Path(args.tree))
        if current["files"] != pins[args.role]["files"]:
            print(f"{args.role}: artifact cron state no longer matches the "
                  "pin — rebuild the pin from the NEW clean artifact",
                  file=sys.stderr)
            return 1
        print(f"{args.role}: cron state matches the pinned artifact")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
