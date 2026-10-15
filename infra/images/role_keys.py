"""Role-appropriate SSH key policy for guest templates (plan 13 phase 3).

One operator public key baked into every account is forbidden: each guest
role accepts ONLY the principals its contract names, and private keys never
exist anywhere near a template (they are generated on the consuming service
VMs). Emergency access is a SEPARATE, explicitly-listed principal — never a
silent duplicate of the daily-use keys.

Principal -> where it may authenticate:
  runner     the platform red-team runner: attacker guest ONLY, `attacker`
  bastion    the member bastion dial: defender guests ONLY, `defender`
  mgmt       provisioning/verifier administration: `root` on every role
             (the management channel runs privileged commands — enrollment,
            DB grants, service control, audit reads; scoping this principal
             to an unprivileged account would silently break provisioning,
             so the policy FAILS CLOSED by requiring the admin mapping)
  emergency  operator break-glass: separate key, only when explicitly baked

The builder passes a key manifest {principal: public_key_line(s)}; this
module resolves it to per-user authorized_keys content, deduplicated, and
fails closed on private-key material, placeholders and unknown principals.
"""
from __future__ import annotations

import re

# principal -> {role: unix user} placement map. A principal absent from a
# role's map MUST NOT appear in that role's authorized_keys anywhere.
PLACEMENT: dict[str, dict[str, str]] = {
    "runner": {"attacker": "attacker"},
    "bastion": {"mojang-web-local": "defender", "mojang-web-db": "defender"},
    "mgmt": {"attacker": "root", "mojang-web-local": "root",
             "mojang-web-db": "root"},
    "emergency": {"attacker": "emergency", "mojang-web-local": "emergency",
                  "mojang-web-db": "emergency"},
}

_PUBKEY_RE = re.compile(
    r"^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-(?:ed25519|ssh)"
    r"@openssh\.com)\s+[A-Za-z0-9+/=]+(\s+\S+)?\s*$")
_PRIVATE_MARKER = "-----BEGIN "
_PLACEHOLDER_RE = re.compile(r"(CHANGE[_ ]?ME|CHANGEME|placeholder|TODO)",
                             re.IGNORECASE)


class KeyPolicyError(ValueError):
    pass


def _validate_public(principal: str, key: str) -> str:
    key = key.strip()
    if _PRIVATE_MARKER in key:
        raise KeyPolicyError(
            f"{principal}: PRIVATE key material refused — private keys are "
            "generated on the consuming service VM and never shipped to a "
            "template")
    if not key or _PLACEHOLDER_RE.search(key):
        raise KeyPolicyError(f"{principal}: placeholder/empty public key "
                             f"{key[:24]!r} — bake only real operator keys")
    for line in key.splitlines():
        if not line.strip():
            continue
        if not _PUBKEY_RE.match(line.strip()):
            raise KeyPolicyError(
                f"{principal}: not a well-formed OpenSSH public key line")
    return key


def resolve_role_keys(role: str, key_manifest: dict[str, str], *,
                      include_emergency: bool = False) -> dict[str, str]:
    """Return {unix user: authorized_keys content} for one guest role.

    * unknown principals are refused (typo'd key must not silently land
      nowhere — or worse, everywhere);
    * `emergency` lands ONLY when include_emergency is explicitly set;
    * keys are validated, deduplicated (per user, order-preserving) and
      newline-terminated.
    """
    if role not in {"attacker", "mojang-web-local", "mojang-web-db"}:
        raise KeyPolicyError(f"unknown guest role {role!r}")
    users: dict[str, list[str]] = {}
    for principal, key in sorted(key_manifest.items()):
        if principal not in PLACEMENT:
            raise KeyPolicyError(
                f"unknown key principal {principal!r} — allowed: "
                f"{sorted(PLACEMENT)}")
        if principal == "emergency" and not include_emergency:
            raise KeyPolicyError(
                "emergency key requested without include_emergency=True — "
                "break-glass access is an explicit, separate decision")
        placement = PLACEMENT[principal].get(role)
        if placement is None:
            continue  # principal has no business in this role: dropped
        _validate_public(principal, key)
        bucket = users.setdefault(placement, [])
        for line in key.splitlines():
            line = line.strip()
            if line and line not in bucket:
                bucket.append(line)
    return {user: "\n".join(lines) + "\n" for user, lines in users.items()}


def bake_script(role: str, key_manifest: dict[str, str], *,
                include_emergency: bool = False) -> str:
    """Shell that creates the role users and writes their authorized_keys
    ATOMICALLY (temp+mv) with correct ownership/modes. Used by the template
    finalize boot; replaces the old bake-one-key-everywhere script."""
    mapping = resolve_role_keys(role, key_manifest,
                                include_emergency=include_emergency)
    lines = ["#!/bin/bash", "set -euo pipefail"]
    for user, keys in sorted(mapping.items()):
        home = "/root" if user == "root" else f"/home/{user}"
        block = keys.rstrip("\n").replace("'", "'\\''")
        lines += [
            f"id -u {user} >/dev/null 2>&1 || useradd -m -s /bin/bash {user}",
            f'install -d -m 0700 -o {user} -g {user} {home}/.ssh',
            f"tmp=$(mktemp); printf '%s\\n' '{block}' > \"$tmp\"",
            f"if [ -f {home}/.ssh/authorized_keys ]; then "
            f"cat {home}/.ssh/authorized_keys >> \"$tmp\"; fi",
            # deduplicate, keep order
            f"awk '!seen[$0]++' \"$tmp\" > \"$tmp.d\"",
            f"install -m 0600 -o {user} -g {user} \"$tmp.d\" "
            f"{home}/.ssh/authorized_keys",
            f"rm -f \"$tmp\" \"$tmp.d\"",
        ]
    return "\n".join(lines) + "\n"
