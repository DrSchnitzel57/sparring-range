"""Pinned attacker tool inventories — capability contract for attacker images.

The AI may only use what is PREINSTALLED and VERIFIED in the attacker image
(no internet package fetching during practice, and a missing binary is a
capability gap we must report, never something the model narrates past).
This module declares the REQUIRED capability set per attacker image
profile; exact package releases are pinned by the build manifest when the
image ships, and preflight re-checks presence by binary name.

Capability categories (all required for live offense against Linux AND
Windows/AD replicas): reconnaissance, SSH, HTTP/TLS, SMB, LDAP/Kerberos,
WinRM, SQL, plus the runtimes those tools need.
"""
from __future__ import annotations

import re

_BINARY_RE = re.compile(r"^[a-z0-9][a-z0-9._+-]{0,63}$")

REQUIRED_CATEGORIES = ("recon", "ssh", "http_tls", "smb", "ldap_kerberos",
                       "winrm", "sql", "runtime")

ATTACKER_PROFILES: dict[str, dict[str, tuple[str, ...]]] = {
    "attacker-debian": {
        "recon": ("nmap", "dnsrecon", "enum4linux-ng", "resolvectl"),
        "ssh": ("ssh", "scp", "ssh-keyscan"),
        "http_tls": ("curl", "wget", "openssl", "httpx", "ffuf"),
        "smb": ("smbclient", "rpcclient", "netexec", "crackmapexec"),
        "ldap_kerberos": ("ldapsearch", "kinit", "klist", "impacket-getst",
                          "impacket-GetUserSPNs".lower(), "impacket-secretsdump"),
        "winrm": ("evil-winrm", "impacket-winvrm", "impacket-wmiexec"),
        "sql": ("sqlcmd", "impacket-mssqlquery", "pymssql-python"),
        "runtime": ("python3", "ruby", "dotnet", "node", "git"),
    },
}


def validate_inventory() -> list[str]:
    """Static self-check used by tests and image preflight (returns issues;
    empty list means the inventory is well-formed)."""
    issues: list[str] = []
    for profile, cats in ATTACKER_PROFILES.items():
        missing = [c for c in REQUIRED_CATEGORIES if c not in cats]
        if missing:
            issues.append(f"{profile}: missing categories {missing}")
        for cat, bins in cats.items():
            if not bins:
                issues.append(f"{profile}.{cat}: empty")
            for b in bins:
                if not _BINARY_RE.match(b):
                    issues.append(f"{profile}.{cat}: unsafe binary name {b!r}")
    return issues


def verify_report(profile: str, which_out: dict[str, bool]) -> dict:
    """Given {binary: present} from the guest, report the honest gaps."""
    cats = ATTACKER_PROFILES.get(profile)
    if cats is None:
        return {"ok": False, "error": f"unknown attacker profile {profile!r}"}
    missing = sorted(b for bins in cats.values() for b in bins
                     if not which_out.get(b))
    return {"ok": not missing, "profile": profile, "missing": missing,
            "capabilities": {c: list(b) for c, b in cats.items()}}
