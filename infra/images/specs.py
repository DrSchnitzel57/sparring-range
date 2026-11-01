"""Canonical Mojang guest budgets (paired 03+04, steps 1/4).

Each guest: 2 vCPU / 2 GiB RAM. Disks: attacker 16 / web-local 12 / web-db 16
GiB. Range totals (mojang-web-db-01): 6 vCPU / 6 GiB / 44 GiB disks;
templates/control/evidence/reserve are additional. The broker enforces these
with actual libvirt read-back; the orchestrator reserves the aggregate before any
side effect. Guessing or resizing to get a green test is forbidden.
"""
from __future__ import annotations

GUEST_BUDGETS: dict[str, dict] = {
    "attacker": {"vcpus": 2, "memory_mb": 2048, "disk_gb": 16,
                 "template_vmid": 9005},
    "mojang-web-local": {"vcpus": 2, "memory_mb": 2048, "disk_gb": 12,
                         "template_vmid": 9011},
    "mojang-web-db": {"vcpus": 2, "memory_mb": 2048, "disk_gb": 16,
                      "template_vmid": 9012},
}

# Template VMID -> guest role (new mojang IDs; legacy snapshots preserved
# separately and are NOT release-ready without manifests).
TEMPLATE_ROLES: dict[int, str] = {
    9005: "attacker",
    9011: "mojang-web-local",
    9012: "mojang-web-db",
}

# Scenario -> expected guest roles (attacker is always fresh per session).
SCENARIO_GUESTS: dict[str, tuple[str, ...]] = {
    "mojang-web-01": ("attacker", "mojang-web-local"),
    "mojang-web-db-01": ("attacker", "mojang-web-local", "mojang-web-db"),
}

RANGE_TOTALS_DB = {"vcpus": 6, "memory_mb": 6144, "disk_gb": 44}

# The ONLY guest-agent path the broker may ever read (step 3): the fresh
# clone's public SSH host key. No arbitrary paths, no exec, no host shell.
ALLOWED_HOST_KEY_PATH = "/etc/ssh/ssh_host_ed25519_key.pub"


def guest_for_template(template_vmid: int) -> str | None:
    return TEMPLATE_ROLES.get(int(template_vmid))


def check_guest_budget(role: str) -> dict:
    spec = GUEST_BUDGETS.get(role)
    if spec is None:
        raise ValueError(f"unknown guest role {role!r}")
    return dict(spec)


def aggregate_for(scenario_id: str) -> dict:
    roles = SCENARIO_GUESTS.get(scenario_id)
    if roles is None:
        raise ValueError(f"no budget record for scenario {scenario_id!r}")
    total = {"vcpus": 0, "memory_mb": 0, "disk_gb": 0}
    for role in roles:
        spec = GUEST_BUDGETS[role]
        total["vcpus"] += spec["vcpus"]
        total["memory_mb"] += spec["memory_mb"]
        total["disk_gb"] += spec["disk_gb"]
    return total
