"""Datapath controllers (F03): one constrained, authenticated mechanism for the
privileged range-datapath operation.

The production implementation runs pre-rendered, range-scoped nftables rules
through a fixed command prefix (`nft_command_prefix`, e.g. `sudo -n`), managing
EXACTLY ONE named set/table by fixed handle — never a global ruleset flush, and
never touching anything outside the configured bridge/VLAN. Apply/release are
idempotent. Every operation returns a truthful result dict; failure is never
reported as success.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from typing import Protocol

from srplatform.settings import Settings, get_settings

EMERGENCY_TABLE = "sr_emergency"
BASELINE_TABLE = "sr_range_baseline"


def config_identity(s: Settings) -> str:
    """Identity of the network/config the safety evidence is bound to (F02).
    Changing bridge/VLAN/CIDR/management invalidates prior proofs."""
    material = json.dumps({
        "range_bridge": s.range_bridge, "range_vlan": s.range_vlan,
        "range_cidr": s.range_cidr, "management_cidr": s.management_cidr,
        "bastion_address": s.bastion_address, "proxmox_node": s.proxmox_node,
    }, sort_keys=True)
    return hashlib.sha256(material.encode()).hexdigest()[:16]


class DatapathController(Protocol):
    def baseline_status(self) -> dict: ...
    def apply_emergency(self) -> dict: ...
    def remove_emergency(self) -> dict: ...


class NoopDatapath:
    """Test/dev controller. Records calls; reports baseline NOT verified unless
    explicitly scripted — safety must not default to 'safe'."""

    mechanism = "noop"

    def __init__(self):
        self.calls: list[tuple[str, dict]] = []
        self.baseline_ok = False
        self.emergency_applied = False
        self.fail_apply = False
        self.fail_remove = False

    def baseline_status(self) -> dict:
        self.calls.append(("baseline_status", {}))
        return {"ok": self.baseline_ok, "detail": "noop controller baseline", "mechanism": "noop"}

    def apply_emergency(self) -> dict:
        self.calls.append(("apply_emergency", {}))
        if self.fail_apply:
            return {"ok": False, "detail": "injected apply failure", "mechanism": "noop"}
        self.emergency_applied = True
        return {"ok": True, "detail": "noop emergency applied (NOT a real datapath proof)", "mechanism": "noop"}

    def remove_emergency(self) -> dict:
        self.calls.append(("remove_emergency", {}))
        if self.fail_remove:
            return {"ok": False, "detail": "injected remove failure", "mechanism": "noop"}
        self.emergency_applied = False
        return {"ok": True, "detail": "noop emergency removed", "mechanism": "noop"}


class NftDatapath:
    """Production controller: renders infra/firewall templates for the actual
    bridge/VLAN and applies them with nft through the constrained prefix."""

    mechanism = "nft"

    def __init__(self, settings: Settings | None = None):
        self.s = settings or get_settings()

    # --- rendering -----------------------------------------------------------
    def render_baseline(self) -> str:
        from srplatform.safety.firewall import render_baseline_ruleset
        return render_baseline_ruleset(self.s)

    def render_emergency(self, drop_existing: bool = False) -> str:
        from srplatform.safety.firewall import render_emergency_ruleset
        return render_emergency_ruleset(self.s, drop_existing=drop_existing)

    def render_emergency_removal(self) -> str:
        from srplatform.safety.firewall import render_emergency_removal
        return render_emergency_removal()

    # --- privileged execution (single constrained mechanism) -------------------
    def _run_nft(self, args: list[str]) -> tuple[int, str]:
        import shlex
        cmd = (shlex.split(self.s.nft_command_prefix) if self.s.nft_command_prefix else []) + [self.s.nft_bin] + args
        if not shutil.which(cmd[0]):
            return 127, f"{cmd[0]} not found"
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            return p.returncode, (p.stdout + p.stderr)[:2000]
        except subprocess.TimeoutExpired:
            return 124, "nft timed out"

    def table_exists(self, table: str) -> bool:
        code, out = self._run_nft(["-nn", "list", "table", table])
        return code == 0

    def list_table(self, table: str) -> str | None:
        code, out = self._run_nft(["-nn", "list", "table", table])
        return out if code == 0 else None

    # Rules whose PRESENCE defines the baseline guarantee — checking table
    # existence alone was the audit R05 fail-open (an empty table "verified").
    REQUIRED_BASELINE_RULES = (
        "chain range_forward",
        "meta nfproto ipv4 drop",
        "meta nfproto ipv6 drop",
        "ip saddr @range_hosts ip daddr @range_hosts accept",
    )

    def baseline_status(self) -> dict:
        listing = self.list_table(f"inet {BASELINE_TABLE}")
        if listing is None:
            return {"ok": False,
                    "detail": f"inet table {BASELINE_TABLE} ABSENT — range egress deny NOT active",
                    "mechanism": "nft"}
        missing = [r for r in self.REQUIRED_BASELINE_RULES if r not in listing]
        if missing:
            return {"ok": False,
                    "detail": f"{BASELINE_TABLE} exists but REQUIRED rules are missing: {missing} "
                              "— re-render and re-apply the baseline",
                    "mechanism": "nft"}
        return {"ok": True, "detail": f"inet table {BASELINE_TABLE} present with required rules",
                "mechanism": "nft"}

    def apply_emergency(self) -> dict:
        s = self.s
        if not [p for p in (s.range_bridge_ports or "").split(",") if p.strip()]:
            # Without the port topology the bridge-family rules cannot drop
            # same-bridge frames — say so instead of claiming the guarantee.
            l2_note = ("WARNING: RANGE_BRIDGE_PORTS not configured — same-bridge L2 drop "
                       "covers the bridge master only; provision the port list!")
        else:
            l2_note = f"inet + bridge families on {s.range_bridge} ports"
        # ATOMIC (audit R05): delete-if-present + replacement in ONE `nft -f`
        # transaction. A failed load applies NOTHING — the previous ruleset
        # (and its protection) stays intact instead of being removed first.
        drop_existing = self.table_exists(f"inet {EMERGENCY_TABLE}") or \
            self.table_exists(f"bridge {EMERGENCY_TABLE}_l2")
        ruleset = self.render_emergency(drop_existing=drop_existing)
        code, out = self._run_nft_stdin(ruleset)
        if code != 0:
            return {"ok": False, "detail": f"emergency apply failed (nothing changed): {out}",
                    "mechanism": "nft"}
        return {"ok": True, "detail": f"emergency drop applied atomically ({l2_note})",
                "mechanism": "nft"}

    def _run_nft_stdin(self, ruleset: str) -> tuple[int, str]:
        import shlex
        cmd = (shlex.split(self.s.nft_command_prefix) if self.s.nft_command_prefix else []) + [self.s.nft_bin, "-f", "-"]
        if not shutil.which(cmd[0]):
            return 127, f"{cmd[0]} not found"
        try:
            p = subprocess.run(cmd, input=ruleset, capture_output=True, text=True, timeout=20)
            return p.returncode, (p.stdout + p.stderr)[:2000]
        except subprocess.TimeoutExpired:
            return 124, "nft timed out"

    def remove_emergency(self) -> dict:
        # ATOMIC removal of BOTH emergency families (audit R05: the old code
        # deleted only inet and reported success with the L2 drop still active),
        # then VERIFY both are gone before claiming release. Baseline remains.
        code, out = self._run_nft_stdin(self.render_emergency_removal())
        if code != 0 and "No such file or directory" not in out and "does not exist" not in out:
            return {"ok": False, "detail": f"emergency remove failed: {out}", "mechanism": "nft"}
        for fam_table in (f"inet {EMERGENCY_TABLE}", f"bridge {EMERGENCY_TABLE}_l2"):
            if self.table_exists(fam_table):
                return {"ok": False,
                        "detail": f"{fam_table} STILL INSTALLED after removal — not released",
                        "mechanism": "nft"}
        base = self.baseline_status()
        if not base["ok"]:
            return {"ok": False,
                    "detail": "emergency tables removed, but baseline egress-deny is NOT active — "
                              "re-render/re-apply baseline immediately",
                    "mechanism": "nft"}
        return {"ok": True, "detail": "both emergency families removed and verified; "
                                      "baseline deny preserved", "mechanism": "nft"}


def get_datapath(settings: Settings | None = None) -> DatapathController:
    s = settings or get_settings()
    if s.datapath_controller == "noop":
        return NoopDatapath()
    return NftDatapath(s)
