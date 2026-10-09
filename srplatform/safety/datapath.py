"""Datapath controllers (F03): one constrained, authenticated mechanism for the
privileged range-datapath operation.

The production implementation runs pre-rendered, range-scoped nftables rules
through a fixed command prefix (`nft_command_prefix`, e.g. `sudo -n`), managing
EXACTLY the named tables by fixed handle — never a global ruleset flush, and
never touching anything outside the configured bridge/VLAN.

Audit N06 requirements implemented here:
  * baseline verification is STRUCTURAL (nft JSON output): correct family,
    table, chain hook/priority, scope rules, allow rules and terminal drops
    in the right ORDER; an unhooked chain, an earlier unconditional accept or
    a modified set FAILS. Substring presence is not sufficient.
  * apply/release are ATOMIC for every table-presence combination (neither /
    inet only / bridge only / both): only tables that exist are deleted, the
    replacement loads in the same transaction, and a failed replacement keeps
    the prior protection.
  * emergency apply REFUSES full success when same-bridge port coverage is
    not established against the actual topology — a warning riding along with
    ok=true was the fail-open.
  * release verifies the baseline BEFORE dropping emergency protection and
    reinstalls emergency protection when baseline verification fails.
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
    Changing bridge/VLAN/CIDR/management/TOPOLOGY/API destination invalidates
    prior proofs (audit N07: bridge ports and the API destination/port change
    the rendered rules, so they are part of the identity)."""
    from srplatform.safety.firewall import _api_host, _api_port, bridge_ports
    material = json.dumps({
        "range_bridge": s.range_bridge, "range_vlan": s.range_vlan,
        "range_cidr": s.range_cidr, "management_cidr": s.management_cidr,
        "bastion_address": s.bastion_address, "proxmox_node": s.proxmox_node,
        "range_bridge_ports": sorted(bridge_ports(s)),
        "api_host": _api_host(s), "api_port": _api_port(s),
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

    def render_emergency(self, drop_existing: bool = False, **kw) -> str:
        from srplatform.safety.firewall import render_emergency_ruleset
        return render_emergency_ruleset(self.s, drop_existing=drop_existing, **kw)

    def render_emergency_removal(self, **kw) -> str:
        from srplatform.safety.firewall import render_emergency_removal
        return render_emergency_removal(**kw)

    # --- privileged execution (single constrained mechanism) -------------------
    def _run_nft(self, args: list[str]) -> tuple[int, str]:
        import shlex
        cmd = (shlex.split(self.s.nft_command_prefix) if self.s.nft_command_prefix else []) + [self.s.nft_bin] + args
        if not shutil.which(cmd[0]):
            return 127, f"{cmd[0]} not found"
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            return p.returncode, (p.stdout + p.stderr)[:20000]
        except subprocess.TimeoutExpired:
            return 124, "nft timed out"

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

    # --- table inspection ------------------------------------------------------
    # TRI-STATE (audit T03): "the table is absent" and "I could not look" are
    # different facts. Only a POSITIVE nft ENOENT answer is absence; a
    # permission/transport/parse failure is UNKNOWN and can never substantiate
    # a successful apply, removal, or baseline verification.
    _ABSENT_MARKERS = ("no such file or directory", "doesn't exist",
                       "cannot parse table", "no such table")

    def inspect_table(self, famtable: str) -> tuple[str, dict | None, str]:
        """(status, table_json, detail) with status in
        present | absent | unknown."""
        code, out = self._run_nft(["-nn", "-j", "list", "table", famtable])
        if code == 0:
            tbl = self._json_table(famtable)
            if tbl is None:
                return "unknown", None, f"nft answered but the table JSON was unparseable: {out[:200]}"
            return "present", tbl, "table listed"
        low = out.lower()
        if any(m in low for m in self._ABSENT_MARKERS):
            return "absent", None, out.strip()[:200]
        return "unknown", None, f"inspection failed (exit {code}): {out.strip()[:200]}"

    def table_exists(self, table: str) -> bool:
        status, _, _ = self.inspect_table(table)
        return status == "present"

    def list_table(self, table: str) -> str | None:
        code, out = self._run_nft(["-nn", "list", "table", table])
        return out if code == 0 else None

    def _json_table(self, famtable: str) -> dict | None:
        """Parsed table from `nft -j list table`, ASSEMBLED from the flat
        nftables JSON entries into {"family","name","chains":[{name, hooks,
        rules}]} — None when absent/unreadable."""
        code, out = self._run_nft(["-nn", "-j", "list", "table", famtable])
        if code != 0:
            return None
        try:
            doc = json.loads(out)
            entries = doc.get("nftables", [])
            table = None
            chains: dict[str, dict] = {}
            order: list[str] = []
            sets: list[dict] = []
            for entry in entries:
                if "table" in entry:
                    t = entry["table"]
                    if t.get("name") == famtable.split()[-1]:
                        table = {"family": t.get("family"), "name": t["name"],
                                 "chains": [], "sets": []}
                elif "chain" in entry and table is not None:
                    c = entry["chain"]
                    if c.get("table") != table["name"]:
                        continue
                    chain = {"name": c.get("name"), "rule": [],
                             "hooks": ([{"hook": c.get("hook"), "prio": c.get("prio"),
                                         "policy": c.get("policy"),
                                         "family": c.get("family") or table["family"]}]
                                       if c.get("hook") else [])}
                    chains[c.get("name")] = chain
                    order.append(c.get("name"))
                elif "rule" in entry and table is not None:
                    r = entry["rule"]
                    ch = chains.get(r.get("chain"))
                    if ch is not None:
                        ch["rule"].append(r)
                elif "set" in entry and table is not None:
                    st = entry["set"]
                    if st.get("table") == table["name"]:
                        sets.append(st)
            if table is None:
                return None
            table["chains"] = [chains[n] for n in order]
            table["sets"] = sets
            return table
        except (json.JSONDecodeError, AttributeError, TypeError):
            return None

    # --- structural baseline verification (audit N06 item 5) -------------------
    def _expected_baseline_statements(self) -> list[str]:
        """Normalized expected rule sequence in the SAME canonical token form
        `_normalize_rule` produces from nft JSON — verification and
        application can never drift apart. This is the COMPLETE effective
        policy: verification checks EXACT membership and order (audit T03),
        so an extra permissive rule anywhere — including a conditional early
        accept such as `meta nfproto ipv4 accept` — fails validation."""
        from srplatform.safety.firewall import _ctrl_addr, _api_port
        s = self.s
        ctrl = _ctrl_addr(s)
        api_port = _api_port(s)
        mgmt = s.management_cidr
        br = s.range_bridge
        return [
            f"meta.iifname!={br} return",
            # established allowances are PORT/DESTINATION-SCOPED (audit T03):
            # management replies carry source port 22; API continuations
            # carry the ingest destination port.
            f"ct.state==established,related ip.daddr=={mgmt} tcp.sport==22 "
            f"meta.iifname=={br} accept",
            f"ct.state==established,related ip.daddr=={ctrl} tcp.dport=={api_port} "
            f"meta.iifname=={br} accept",
            "ip.saddr==@range_hosts ip.daddr==@range_hosts accept",
            f"ip.protocol==tcp ip.daddr=={ctrl} tcp.dport=={api_port} ct.state==new accept",
            f"ip.protocol==tcp ip.saddr=={mgmt} ip.daddr==@range_hosts "
            f"tcp.dport==22 ct.state==new accept",
            "meta.nfproto==2 drop",
            "meta.nfproto==10 drop",
        ]

    _CT_STATE_BITS = [(1, "invalid"), (2, "established"), (4, "related"),
                      (8, "new"), (16, "untracked"), (32, "destroyed"),
                      (64, "reject"), (128, "unknown")
                      ]
    _IP_PROTO = {1: "icmp", 6: "tcp", 17: "udp", 58: "icmpv6"}

    @classmethod
    def _canon_rhs(cls, left: dict, right) -> str:
        if isinstance(right, dict) and "prefix" in right:
            return f"{right['prefix'].get('addr')}/{right['prefix'].get('len')}"
        if "ct" in left:  # ct state: JSON gives a list of bit values or a mask
            values = right if isinstance(right, list) else [right]
            if all(isinstance(v, int) for v in values):
                mask = 0
                for v in values:
                    mask |= v
                names = [n for bit, n in cls._CT_STATE_BITS if mask & bit]
                if names:
                    return ",".join(sorted(names))
            return str(sorted(values))
        if isinstance(right, int) and left.get("payload", {}).get("field") == "protocol":
            return cls._IP_PROTO.get(right, str(right))
        return str(right)

    @staticmethod
    def _canon_lhs(left: dict) -> str:
        if "meta" in left:
            return f"meta.{left['meta'].get('key')}"
        if "ct" in left:
            return f"ct.{left['ct'].get('key')}"
        if "payload" in left:
            p = left["payload"]
            return f"{p.get('protocol')}.{p.get('field')}"
        return str(sorted(left.items()))

    @classmethod
    def _normalize_rule(cls, rule: dict) -> str:
        """Canonical token form of one nft JSON rule's expr chain:
        '<lhs><op><rhs> ... <verdict>' — stable across nft JSON renderings
        (prefixes, quoting, protocol names)."""
        parts: list[str] = []
        for e in rule.get("expr", []):
            done = False
            for k in ("accept", "drop", "reject", "return"):
                if k in e:
                    parts.append(k)
                    done = True
                    break
            if done:
                continue
            if "match" in e:
                m = e["match"]
                left = m.get("left") or {}
                op = m.get("op", "==")
                if "ct" in left:  # nft renders ct-state membership as "in"
                    op = "=="
                parts.append(f"{cls._canon_lhs(left)}{op}"
                             f"{cls._canon_rhs(left, m.get('right'))}")
            elif "counter" in e:
                parts.append("counter")
            elif "log" in e:
                parts.append("log")
            else:
                parts.append(str(sorted(e.items())))
        return " ".join(parts)

    def baseline_status(self) -> dict:
        from srplatform.safety.firewall import validate_port_coverage
        status, tbl, why = self.inspect_table(f"inet {BASELINE_TABLE}")
        if status == "absent":
            return {"ok": False,
                    "detail": f"inet table {BASELINE_TABLE} ABSENT — range egress deny NOT active",
                    "mechanism": "nft"}
        if status == "unknown":
            # T03: an inspection error is NOT absence and can never be treated
            # as verification either — it is reported as UNKNOWN.
            return {"ok": False, "unknown": True,
                    "detail": f"{BASELINE_TABLE} inspection UNAVAILABLE (not 'absent', "
                              f"not verified): {why}", "mechanism": "nft"}
        if tbl.get("family") != "inet":
            return {"ok": False, "detail": f"{BASELINE_TABLE} family is "
                      f"{tbl.get('family')!r}, expected 'inet' — wrong scope", "mechanism": "nft"}
        chains = tbl.get("chains") or []
        fwd = next((c for c in chains if c.get("name") == "range_forward"), None)
        if fwd is None:
            return {"ok": False, "detail": "chain range_forward missing", "mechanism": "nft"}
        hook = fwd.get("hooks") or []
        ok_hook = any(h.get("hook") == "forward" and h.get("family") == "inet"
                      and h.get("prio") == 0 and h.get("policy") == "accept" for h in hook)
        if not ok_hook:
            # THE unhooked-chain fail-open (audit N06): rules in a chain with
            # no forward hook filter NOTHING.
            return {"ok": False, "detail": "range_forward is NOT hooked (forward/inet/"
                      "priority 0) — its rules filter no traffic", "mechanism": "nft"}
        sets = {s.get("name"): s for s in (tbl.get("sets") or [])}
        rng = sets.get("range_hosts")
        if not rng or rng.get("type") != "ipv4_addr" or "interval" not in (rng.get("flags") or []):
            return {"ok": False, "detail": "set range_hosts missing or malformed "
                      "(expected ipv4_addr with interval flag)", "mechanism": "nft"}
        actual_elems = set()
        for e in (rng.get("elem") or []):
            if isinstance(e, dict) and "prefix" in e:
                actual_elems.add(f"{e['prefix'].get('addr')}/{e['prefix'].get('len')}")
            else:
                actual_elems.add(str(e))
        # EXACT SET MEMBERSHIP (audit T03): the configured range CIDR must be
        # the ONLY element. Containment of one required element let an added
        # 0.0.0.0/1 turn the intra-range accept into an external allowance.
        if actual_elems != {str(self.s.range_cidr)}:
            return {"ok": False, "detail": f"set range_hosts is not exactly "
                      f"{{{self.s.range_cidr}}}: found {sorted(actual_elems)} — "
                      "expanded sets fail validation", "mechanism": "nft"}

        actual = [self._normalize_rule(r) for r in fwd.get("rule", [])]
        expected = self._expected_baseline_statements()
        # EXACT EFFECTIVE-POLICY EQUIVALENCE (audit T03): same rules, same
        # order, NOTHING ELSE. The old subsequence check accepted an inserted
        # `meta nfproto ipv4 accept` (or any other permissive rule) before
        # the expected sequence — an inserted rule now fails by construction.
        if len(actual) != len(expected) or not all(
                _rules_equivalent(a, e) for a, e in zip(actual, expected)):
            return {"ok": False, "detail": "effective policy is NOT exactly the expected "
                      f"baseline (extra, missing, reordered or modified rules): "
                      f"actual={actual} expected={expected}", "mechanism": "nft"}
        cov_ok, cov_why = validate_port_coverage(self.s)
        out = {"ok": True, "detail": f"inet table {BASELINE_TABLE} verified as the EXACT "
                 f"expected policy (hook, scope, sets, rules, order, terminal drops)",
               "mechanism": "nft"}
        if not cov_ok:
            out["coverage_warning"] = cov_why
        return out

    # --- emergency apply / remove (atomic per table-presence) ------------------
    def apply_emergency(self) -> dict:
        from srplatform.safety.firewall import validate_port_coverage
        s = self.s
        # TRUTHFUL COVERAGE (audit N06 item 1): without established same-
        # bridge port coverage this is NOT a full-success emergency.
        cov_ok, cov_why = validate_port_coverage(s)
        if not cov_ok:
            return {"ok": False,
                    "detail": f"emergency apply REFUSED: {cov_why} — same-bridge traffic "
                              "would survive the killswitch. Provision RANGE_BRIDGE_PORTS "
                              "from the live bridge inventory and retry.",
                    "mechanism": "nft", "coverage": cov_why}
        have_inet_s, _, inet_why = self.inspect_table(f"inet {EMERGENCY_TABLE}")
        have_bridge_s, _, bridge_why = self.inspect_table(f"bridge {EMERGENCY_TABLE}_l2")
        if "unknown" in (have_inet_s, have_bridge_s):
            # T03: without knowing which emergency tables exist, the atomic
            # replace cannot be rendered truthfully — refuse, change nothing.
            return {"ok": False,
                    "detail": "emergency apply REFUSED: existing table inspection "
                              f"UNAVAILABLE (inet: {inet_why}; bridge: {bridge_why}) — "
                              "cannot render an atomic replacement over unknown state",
                    "mechanism": "nft"}
        have_inet = have_inet_s == "present"
        have_bridge = have_bridge_s == "present"
        ruleset = self.render_emergency(drop_inet=have_inet, drop_bridge=have_bridge)
        code, out = self._run_nft_stdin(ruleset)
        if code != 0:
            return {"ok": False, "detail": f"emergency apply failed (nothing changed): {out}",
                    "mechanism": "nft"}
        # verify BOTH families are actually hooked after the transaction
        for fam, table in (("inet", EMERGENCY_TABLE), ("bridge", f"{EMERGENCY_TABLE}_l2")):
            status, tbl, why = self.inspect_table(f"{fam} {table}")
            if status != "present":
                return {"ok": False, "detail": f"{fam} {table} not positively present after "
                          f"apply ({status}: {why})", "mechanism": "nft"}
            hooked = any(h.get("hook") == "forward" and h.get("family") == fam
                         for c in (tbl.get("chains") or []) for h in (c.get("hooks") or []))
            if not hooked:
                return {"ok": False, "detail": f"{fam} {table} has no hooked forward chain "
                          "after apply — emergency NOT in the datapath", "mechanism": "nft"}
        return {"ok": True,
                "detail": f"emergency drop applied atomically and verified on {s.range_bridge} "
                          f"ports ({cov_why})", "mechanism": "nft", "coverage": cov_why}

    def remove_emergency(self) -> dict:
        # 1. BASELINE FIRST (audit N06 item 6): never drop emergency protection
        #    before confirming the baseline deny is in place.
        base = self.baseline_status()
        if not base["ok"]:
            return {"ok": False,
                    "detail": "release REFUSED: baseline egress-deny is NOT verified "
                              f"({base['detail']}) — emergency protection RETAINED",
                    "mechanism": "nft"}
        have_inet_s, _, inet_why = self.inspect_table(f"inet {EMERGENCY_TABLE}")
        have_bridge_s, _, bridge_why = self.inspect_table(f"bridge {EMERGENCY_TABLE}_l2")
        if "unknown" in (have_inet_s, have_bridge_s):
            # T03: UNKNOWN inspection cannot substantiate successful removal
            # — refusing keeps whatever protection exists rather than
            # reporting a release it cannot see.
            return {"ok": False,
                    "detail": "release REFUSED: emergency table inspection UNAVAILABLE "
                              f"(inet: {inet_why}; bridge: {bridge_why}) — unknown "
                              "inspection cannot substantiate removal; protection retained",
                    "mechanism": "nft"}
        have_inet = have_inet_s == "present"
        have_bridge = have_bridge_s == "present"
        if not have_inet and not have_bridge:
            return {"ok": True, "detail": "no emergency tables present (idempotent release); "
                                          "baseline deny verified", "mechanism": "nft"}
        code, out = self._run_nft_stdin(
            self.render_emergency_removal(drop_inet=have_inet, drop_bridge=have_bridge))
        if code != 0:
            return {"ok": False, "detail": f"emergency remove failed (protection retained): {out}",
                    "mechanism": "nft"}
        for fam_table in (f"inet {EMERGENCY_TABLE}", f"bridge {EMERGENCY_TABLE}_l2"):
            status, _, why = self.inspect_table(fam_table)
            if status == "present":
                return {"ok": False,
                        "detail": f"{fam_table} STILL INSTALLED after removal — not released",
                        "mechanism": "nft"}
            if status == "unknown":
                return {"ok": False,
                        "detail": f"{fam_table} removal UNCONFIRMED (inspection unavailable: "
                                  f"{why}) — cannot claim release", "mechanism": "nft"}
        # 2. post-removal baseline re-verification; on failure REINSTATE emergency
        base = self.baseline_status()
        if not base["ok"]:
            reinstate = self.apply_emergency()
            return {"ok": False,
                    "detail": "emergency tables removed, but baseline egress-deny is NOT "
                              f"active ({base['detail']}) — emergency "
                              f"{'REINSTALLED' if reinstate['ok'] else 'REINSTALL FAILED'}: "
                              f"{reinstate['detail']}",
                    "mechanism": "nft"}
        return {"ok": True, "detail": "both emergency families removed and verified; "
                                      "baseline deny preserved", "mechanism": "nft"}


def _rules_equivalent(actual: str, expected: str) -> bool:
    """Tolerant comparison of normalized rule text: nft JSON renders prefixes
    and quoting differently across versions (e.g. 'ip daddr 10.0.0.1' vs
    'ip daddr 10.0.0.1 .'), so compare token multisets with quoting stripped."""
    def toks(rule: str) -> list[str]:
        return sorted(t.strip("'\"") for t in rule.replace("  ", " ").split())
    return toks(actual) == toks(expected)


class StaticIsolationDatapath:
    """Milestone 02 runtime datapath: isolation is OPERATOR-MANAGED STATIC
    (nft rulesets installed via the deployment boundary, verified by the
    operator runbook and the packet acceptance layer). The application never
    executes nft, root commands, SSH, or a shell against the host at runtime.

    apply_emergency is therefore honest about what the runtime CAN do: the
    static deny stays permanently loaded (nothing to apply), and real traffic
    cessation happens by hard-stopping the owned VMs through the broker —
    which the Supervisor attempts as its own independent layer.
    """

    mechanism = "static"

    def baseline_status(self) -> dict:
        return {"ok": None, "mechanism": "static",
                "detail": "operator-managed static isolation — the runtime does "
                          "not inspect or modify the host firewall; verify via "
                          "the operator runbook + packet acceptance layer"}

    def apply_emergency(self) -> dict:
        return {"ok": True, "mechanism": "static",
                "detail": "static isolation is permanently loaded by the operator; "
                          "runtime cessation is the broker VM hard-stop layer"}

    def remove_emergency(self) -> dict:
        return {"ok": True, "mechanism": "static",
                "detail": "static isolation is never removed by the runtime"}


def get_datapath(settings: Settings | None = None) -> DatapathController:
    s = settings or get_settings()
    if s.datapath_controller == "noop":
        return NoopDatapath()
    if s.datapath_controller == "static":
        return StaticIsolationDatapath()
    if s.datapath_controller == "nft":
        raise RuntimeError(
            "runtime nft datapath was REMOVED (milestone 02): the application "
            "never executes host firewall commands. Isolation is operator-"
            "managed static; cessation is the broker VM hard-stop. The nft "
            "machinery remains for operator scripts and the packet acceptance "
            "layer only (datapath_controller=static).")
    raise RuntimeError(f"unknown datapath_controller {s.datapath_controller!r}")
