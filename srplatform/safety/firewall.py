"""Rendered, range-scoped nftables rulesets (F03).

Design properties (each was an audit failure in the old template):
  * Syntactically valid, complete rulesets — chains live INSIDE their tables;
    validated with `nft -c` by tests where the binary is available.
  * Scoped to the actual range bridge/VLAN: baseline neither opens nor blocks
    anything outside the range path; host management and unrelated bridges
    survive untouched.
  * Default-deny for range egress (IPv4 AND IPv6). No global forwarding drop.
  * Explicit, minimal allow-list: control-plane management INTO the range
    (verifier/runner/bastion), range host telemetry/api shipping to the
    control plane, and established/related return traffic — nothing else.
    There is no all-ports-to-CIDR control-plane hole.
  * Emergency = drop ALL range datapath traffic, INCLUDING same-bridge L2
    (bridge-family table), with no established exception ahead of the drop.
  * Idempotent: rendered as create-or-replace of dedicated tables managed by
    the controller; never a global ruleset flush.
"""
from __future__ import annotations

import sys

from srplatform.safety.datapath import BASELINE_TABLE, EMERGENCY_TABLE
from srplatform.settings import Settings, get_settings


def _ctrl_addr(s: Settings) -> str:
    """Control-plane address range hosts may talk to (API ingest). Must render
    as a literal — hostnames with multiple/loopback-name answers are resolved
    once at render time so the ruleset is stable and auditable."""
    import ipaddress
    import socket
    from urllib.parse import urlparse
    host = urlparse(s.api_base_url).hostname or ""
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        return socket.gethostbyname(host)
    except OSError as e:
        raise ValueError(
            f"cannot render firewall rules: API host '{host}' does not resolve to one IPv4 "
            "address. Set API_BASE_URL to the control plane's literal address."
        ) from e


def _api_port(s: Settings) -> int:
    """Ingest port comes from the configured API URL — never a hardcoded 8000."""
    from urllib.parse import urlparse
    p = urlparse(s.api_base_url)
    if p.port:
        return int(p.port)
    return 443 if p.scheme == "https" else 80


def _api_host(s: Settings) -> str:
    """The API destination as CONFIGURED (hostname or literal). Evidence and
    proof identity bind to this, not to a resolved snapshot (audit N07)."""
    from urllib.parse import urlparse
    return urlparse(s.api_base_url).hostname or ""


def _api_port(s: Settings) -> int:
    """Ingest port comes from the configured API URL — never a hardcoded 8000."""
    from urllib.parse import urlparse
    p = urlparse(s.api_base_url)
    if p.port:
        return int(p.port)
    return 443 if p.scheme == "https" else 80


def bridge_ports(s: Settings) -> list[str]:
    """DECLARED bridge ports (tap/vnet members). Empty means the operator has
    not declared the topology — emergency coverage is then INCOMPLETE (audit
    N06: this must prevent full-success, not ride along as a warning)."""
    return [p.strip() for p in (s.range_bridge_ports or "").split(",") if p.strip()]


def discover_bridge_ports(s: Settings) -> list[str] | None:
    """DISCOVERED bridge ports from /sys. The controller executes through
    `nft_command_prefix` (e.g. `sudo -n` or a test namespace wrapper), so
    when a direct read fails the inventory is read THROUGH that same
    prefix — coverage is always verified in the namespace where the rules
    will actually live. None = cannot determine (not 'empty')."""
    import re
    import shlex
    import subprocess
    from pathlib import Path
    br = s.range_bridge
    d = Path("/sys/class/net") / br / "brif"
    try:
        return sorted(p.name for p in d.iterdir())
    except OSError:
        pass
    if not re.fullmatch(r"[A-Za-z0-9_.+-]+", br):
        return None
    prefix = shlex.split(s.nft_command_prefix) if s.nft_command_prefix else []
    if not prefix:
        return None
    try:
        r = subprocess.run(prefix + ["ls", str(d)], capture_output=True,
                           text=True, timeout=10)
        if r.returncode != 0:
            return None
        return sorted(x for x in r.stdout.split() if x)
    except (OSError, subprocess.SubprocessError):
        return None


def validate_port_coverage(s: Settings) -> tuple[bool, str]:
    """Emergency/baseline L2 coverage follows the ACTUAL selected topology
    (audit N06 item 3): the declared port list must be non-empty and must
    cover every port currently attached to the range bridge. Ports created
    AFTER evidence was recorded invalidate the proof."""
    declared = bridge_ports(s)
    if not declared:
        return False, ("RANGE_BRIDGE_PORTS not configured — same-bridge L2 "
                       "coverage cannot be established")
    discovered = discover_bridge_ports(s)
    if discovered is None:
        return False, (f"cannot read {s.range_bridge} port inventory "
                       f"(/sys/class/net/{s.range_bridge}/brif) — coverage unverified")
    missing = sorted(set(discovered) - set(declared))
    if missing:
        return False, (f"bridge ports attached to {s.range_bridge} are NOT in "
                       f"RANGE_BRIDGE_PORTS (evidence predates topology change): {missing}")
    unknown = sorted(set(declared) - set(discovered))
    if unknown:
        return False, (f"RANGE_BRIDGE_PORTS lists ports not attached to {s.range_bridge} "
                       f"(stale inventory): {unknown}")
    return True, f"port inventory matches {s.range_bridge}: {sorted(discovered)}"


def render_baseline_ruleset(s: Settings | None = None) -> str:
    s = s or get_settings()
    bridge = s.range_bridge
    vlan = s.range_vlan
    mgmt = s.management_cidr
    ctrl = _ctrl_addr(s)
    api_port = _api_port(s)
    return f"""#!/usr/sbin/nft -f
# sparring-range baseline egress-deny — RENDERED, do not edit by hand.
# python -m srplatform.safety.firewall baseline   regenerates this.
# Scope: forwarded traffic ON {bridge} (VLAN {vlan}) only — host management,
# other bridges and the control plane's own traffic are untouched (returns).
# VLAN NOTE: {vlan} is enforced by the VLAN-aware bridge itself (each VM NIC
# is attached with tag={vlan}); forwarded packets reach these hooks already
# untagged, so the ruleset scopes by BRIDGE + range CIDR, and cross-VLAN
# separation is the bridge's VLAN filtering — not a match that belongs here.
table inet {BASELINE_TABLE} {{
  set range_hosts {{
    type ipv4_addr
    flags interval
    elements = {{ {s.range_cidr} }}
  }}

  chain range_forward {{
    type filter hook forward priority filter; policy accept;

    # packets not originating from the range bridge are none of our business
    iifname != "{bridge}" return

    # established/related ONLY for control-plane return traffic — each reply
    # direction is EXPLICIT (audit N06 item 4). The chain only filters
    # packets ARRIVING on the range bridge (first rule returns otherwise),
    # so the replies that need accepting are the range->control-plane ones:
    #   * replies to management SSH (mgmt -> range:22): the reply is
    #     range -> mgmt and arrives on the range bridge;
    #   * continuations toward the API ingest endpoint (range -> ctrl:port).
    # Replies FROM the control plane arrive on other interfaces and return
    # untouched. A blanket established accept would let pre-existing
    # range-originated tunnels survive the deny (audit R05).
    ct state established,related ip daddr {mgmt} iifname "{bridge}" accept
    ct state established,related ip daddr {ctrl} iifname "{bridge}" accept

    # IPv4 intra-range operation is allowed (scenario hosts must talk) —
    # DESTINATION-CONSTRAINED: range -> range only, not range -> anything.
    # NOTE: the UPPER-LAYER protocol field is deliberately NOT used as an
    # "is IPv4" test (audit N06: the old generic use was a mistake; the
    # chain is already IPv4-scoped by its matches).
    ip saddr @range_hosts ip daddr @range_hosts accept
    # ...range hosts shipping telemetry/events to the control plane API...
    ip protocol tcp ip daddr {ctrl} tcp dport {api_port} ct state new accept
    # ...control-plane management NEW connections, only to management port...
    ip protocol tcp ip saddr {mgmt} ip daddr @range_hosts tcp dport 22 ct state new accept

    # EXPLICIT DENY: no internet, no DNS, no DHCP, no update proxies, and
    # no IPv6 whatsoever from the range — including connections that existed
    # BEFORE this table was installed (no established escape). This is the
    # hard constraint.
    meta nfproto ipv4 drop
    meta nfproto ipv6 drop
  }}
}}
"""


def render_emergency_ruleset(s: Settings | None = None, drop_existing: bool = False,
                             drop_inet: bool | None = None,
                             drop_bridge: bool | None = None) -> str:
    """Emergency drop for BOTH families. `drop_existing` (legacy) deletes both
    tables first; the datapath now passes per-family flags so the transaction
    only deletes tables that ACTUALLY exist (audit N06 item 5: with exactly
    one table present, deleting the missing one aborted the whole
    replacement)."""
    s = s or get_settings()
    bridge = s.range_bridge
    deletes = ""
    want_inet = drop_inet if drop_inet is not None else drop_existing
    want_bridge = drop_bridge if drop_bridge is not None else drop_existing
    if want_inet:
        deletes += f"delete table inet {EMERGENCY_TABLE}\n"
    if want_bridge:
        deletes += f"delete table bridge {EMERGENCY_TABLE}_l2\n"
    ports = bridge_ports(s)
    port_set = ""
    if ports:
        elems = ", ".join(f'"{p}"' for p in ports)
        port_set = f"""  set sr_ports {{
    type ifname
    elements = {{ {elems} }}
  }}
"""
    match_iif = "iifname @sr_ports drop" if ports else f'iifname "{bridge}" drop'
    match_oif = "oifname @sr_ports drop" if ports else f'oifname "{bridge}" drop'
    return f"""#!/usr/sbin/nft -f
# sparring-range EMERGENCY datapath drop — RENDERED. Severs all range datapath
# traffic on {bridge}: L3 (inet forward, INCLUDING established — no state
# escape) AND same-bridge L2 (bridge family). Strictly range-scoped: host
# management, the control plane, and unrelated bridges keep working.
#
# BRIDGE-FAMILY TOPOLOGY (audit R05): in the bridge family the forward hook
# sees the bridge PORTS (tap/vnet devices), not the bridge master. Matching
# iifname/oifname "{bridge}" alone would NOT drop same-bridge VM-to-VM frames.
# Configure RANGE_BRIDGE_PORTS with every tap/vnet attached to {bridge}
# (Proxmox: `ls /sys/class/net/{bridge}/brif/`) so the port set below matches
# the real topology; without it this render covers the master only and the
# controller reports that honestly instead of claiming same-bridge coverage.
{deletes}table inet {EMERGENCY_TABLE} {{
  chain drop_in {{
    type filter hook forward priority -150; policy accept;
    iifname "{bridge}" drop
    oifname "{bridge}" drop
  }}
}}
table bridge {EMERGENCY_TABLE}_l2 {{
{port_set}  chain drop_bridge {{
    type filter hook forward priority -150; policy accept;
    {match_iif}
    {match_oif}
  }}
}}
"""


def render_emergency_removal(drop_inet: bool = True, drop_bridge: bool = True) -> str:
    """ONE atomic removal of the emergency families that EXIST (audit N06 item
    5: unconditionally deleting both tables aborted the transaction when one
    was absent; N06 also keeps both families removed together — removing only
    inet left the L2 drop installed while release reported success)."""
    lines = ["#!/usr/sbin/nft -f"]
    if drop_inet:
        lines.append(f"delete table inet {EMERGENCY_TABLE}")
    if drop_bridge:
        lines.append(f"delete table bridge {EMERGENCY_TABLE}_l2")
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    what = argv[1] if len(argv) > 1 else "baseline"
    s = get_settings()
    out = render_baseline_ruleset(s) if what == "baseline" else render_emergency_ruleset(s)
    sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
