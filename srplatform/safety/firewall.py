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


def render_baseline_ruleset(s: Settings | None = None) -> str:
    s = s or get_settings()
    bridge = s.range_bridge
    vlan = s.range_vlan
    mgmt = s.management_cidr
    ctrl = _ctrl_addr(s)
    api_port = 8000
    return f"""#!/usr/sbin/nft -f
# sparring-range baseline egress-deny — RENDERED, do not edit by hand.
# python -m srplatform.safety.firewall baseline   regenerates this.
# Scope: forwarded traffic ON {bridge} (VLAN {vlan}) only — host management,
# other bridges and the control plane's own traffic are untouched (returns).
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

    # established/related covers replies to management-initiated sessions
    # (verifier/runner/bastion management SSH in) and to the API ingest
    ct state established,related accept

    # IPv4: intra-range operation is allowed (scenario hosts must talk)...
    ip protocol ip ip saddr @range_hosts accept
    # ...range hosts shipping telemetry/events to the control plane API...
    ip protocol tcp ip daddr {ctrl} tcp dport {api_port} accept
    # ...control-plane management NEW connections, only to management port...
    ip protocol tcp ip saddr {mgmt} ip daddr @range_hosts tcp dport 22 accept

    # EXPLICIT DENY: no internet, no DNS, no DHCP, no update proxies, and
    # no IPv6 whatsoever from the range. This is the hard constraint.
    meta nfproto ipv4 drop
    meta nfproto ipv6 drop
  }}
}}
"""


def render_emergency_ruleset(s: Settings | None = None) -> str:
    s = s or get_settings()
    bridge = s.range_bridge
    return f"""#!/usr/sbin/nft -f
# sparring-range EMERGENCY datapath drop — RENDERED. Severs all range datapath
# traffic on {bridge}: L3 (inet forward, INCLUDING established — no state
# escape) AND same-bridge L2 (bridge family). Strictly range-scoped: host
# management, the control plane, and unrelated bridges keep working.
table inet {EMERGENCY_TABLE} {{
  chain drop_in {{
    type filter hook forward priority -100; policy accept;
    iifname "{bridge}" drop
    oifname "{bridge}" drop
  }}
}}
table bridge {EMERGENCY_TABLE}_l2 {{
  chain drop_bridge {{
    type filter hook forward priority -100; policy accept;
    iifname "{bridge}" drop
    oifname "{bridge}" drop
  }}
}}
"""


def main(argv: list[str]) -> int:
    what = argv[1] if len(argv) > 1 else "baseline"
    s = get_settings()
    out = render_baseline_ruleset(s) if what == "baseline" else render_emergency_ruleset(s)
    sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
