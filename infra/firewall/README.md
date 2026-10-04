# Firewall — rendered, not templated (audit F03)

The old hand-written `range-egress-deny.nft.conf.tmpl` was not a valid,
deployable ruleset (table/chain separation, unscoped global drop, unused
VLAN variable, established-first ordering). It has been removed.

The real rulesets are RENDERED from settings so bridge/VLAN/CIDR are
consistent with the deployment, and validated with `nft -c`:

    # baseline egress-deny (install on the Proxmox host at boot):
    python -m srplatform.safety.firewall baseline  > /etc/nftables-sparring.conf
    nft -c -f /etc/nftables-sparring.conf && nft -f /etc/nftables-sparring.conf

    # emergency (normally invoked via POST /safety/killswitch, which uses the
    # same renderer through one constrained mechanism — or directly, offline:
    sudo ./killswitch.sh

Properties enforced by `tests/test_b_firewall_render.py`:
valid syntax (`nft -c` when available), default-deny for range egress,
IPv4 + IPv6 coverage, established handled per-layer, management + foreign
bridges survive, emergency covers same-bridge L2, idempotent re-apply.

Live packet behaviour (ping/DNS/IPv6 from a range VM) is an operator gate:
see docs/OPERATOR_RUNBOOK.md.
