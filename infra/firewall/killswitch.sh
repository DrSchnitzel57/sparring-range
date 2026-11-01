#!/usr/bin/env bash
# sparring-range EMERGENCY datapath switch — operator recovery path (audit F02/F03).
#
# This script is the path that does NOT depend on the API/network: run it on
# the appliance host when in doubt. It is:
#   * idempotent (safe to run repeatedly),
#   * range-scoped (only the configured bridge; host management and unrelated
#     bridges keep working),
#   * dual-family (inet forward AND bridge-family, so same-bridge L2 traffic
#     is severed too, including established connections),
#   * honest (any nft failure exits non-zero; nothing is claimed on error).
#
# Usage:  RANGE_BRIDGE=vmbr1 sudo ./killswitch.sh
# Release (operator, after assessment):  sudo ./killswitch.sh --release
#   (removes ONLY the emergency tables; the baseline egress-deny must already
#    be loaded — verify with: nft list table inet sr_range_baseline)
set -euo pipefail

RANGE_BRIDGE="${RANGE_BRIDGE:-vmbr1}"
NFT="${NFT:-nft}"
EM_TABLE="inet sr_emergency"
EM_L2="bridge sr_emergency_l2"

if [[ "${EUID}" -ne 0 ]]; then
  echo "killswitch must run as root on the appliance host" >&2
  exit 1
fi

if [[ "${1:-}" == "--release" ]]; then
  $NFT delete table $EM_L2 2>/dev/null || true
  $NFT delete table $EM_TABLE 2>/dev/null || true
  if ! $NFT list table inet sr_range_baseline >/dev/null 2>&1; then
    echo "WARNING: emergency tables removed but BASELINE egress-deny is not loaded." >&2
    echo "         Re-apply it NOW: python3 -m srplatform.safety.firewall baseline > /tmp/base.nft && nft -f /tmp/base.nft" >&2
    exit 2
  fi
  echo "released: emergency tables removed; baseline deny still active"
  exit 0
fi

# Engage: create-or-replace the emergency tables. Delete first (idempotent).
$NFT delete table $EM_L2 2>/dev/null || true
$NFT delete table $EM_TABLE 2>/dev/null || true

$NFT -f - <<EOF
table inet sr_emergency {
  chain drop_in {
    type filter hook forward priority -100; policy accept;
    iifname "$RANGE_BRIDGE" drop
    oifname "$RANGE_BRIDGE" drop
  }
}
table bridge sr_emergency_l2 {
  chain drop_bridge {
    type filter hook forward priority -100; policy accept;
    iifname "$RANGE_BRIDGE" drop
    oifname "$RANGE_BRIDGE" drop
  }
}
EOF

echo "KILLSWITCH ENGAGED: all datapath traffic on $RANGE_BRIDGE dropped (inet + bridge families)."
echo "Workers: terminate via the platform, or list range VMs: qm list"
