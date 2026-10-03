#!/usr/bin/env bash
# Killswitch datapath half (hard constraint #2): drop ALL traffic through the
# range bridge datapath. The service half (stop the red agent) is done by
# `rangectl safety killswitch` via the API supervisor.
#
# Drew: this runs ON the Proxmox host (or via its api). Test it before any
# model-driven attack runs — provably, from inside a range VM.
set -euo pipefail

RANGE_BRIDGE="${RANGE_BRIDGE:-vmbr1}"

echo "[killswitch] dropping datapath on ${RANGE_BRIDGE} (from the host side)"
nft add table inet sparring_killswitch
nft add chain inet sparring_killswitch drop '{ type filter hook forward priority -10; policy drop; }'
nft add rule inet sparring_killswitch drop counter drop

echo "[killswitch] active. Verify from INSIDE a range VM:  ping -c1 1.1.1.1  -> must fail"

# `rangectl safety killswitch-release` reverses it:
#   nft delete table inet sparring_killswitch
