# Legacy firewall artifacts — not the release deployment path

`srplatform/safety/firewall.py` renders scoped inet/bridge nft rules, and
`killswitch.sh` is the old privileged adapter's standalone mechanism. Preserve
their policy/packet regressions, but renderer/parser tests are not proof of real
R740 isolation or permission safety.

The agreed release uses **operator-installed permanent isolation** and a private
restricted-PVE boundary that independently hard-stops owned full lab VMs. The
running application/model does not receive Proxmox host root, host SSH or runtime
host-firewall execution. That redesign is milestone 02, not already implemented.

Do not apply these scripts to the host as a development/planning action. Only
operator-approved isolated packet fixtures may exercise privileged policy tests;
never flush/reset unrelated host rules or reconfigure other workloads.

See [architecture](../../docs/ARCHITECTURE.md),
[roadmap](../../docs/ROADMAP.md), and
[operator gates](../../docs/OPERATOR_RUNBOOK.md) for the authoritative contract.
