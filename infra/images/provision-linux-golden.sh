#!/usr/bin/env bash
# Golden-image provisioning for Linux templates (Drew runs this ONCE per golden
# image inside the template VM, then snapshots it as a Proxmox template — Part 5/M1).
#
# What must be true of every Linux golden image:
#   * auditd installed and running with the repo's rules (telemetry/auditd.rules)
#   * the telemetry shipper installed (telemetry/shipper.py) pointing at the API
#   * no WAN egress needed or expected (range VLAN default-deny)
#   * a flag-writing convention for verifiers (flags land in /root/flag_*.txt)
set -euo pipefail

apt-get install -y auditd audispd-plugins

# install the repo's audit rules (copied into this VM by Drew or pulled via scp
# from the control plane — the range has no internet, remember)
install -m 0640 telemetry/auditd.rules /etc/audit/rules.d/50-sparring.rules

# install the shipper as a systemd service
install -m 0755 telemetry/shipper.py /usr/local/bin/sparring-shipper
install -d /etc/sparring-range
cp infra/cloud-init/golden-linux.yaml /etc/sparring-range/cloud-init-baked.yaml 2>/dev/null || true

systemctl enable auditd
echo "[golden] done. Snapshot this VM as a Proxmox template; put its VMID in .env."
