#!/usr/bin/env bash
# Golden-image provisioning for Linux templates (Drew runs this ONCE per golden
# image inside the template VM, then snapshots it as a Proxmox template — Part 5/M1).
#
# What must be true of every Linux golden image:
#   * auditd installed and running with the repo's rules (telemetry/auditd.rules)
#   * the telemetry shipper installed as a systemd SERVICE (via
#     telemetry/install.sh — the single installer; copying the .py alone does
#     NOT create the unit, the ENRICHED format or the spool dir — audit R12)
#   * no WAN egress needed or expected (range VLAN default-deny)
#   * a flag-writing convention for verifiers (flags land in /root/flag_*.txt)
#
# NOTE ON SCOPE: this script does NOT install vulnerable scenario services.
# Vulnerable services belong to the SCENARIO deployment (cloud-init per host),
# not the golden template — the runbook is aligned with this.
set -euo pipefail

apt-get install -y auditd audispd-plugins

# ONE installer for the whole pipeline: rules + ENRICHED log_format + shipper
# + systemd unit + spool directory + per-clone configuration placeholders.
# (telemetry/install.sh is idempotent and is what the unit tests exercise.)
bash telemetry/install.sh

install -d /etc/sparring-range
cp infra/cloud-init/golden-linux.yaml /etc/sparring-range/cloud-init-baked.yaml 2>/dev/null || true

systemctl enable auditd sparring-shipper
echo "[golden] done. Snapshot this VM as a Proxmox template; put its VMID in .env."
