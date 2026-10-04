#!/usr/bin/env bash
# Install the telemetry pipeline on a Linux golden/clone host (F09).
# This does what the old "install the .py file and hope" script claimed:
#   1. auditd + rules (telemetry/auditd.rules)
#   2. auditd log_format=ENRICHED (the INPUT FORMAT the shipper parses)
#   3. shipper (stdlib-only python3) + systemd unit + env configuration
#   4. spool directory (bounded, gap-counted)
# Usage (inside the golden image build, run as root, repo checked out at /opt/sparring-range):
#   /opt/sparring-range/telemetry/install.sh
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"

command -v python3 >/dev/null || { echo "python3 required (stdlib only — no pip needed on the range)"; exit 1; }
apt-get install -y --no-install-recommends auditd

# 1) rules
install -m 0640 "$REPO/telemetry/auditd.rules" /etc/audit/rules.d/50-sparring.rules

# 2) documented input format
if ! grep -q "^log_format" /etc/audit/auditd.conf 2>/dev/null; then
  echo "log_format = ENRICHED" >> /etc/audit/auditd.conf
else
  sed -i 's/^log_format.*/log_format = ENRICHED/' /etc/audit/auditd.conf
fi

# 3) shipper + unit
install -m 0755 "$REPO/telemetry/shipper.py" /usr/local/bin/sparring-shipper
install -m 0644 "$REPO/telemetry/sparring-shipper.service" /etc/systemd/system/sparring-shipper.service

# 4) configuration (HOST + token MUST be re-provisioned per deployment —
#    golden images must NOT ship live tokens; per-clone provisioning replaces this)
install -d /etc/sparring-range /var/lib/sparring-range/shipper
if [ ! -f /etc/sparring-range/shipper.env ]; then
  cat > /etc/sparring-range/shipper.env <<EOF
SR_API_URL=http://CONTROL-PLANE-ADDRESS:8000
SR_TELEMETRY_TOKEN=PROVISION-PER-DEPLOYMENT
SR_HOST=SET-PER-CLONE
SR_SPOOL_DIR=/var/lib/sparring-range/shipper
EOF
  chmod 0640 /etc/sparring-range/shipper.env
fi

systemctl daemon-reload
systemctl enable auditd sparring-shipper
echo "[install] telemetry pipeline installed. Restart auditd + shipper at next boot (golden image) or now:"
echo "  systemctl restart auditd sparring-shipper"
