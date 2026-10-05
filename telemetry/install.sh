#!/usr/bin/env bash
# Install the telemetry pipeline on a Linux golden/clone host (F09).
# This does what the old "install the .py file and hope" script claimed:
#   1. auditd + rules (telemetry/auditd.rules)
#   2. auditd log_format=ENRICHED (the INPUT FORMAT the shipper parses) and
#      log_group=adm (the ONLY log access the shipper identity gets)
#   3. shipper (stdlib-only python3, installed WITH its shebang so the unit's
#      ExecStart executes the artifact directly) + systemd unit + env file
#   4. spool directory (bounded, gap-counted) writable by the service identity
# Usage (inside the golden image build, run as root, repo checked out at /opt/sparring-range):
#   /opt/sparring-range/telemetry/install.sh
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"

command -v python3 >/dev/null || { echo "python3 required (stdlib only — no pip needed on the range)"; exit 1; }
apt-get install -y --no-install-recommends auditd

# 1) rules
install -m 0640 "$REPO/telemetry/auditd.rules" /etc/audit/rules.d/50-sparring.rules

# 2) documented input format + the ONE log-read grant (audit N08)
if ! grep -q "^log_format" /etc/audit/auditd.conf 2>/dev/null; then
  echo "log_format = ENRICHED" >> /etc/audit/auditd.conf
else
  sed -i 's/^log_format.*/log_format = ENRICHED/' /etc/audit/auditd.conf
fi
if ! grep -q "^log_group" /etc/audit/auditd.conf 2>/dev/null; then
  echo "log_group = adm" >> /etc/audit/auditd.conf
else
  sed -i 's/^log_group.*/log_group = adm/' /etc/audit/auditd.conf
fi

# 3) service identity (audit N08: the unit runs as a real user whose ONLY
#    extra right is the adm-group read on the audit log — DynamicUser could
#    not hold that group, so the installed unit previously could not read the
#    log it exists to ship)
id -u srshipper >/dev/null 2>&1 || \
  useradd --system --no-create-home --shell /usr/sbin/nologin srshipper
getent group adm >/dev/null && usermod -aG adm srshipper

# 4) shipper + unit. The source file carries `#!/usr/bin/env python3`;
#    verify the INSTALLED artifact is directly executable (audit N08:
#    exercise the installed artifact, not just the source import).
install -m 0755 "$REPO/telemetry/shipper.py" /usr/local/bin/sparring-shipper
head -n1 /usr/local/bin/sparring-shipper | grep -q '^#!' || {
  echo "[install] FATAL: installed shipper has no shebang — refusing"; exit 1; }
/usr/local/bin/sparring-shipper --help >/dev/null || {
  echo "[install] FATAL: installed shipper is not executable"; exit 1; }
install -m 0644 "$REPO/telemetry/sparring-shipper.service" /etc/systemd/system/sparring-shipper.service

# 5) configuration + writable spool for the service identity
install -d -o srshipper -g srshipper /etc/sparring-range /var/lib/sparring-range/shipper
if [ ! -f /etc/sparring-range/shipper.env ]; then
  cat > /etc/sparring-range/shipper.env <<EOF
SR_API_URL=http://CONTROL-PLANE-ADDRESS:8000
SR_TELEMETRY_TOKEN=PROVISION-PER-DEPLOYMENT
SR_HOST=SET-PER-CLONE
SR_SPOOL_DIR=/var/lib/sparring-range/shipper
EOF
  chmod 0640 /etc/sparring-range/shipper.env
  chown root:srshipper /etc/sparring-range/shipper.env
fi

systemctl daemon-reload
systemctl enable auditd sparring-shipper
echo "[install] telemetry pipeline installed. Restart auditd + shipper at next boot (golden image) or now:"
echo "  systemctl restart auditd sparring-shipper"
echo "[install] ENROLLMENT (audit N09): golden images must NOT ship live tokens."
echo "  Per clone, provision /etc/sparring-range/shipper.env with the deploy"
echo "  response's telemetry enrollment (SR_API_URL, SR_HOST, session-bound"
echo "  SR_TELEMETRY_TOKEN) — tokens are revoked on session end/reset/teardown."
