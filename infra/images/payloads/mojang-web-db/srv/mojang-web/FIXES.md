# Documented fixes (paired 03+04) — repairs MUST keep services ready.
#
# Diagnostic flaw (`/diagnostic?cmd=` runs as limited `web-user`):
#   echo 'MOJANG_DIAG_ENABLED=off' >> /etc/mojang-web/config.env  # or set off
#   systemctl restart mojang-web
#   curl -sf http://127.0.0.1:8080/ | grep -q 'Minecraft Legends'  # still serves
#
# Maintenance helper (`/usr/local/bin/mojang-maintenance`, setuid + unsafe PATH):
#   chmod u-s /usr/local/bin/mojang-maintenance
#   # pin PATH=/usr/bin:/bin inside the script
#   systemctl is-active mojang-web nginx  # both still active
#
# Verify with the trusted channel (probes run from the control plane, never
# from the attacker VM): `http_content` still passes, `no_rogue_admin` and
# `cron_persistence_present (absent)` confirm the repair.
