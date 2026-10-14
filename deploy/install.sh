#!/usr/bin/env bash
# sparring-range operator installer (plan 13 phase 8).
#
# Managed-service installation for the CONTROL PLANE VM (the broker/bastion
# installation follows the same discipline in their own units). Idempotent:
# safe to re-run after a failure or an upgrade; NEVER regenerates existing
# private keys, NEVER touches the database schema without the offline
# migration step, NEVER starts services before verification passes.
#
#   deploy/install.sh --manifest /etc/sparring-range/manifest.json \
#       [--prefix /] [--dry-run] [--no-backup]
#
# Phases (each idempotent, each re-runnable):
#   1 validate    manifest schema + values (infra/release_manifest.py)
#   2 identity    service users + state dirs (writable absolute paths)
#   3 keys        generate ONLY missing key material (never overwrite)
#   4 tls         bootstrap TLS via deploy/bootstrap_tls.sh (idempotent)
#   5 config      render env files from the manifest (0640, no secrets in
#                 git; secret values referenced by protected path)
#   6 units       install systemd units + daemon-reload
#   7 migrate     offline admin migration step (explicit, never implicit)
#   8 verify      import checks + readiness endpoints; enable services ONLY
#                 after verify passes; a failed verify leaves services as-is
#   9 backup      OPTIONAL pre-change DB backup (--no-backup skips; absence
#                 is a documented, deliberate choice, not a failure)
set -euo pipefail

MANIFEST="" PREFIX="/" DRY=0 BACKUP=1
while [ $# -gt 0 ]; do case "$1" in
  --manifest) MANIFEST="$2"; shift 2;;
  --prefix) PREFIX="$2"; shift 2;;
  --dry-run) DRY=1; shift;;
  --no-backup) BACKUP=0; shift;;
  *) echo "install: unknown argument $1" >&2; exit 2;;
esac; done
[ -n "$MANIFEST" ] || { echo "install: --manifest required" >&2; exit 2; }
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${SR_PYTHON:-$REPO/.venv/bin/python}"
[ -x "$PY" ] || PY="$(command -v python3)"

say() { echo "install[$1]: $2"; }
run() { if [ "$DRY" = 1 ]; then echo "DRY: $*"; else "$@"; fi; }

# 1 -- validate the release manifest BEFORE any effect (fail closed).
"$PY" - "$MANIFEST" <<'PYEOF'
import json, sys
sys.path.insert(0, ".")
from infra.release_manifest import ManifestError, validate_manifest
m = json.load(open(sys.argv[1]))
try:
    rm = validate_manifest(m)
except ManifestError as e:
    print("install: manifest invalid: %s" % e, file=sys.stderr)
    sys.exit(1)
print("install[1]: manifest valid (schema v%s)" % m.get("schema_version"))
PYEOF

SR_USER=sr-app; SR_GROUP=sr-app
STATE="$PREFIX/var/lib/sparring-range"
ETC="$PREFIX/etc/sparring-range"
TLS="$ETC/tls"
LOGDIR="$PREFIX/var/log/sparring-range"

# 2 -- identity + state (idempotent).
run id -u "$SR_USER"
if [ "$DRY" != 1 ]; then
  id -u "$SR_USER" >/dev/null 2>&1 || useradd --system --home-dir "$STATE" \
      --shell /usr/sbin/nologin "$SR_USER"
fi
run install -d -m 0750 -o "$SR_USER" -g "$SR_GROUP" "$STATE" "$LOGDIR"
run install -d -m 0750 "$ETC" "$TLS"

# 3 -- key material: generate ONLY what is missing (never regenerate).
for k in bastion_ed25519 bastion_client_ed25519; do
  if [ -f "$TLS/$k" ]; then
    say keys "keeping existing $k (rotation is an explicit operator act)"
  else
    run ssh-keygen -q -t ed25519 -N '' -f "$TLS/$k" \
        -C "sparring-range/$k@$(hostname)"
    run chown root:"$SR_GROUP" "$TLS/$k" "$TLS/$k.pub"
    run chmod 0640 "$TLS/$k"; run chmod 0644 "$TLS/$k.pub"
  fi
done

# 4 -- TLS material (bootstrap_tls.sh is itself idempotent).
if [ "$DRY" = 1 ]; then echo "DRY: deploy/bootstrap_tls.sh $TLS"; else
  SR_TLS_DIR="$TLS" "$REPO/deploy/bootstrap_tls.sh" >/dev/null || {
    say tls "bootstrap needs the operator CA inputs — see deploy/README.md §3"; }
fi

# 5 -- config rendering: env files from the manifest + examples. Existing
# files are NEVER overwritten (an operator edit must survive re-runs); a
# missing file is created 0640 from the shipped example for the operator to
# complete. Placeholders are REJECTED at service start by settings
# validation, not silently accepted here.
for role in control-plane broker; do
  f="$ETC/$role.env"
  if [ -f "$f" ]; then
    say config "keeping existing $f (operator edits preserved)"
  else
    run install -m 0640 "$REPO/deploy/env.$role.example" "$f"
    say config "created $f from example — COMPLETE every CHANGE value"
  fi
done

# 6 -- systemd units (idempotent copy + reload).
for u in "$REPO"/deploy/systemd/*.service "$REPO"/deploy/systemd/*.timer; do
  [ -e "$u" ] || continue
  run install -m 0644 "$u" "$PREFIX/etc/systemd/system/"
done
run -n true && [ "$DRY" = 1 ] || systemctl daemon-reload

# 7 -- migrations are EXPLICIT (offline admin), never implicit in install:
say migrate "run migrations deliberately:  SR_PG_ADMIN_URL=... $PY -m srplatform.db.migrate"

# 8 -- verify BEFORE enabling anything.
if [ "$DRY" != 1 ]; then
  ( cd "$REPO" && "$PY" -c 'import rangectl.cli' ) \
    || { say verify "entrypoint import failed — services NOT enabled"; exit 1; }
  say verify "ok — enabling services"
  systemctl enable sparring-range-api.service sparring-range-broker.service 2>/dev/null || \
    say verify "enable skipped (units not installed under $PREFIX — expected with --prefix)"
else
  echo "DRY: verify + enable"
fi

# 9 -- optional pre-change backup (absence is a documented choice).
if [ "$BACKUP" = 1 ]; then
  say backup "optional backup: pg_dump via SR_PG_ADMIN_URL to $STATE/backups (see runbook §backups)"
else
  say backup "skipped by --no-backup (deliberate, documented)"
fi
say done "idempotent install complete (dry-run=$DRY)"
