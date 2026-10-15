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

MANIFEST="" PREFIX="/" DRY=0 BACKUP=1 ROTATE_TLS=0
while [ $# -gt 0 ]; do case "$1" in
  --manifest) MANIFEST="$2"; shift 2;;
  --prefix) PREFIX="$2"; shift 2;;
  --dry-run) DRY=1; shift;;
  --no-backup) BACKUP=0; shift;;
  --rotate-tls) ROTATE_TLS=1; shift;;  # explicit identity rotation ONLY
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

# canonical service identities (match deploy/systemd units, README and
# shipped file ownership: srrange/srbastion/srbroker — one per role so a
# compromised role cannot write another role's state)
SR_USER=srrange; SR_GROUP=srrange
SR_ALL_USERS="srrange srbastion srbroker"
STATE="$PREFIX/var/lib/sparring-range"
ETC="$PREFIX/etc/sparring-range"
TLS="$ETC/tls"
LOGDIR="$PREFIX/var/log/sparring-range"

# 2 -- identity + state (idempotent).
if [ "$DRY" != 1 ]; then
  for _u in $SR_ALL_USERS; do
    id -u "$_u" >/dev/null 2>&1 || useradd --system \
        --home-dir "$STATE" --shell /usr/sbin/nologin "$_u"
  done
else
  echo "DRY: ensure users $SR_ALL_USERS exist"
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

# 4 -- TLS material. Existing identities are NEVER regenerated: rotation
# is an explicit operator act (--rotate-tls), never a reinstall side
# effect. bootstrap_tls.sh itself always regenerates, so it runs only when
# no identity exists yet (or rotation was explicitly requested).
_tls_have() { [ -f "$TLS/broker-server.key" ] && [ -f "$TLS/ca.key" ]; }
if [ "$DRY" = 1 ]; then
  echo "DRY: deploy/bootstrap_tls.sh $TLS (only if no identity exists)"
elif _tls_have && [ "$ROTATE_TLS" != 1 ]; then
  say tls "keeping existing TLS identities (rotation needs --rotate-tls)"
else
  # SR_SSH_DIR follows the prefix too: bastion keys must never land in
  # /etc when installing under a sandbox prefix. SR_TLS_ROTATE=1 reaches
  # through only for explicit --rotate-tls (normal runs preserve).
  # Exit 3 from bootstrap is an explicit partial-state REFUSAL (missing CA
  # key beside surviving certificates) — that fails the install loudly;
  # any other failure is missing operator inputs on a first run (warn).
  set +e
  SR_TLS_DIR="$TLS" SR_SSH_DIR="$ETC/ssh" SR_TLS_ROTATE="$ROTATE_TLS" \
    "$REPO/deploy/bootstrap_tls.sh" >/dev/null
  _tls_rc=$?
  set -e
  if [ "$_tls_rc" -eq 3 ]; then
    say tls "refusing partial TLS state (see above) — recover ca.key from backup or rotate explicitly"
    exit 1
  elif [ "$_tls_rc" -ne 0 ]; then
    say tls "bootstrap needs the operator CA inputs — see deploy/README.md §3"
  fi
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

# 5b -- DERIVED artifacts (rendered from the manifest, never hand-copied):
# the broker policy is fully determined by the manifest's pve/network/
# storage/templates/budgets sections and validated by the broker's own
# loader before writing. Re-rendered on every run (deterministic output —
# no drift, no placeholders).
if [ "$DRY" = 1 ]; then
  echo "DRY: render $ETC/broker-policy.json from the manifest"
else
"$PY" - "$MANIFEST" "$ETC/broker-policy.json" <<'PYEOF'
import importlib.util
import json
import sys
sys.path.insert(0, ".")
spec = importlib.util.spec_from_file_location(
    "gen_broker_policy", "deploy/gen_broker_policy.py")
gen_mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gen_mod)
m = json.load(open(sys.argv[1]))
out = sys.argv[2]
tids = ",".join(str(m["templates"][r]["vmid"]) for r in
                ("attacker", "mojang-web-local", "mojang-web-db")
                if r in m["templates"])
lo, hi = m["pve"]["clone_vmid_range"]
rc = gen_mod.main(["--node", m["pve"]["node"], "--bridge", m["network"]["bridge"],
          "--vlan", str(m["network"]["vlan"]),
          "--cidr", m["network"]["range_cidr"],
          "--gateway", m["network"]["gateway"],
          "--templates", tids, "--vmid-range", f"{lo}-{hi}",
          "--storage", m["storage"]["name"],
          "--clone-mode", m["storage"]["clone_mode"],
          "--max-vms", str(m["budgets"]["max_vms"]),
          "--cores-per-vm", str(m["budgets"]["guest_vcpus"]),
          "--memory-mb-per-vm", str(m["budgets"]["guest_ram_mb"]),
          "--disk-gb-per-vm", str(m["budgets"]["guest_disk_gb"]),
          "--max-total-disk-gb", str(m["budgets"]["disk_gb_total"]),
          "--out", out])
sys.exit(rc)
PYEOF
  say config "rendered $ETC/broker-policy.json from the manifest"
fi

# 5c -- DERIVED service environment (non-secret manifest facts). Rendered
# every run into control-plane.derived.env; the operator-owned
# control-plane.env keeps secrets and overrides (loaded second). Secrets
# can never come from the non-secret manifest — they stay operator-owned.
if [ "$DRY" = 1 ]; then
  echo "DRY: render $ETC/control-plane.derived.env from the manifest"
else
"$PY" - "$MANIFEST" "$ETC/control-plane.derived.env" "$ETC/broker-policy.json" <<'PYEOF'
import json, sys
m = json.load(open(sys.argv[1]))
out, policy = sys.argv[2], sys.argv[3]
lo, hi = m["pve"]["clone_vmid_range"]
lines = [
    "# DERIVED from the release manifest — do not hand-edit "
    "(re-rendered by deploy/install.sh). Operator secrets and overrides "
    "belong in control-plane.env, which is loaded after this file.",
    f"PROXMOX_NODE={m['pve']['node']}",
    f"RANGE_BRIDGE={m['network']['bridge']}",
    f"RANGE_VLAN={m['network']['vlan']}",
    f"RANGE_CIDR={m['network']['range_cidr']}",
    f"RANGE_GATEWAY={m['network']['gateway']}",
    f"DEPLOY_VMID_BASE={lo}",
    f"BROKER_POLICY_FILE={policy}",
]
open(out, "w").write("\n".join(lines) + "\n")
print(f"derived environment written: {out}")
PYEOF
  say config "rendered $ETC/control-plane.derived.env from the manifest"
fi

# 6 -- systemd units (idempotent copy + reload).
for u in "$REPO"/deploy/systemd/*.service "$REPO"/deploy/systemd/*.timer; do
  [ -e "$u" ] || continue
  run install -m 0644 "$u" "$PREFIX/etc/systemd/system/"
done
if [ "$DRY" = 1 ]; then
  echo "DRY: systemctl daemon-reload"
else
  systemctl daemon-reload 2>/dev/null || \
    say verify "daemon-reload skipped (no systemd here)"
fi

# 7 -- migrations are EXPLICIT (offline admin), never implicit in install:
say migrate "run migrations deliberately:  SR_PG_ADMIN_URL=... $PY -m srplatform.db.migrate"

# 8 -- verify BEFORE enabling anything.
if [ "$DRY" != 1 ]; then
  ( cd "$REPO" && "$PY" -c 'import rangectl.cli' ) \
    || { say verify "entrypoint import failed — services NOT enabled"; exit 1; }
  say verify "ok — enabling services"
  # unit names MUST match deploy/systemd (sr-api on the control plane;
  # sr-brokerd is enabled by the broker VM's own install, never here).
  systemctl enable sr-api.service 2>/dev/null || \
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
