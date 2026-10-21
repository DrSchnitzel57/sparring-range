#!/usr/bin/env bash
# Appliance hand-off: take the bundle into a fresh appliance VM.
#
# Every step is checked and the script stops at the first failure, so a
# half-installed appliance is never mistaken for a working one.  Nothing here
# touches the host until the `apply` step, and `apply` is the only step that
# changes the machine.
#
#   ./deploy/hand_off.sh --bundle /opt/sparring-range \
#        --installation-id "$(uuidgen)" \
#        --lan-address 10.10.10.50 --range-cidr 10.66.0.0/24 \
#        --public-url https://sr.example.edu \
    --model-base-url http://127.0.0.1:8001/v1 --model-alias my-model
#
# The internal and ingest URLs default to the loopback API and the
# controller's range address; override them with --internal-url/--ingest-url
# when the appliance is not the controller host.
set -euo pipefail

BUNDLE=""
INSTALLATION_ID=""
LAN_ADDRESS=""
RANGE_CIDR=""
PUBLIC_URL=""
INTERNAL_URL=""
INGEST_URL=""
RANGE_BRIDGE="srlab0"
MODEL_BASE_URL="http://127.0.0.1:8001/v1"
MODEL_ALIAS="sr-model"
HOSTNAME="sr-appliance"
KEYS_DIR="/etc/sparring-range/keys"
SECRETS_DIR="/etc/sparring-range/secrets"
MANIFEST="/etc/sparring-range/appliance-manifest.json"
DB_HOST="127.0.0.1"
DB_NAME="sparring_range"
PYTHON="${SR_PYTHON:-python3}"

usage() {
  sed -n '2,20p' "$0" >&2
  exit 2
}

while [ $# -gt 0 ]; do
  case "$1" in
    --bundle) BUNDLE="$2"; shift 2;;
    --installation-id) INSTALLATION_ID="$2"; shift 2;;
    --lan-address) LAN_ADDRESS="$2"; shift 2;;
    --range-cidr) RANGE_CIDR="$2"; shift 2;;
    --public-url) PUBLIC_URL="$2"; shift 2;;
    --internal-url) INTERNAL_URL="$2"; shift 2;;
    --ingest-url) INGEST_URL="$2"; shift 2;;
  --db-host) DB_HOST="$2"; shift 2;;
    --bridge) RANGE_BRIDGE="$2"; shift 2;;
    --hostname) HOSTNAME="$2"; shift 2;;
    --model-base-url) MODEL_BASE_URL="$2"; shift 2;;
    --model-alias) MODEL_ALIAS="$2"; shift 2;;
    --keys-dir) KEYS_DIR="$2"; shift 2;;
    --secrets-dir) SECRETS_DIR="$2"; shift 2;;
    --manifest) MANIFEST="$2"; shift 2;;
    --python) PYTHON="$2"; shift 2;;
    -h|--help) usage;;
    *) echo "unknown argument: $1" >&2; usage;;
  esac
done

[ -n "$BUNDLE" ] && [ -n "$INSTALLATION_ID" ] && [ -n "$LAN_ADDRESS" ] && \
  [ -n "$RANGE_CIDR" ] && [ -n "$PUBLIC_URL" ] || usage

BUNDLE="$(cd "$BUNDLE" && pwd)"
cd "$BUNDLE"

say() { printf '\n== %s\n' "$*"; }

say "1/7 verify the bundle"
"$PYTHON" deploy/bundle.py verify .

say "2/7 prepare the operator's keys and secrets"
install -d -m 0750 "$KEYS_DIR"
install -d -m 0700 "$SECRETS_DIR"
for role in runner bastion mgmt; do
  if [ ! -f "$KEYS_DIR/$role" ]; then
    ssh-keygen -q -t ed25519 -N '' -f "$KEYS_DIR/$role"
    echo "  generated $KEYS_DIR/$role (keep the PRIVATE half safe)"
  fi
done
if [ ! -f "$SECRETS_DIR/model.key" ]; then
  install -m 0600 /dev/null "$SECRETS_DIR/model.key"
  echo "  created $SECRETS_DIR/model.key - put the model credential in it"
fi
# The SCHEMA OWNER credential and the RUNTIME credential are separate files.
# The owner URL is used ONLY to run the migrations and lives in a root-only
# file that no service loads; the runtime URL goes into the env the API,
# the ingest listener and the bastion load.  Never put the owner URL in
# control-plane.env: every service would then hold the schema owner.
install -d -m 0750 "$SECRETS_DIR"
if [ ! -f "$SECRETS_DIR/db-owner.env" ]; then
  OWNER_PW="$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)"
  umask 077
  printf 'SR_POSTGRES_URL_OWNER=postgresql+psycopg2://sr_owner:%s@%s:5432/%s\n' \
    "$OWNER_PW" "$DB_HOST" "$DB_NAME" > "$SECRETS_DIR/db-owner.env"
  chmod 0600 "$SECRETS_DIR/db-owner.env"
  echo "  created $SECRETS_DIR/db-owner.env (schema owner; 0600, root only)"
fi
if [ ! -f /etc/sparring-range/control-plane.env ]; then
  APP_PW="$(head -c 24 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)"
  umask 027
  printf '# Runtime environment for the API, the ingest listener and the bastion.\n'
  printf '# The schema OWNER credential is NOT here: it lives in %s.\n' \
    "$SECRETS_DIR/db-owner.env"
  printf 'SR_POSTGRES_URL=postgresql+psycopg2://sr_app:%s@%s:5432/%s\n' \
    "$APP_PW" "$DB_HOST" "$DB_NAME" > /etc/sparring-range/control-plane.env
  chmod 0640 /etc/sparring-range/control-plane.env
  chgrp srrange /etc/sparring-range/control-plane.env 2>/dev/null || true
  echo "  created /etc/sparring-range/control-plane.env (runtime role only)"
fi

say "3/7 render the operator manifest from the bundle"
[ -n "$INTERNAL_URL" ] || INTERNAL_URL="http://127.0.0.1:8000"
if [ -z "$INGEST_URL" ]; then
  INGEST_URL="https://$(printf '%s' "$RANGE_CIDR" | awk -F. '{print $1"."$2"."$3".1"}'):8443"
fi
"$PYTHON" deploy/bundle.py manifest . --out "$MANIFEST" \
  --installation-id "$INSTALLATION_ID" \
  --lan-address "$LAN_ADDRESS" --range-cidr "$RANGE_CIDR" \
  --public-url "$PUBLIC_URL" --internal-url "$INTERNAL_URL" \
  --ingest-url "$INGEST_URL" --range-bridge "$RANGE_BRIDGE" \
  --hostname "$HOSTNAME" \
  --access-key "runner=$KEYS_DIR/runner.pub" \
  --access-key "bastion=$KEYS_DIR/bastion.pub" \
  --access-key "mgmt=$KEYS_DIR/mgmt.pub" \
  --model-api-key-file "$SECRETS_DIR/model.key" \
  --model-base-url "$MODEL_BASE_URL" --model-alias "$MODEL_ALIAS"

say "4/7 plan the installation"
"$PYTHON" deploy/appliance.py plan --manifest "$MANIFEST"

say "5/7 apply the installation"
if [ "$(id -u)" != "0" ]; then
  echo "apply needs root: re-run this step with sudo" >&2
  exit 1
fi
"$PYTHON" deploy/appliance.py apply --manifest "$MANIFEST"

say "6/7 apply the range network and start the services"
cat <<'NOTE'
The inner bridge and the fixed nftables rules are RENDERED but not applied:
they change the host's networking, so the operator reviews and applies them
in a maintenance window.

  less /etc/nftables.d/sr-appliance.nft
  less /etc/systemd/network/10-srlab.netdev /etc/systemd/network/20-srlab.network
  networkctl reload
  nft -f /etc/nftables.d/sr-appliance.nft
  systemctl enable --now sr-appliance-broker sr-api sr-appliance-ingest \
    sr-worker-supervisor sr-bastion sr-web
NOTE

say "7/7 check that the appliance came up"
"$PYTHON" deploy/appliance.py firstboot --manifest "$MANIFEST"

printf '\nhand-off complete: the manual rehearsal (fresh launch, member SSH,\n'
printf 'sudo, reconnect, replay, cleanup, second fresh launch) is still yours.\n'
