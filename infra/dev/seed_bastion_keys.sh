#!/bin/sh
# seed-bastion-keys — compose one-shot that POPULATES the bastion-keys volume
# and the recordings dir from operator-supplied files (Stage 5 item 3).
# Declaring a volume is not provisioning it: without this step the bastion
# starts with no member keys and no pinned host keys, silently.
#
#   SR_SEED_SRC_DIR   operator files, mounted READ-ONLY (compose bind mount):
#                       authorized_keys       "<username> <algo> <base64>" lines
#                       target_known_hosts    pinned range-host keys
#   SR_SEED_DEST_DIR  bastion-keys volume mount (compose: /etc/sparring-range)
#   SR_SEED_REC_DIR   recordings volume mount (compose: .../recordings)
#
# Idempotent: identical content is left untouched, changed content replaces.
# Fails loudly (exit 1) on missing/empty inputs — a bastion with no member
# keys or no pinned host keys must never start silently.
# NEVER commit the source files: they are live key material.
set -eu

SRC="${SR_SEED_SRC_DIR:-/operator-keys}"
DEST="${SR_SEED_DEST_DIR:-/etc/sparring-range}"
REC="${SR_SEED_REC_DIR:-/var/lib/sparring-range/recordings}"
RUNBOOK="docs/OPERATOR_RUNBOOK.md section 0 (fresh-stack bootstrap)"

fail() { echo "[seed-bastion-keys] ERROR: $*" >&2; exit 1; }

[ -d "$SRC" ] || fail "operator keys dir '$SRC' is not mounted — bind your deploy dir \
(default ./deploy/bastion, override SR_DEPLOY_KEYS_DIR) per $RUNBOOK"

mkdir -p "$DEST" "$REC"
[ -w "$DEST" ] || fail "'$DEST' (bastion-keys volume) is not writable"
[ -w "$REC" ]  || fail "'$REC' (recordings volume) is not writable"

for f in authorized_keys target_known_hosts; do
    [ -f "$SRC/$f" ] || fail "missing $SRC/$f — the bastion cannot authenticate members / \
verify range hosts without it; provide it per $RUNBOOK"
    [ -s "$SRC/$f" ] || fail "$SRC/$f is empty — it would authorize or authenticate nothing"
    if [ -f "$DEST/$f" ] && cmp -s "$SRC/$f" "$DEST/$f"; then
        echo "[seed-bastion-keys] $f: unchanged"
    else
        install -m 0644 "$SRC/$f" "$DEST/$f"
        echo "[seed-bastion-keys] $f: seeded -> $DEST/$f"
    fi
done
echo "[seed-bastion-keys] recordings dir ready: $REC"
