#!/usr/bin/env bash
# Pilot step 7: TLS + key material bootstrap (operator executes on the
# control plane / broker VM; the agent ships the script, nothing secret).
#
# Produces (0600/0640, never in git):
#   $SR_TLS_DIR/ca.{crt,key}            broker CA (private, broker VM only)
#   $SR_TLS_DIR/broker-server.{crt,key} broker server cert (its hostname/IP SAN)
#   $SR_TLS_DIR/api-client.{crt,key}    API client cert (mutual TLS identity)
#   $SR_TLS_DIR/https.{crt,key}         web UI cert: self-signed with IP-SAN
#                                       (clients trust it via the printed
#                                       fingerprint / trust instructions)
#   $SR_SSH_DIR/bastion_ed25519[.pub]   bastion dial key: the PUBLIC half is
#                                       baked into the guest templates at
#                                       build time (per-generation rotation =
#                                       rebuild + reimport)
set -euo pipefail

SR_TLS_DIR="${SR_TLS_DIR:-/etc/sparring-range/tls}"
SR_SSH_DIR="${SR_SSH_DIR:-/etc/sparring-range/ssh}"
# Service group entitled to READ generation keys (review find 2026-10-15:
# ssh-keygen mints root-only 0600, which silently denies the entitled
# service consumer — the group must be explicit, never assumed).
SR_SSH_GROUP="${SR_SSH_GROUP:-srrange}"
BROKER_HOST="${BROKER_HOST:-broker.range.internal}"   # how the API dials the broker
API_HOST="${API_HOST:-control-plane}"                 # client-cert identity label
HTTPS_IP="${HTTPS_IP:-}"                              # control-plane LAN IP
DAYS=397                                              # browsers reject longer

umask 077
mkdir -p "$SR_TLS_DIR" "$SR_SSH_DIR"
cd "$SR_TLS_DIR"
# Explicit rotation bypasses every preservation guard (installer passes
# SR_TLS_ROTATE=1 only for --rotate-tls; normal runs preserve survivors).
FRESH="${SR_TLS_ROTATE:-0}"
fresh() { [ "$FRESH" = 1 ] || [ ! -f "$1" ]; }

# Partial-state refusal: a missing CA key alongside surviving CA-signed
# certificates would silently orphan those identities on regeneration.
# Either everything is fresh (first run) or rotation is explicit.
if [ "$FRESH" != 1 ] && [ ! -f ca.key ] && { [ -f broker-server.crt ] || [ -f api-client.crt ]; }; then
  echo "bootstrap_tls: ca.key missing but CA-signed certificates exist —" >&2
  echo "refusing partial regeneration (would orphan live identities)." >&2
  echo "Recover ca.key from backup, or delete the stale certificates for an" >&2
  echo "explicit full rotation." >&2
  exit 3
fi
if fresh ca.key || [ ! -f ca.crt ]; then
  { [ "$FRESH" = 1 ] && rm -f ca.key; } || true
  [ -f ca.key ] || openssl genrsa -out ca.key 4096
  openssl req -x509 -new -key ca.key -sha256 -days "$DAYS" -subj "/CN=sparring-range-broker-CA" -out ca.crt
fi

# broker server cert — SAN type must match how the API dials it: an IP
# target requires an iPAddress SAN (a DNS SAN never matches an IP).
if printf '%s' "$BROKER_HOST" | grep -qE '^[0-9.]+$|:'; then
  broker_san="IP:$BROKER_HOST"
else
  broker_san="DNS:$BROKER_HOST"
fi
# Per-artifact preservation: surviving identities are NEVER
# regenerated as a side effect — only missing artifacts are created.
if fresh broker-server.key || [ ! -f broker-server.crt ]; then
{ [ "$FRESH" = 1 ] && rm -f broker-server.key; } || true
[ -f broker-server.key ] || openssl genrsa -out broker-server.key 2048
openssl req -new -key broker-server.key -subj "/CN=$BROKER_HOST" -out broker-server.csr
printf "subjectAltName=%s%s\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n" \
  "$broker_san" "${HTTPS_IP:+,IP:$HTTPS_IP}" > broker-server.ext
openssl x509 -req -in broker-server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days "$DAYS" -sha256 -extfile broker-server.ext -out broker-server.crt
fi

# API client cert (mutual TLS: the broker only accepts this identity)
if fresh api-client.key || [ ! -f api-client.crt ]; then
{ [ "$FRESH" = 1 ] && rm -f api-client.key; } || true
[ -f api-client.key ] || openssl genrsa -out api-client.key 2048
openssl req -new -key api-client.key -subj "/CN=$API_HOST" -out api-client.csr
fi
printf "basicConstraints=critical,CA:FALSE\nextendedKeyUsage=clientAuth\n" > api-client.ext
openssl x509 -req -in api-client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days "$DAYS" -sha256 -extfile api-client.ext -out api-client.crt

# Guest-facing ingest listener (plan 13 phase 4): a DEDICATED API CA
# signs ONLY this certificate — compromise of the web UI or broker keys
# never yields a valid guest-facing identity, and vice versa. SANs come
# from INGEST_SANS (space-separated "IP:<addr>" / "DNS:<name>" entries;
# the installer derives them from manifest trust.san_ips). The public
# half (api-ca.crt) is what enrollments provision into guests as their
# explicit trust anchor (SR_TELEMETRY_CA_FILE).
if [ -z "${INGEST_SANS:-}" ]; then
  echo "bootstrap_tls: INGEST_SANS empty — skipping ingest-server cert (set it from manifest trust.san_ips)" >&2
elif [ "$FRESH" != 1 ] && [ ! -f api-ca.key ] && [ -f ingest-server.crt ]; then
  # Same partial-state rule as the broker CA: a missing API CA key
  # beside surviving API-signed certificates would silently orphan guest
  # trust already installed — refuse unless rotation is explicit.
  echo "bootstrap_tls: api-ca.key missing but ingest-server.crt exists —" >&2
  echo "refusing partial regeneration (would orphan installed guest trust)." >&2
  echo "Recover api-ca.key from backup, or delete the stale certificate for" >&2
  echo "an explicit full rotation." >&2
  exit 3
elif [ "$FRESH" = 1 ] || [ ! -f api-ca.key ] || [ ! -f api-ca.crt ] || [ ! -f ingest-server.key ] || [ ! -f ingest-server.crt ]; then
  if [ "$FRESH" = 1 ]; then
    rm -f api-ca.key api-ca.crt ingest-server.key ingest-server.crt ingest-server.csr
  fi
  [ -f api-ca.key ] || openssl genrsa -out api-ca.key 4096
  openssl req -x509 -new -key api-ca.key -sha256 -days "$DAYS" -subj "/CN=sparring-range-api-CA" -out api-ca.crt
  sans_list=""
  for _san in $INGEST_SANS; do
    case "$_san" in
      IP:*|DNS:*) sans_list="${sans_list:+$sans_list,}$_san" ;;
      *) echo "bootstrap_tls: refusing malformed SAN $_san" >&2; exit 2 ;;
    esac
  done
  [ -n "$sans_list" ] || { echo "bootstrap_tls: no valid SANs" >&2; exit 2; }
  {
    echo "basicConstraints=critical,CA:FALSE"
    echo "extendedKeyUsage=serverAuth"
    echo "subjectAltName=$sans_list"
  } > ingest-server.ext
  [ -f ingest-server.key ] || openssl genrsa -out ingest-server.key 2048
  openssl req -new -key ingest-server.key -subj "/CN=sparring-range-ingest" -out ingest-server.csr
  openssl x509 -req -in ingest-server.csr -CA api-ca.crt -CAkey api-ca.key -CAcreateserial \
    -days "$DAYS" -sha256 -extfile ingest-server.ext -out ingest-server.crt
fi

# web UI: self-signed with the LAN IP in the SAN (teammates import/verify it)
# Explicit rotation ALWAYS regenerates (FRESH takes precedence over
# every preservation branch below — rotation that keeps the old key is a
# silent no-op, the worst possible outcome for a rotation ceremony).
if [ -n "$HTTPS_IP" ] && [ "$FRESH" = 1 ]; then
  rm -f https.key https.crt
fi
if [ -n "$HTTPS_IP" ] && { [ ! -f https.key ] || [ ! -f https.crt ]; }; then
  if [ -f https.key ] && [ ! -f https.crt ]; then
    # surviving key, missing certificate: re-issue the cert onto the SAME
    # key (clients pinning the key are unaffected; rotation is untouched
    # because FRESH already replaced the key above when requested)
    openssl req -x509 -key https.key -sha256 -days "$DAYS" -nodes \
      -out https.crt -subj "/CN=$HTTPS_IP" \
      -addext "subjectAltName=IP:$HTTPS_IP"
  else
    openssl req -x509 -newkey rsa:2048 -sha256 -days "$DAYS" -nodes \
      -keyout https.key -out https.crt -subj "/CN=$HTTPS_IP" \
      -addext "subjectAltName=IP:$HTTPS_IP"
  fi
  echo "web UI certificate SHA256 fingerprint (verify out-of-band):"
  openssl x509 -in https.crt -noout -fingerprint -sha256
else
  echo "HTTPS_IP not set — skipping web UI cert (set it to the control-plane LAN IP)" >&2
fi

# bastion dial keypair (public half -> pve_template_build.py --pubkey)
if [ "$FRESH" = 1 ] || [ ! -f "$SR_SSH_DIR/bastion_ed25519" ]; then
  # rotation must not hang on ssh-keygen's overwrite prompt (non-interactive)
  if [ "$FRESH" = 1 ]; then
    rm -f "$SR_SSH_DIR/bastion_ed25519" "$SR_SSH_DIR/bastion_ed25519.pub"
  fi
  ssh-keygen -q -t ed25519 -N '' -C 'sr-bastion-generation-1' -f "$SR_SSH_DIR/bastion_ed25519"
fi
# Service-readable, never regenerated above: the entitled group traverses
# (0750) and reads the private half (0640); the public half is world-
# readable (builds copy it). A missing group fails LOUD, never silent.
chown root:"$SR_SSH_GROUP" "$SR_SSH_DIR" && chmod 0750 "$SR_SSH_DIR"
chown root:"$SR_SSH_GROUP" "$SR_SSH_DIR/bastion_ed25519" \
    "$SR_SSH_DIR/bastion_ed25519.pub"
chmod 0640 "$SR_SSH_DIR/bastion_ed25519"
chmod 0644 "$SR_SSH_DIR/bastion_ed25519.pub"

# TLS material per-FILE ownership (plan 18 review): a blanket chmod made
# the ingest key pair root-only 0640 — the sringest unit could not even
# read the certificate it serves — and pinned every .crt root:root 0640,
# so no service identity could read a trust anchor.  Every file has a
# named consumer now; the private CA key material stays root-only.
chmod 0600 ./*.key 2>/dev/null || true
if [ -f ingest-server.key ]; then
  # The ingest listener (sringest) serves this pair: group-readable,
  # never world-readable. A missing group fails LOUD, never silent.
  chown root:"${SR_INGEST_GROUP:?SR_INGEST_GROUP required}" \
    ingest-server.key ingest-server.crt
  chmod 0640 ingest-server.key ingest-server.crt
fi
# Public trust material is world-readable (a certificate carries no
# secret): api-ca.crt and ca.crt are pinned by API/ingest/bastion,
# https.crt is the anchor for the surface nginx actually presents.
chmod 0644 ca.crt api-ca.crt https.crt 2>/dev/null || true
# Broker-CA artefacts with no local appliance consumer stay root-only:
chmod 0640 broker-server.crt api-client.crt broker-server.csr \
    api-client.csr ca.srl 2>/dev/null || true
echo
echo "done. Distribute: ca.crt + api-client.* -> control plane; ca.crt +
broker-server.* -> broker VM; $SR_SSH_DIR/bastion_ed25519 stays on the
bastion; its .pub is the --pubkey for infra/images/pve_template_build.py."
