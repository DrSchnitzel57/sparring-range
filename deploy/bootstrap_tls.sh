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
BROKER_HOST="${BROKER_HOST:-broker.range.internal}"   # how the API dials the broker
API_HOST="${API_HOST:-control-plane}"                 # client-cert identity label
HTTPS_IP="${HTTPS_IP:-}"                              # control-plane LAN IP
DAYS=397                                              # browsers reject longer

umask 077
mkdir -p "$SR_TLS_DIR" "$SR_SSH_DIR"
cd "$SR_TLS_DIR"

if [ ! -f ca.crt ]; then
  openssl genrsa -out ca.key 4096
  openssl req -x509 -new -key ca.key -sha256 -days "$DAYS" -subj "/CN=sparring-range-broker-CA" -out ca.crt
fi

# broker server cert — SAN type must match how the API dials it: an IP
# target requires an iPAddress SAN (a DNS SAN never matches an IP).
if printf '%s' "$BROKER_HOST" | grep -qE '^[0-9.]+$|:'; then
  broker_san="IP:$BROKER_HOST"
else
  broker_san="DNS:$BROKER_HOST"
fi
openssl genrsa -out broker-server.key 2048
openssl req -new -key broker-server.key -subj "/CN=$BROKER_HOST" -out broker-server.csr
printf "subjectAltName=%s%s\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n" \
  "$broker_san" "${HTTPS_IP:+,IP:$HTTPS_IP}" > broker-server.ext
openssl x509 -req -in broker-server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days "$DAYS" -sha256 -extfile broker-server.ext -out broker-server.crt

# API client cert (mutual TLS: the broker only accepts this identity)
openssl genrsa -out api-client.key 2048
openssl req -new -key api-client.key -subj "/CN=$API_HOST" -out api-client.csr
printf "basicConstraints=critical,CA:FALSE\nextendedKeyUsage=clientAuth\n" > api-client.ext
openssl x509 -req -in api-client.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days "$DAYS" -sha256 -extfile api-client.ext -out api-client.crt

# web UI: self-signed with the LAN IP in the SAN (teammates import/verify it)
if [ -n "$HTTPS_IP" ]; then
  openssl req -x509 -newkey rsa:2048 -sha256 -days "$DAYS" -nodes \
    -keyout https.key -out https.crt -subj "/CN=$HTTPS_IP" \
    -addext "subjectAltName=IP:$HTTPS_IP"
  echo "web UI certificate SHA256 fingerprint (verify out-of-band):"
  openssl x509 -in https.crt -noout -fingerprint -sha256
else
  echo "HTTPS_IP not set — skipping web UI cert (set it to the control-plane LAN IP)" >&2
fi

# bastion dial keypair (public half -> pve_template_build.py --pubkey)
if [ ! -f "$SR_SSH_DIR/bastion_ed25519" ]; then
  ssh-keygen -q -t ed25519 -N '' -C 'sr-bastion-generation-1' -f "$SR_SSH_DIR/bastion_ed25519"
fi

chmod 600 ./*.key ca.key 2>/dev/null || true
chmod 640 ./*.crt 2>/dev/null || true
echo
echo "done. Distribute: ca.crt + api-client.* -> control plane; ca.crt +
broker-server.* -> broker VM; $SR_SSH_DIR/bastion_ed25519 stays on the
bastion; its .pub is the --pubkey for infra/images/pve_template_build.py."
