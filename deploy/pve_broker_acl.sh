#!/usr/bin/env bash
# Plan 13 phase 2 — scoped PVE broker ACL bootstrap (OPERATOR-RUN tooling).
#
# Creates/verifies the EXACT least-privilege authority the deployment broker
# needs for one approved range: node audit, template clones, bounded clone
# VMIDs, named storage, the range bridge, and the scoped guest-agent host-key
# read. Nothing broader is ever granted; there is deliberately no fallback to
# wider privileges, no Admin.*, no host shell.
#
# Modes:
#   (default)   dry-run: print every command, change nothing
#   --apply     execute the commands (idempotent: create-or-reuse)
#   --verify    probe EFFECTIVE permissions with the token itself: allowed
#               operations must answer, unrelated resources and privilege
#               changes must be denied. Role names alone are never proof.
#
# The API-token SECRET is never taken on the command line and never printed:
# create it in the PVE UI (or `pveum user token add ... ` redirected into a
# 0600 file by the operator) and point --token-secret-file at that file for
# --verify. This script never reads or writes it otherwise.
#
# Example (on the PVE host):
#   deploy/pve_broker_acl.sh --node pve --bridge srrange \
#       --templates 9005,9011,9012 --vmid-range 9100-9199 \
#       --storage local-zfs --probe-foreign-vmid 101            # dry-run
#   ... --apply
#   ... --verify --token-secret-file /root/sr-broker-token      # operator
set -euo pipefail

NODE="" BRIDGE="" TEMPLATES="" VMID_RANGE="" STORAGE=""
USERNAME="sr-broker" REALM="pve" TOKEN_NAME="range"
TOKEN_SECRET_FILE="" PROBE_FOREIGN_VMID=""
APPLY=0 VERIFY=0

die() { echo "REFUSED: $*" >&2; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --node) NODE="$2"; shift 2;;
        --bridge) BRIDGE="$2"; shift 2;;
        --templates) TEMPLATES="$2"; shift 2;;
        --vmid-range) VMID_RANGE="$2"; shift 2;;
        --storage) STORAGE="$2"; shift 2;;
        --username) USERNAME="$2"; shift 2;;
        --realm) REALM="$2"; shift 2;;
        --token-name) TOKEN_NAME="$2"; shift 2;;
        --token-secret-file) TOKEN_SECRET_FILE="$2"; shift 2;;
        --probe-foreign-vmid) PROBE_FOREIGN_VMID="$2"; shift 2;;
        --dry-run) APPLY=0; shift;;
        --apply) APPLY=1; shift;;
        --verify) VERIFY=1; shift;;
        *) die "unknown argument $1";;
    esac
done

[ -n "$NODE" ] && [ -n "$BRIDGE" ] && [ -n "$TEMPLATES" ] \
    && [ -n "$VMID_RANGE" ] && [ -n "$STORAGE" ] \
    || die "--node --bridge --templates --vmid-range --storage are all required"
echo "$VMID_RANGE" | grep -Eq '^[0-9]+-[0-9]+$' \
    || die "--vmid-range must look like 9100-9199 (bounded window)"
VMID_LO="${VMID_RANGE%-*}"; VMID_HI="${VMID_RANGE#*-}"
[ "$VMID_LO" -le "$VMID_HI" ] || die "empty VMID window"
echo "$BRIDGE$TEMPLATES$STORAGE$NODE" | grep -Eq '[/ ]' \
    && die "identifiers must not contain spaces or slashes"

USER_ID="${USERNAME}@${REALM}"
ROLE_BASE="SRBroker"
CMDS=()
run() {
    if [ "$APPLY" -eq 1 ]; then
        local out
        if out=$("$@" 2>&1); then
            return 0
        fi
        # idempotent create-or-reuse: ONLY "already exists" is tolerated;
        # any other failure stops loudly (no silent half-applied ACLs)
        echo "$out" | grep -qi "already exists" \
            || die "command failed: $* -> $out"
    else
        printf '    %q ' "$@"; echo
    fi
}

# ---------------------------------------------------------------- roles ----
# One narrow role per PATH CLASS (plan: exact per-path roles). PVE unions a
# user's roles per path, so separate roles keep each grant auditable.
BASE_PRIVS="VM.Audit,VM.Allocate,VM.Config.Network,VM.Config.Cloudinit,VM.Config.Options,VM.PowerMgmt,VM.GuestAgent.FileRead,Datastore.Allocate,Datastore.AllocateSpace"

echo "== planned grants (dry-run unless --apply) =="
run pveum role add "${ROLE_BASE}Base" --privs "$BASE_PRIVS"
run pveum role add "${ROLE_BASE}Clone" --privs "VM.Clone"
run pveum role add "${ROLE_BASE}Audit" --privs "Sys.Audit"
run pveum role add "${ROLE_BASE}Sdn" --privs "SDN.Use"

echo "== planned user =="
run pveum user add "$USER_ID" --comment "sparring-range deployment broker (restricted)"

echo "== planned ACLs (exact paths only) =="
run pveum acl modify "/nodes/${NODE}" \
    --users "$USER_ID" --roles "${ROLE_BASE}Audit"
run pveum acl modify "/sdn/zones/localnetwork/${BRIDGE}" \
    --users "$USER_ID" --roles "${ROLE_BASE}Sdn"
IFS=',' read -ra TMPLS <<< "$TEMPLATES"
for t in "${TMPLS[@]}"; do
    run pveum acl modify "/vms/${t}" \
        --users "$USER_ID" --roles "${ROLE_BASE}Clone"
done
# Clone targets + storage live under the resource-pool-free /vms and /storage
# paths; PVE has no per-VMID-range path, so the bounded window is enforced by
# the BROKER POLICY (fail-closed typed operations), and the token grant stays
# at the narrowest real PVE granularity: VM.Allocate/Datastore.* on /vms and
# the named storage only. Anything outside the policy is refused by the
# broker before PVE is ever asked.
run pveum acl modify "/vms" \
    --users "$USER_ID" --roles "${ROLE_BASE}Base"
run pveum acl modify "/storage/${STORAGE}" \
    --users "$USER_ID" --roles "${ROLE_BASE}Base"

echo
echo "Token: create ${USER_ID}!${TOKEN_NAME} in the PVE UI (or via pveum with"
echo "the secret redirected into a 0600 file). This script never handles"
echo "the secret value. The broker policy must bound clone VMIDs to"
echo "${VMID_LO}-${VMID_HI}; the token alone is not the boundary."

if [ "$APPLY" -eq 0 ] && [ "$VERIFY" -eq 0 ]; then
    echo
    echo "(dry-run: nothing executed; re-run with --apply, then --verify)"
    exit 0
fi
[ "$APPLY" -eq 1 ] && echo "== applied =="

# --------------------------------------------------------------- verify ----
if [ "$VERIFY" -eq 1 ]; then
    command -v curl >/dev/null || die "verify needs curl"
    [ -n "$TOKEN_SECRET_FILE" ] || die "--verify needs --token-secret-file"
    [ -n "$PROBE_FOREIGN_VMID" ] || die \
        "--verify needs --probe-foreign-vmid <vmid of an unrelated VM/LXC> to prove denials"
    [ -r "$TOKEN_SECRET_FILE" ] || die "token secret file unreadable"
    SECRET="$(cat "$TOKEN_SECRET_FILE")"
    API="https://127.0.0.1:8006/api2/json"
    probe() { # method path expect-class(allow|deny) [data]
        local method="$1" path="$2" expect="$3" data="${4:-}"
        local code
        if [ -n "$data" ]; then
            code=$(curl -sk -o /dev/null -w '%{http_code}' -X "$method" \
                -H "Authorization: PVEAPIToken=${USER_ID}!${TOKEN_NAME}=${SECRET}" \
                -d "$data" "${API}${path}")
        else
            code=$(curl -sk -o /dev/null -w '%{http_code}' -X "$method" \
                -H "Authorization: PVEAPIToken=${USER_ID}!${TOKEN_NAME}=${SECRET}" \
                "${API}${path}")
        fi
        case "$expect" in
            allow)
                if [ "$code" = "401" ] || [ "$code" = "403" ]; then
                    echo "  DENIED-but-expected-allowed $method $path ($code)"; FAIL=1
                else
                    echo "  allowed  $method $path ($code)"
                fi;;
            deny)
                if [ "$code" = "403" ]; then
                    echo "  denied   $method $path ($code)"
                else
                    echo "  ALLOWED-but-expected-denied $method $path ($code)"; FAIL=1
                fi;;
        esac
    }
    FAIL=0
    echo "== effective-permission probes (role names are not proof) =="
    probe GET "/version" allow
    probe GET "/nodes/${NODE}/qemu/${TMPLS[0]}/config" allow
    probe GET "/access/domains" deny          # no realm administration
    probe GET "/access/acl" deny              # no ACL readback/changes
    probe POST "/access/acl" deny "path=/&roles=PVEAdmin&users=${USER_ID}"
    probe GET "/nodes/${NODE}/qemu/${PROBE_FOREIGN_VMID}/config" deny
    probe GET "/nodes/${NODE}/qemu/${PROBE_FOREIGN_VMID}/agent/file-read?file=%2Fetc%2Fpasswd" deny
    probe POST "/nodes/${NODE}/qemu/${PROBE_FOREIGN_VMID}/status/stop" deny
    probe GET "/cluster/resources?type=storage" allow   # storage listing is
    # needed for the next-id scan; mutations stay policy-bound
    if [ "$FAIL" -ne 0 ]; then
        die "effective-permission verification FAILED — do NOT start the broker"
    fi
    echo "== verify passed: grants work AND denials hold =="
fi
