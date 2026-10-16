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
APPLY=0 VERIFY=0 CHECK=0

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
        --check) CHECK=1; shift;;
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
# Split by operation class (audit A7): creation-time privileges
# (VM.Allocate for clone-newid + destroy, Datastore.* for images) live in
# Base; template-source Clone lives in Clone. Runtime power/config/guest
# privileges ride the SAME per-path grants (templates + enumerated window),
# never a bare /vms path.
# Per-VM runtime scope (audit A7): audit/allocate(clone-newid +
# destroy)/config/power/guest-agent — granted ONLY on approved per-VMID
# paths (templates + enumerated clone window). Datastore privileges are
# meaningless on VM paths, so they live in their own role on the named
# storage only.
BASE_PRIVS="VM.Audit,VM.Allocate,VM.Config.Network,VM.Config.Cloudinit,VM.Config.Options,VM.PowerMgmt,VM.GuestAgent.FileRead"
STORAGE_PRIVS="Datastore.Allocate,Datastore.AllocateSpace"

echo "== planned grants (dry-run unless --apply) =="
run pveum role add "${ROLE_BASE}Base" --privs "$BASE_PRIVS"
run pveum role add "${ROLE_BASE}Storage" --privs "$STORAGE_PRIVS"
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
# Templates carry Clone (source) plus a dedicated Audit-only grant:
# --verify reads template configuration through the token itself, but the
# full Base role would also hand token holders power/config/guest-file
# rights over the GOLDEN templates (mutate/delete the gold image). Scope
# precisely: Clone + Audit, nothing else, on template paths only.
run pveum role add "${ROLE_BASE}Template" --privs "VM.Clone,VM.Audit"
for t in "${TMPLS[@]}"; do
    # PVE ACL modification is ADDITIVE: earlier (broader) grants are never
    # replaced by narrower ones. Explicitly revoke any previously granted
    # Base role on template paths first, so a re-run that narrows scope
    # cannot leave the golden templates mutable/deletable. Revocation of
    # an absent grant is a loud no-op failure mode: tolerate ONLY the
    # "no such ACL" wording, nothing else.
    if [ "$APPLY" -eq 1 ]; then
        _revoke_out=$(pveum acl delete "/vms/${t}" --users "$USER_ID" \
            --roles "${ROLE_BASE}Base" 2>&1) || echo "$_revoke_out" | grep -qi \
            "no such\|does not exist\|no acl" \
            || die "revocation failed: /vms/${t} Base -> $_revoke_out"
    else
        printf '    %q ' pveum acl delete "/vms/${t}" --users "$USER_ID" \
            --roles "${ROLE_BASE}Base"; echo "  # revoke superseded broad grant"
    fi
    run pveum acl modify "/vms/${t}" \
        --users "$USER_ID" --roles "${ROLE_BASE}Template"
done
# ---------------------------------------------------------------- check ----
# PVE deletes per-VMID ACL entries WITH the destroyed VM (source-verified:
# destroy_vm checks VM.Allocate on the literal /vms/{vmid} path, which no
# pool grant can cover). Every teardown therefore eats the grants its
# clones used. --check diffs the live ACL table against the exact expected
# set and exits 1 listing what --apply would restore. Dry-run safe:
# reads `pveum acl list` only, changes nothing.
if [ "$CHECK" -eq 1 ]; then
    command -v python3 >/dev/null || die "--check needs python3 (JSON parse)"
    _expected="$(mktemp)"
    {
        echo "/nodes/${NODE} ${USER_ID} ${ROLE_BASE}Audit"
        echo "/sdn/zones/localnetwork/${BRIDGE} ${USER_ID} ${ROLE_BASE}Sdn"
        for t in "${TMPLS[@]}"; do
            echo "/vms/${t} ${USER_ID} ${ROLE_BASE}Template"
        done
        for _v in $(seq "$VMID_LO" "$VMID_HI"); do
            echo "/vms/${_v} ${USER_ID} ${ROLE_BASE}Base"
        done
        echo "/storage/${STORAGE} ${USER_ID} ${ROLE_BASE}Storage"
    } > "$_expected"
    _live_file="$(mktemp)"
    pveum acl list --output-format json > "$_live_file" \
        || die "could not read the live ACL table"
    python3 - "$_expected" "$_live_file" <<'PYEOF'
import json, sys
expected = [l.split() for l in open(sys.argv[1]) if l.strip()]
live = json.load(open(sys.argv[2]))
have = {(e.get("path"), e.get("ugid"), e.get("roleid")) for e in live}
missing = [w for w in expected if tuple(w) not in have]
for path, user, role in missing:
    print(f"MISSING {path} {user} {role}")
print(f"acl-check: {len(expected) - len(missing)}/{len(expected)} exact-path "
      f"grants present")
sys.exit(1 if missing else 0)
PYEOF
    _rc=$?
    rm -f "$_expected" "$_live_file"
    if [ "$_rc" -ne 0 ]; then
        echo "(grants missing — re-run with --apply to restore exactly these)"
    fi
    exit "$_rc"
fi
# Clone-window runtime scope (PVE 9.2 audit A7): PVE has no per-VMID-RANGE
# path and destroy has NO pool alternative, so the bounded window is
# enumerated as individual per-VMID grants — every approved clone identity
# gets the runtime role, and NOTHING else does. VM.Allocate on a window
# path covers both clone-newid creation and destroy (Qemu.pm permission
# blocks); the broker policy independently enforces the same window with
# fail-closed typed operations (defense in depth, tested by the authority
# gate). A bare `/vms` grant is NEVER issued: token theft cannot reach
# unrelated VMs through PVE itself.
[ "$((VMID_HI - VMID_LO + 1))" -le 512 ] \
    || die "VMID window larger than 512 — enumerate explicitly or narrow it"
for _v in $(seq "$VMID_LO" "$VMID_HI"); do
    run pveum acl modify "/vms/${_v}" \
        --users "$USER_ID" --roles "${ROLE_BASE}Base"
done
run pveum acl modify "/storage/${STORAGE}" \
    --users "$USER_ID" --roles "${ROLE_BASE}Storage"

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
    # Authenticated-metadata endpoints readable by any valid token (like
    # /version): realm/ACL readback is permission-filtered, not a grant.
    # The load-bearing boundaries are the foreign-VM and ACL-write denials.
    probe GET "/access/domains" allow
    probe GET "/access/acl" allow
    # Privilege escalation must be denied: ACL writes use PUT (POST answers
    # 501 Method not implemented, which proves nothing about permissions).
    probe PUT "/access/acl" deny "path=/&roles=PVEAdmin&users=${USER_ID}"
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
