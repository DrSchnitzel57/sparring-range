# Handoff — live deployment session, night of 2026-10-13/14

Purpose: everything needed to (a) finish getting the first real Launch
green, (b) troubleshoot later, (c) run the requested PVE 9.2 alignment
audit. Written at ~01:50 UTC 2026-10-14 by the deploying agent.
Companion: `.openchamber/plans/13-live-deploy-hardening.md` (running
fix list) and `deploy/README.md` (runbook, corrected tonight).

## 1. Live infrastructure (operator-owned; agent never holds these creds)

| Piece | Value |
|---|---|
| PVE node | name `pve`, cert CN `pve.internal`, mgmt IP `192.168.86.83` (net `192.168.86.0/24`, gw `.1`), PVE 9.2.x, storage `local-zfs` |
| Lab net | VMs on VLAN 10 (`10.10.10.0/24`, gw `.1` = OPNsense); OPNsense blocks private↔private between VLANs by policy |
| Control-plane VM | `201`, Ubuntu 24.04, `control-plane@control-plane`, mgmt `10.10.10.132` (net0 tag=10), range NIC net1 `10.66.0.1/24` on `srrange` **tag=66 firewall=1** |
| Broker VM | `202`, `broker@broker`, `10.10.10.141`; user `srbroker`; runs `sr-brokerd` (mTLS :8443) |
| Range bridge | `srrange` on PVE host, `bridge-vlan-aware yes`, `bridge-vids 66`, no ports/gateway — host-local only |
| Templates | 9005 `tpl-attacker`, 9011 `tpl-mojang-web-local` (operator SSH key baked in; shas in FINDINGS) |
| PVE identity | user `srbroker@pve` (random pwd, never used), token `range`, privilege separation OFF |
| PVE roles | SRBrokerBase (VM.Audit/PowerMgmt/Config.Network/Config.Cloudinit/Config.Options/GuestAgent.FileRead/Allocate), SRBrokerClone (Audit+Clone on /vms/9005,/vms/9011), SRBrokerStore (Datastore.Allocate+AllocateSpace on /storage/local-zfs), SRBrokerNode (Sys.Audit on /nodes/pve) |
| Services | `sr-api` (uvicorn 127.0.0.1:8000), `sr-bastion` (:2222), `sr-web` (Next standalone :3000), nginx TLS :443 (`/etc/sparring-range/tls/https.crt`, IP SAN 10.10.10.132), `sr-brokerd` |
| Code | both VMs: `/opt/sparring-range` (public GitHub master), venv `.venv`; source runs from checkout (not wheel) |
| DB | PostgreSQL `sparring_range`, roles `sr_owner`/`sr_app`; env `/etc/sparring-range/control-plane.env` (root:srrange 640) |
| TLS | CA + api-client on control plane (dir 750 root:srrange); broker-server + pve-ca (cluster CA `/etc/pve/pve-root-ca.pem`) on broker; broker-server cert has **IP SAN** 10.10.10.141 |

## 2. Current blocker (exactly where we stopped)

After the path-adapter fix (`db01932`), the broker's PVE calls now route
correctly but the 01:45 Launch failed with:

```
broker refused next_vmid (HTTP 500): broker internal error:
PVE status 401: 401 Unauthorized: Authentication failed!
```

Yet the SAME token+secret from `broker.env` works via curl on the broker
VM (GET `/api2/json/nodes/pve/qemu/9005/config` → full JSON). Leading
hypothesis: **the running `sr-brokerd` process holds a stale
`PROXMOX_TOKEN_SECRET`** (broker.env was edited/restarted at 01:25; the
token secret may have been re-entered afterwards without another
restart, or a line edit changed whitespace).

Next steps, in order (all operator-driven):
1. `sudo systemctl restart sr-brokerd` on the broker VM (re-reads env).
2. If still 401: compare `sudo grep TOKEN /etc/sparring-range/broker.env`
   against `pveum user token list srbroker@pve` on the node; if in doubt,
   delete + re-add token `range`, paste new secret into broker.env, restart.
3. End the newest failed session (see §5 psql) to free the range.
4. Launch `mojang-web-01` in the web UI; expect clones 9101/9102
   (`sr-mojang-web-01-attacker-<sid>` / `...-web-...`), then boot.
5. FIRST-BOOT gates before any attack traffic (deploy/README §7):
   from the attacker VM: `ping -c1 1.1.1.1` FAIL, `getent hosts
   example.com` FAIL, `ip -6 route` no default, `ip route` only
   10.66.0.0/24. Also verify `ip forward` off on control-plane VM.
6. Then the demo flow: begin match → start red → flag capture → teardown.

## 3. Ledger/DB cleanup owed after the first green deploy

- Broker ledger: VMID 9100 has a `reserved` claim + likely a
  `clone-outcome-unknown` obligation from the aborted attempts (PVE
  never created it — verify `qm config 9100` absent, then settle via
  `python -m infra.broker.tools status` / teardown path; do NOT hand-edit
  the sqlite ledger).
- DB `sessions`: several `failed`/`preparing` rows; `range_lease` rows
  all released. Harmless; clean up post-demo.
- `readyz` runner `ok:false` (known_hosts.runner missing) is EXPECTED
  until the first successful deploy pins keys.

## 4. Everything learned tonight (all fixed in master; details plan 13)

1. `requests` missing for proxmoxer https backend (`0494ca4`).
2. broker-server cert needs iPAddress SAN when dialed by IP (`71cb483`).
3. PVE 9 privilege renames: `VM.Allocate` (was VM.Create),
   `VM.GuestAgent.FileRead` (was VM.AgentFileRead) (`e58187a`, `c75e712`).
4. Agent file-read is an ACL privilege, not a `qm create` flag (`e58187a`).
5. `set_config` needs `VM.Config.Cloudinit` (ipconfig0) +
   `VM.Config.Options` (tags) (`4c840e7`).
6. Token needs `Sys.Audit` on `/nodes/<node>` or PVE hides the whole
   node subtree with "no such file" (`4f7bb4d`).
7. Dev defaults in settings (node `r740`, vmid base 210, bridge vmbr1,
   clone mode linked) must be overridden per deployment; example env now
   pins `PROXMOX_NODE/DEPLOY_VMID_BASE/RANGE_BRIDGE/DEPLOY_CLONE_MODE`
   (`455a840`, `30144ce`, `b03a889`).
8. Dead-man switch lifecycle: armed lease was never disarmed → broker
   re-latched after every session; heartbeat now disarms idle leases
   (`6c42160`). Latch release is broker-local ONLY:
   `python -m infra.broker.tools release --operator <name> --note ...`
   (source env first: `sudo bash -c 'set -o allexport; source
   /etc/sparring-range/broker.env; set +o allexport; ...'`).
9. PVE answers per-guest paths for nonexistent VMIDs with 500 "no such
   file" (not 404) — classified as absence (`e41c156`).
10. Clone names must carry the policy `sr-` prefix; fixture now enforces
    (`b63e0af`).
11. **ROOT CAUSE of the clone wall**: proxmoxer `url_join` uses
    posixpath.join — a leading-slash path REPLACES the `/api2/json`
    base, so every real PVE call 404'd as "no such file" while all fake
    tests stayed green. Fixed with `_ProxmoxerPathAdapter` (`db01932`).
12. Ops UX gaps hit tonight: no session list in web UI (failed sessions
    URL-only), no latch UI, `-s` curl hid errors, PVE 9.2 `pveum` has no
    `node list` (use `ls /etc/pve/nodes/`), bash history expansion eats
    `!` in token headers (`set +H`), `sudo` needed for 640 cert files.

## 5. Quick reference

```bash
# control-plane logs / DB
journalctl -u sr-api -n 40 --no-pager
sudo -u postgres psql -d sparring_range -c "select session_id,status,started_at from sessions order by started_at desc limit 3;"
sudo -u postgres psql -d sparring_range -c "select * from range_lease;"
# broker
journalctl -u sr-brokerd -n 40 --no-pager
cd /opt/sparring-range && sudo bash -c 'set -o allexport; source /etc/sparring-range/broker.env; set +o allexport; .venv/bin/python -m infra.broker.tools status'
# token-eyes probe (broker VM; set +H first!)
set +H; SECRET=*** sudo grep PROXMOX_TOKEN_SECRET /etc/sparring-range/broker.env | cut -d= -f2)
curl -s --cacert /etc/sparring-range/tls/pve-ca.crt -H "Authorization: PVEAPIToken=srbroker@pve!range=$SECRET" https://pve.internal:8006/api2/json/nodes/pve/qemu/9005/config
# mTLS health (control-plane VM)
sudo curl -s --cacert /etc/sparring-range/tls/ca.crt --cert /etc/sparring-range/tls/api-client.crt --key /etc/sparring-range/tls/api-client.key https://10.10.10.141:8443/v1/health
# end a stuck session: open https://10.10.10.132/session/<id> → red "end session"
# fast suite (dev box): env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -ra -p no:cacheprovider
```

## 6. REQUESTED: full PVE 9.2 alignment audit (new work item)

Goal: systematically verify EVERY Proxmox interaction in the codebase
against PVE 9.2.x reality (host: `pve.internal`, single node), not just
the paths that broke tonight. Deliverable: audit report + fixes with
regression tests + updated runbook. Scope:

1. **API surface**: every path/verb/param in `infra/proxmox_client.py`,
   `infra/broker/*` vs the PVE 9.2 API viewer
   (`https://pve.internal:8006/doc.html` / pve-docs). Check: clone
   params (`newid`/`full`/`storage`), config set (`ipconfig0`, `net0`,
   `tags`), task status/upid format, `/cluster/nextid`, resource list
   fields, guest-agent endpoints (`agent/file-read` path + response
   shape), start/stop/destroy semantics, `template` flag handling.
2. **Error taxonomy**: enumerate real PVE 9.2 responses (400/401/403/500
   bodies, "no such file", "Permission denied", task exit statuses) and
   confirm `classify_pve_error` maps each correctly; extend the fake to
   replay them.
3. **Privilege model**: re-derive the minimal ACL set from PVE 9.2
   source/docs (incl. node Sys.Audit, Cloudinit/Options split,
   GuestAgent.* family, Allocate vs removed Create); encode as
   `deploy/pve_broker_acl.sh` (idempotent) and test against a throwaway
   token.
4. **proxmoxer 2.3.x**: audit every call for the URL-joining class of
   bug (path forms, kwargs vs params, pagination, timeouts); add the
   real-client-vs-HTTP-mock smoke from plan 13.
5. **Cloud-Init on PVE 9.2**: template cloudinit drive settings,
   per-clone identity regeneration (host keys, machine-id), ipconfig0
   parsing, agent readiness detection timing.
6. **ZFS/storage**: full-clone behavior on `local-zfs`, `discard=on`,
   capacity errors, snapshot/base-clone interactions (linked clones are
   policy-forbidden — verify nothing creates one).
7. **Docs sweep**: deploy/README.md + IMPORT-STEPS + env examples
   re-checked line-by-line against PVE 9.2 CLI (`qm`, `pveum`, `pvesh`
   syntax changes from 8.x).

Constraints for the auditor: read-only against the live host (GET
probes only; no VM/ACL mutations without operator), never weaken a
validator to make a test pass, every finding gets a regression test,
fast suite must stay green.

## 7. Non-negotiables (unchanged)

Broker is the sole PVE authority; policy fail-closed; no TOFU host keys;
no `insecure` TLS overrides; range never routes to LAN/WAN (control-plane
VM is not a router); latch release stays broker-local; append-only
events; operator drives all Proxmox mutations.
