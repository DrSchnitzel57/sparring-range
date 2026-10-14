# PVE 9.2 alignment audit (plan 13, handoff §6)

Date: 2026-10-14. Auditor: overnight audit session (`openchamber/tomorrow-pilot`
at `e370e95`). Live host: **read-only** — no Proxmox mutations were made or
needed: every fact below was verified against the **actual PVE 9.2 source**
(`pve-manager 9.2.21`, `qemu-server 9.2.11`, `libpve-common-perl 9.2.3`,
`libpve-access-control 9.1.2`, `libpve-storage-perl 9.1.13`,
`libpve-http-server-perl 6.0.5` — .deb packages extracted under
`/tmp/opencode/pve/pkgs/`, same versions the live node runs), against the
installed `proxmoxer` 2.3.x sources, and against the live captures recorded in
plan 13 / the handoff. Where a fact still needs live confirmation it is marked
**needs operator probe** with the exact command.

Line numbers refer to `e370e95`.

## Findings table

| # | File:line | Current code | PVE 9.2 reality (source) | Severity | Fix |
|---|---|---|---|---|---|
| A1 | `infra/proxmox_client.py:83-89` | any 500 containing `no such file` → `PveNotFound` (confirmed absence) | That string is emitted ONLY by the API router's static-file fallback (`PVE::APIServer::AnyEvent:1265` `die "no such file '$path'"` → 500) when the request matches **no API route** — i.e. it is the signature of a URL-prefix bug (the `db01932` class), never of a free VMID. The genuine per-VMID absence wording is 500 `Configuration file 'nodes/<node>/qemu-server/<vmid>.conf' does not exist` (`PVE::QemuConfig->load_config` via cfs), already handled by `_PVE_ABSENT_CONFIG_RE` | **HIGH** | Remove the `no such file` → absence branch; such a 500 stays `PveUnavailable` with a routing-bug hint. A URL bug must fail loud, never masquerade as "VM absent" (which would hand out occupied VMIDs and report `already-absent` teardowns while VMs run) |
| A2 | `infra/proxmox_client.py:351-358` | `_KEY_NOT_READY_SIGNATURES` retries on `no such file` / `does not exist` | Both strings are unreachable as "key not ready": via `classify_pve_error` they map to `PveNotFound` (raised before matching), and after A1 they map to routing-bug/absence — retrying them for 120 s hides a systematic bug behind a slow failure | MEDIUM | Drop both signatures; retry only the agent/key dialects (`guest agent is not running`, key-not-regenerated wording) |
| A3 | `infra/proxmox_client.py:169-170` | `version()` → `self.api.version()` | proxmoxer `api.version` is a resource object; calling it with no verb returns the **resource**, not data (`proxmoxer/core.py __call__` returns `self` for no id). Real PVE is never queried; the fake returned a dict so tests stayed green | LOW | `self.api.get("/version")` (GET `/version` is `user => 'all'`, `PVE::API2:86-89`); fake serves `version` on GET; smoke test asserts the real client issues `GET …/api2/json/version` |
| A4 | `infra/proxmox_client.py:207-219` | `next_vmid()` docstring: "Ask PVE for a free VMID (allocator handles concurrency)" | `GET /cluster/nextid?vmid=N` is an **assertion**: returns N if free, else **400 `VM N already exists`** (`PVE::API2::Cluster:1013-1041`). Without `vmid` it scans from the datacenter `next-id.lower` (100), never from `start`. The "next free ≥ start" behaviour came only from the scan fallback | MEDIUM | Correct the docstring; keep assert-then-scan but make the fallback explicit; regression test replays the real 400. (Broker's own `next_vmid` loop uses per-candidate `status/current` probes and is unaffected) |
| A5 | `infra/proxmox_client.py:161` | `token_id.partition("!")` — no validation | A `PROXMOX_TOKEN_ID` without `!` (or with a wrong realm user) yields a malformed `PVEAPIToken` header → 401 "Authentication failed!" — the exact live incident of 2026-10-14 | LOW | Fail fast at construction with a clear message when the id is not `user@realm!tokenname` |
| A6 | `srplatform/scenario_engine/orchestrator.py:680-691` | resume path: `state == "created"` → skip clone AND skip host-key pin | If the bounded agent/key wait eventually fails (slow first boot > 120 s), the deploy fails with the resource already committed `created`; every retry skips `_pin_host_key`, so the range goes `ready` with **no pinned host key** and SSH clients (StrictHostKeyChecking, no TOFU) fail later | MEDIUM | Resume re-pins when `state == "created"` but `host_key_ref` is missing (idempotent; broker still enforces generation + same-generation key stability) |
| A7 | privilege model (runbook §2, handoff §1 roles) | roles documented piecemeal; `SRBrokerBase` ACL **path** never pinned down; `SDN.Use` added live (`d7b8422`) | Source-derived minimal set: `VM.Clone` on `/vms/<tpl>`; `VM.Allocate` on `/vms/<newid>` (clone) **and on `/vms/<vmid>` for destroy** (`Qemu.pm` clone/destroy permission blocks — destroy has NO pool alternative); `VM.Audit`/`VM.PowerMgmt`/`VM.Config.Network`/`VM.Config.Cloudinit`/`VM.Config.Options`/`VM.GuestAgent.FileRead` on the clone VMIDs; `Datastore.AllocateSpace` on `/storage/<stg>`; `Sys.Audit` on `/nodes/<node>` (also required to read task status of foreign-owned tasks, `Tasks.pm:457-460`); `SDN.Use` on `/sdn/zones/localnetwork/<bridge>` — tagged NICs check `/sdn/zones/localnetwork/<bridge>/<tag>` and are covered by parent→child ACL propagation (`PVE::GuestHelpers::check_vnet_access`) | MEDIUM | `deploy/pve_broker_acl.sh` (idempotent, `--dry-run`, `--verify` via `pveum user token permissions`) pins roles + per-path grants deterministically |
| A8 | clone + template bridge | `IMPORT-STEPS` creates templates with `--net0 virtio,bridge=<BRIDGE>` (placeholder) | Clone runs `check_bridge_access` on the **template's** net0 (`Qemu.pm:4525`): if the template's bridge differs from the range bridge, `SDN.Use` is needed on THAT bridge object too, or the clone task dies 403 | MEDIUM | IMPORT-STEPS + README: build templates on the range bridge (or grant `SDN.Use` for the template bridge as well) |
| A9 | `infra/proxmox_client.py:578` (fake) | clone onto used VMID → 400 `VMID N in use` | Real PVE: plain `die "unable to create VM $newid: config file already exists"` → **500** (`Qemu.pm` clone code); unknown params → 400 (matches); missing `newid` → 400 (matches) | LOW | Fake `pve_no_such_file=True` mode replays the real 500 dialects (absence + clone collision); 404 mode kept |
| A10 | fake per-guest 404s (`:541,:551`) | missing VMID → `PveNotFound` (404) | Real PVE answers per-guest paths for a free VMID with **500 config-file dialect**, not 404 (live-confirmed 2026-10-14; `load_config` via cfs). 404 is essentially never produced for these paths | MEDIUM | Same `pve_no_such_file=True` mode: per-guest GETs answer the real 500 wording; deploy path treats it as absence (test) |
| A11 | query strings embedded in paths (`nextid?vmid=`, `agent/file-read?file=`) | works because `url_join` keeps the `?…` segment and requests splits it | Correct for proxmoxer 2.3.x, but untested against the REAL client until now — this is the same bug class as `db01932` | LOW | Real-proxmoxer HTTP-mock smoke test asserts full URLs (`/api2/json` prefix + query) and form bodies end to end |
| A12 | `deploy/env.broker.example:17-18` | privilege comment lists only `Datastore.AllocateSpace, VM.Audit, VM.Clone, VM.Config.Network, VM.PowerMgmt` | Missing `VM.Allocate`, `VM.Config.Cloudinit`, `VM.Config.Options`, `VM.GuestAgent.FileRead`, `Datastore.Allocate`, `Sys.Audit`, `SDN.Use` — an operator following the comment gets a token that fails at clone | MEDIUM | Comment updated to the A7 set (pointer to `pve_broker_acl.sh`) |
| A13 | `deploy/env.control-plane.example:32` | "Exact PVE node name (`pveum node list`)" | PVE 9.2 `pveum` has **no** `node` command (`pveum.pm $cmddef`); the handoff already recorded this live | LOW | Use `ls /etc/pve/nodes/` or `pvesh get /nodes` |
| A14 | `deploy/README.md` §2 privilege paragraph | prose list, correct after `d7b8422`, but no per-path mapping and no way to apply it reproducibly | — | LOW | README points at `deploy/pve_broker_acl.sh` which encodes the mapping |

## Verified-correct (no change)

- **Clone call shape** (`Qemu.pm:4360-4450`): params `newid` (required), `name`,
  `description`, `full`, `storage`, `target`, `format`, `snapname`, `pool`,
  `bwlimit`; `additionalProperties => 0` (unknown params → 400 — the fake
  models this). `full=1` + `storage` allowed; `storage`/`format` rejected for
  linked clones (we only send `storage` when full). `full` defaults to
  `!is_template` — we always pass it explicitly.
- **Config set**: POST `/config` exists (`update_vm_async`, recommended);
  `net0` → `VM.Config.Network`; `ipconfig0` → `VM.Config.Cloudinit`;
  `name` → `VM.Config.Options` (`$generaloptions`); `tags` →
  `VM.Config.Options` via `assert_tag_permissions` (plus freeform-tag rule —
  default datacenter tag-style allows freeform, so `srsess-<32hex>` passes).
- **Status/start/stop/shutdown**: `VM.PowerMgmt`; `status/current`:
  `VM.Audit`; responses are UPID strings; task status fields `status ∈
  {running, stopped}`, `exitstatus == "OK"` on success (`Tasks.pm:475-490`) —
  matches `wait_for_task`.
- **Guest agent file-read**: GET `agent/file-read?file=…`, response
  `{content, truncated?}`, privilege `VM.GuestAgent.FileRead` (or
  `Unrestricted`) — matches `read_guest_file`. Agent-not-running wording
  `QEMU guest agent is not running` (`QemuServer/Agent.pm:109-113`) — matches
  the retry signature. There is deliberately **no** `agent/status` endpoint
  (501 live); `agent/info` exists but needs `VM.GuestAgent.Audit` — not used,
  keeping the privilege set minimal.
- **Privilege IDs** all exist in 9.2 (`AccessControl.pm $privgroups`):
  `VM.Allocate` (replaces PVE 8 `VM.Create`), `VM.GuestAgent.*` family,
  `Sys.Audit`, `SDN.Use`, `Datastore.Allocate/AllocateSpace`.
- **pveum syntax** (`pveum.pm $cmddef`): `user add`, `user token add --privsep`,
  `role add --privs`, `acl modify`, `acl list`, `role list`,
  `user token permissions <user> <id>` (effective-permission check used by
  `--verify`).
- **ZFS `local-zfs`**: full clone is the supported mode (ZFS snapshot+clone;
  the clone is independent of the template afterwards); linked clones are
  policy-forbidden and nothing in the code path creates one (broker passes
  `full` from policy; `check_clone_mode` refuses mismatch). `discard=on` in
  IMPORT-STEPS is correct for zvol+virtio-scsi.
- **Cloud-Init on 9.2**: `ide2:<storage>:cloudinit` drive still valid;
  `ciupgrade` exists (drive-format upgrade only — not needed); `ipconfig0`
  parsing unchanged; per-clone identity regeneration (scrubbed template +
  cloud-init first-boot key regeneration) matches the template build contract
  and the live empty-key finding.
- **Token auth header** (`proxmoxer/backends/https.py:134-150`):
  `PVEAPIToken=user!name=secret` — correct; `verify_ssl` CA path honoured;
  `timeout=30` propagates to requests.
- **`/cluster/nextid` & `/cluster/resources` permissions**: `user => 'all'`
  (resources results are permission-filtered — noted in A4's fallback caveat).
- **401/403 taxonomy**: 401 `Authentication failed!` (bad token/user), 403
  `Permission check failed (<path>, <PRIV>)` — both live-captured, both map to
  `PveUnavailable` (uncertain), which is correct: neither is absence.

## Needs operator probe (read-only, exact commands)

1. Confirm the live node answers free-VMID probes with the config dialect and
   never with `no such file` (validates A1 on the host):
   `curl -s --cacert /etc/sparring-range/tls/pve-ca.crt -H "Authorization: PVEAPIToken=srbroker@pve!range=$SECRET" https://pve.internal:8006/api2/json/nodes/pve/qemu/999999/status/current`
2. Confirm effective token permissions after `pve_broker_acl.sh`:
   `pveum user token permissions srbroker@pve range`
3. Confirm the template net0 bridge equals the range bridge (A8):
   `qm config 9005 | grep ^net0; qm config 9011 | grep ^net0`

## Manual checks (operator)

- Run `deploy/pve_broker_acl.sh --dry-run` then for real on the node; then
  `deploy/pve_broker_acl.sh --verify` and compare with the ACLs hand-created
  on 2026-10-13 (the script must be a superset-equivalent).
- After the next Launch: `journalctl -u sr-brokerd` shows no `no such file`
  500s (they would now be loud `PveUnavailable` routing-bug errors — A1).
