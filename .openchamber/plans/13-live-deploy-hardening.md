# 13 — Live-deploy hardening (running plan)

Status: RUNNING — append findings as they occur; tick items when fixed.

## Goal
Close the quality gaps the first real Proxmox deployment (2026-10-13/14)
exposed: dev defaults that fail closed at the broker, test fixtures that
don't match production policy, and operator-facing UX that made every
refusal a journal-dig.

## Context
The pilot deployed end-to-end on real hardware caught nine issues the
compose rehearsal could not, because the rehearsal used a permissive
policy fixture and dev-value defaults. Each item below records what the
fence caught and what layer should have caught it earlier.

## Done during the live deploy (verified fixes, in master)
- [x] `requests` added — proxmoxer https backend needs it at runtime (`0494ca4`).
- [x] `bootstrap_tls.sh`: iPAddress SAN when `BROKER_HOST` is an address (`71cb483`).
- [x] Runbook PVE 9 privileges: `VM.Allocate`, `VM.GuestAgent.FileRead`,
      `VM.Config.Cloudinit`, `VM.Config.Options` (`e58187a`, `c75e712`, `4c840e7`).
- [x] IMPORT-STEPS: agent file-read is an ACL privilege, not a VM flag (`e58187a`).
- [x] Control-plane env example pins `PROXMOX_NODE`, `DEPLOY_VMID_BASE`,
      `RANGE_BRIDGE`, `DEPLOY_CLONE_MODE` (`455a840`, `30144ce`, `b03a889`).
- [x] Heartbeat disarms idle broker lease — dead-man lifecycle fix + tests (`6c42160`).
- [x] PVE 500 "no such file" classified as confirmed absence + tests (`e41c156`).
- [x] Clone names carry `sr-` prefix; fixture policy enforces it (`b63e0af`).
- [x] Broker token needs `Sys.Audit` on `/nodes/<node>` — documented (`4f7bb4d`).
- [x] **ROOT CAUSE**: proxmoxer path adapter — leading-slash paths lost the
      `/api2/json` prefix (posixpath.join replaces on absolute segments), so
      every real PVE call answered "no such file" while 158 fake-boundary
      tests stayed green (`db01932`).
- [x] Dead-man switch demonstrated live: lease expiry latched, honest
      release with empty ledger (audit trail #1–#5).
- [x] 401 wall resolved: running `sr-brokerd` held a stale/placeholder
      `PROXMOX_TOKEN_ID` (example shipped `sr-broker@pve` with a stray
      hyphen); live probe proved file+client+token healthy after restart
      (`version()` 200 on PVE 9.2.21). Example placeholder defused (`12e22fa`).
- [x] PVE's SECOND absence dialect — 500 "Configuration file
      'nodes/<n>/qemu-server/<vmid>.conf' does not exist" — classified as
      confirmed absence + tests (`d45f8f7`); this unblocked `next_vmid`
      against the real host.
- [x] PVE 9 SDN bridge check: cloning a NIC onto a bridge requires
      `SDN.Use` on `/sdn/zones/localnetwork/<bridge>` — clone task starts
      then dies 403 without it (live find 2026-10-14; runbook documents
      `SRBrokerSdn` role + ACL line).
- [x] Guest-agent first-boot race: after `start_and_wait` returns, PVE
      answers agent reads with 500 "QEMU guest agent is not running" for
      tens of seconds — the host-key pin failed there on the FIRST real
      clone. And there is NO `/agent/status` endpoint (a probe for it
      answered 501 "Not Implemented" — my invented path, caught live).
      `read_guest_file_when_ready` now retries the REAL allowlisted read,
      bounded (`PROXMOX_AGENT_READY_TIMEOUT_S=120`), only that signature,
      timeout stays uncertain; client gives `read_host_key` a 150 s
      per-op timeout. 6 tests.

## Remaining improvements
- [ ] Launch is a synchronous HTTP request held for the whole deploy
      (minutes with agent waits) — nginx 504s the browser at 60s while the
      deploy keeps running. Run deploys as a background task and let the
      session page poll status; until then the runbook pins nginx
      `proxy_read_timeout 900s`.
- [ ] Production settings validation: refuse to start `sr-api` with
      dev-default `proxmox_node=r740`, `deploy_vmid_base=210`,
      `range_bridge=vmbr1`, `deploy_clone_mode=linked` when `SR_ENV=production`.
- [ ] Compose rehearsal: generate the policy with production shape
      (`name_prefix sr-`, `clone_mode full`, real bridge name) and run the
      production config validator, so fixtures can't diverge again.
- [ ] `FakePVEHttp`: option to answer per-guest paths with PVE's real
      500 "no such file" quirk (keep 404 mode too).
- [ ] Add one integration smoke that drives the REAL proxmoxer client
      against a local HTTP mock, so URL joining (the `/api2/json` prefix
      bug class) is covered end to end, not just the fake boundary.
- [ ] Web UI: session list reachable from library (active + failed);
      failed sessions currently URL-only.
- [ ] Web UI: session page surfaces the latest deploy refusal reason
      (broker 403/423 text) from events, not just journalctl.
- [ ] Web UI: safety panel — latch state + reason; for a broker latch,
      print the exact broker-local release command (operator-only host).
- [ ] `deploy/pve_broker_acl.sh`: idempotent `pveum` role/ACL/token setup
      for PVE 9 (replaces tonight's hand-pasted blocks).
- [ ] Provisioning: create empty `known_hosts.runner|bastion|verifier`
      files so `readyz` is clean before first deploy.
- [ ] `rangectl sessions` (list + lease holder) for operators without DB access.
- [ ] DEMO-DAY.md one-pager: launch → isolation gate checks → teardown →
    latch-release runbook, printable.
- [ ] **Full PVE 9.2 alignment audit** — scope in
      `docs/HANDOFF-2026-10-14-live-deploy.md` §6 (API surface, error
      taxonomy, privilege model, proxmoxer call audit, cloud-init,
      zfs/storage, docs sweep). Read-only against the live host.
- [ ] Settle broker ledger residue from the aborted attempts: VMID 9100
      reserved claim + possible `clone-outcome-unknown` obligation
      (verify absent in PVE, settle via tools/teardown, never by
      hand-editing the ledger).
- [ ] Live carry-over: first green Launch still pending — after pulling
      `d45f8f7` on the broker VM, next attempt reaches the real clone
      path (new-error territory: storage/ACL/boot, not auth).

## Out of scope
Re-architecting the lease/latch model; relaxing any policy check;
UI framework changes beyond linking existing data.

## Acceptance criteria
1. `pytest -q` fast suite green including new validator/fixture tests.
2. `SR_ENV=production` with any dev default node/vmid/bridge/clone-mode
   makes `sr-api` refuse startup with a message naming the variable.
3. Compose rehearsal policy contains `"name_prefix": "sr-"` and
   `"clone_mode": "full"` and still passes.
4. `FakePVEHttp(pve_no_such_file=True)` returns PVE-shaped 500s and the
   deploy path treats them as absence (test).
5. Library page links every non-complete session for the user.
6. Session page shows the last refusal reason within 5s of the event.
7. `bash deploy/pve_broker_acl.sh --help` documents roles/ACLs and is
   idempotent (run twice → same `pveum acl list`).
8. Fresh provision → `readyz` has no host-key-file complaints.

## Manual checks (operator)
- Run `pve_broker_acl.sh` against a disposable PVE test host.
- Browser walkthrough of session list with a failed deploy.
