# Plan 13 (full update, 2026-10-14 ~04:00 UTC) — live deploy hardening

Companion docs: `docs/HANDOFF-2026-10-14-live-deploy.md` (night-of state),
`deploy/README.md` (runbook, corrected all night),
`docs/audits/pve92-alignment.md` (PVE 9.2 audit — started, unfinished).
This plan supersedes its earlier versions. The `openchamber/tomorrow-pilot`
branch was deleted after the demo night (content identical to master);
work continues fresh from `master`.

## Goal

Get one rehearsal match genuinely green on the real LAN: launch →
readiness → isolation gates → begin match → red run → flag verified →
teardown. Everything below is what the live PVE 9.2 host taught us and
what still stands between "deployed" and "ready".

## Where we actually are (verified live, 2026-10-14)

PROVEN WORKING end to end against real PVE 9.2.21 (`pve.internal`):

- broker mTLS control plane → broker → PVE token auth (after the 401/
  hyphen and path-adapter fixes below)
- VMID claim (`next_vmid`), full clone from 9005/9011, `set_config`
  (ipconfig0/net0/tags), NIC attach on SDN bridge `srrange` (SDN.Use),
  start, boot
- guest-agent host-key read (agent boot wait + cloud-init key
  regeneration wait + `root@hostname` comment stripped) and pinning;
  pinned keys published to `known_hosts.runner` AND `known_hosts.verifier`
- manual SSH from the control plane into both clones as `attacker` and as
  `root` with the pinned known_hosts (prints `ok`)
- dead-man latch lifecycle (armed/disarmed/latched/released, live twice)
- teardown destroys clones on end session

STILL FAILING — the readiness gate (`readiness_failed`, last seen
03:58 session `d2baa057…`):

- service checks (`sshd`/`nginx`/`mojang-web`) + telemetry enrollment
  returned exit 255 / `provision_failed`
- the sshd boot-race fix (`c952831`, retries provisioning ONLY on ssh
  exit 255 for `MANAGEMENT_READY_WAIT_S=90`) was pushed but its
  deployment on the control-plane VM is UNCONFIRMED — the last failure
  came 2 s after deploy, which means either the fix was not running or
  the failure was not the 255 dialect. First morning task is to know
  which.

## Morning procedure (fresh start, in order)

1. House-clean the night: on the control-plane VM, end session
   `d2baa057-7114-4165-bd05-5dd5352a6fda` (or restart `sr-api` if it
   wedges with `operation_in_progress`), then
   `sudo -u postgres psql -d sparring_range -c "delete from sessions where status in ('failed');" `
   is NOT allowed (append-only discipline) — leave failed rows; they're
   history. Just end anything still holding the range lease.
2. Confirm both VMs run current master and services were restarted:
   `sudo git -C /opt/sparring-range log --oneline -1` → must be ≥
   `c952831` on BOTH VMs; `sudo systemctl restart sr-api sr-brokerd`
   (each VM restarts its own service). Rule from tonight: BOTH VMs run
   code — pull and restart both.
3. Launch `mojang-web-01`. If readiness passes → isolation gates (§
   below) → demo flow. If it fails again, read the exact payload before
   touching anything:
   `sudo -u postgres psql -d sparring_range -c "select payload from events where session_id='<sid>' and action_type='readiness_failed' order by event_id desc limit 1;"`
   (column is `action_type`, not `event_type`).
4. Interpret the payload:
   - `exit 255` on web01 only, seconds after its boot → boot race again
     → confirm step 2 actually happened (the fix retries up to 90 s, so
     a 2-second failure means the fix was NOT running).
   - `confirm_failed / delivery_confirmed` stage → the shipper inside
     the clone never called back. Suspects, in order: (a) the API URL
     baked by `_provision_command` must be reachable FROM the range
     (`https://10.66.0.1/...`, not `10.10.10.132` — the range is
     isolated); (b) TLS: `https.crt` SAN is `10.10.10.132`, so a
     shipper validating certs against `10.66.0.1` fails — check what
     the shipper pins/skips and what `_provision_command` actually
     writes; (c) shipper unit state via
     `sudo ssh -i /var/lib/sparring-range/ssh/verifier_ed25519 -o UserKnownHostsFile=/var/lib/sparring-range/known_hosts.verifier root@10.66.0.9 'systemctl status sparring-shipper'`.
   - `unknown` service checks with rc≠255 → run the failing command
     manually through the verifier channel and read stderr.
5. Isolation gates from the attacker VM before any attack traffic:
   `ping -c1 -W2 1.1.1.1` FAIL · `getent hosts example.com` FAIL ·
   `ip route` only `10.66.0.0/24` · `ip -6 route` no default. Also
   `ip forward` off on the control-plane VM.

## Everything master gained tonight (all pushed, all with tests)

| Fix | Commits |
|---|---|
| `requests` for proxmoxer https backend | `0494ca4` |
| broker-server cert IP SAN | `71cb483` |
| PVE 9 privilege docs (`VM.Allocate`, `VM.GuestAgent.FileRead`, `VM.Config.Cloudinit/Options`, `Sys.Audit` on `/nodes/<n>`) | `e58187a` `c75e712` `4c840e7` `4f7bb4d` |
| env examples pin node/vmid-base/bridge/clone-mode; TOKEN_ID exact-match warning | `455a840` `30144ce` `b03a889` `12e22fa` |
| heartbeat disarms idle broker lease (dead-man lifecycle) | `6c42160` |
| absence dialect 1: 500 "no such file" | `e41c156` |
| absence dialect 2: 500 "Configuration file '…<vmid>.conf' does not exist" | `d45f8f7` |
| clone names carry `sr-` prefix (fixture enforces) | `b63e0af` |
| ROOT CAUSE: `_ProxmoxerPathAdapter` — leading-slash paths lost `/api2/json` (posixpath.join replaces on absolute segments); 158 fake tests stayed green while every real call 404'd | `db01932` |
| SDN.Use on `/sdn/zones/localnetwork/<bridge>` documented (clone 403 without it) | `cc68f69` |
| guest-agent first-boot wait; NO `/agent/status` endpoint exists (501) — retry the real read instead; cloud-init regeneration wait (empty key); `root@host` comment accepted and stripped from the pin | `fc04050` `a6fb74d` `1a14ba1` `f19ab36` |
| sshd boot race: provisioning retries ONLY ssh-255 within `MANAGEMENT_READY_WAIT_S=90` | `c952831` |
| runbook: nginx proxy timeouts; handoff doc; plan/handoff bookkeeping | `15b1539` `8698af2` others |

Suite at `c952831`: **176 passed, 206 deselected** (fast, infra-free).

## Ops lessons (burned into the runbook or belonging there)

- BOTH VMs run code: pull + restart `sr-api` AND `sr-brokerd` after any
  push. Tonight's "still broken" moments were each a half-update.
- Never paste key material between machines (the 23:47 runner+verifier
  private keys were corrupt from a bad paste — `error in libcrypto`);
  generate with `ssh-keygen` on the target VM.
- `https://` not `http://` (no port 80); `set +H` before pasting token
  headers; `<placeholder>` text gets pasted literally; `sudo` needed on
  640 cert files; PVE 9.2 `pveum` has no `node list` (`ls /etc/pve/nodes/`).
- The web UI keeps showing a failed session's stored error until a NEW
  launch; "end session" is refused while an operation is in progress
  (correct — wait for the bounded operation to finish).
- One operator key currently serves operator+bastion+runner+verifier
  (the templates bake `bastion_ed25519.pub` into root/defender/attacker).
  Works; split after the demo (below).

## Remaining improvements (post-demo, roughly prioritized)

- [ ] Finish the readiness gate live (morning procedure above) — the
      only thing between here and a demo-able range.
- [ ] Async launch: POST returns 202 immediately, deploy runs as a
      background operation, session page polls (kills the 504 class and
      the stale `operation_in_progress` on restart). nginx
      `proxy_read_timeout 900s` meanwhile (runbook documents it; the
      live VM still has the 60 s default).
- [ ] Session page surfaces the latest `readiness_failed`/refusal
      payload (it's in `events` already; the UI just doesn't show it —
      tonight cost 30 min/round-trip without it).
- [ ] Web UI: session list from library (failed sessions are URL-only);
      safety panel with latch state + release command; `rangectl
      sessions` for lease holder.
- [ ] Key separation: dedicated runner/verifier/bastion keypairs, all
      pubkeys baked into templates at build; `readyz` parse-checks each
      private key (`ssh-keygen -y`) and warns when its pubkey is not in
      the template bake list.
- [ ] Broker ledger settle from the aborted attempts: VMID 9100-era
      claims + `host-key-read-uncertain` obligations — verify via
      `python -m infra.broker.tools status`, settle via teardown/
      reconcile paths, never by hand-editing sqlite.
- [ ] Template finalize appends the operator pubkey twice (harmless;
      dedupe) and the images should bake the SEPARATED keys.
- [ ] `deploy/pve_broker_acl.sh`: idempotent pveum setup incl. the
      SRBrokerSdn line (replaces hand-pasted blocks).
- [ ] Full PVE 9.2 alignment audit — scope in HANDOFF §6; report file
      started at `docs/audits/pve92-alignment.md` (unfinished; the
      session that began it was stopped). Every finding tonight was an
      instance of the fake PVE agreeing with our assumptions — the
      audit's highest-value item is the real-proxmoxer-vs-HTTP-mock
      smoke and a fake that replays PVE's real error dialects
      (both already listed below and in HANDOFF §6).
- [ ] `FakePVEHttp` modes: per-guest 500 absence dialects, agent
      not-running/empty-key windows (partially done:
      `agent_not_ready_polls`, `empty_key_polls`), plus one integration
      smoke driving the REAL proxmoxer client against a local HTTP mock
      (the `/api2/json` prefix bug class must be impossible to
      reintroduce silently).
- [ ] Production settings validation (refuse dev-default node/vmid
      base/bridge/clone-mode under `SR_ENV=production`); compose
      rehearsal with production-shaped policy.
- [ ] DEMO-DAY.md one-pager: launch → isolation gates → begin match →
      red run → flag → teardown → latch release runbook, printable.
- [ ] Rotate the DB passwords and the broker token secret pasted into
      chat during the live night (operator action; nothing else leaked).

## Out of scope

Real competition multi-tenant hardening, scoring changes, new scenarios,
anything requiring the inference LXC or NAS. The existing inference LXC
stays outside the attack network.

## Acceptance criteria (this plan is done when all pass)

1. `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -ra -p no:cacheprovider` → 0 failed.
2. Launch `mojang-web-01` from the web UI reaches **ready** without manual DB/ledger surgery.
3. From the attacker clone: `ping -c1 -W2 1.1.1.1` fails, `getent hosts example.com` fails, `ip route` shows only `10.66.0.0/24`, `ip -6 route` has no default.
4. Begin match → start red → one objective verified → end session → `qm list` shows no `sr-*` VMs and `python -m infra.broker.tools status` shows no open obligations.
5. `journalctl -u sr-api` and `-u sr-brokerd` contain no unexplained ERROR after the full flow.
6. Both VMs at the same master commit, services restarted once after pull (documented in FINDINGS with the commit hash).

## Manual checks (operator)

- Confirm `pveum user permissions srbroker@pve` still lists exactly the
  SRBroker* roles (no drift from debugging).
- Confirm OPNsense rule 10.10.10.141→192.168.86.83:8006 is the ONLY
  broker→LAN path, and nothing on VLAN 66 ever reaches WAN (spot-check
  OPNsense live view during the isolation gates).
- Decide on rotating the pasted secrets (listed above) before teammates
  get accounts.
