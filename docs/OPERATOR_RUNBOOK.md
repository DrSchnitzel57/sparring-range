# Operator Runbook

Everything here reflects the code as shipped. Steps marked **[LIVE GATE]**
require Drew's R740/model/range VMs and remain unaccepted until executed —
the harness cannot honestly close them.

## 1. One-time setup (control plane host)

1. `.env` from `.env.example` (all variables documented there). `SR_ENV=production`
   refuses to start with placeholder secrets.
2. Postgres 16+: create roles/db per §Database below, then
   `rangectl db migrate` (runs Alembic as `POSTGRES_URL_OWNER` — the ONE
   sanctioned non-HTTP operation; app role has no DDL and cannot
   UPDATE/DELETE/TRUNCATE `events` — trigger + grants).
3. Bootstrap the operator (works only while NO account has a password):
   `curl -X POST $API/auth/bootstrap -d '{"username":"drew","password":"<10+ chars>"}'`
   Later accounts: `POST /users` (operator token) — members get real
   passwords; username knowledge is never authentication.
4. Mint long-lived capabilities (shown ONCE, store in your secret store):
   - Bastion: `POST /admin/service_tokens {"scope":"bastion"}` → set as
     `SR_BASTION_TOKEN` on the bastion LXC.
   - Per range host: `{"scope":"telemetry","host":"web01"}` (host-bound;
     bind `session_id` too for strict per-session correlation).
   - Runner tokens are created per run by the API; nothing to provision.
5. Member bastion logins: append `"<username> ssh-ed25519 AAAA..."` lines to
   `BASTION_AUTHORIZED_KEYS_FILE`. The bastion requires the member KEY *and*
   a live per-session token as the SSH username.

## 2. Network datapath (F01/F02 — run on the Proxmox host)

- Baseline default-deny + emergency rulesets are rendered from
  `srplatform/safety/firewall.py` for YOUR bridge/VLAN (validated with
  `nft -c -f` in CI/tests). Install baseline persistently:
  `python -m srplatform.safety.firewall baseline > /etc/nftables.d/sr-baseline.nft && nft -f ...`
- Standalone killswitch (works even if the platform is down):
  `infra/firewall/killswitch.sh` (installs emergency drop),
  `infra/firewall/killswitch.sh --release` (removes ONLY the emergency set,
  baseline deny stays).
- Platform safety latch: `POST /safety/killswitch` (engage) stops all run
  workers by process GROUP and applies the emergency ruleset; each layer is
  reported independently — partial engagement says so loudly. Release via
  `/safety/killswitch-release`; release INVALIDATES fresh-evidence records.
- **[LIVE GATE] Full egress proof** from a booted range VM (not from a
  network namespace on the control plane):
  `ping -c1 1.1.1.1` must FAIL; `getent hosts example.com` must FAIL;
  `ip -6 route` must show NO default route. Record the attestation:
  `POST /safety/datapath-proof {"probes": {...}, "vm_hostname": "web01-..."}`.
- Freshness: `/run` is refused (423) unless (a) not latched, (b) runner
  configured (ssh + pinned known_hosts), and in production (c) a FRESH
  `baseline-check` + operator `datapath-proof` exist that match the current
  config identity (`/safety/status` shows `config_identity` — any bridge/CIDR
  change invalidates both).

## 3. Deployment / golden images

1. **[LIVE GATE]** Build golden images: `infra/images/provision-linux-golden.sh`
  (telemetry pipeline via `telemetry/install.sh` — auditd rules, ENRICHED
  format, shipper + systemd unit; vulnerable scenario services are NOT part of
  the golden image, they belong to per-host scenario cloud-init) or
  `infra/images/golden-linux.pkr.hcl` (hashicorp packer plugin; transfers the
  files properly — run `packer validate` against your PVE). Convert to
  template (`qm template <vmid>`); record VMIDs in `.env`
  (`TEMPLATE_VMID_*`). Windows + Sysmon: `infra/images/WINDOWS-CHECKLIST.md`.
2. Deploy is session-scoped: `POST /sessions {"scenario_id"}` then
  `POST /sessions/{id}/launch` (CLI `launch`, browser "launch" — identical
  backend path). Sequence: lease acquire (single active range; conflicts
  return 409 `range_busy` with holder) → linked clone → set
  ipconfig/net0(`bridge=RANGE_BRIDGE,tag=RANGE_VLAN`)+ownership tag → **NIC
  read-back validation** → start with UPID task waiting. Every created VM is
  recorded to the deployment row BEFORE the next side effect; failures
  persist `deploy_failed` + partial ownership (commits survive rollback).
3. `reset` = destroy owned + fresh clones (idempotent). `teardown` removes
  EXACTLY the resources recorded for that session — never a name-prefix
  sweep. `end` keeps VMs (documented decision) but stops runs, takes the
  final trusted score, revokes session capabilities, and releases the lease.
4. **[LIVE GATE]** Real PVE clone/reset/teardown with concurrent-launch
  conflict on your cluster.

## 4. Bastion & recordings (F16)

- Run: `python -m srplatform.bastion.proxy` on the bastion LXC
  (`SR_BASTION_TOKEN` + `API_BASE_URL` set). Users connect with their member
  key + launch-issued token (`tok-<host>-xxxxxx` shown by CLI/web).
- Recordings: exclusive-create files named by UUID (NEVER by token); the
  bastion registers each via `POST /sessions/{id}/recordings` and clients
  only ever see opaque `recording_id`s. Cast header carries the recording
  `timestamp` epoch — the web replay anchors its timeline there.
- **Shared-storage contract**: the API host must see the same
  `RECORDINGS_DIR` path (NFS export from the bastion mounted at the same
  path, or run both on one host). Missing file → explicit 404 message, not a
  broken player.
- Terminal resize frames are recorded; byte cap (`RECORDING_MAX_BYTES`)
  truncates visibly (`truncated` flag in the session_end event).

## 5. Telemetry (F09)

- Golden hosts run `telemetry/install.sh`: auditd rules
  (`telemetry/auditd.rules`), `log_format = ENRICHED` (the format the
  shipper PARSES — documented), `/usr/local/bin/sparring-shipper`, and the
  systemd unit (`tail -F -n 0 /var/log/audit/audit.log | sparring-shipper`).
- Shipper config `/etc/sparring-range/shipper.env`: `SR_API_URL`,
  `SR_TELEMETRY_TOKEN` (host-bound), `SR_HOST`, `SR_SPOOL_DIR`. Offline
  records buffer in the bounded spool (drops oldest, counts `spool_dropped`
  gap events) and retry with backoff. Identity/session comes from the
  CAPABILITY, never the payload; duplicate `boot_id:source_id` dedups at the
  boundary.
- Windows/Sysmon: WEC collector → convert to `detection` events; fixture at
  `telemetry/fixtures/sysmon-detection-sample.json`; mapping documented in
  `infra/images/WINDOWS_CHECKLIST` (see WINDOWS-CHECKLIST.md).
- **[LIVE GATE]** A command on a real range VM lands in the right session's
  log with the right host and source time (both Linux and Windows paths).

## 6. Red runs (F01/F13/F18)

- Runner: `RUNNER_TRANSPORT=ssh` to a fixed Kali target with
  `RUNNER_SSH_KNOWN_HOSTS` pinned; the API spawns a per-run WORKER
  subprocess (`srplatform.red_agent.worker`) in its own process group with a
  run-scoped capability token (sha256 stored). Stop = killpg; a worker that
  dies uncleanly is failed by the watchdog; API restart reconciles
  (`reconcile_on_startup` fails gone workers, kills live ones when latched).
- Model outages are recorded events (`model_unavailable`), never silent
  successes; the gateway is bounded priority (hints > red > AAR) with
  visible overflow 503s.
- Verifier truth: only backend-executed verifier events confirm objectives;
  agent `DONE` requires ALL objectives verifier-confirmed; intents are
  logged BEFORE execution and never blindly replayed after a crash.
- **[LIVE GATE]** Full red run against real Kali + real scenario hosts with
  your model endpoint.

## 7. Web

- `web/` (Next 14): `npm ci && npm run build && npm start`;
  `NEXT_PUBLIC_API_URL` must point at the API. Bearer tokens; 401 → login.
  Replay uses vendored asciinema-player (npm) fed via blob URL.
- Login page expects username+password. Library filters use scenario
  metadata; live dashboard polls `/live` (cursor-tailed); report page GETs
  the PERSISTED AAR (generation is explicit); progress reads
  `v_score_items` (trusted snapshots only).

## 8. Upgrades / migrations

- Apply migrations via `rangectl db migrate` before restarting the API.
  If migration list changes `v_score_items` or safety tables, re-run
  `POST /safety/baseline-check` afterwards (config identity changes
  invalidate old evidence by design).

## 9. Known gaps (honesty list)

- Single-active-range lease (v1 assumption). Windows automation is
  checklist-driven. `POSTGRES` cluster default collation must be UTF8-safe
  (tests create with explicit ENCODING).
- All **[LIVE GATE]** items above.
