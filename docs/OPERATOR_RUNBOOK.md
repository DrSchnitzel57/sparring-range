# Operator Runbook

Everything here reflects the code as shipped. Steps marked **[LIVE GATE]**
require Drew's R740/model/range VMs and remain unaccepted until executed —
the harness cannot honestly close them.

## 0. Fresh-stack bootstrap (dev compose: empty deployment → running stack)

One documented, idempotent path: compose seed step + `rangectl bootstrap`.

1. `cp .env.example .env` (compose dev passwords have documented defaults;
   `SR_ENV=production` refuses placeholders).
2. Operator-supplied key material in `./deploy/bastion/` (override the dir
   with `SR_DEPLOY_KEYS_DIR`). **Secret material — never commit it** (this
   directory is not in `.gitignore`; keep it outside the repo or ignore it
   yourself):
   - `authorized_keys` — one `"<username> <algo> <base64>"` line per member
     (exactly the format `BASTION_AUTHORIZED_KEYS_FILE` is read in
     `srplatform/bastion/proxy.py`).
   - `target_known_hosts` — pinned range-host keys
     (`ssh-keyscan -p 22 <range-host> > deploy/bastion/target_known_hosts`).
   - **[DEV-ONLY substitution]** with no range hosts yet, generate a
     placeholder pin:
     `ssh-keygen -q -t ed25519 -N '' -f /tmp/devtarget && printf 'target01 %s\n' "$(cat /tmp/devtarget.pub)" > deploy/bastion/target_known_hosts`
     — DEV ONLY: production refuses TOFU, so placeholder pins must never ship;
     re-key against real host keys before any member session.
3. `docker compose up -d` — postgres → bootstrap-roles → migrate →
   **seed-bastion-keys** (copies both files into the `bastion-keys` volume at
   `/etc/sparring-range/{authorized_keys,target_known_hosts}` and creates the
   recordings dir; exits 1 with a runbook pointer if a file is missing or
   empty) → api → bastion.
4. `rangectl bootstrap --telemetry-host web01 [--telemetry-host ...]`
   (password via `--password`, `$BOOTSTRAP_OPERATOR_PASSWORD`, or prompt):
   creates the operator via `POST /auth/bootstrap`, mints the bastion +
   per-host telemetry capabilities via `POST /admin/service_tokens` (printed
   ONCE, recorded 0600 in `~/.rangectl/bootstrap.json`), validates the key
   material and ensures the recordings dir. **Re-running is a no-op**: a
   closed bootstrap and already-minted capabilities are reported, never
   re-minted (the state file is the mint ledger — deleting it re-mints).
5. Wire the minted bastion capability: set `SR_DEV_BASTION_TOKEN` in `.env`,
   then `docker compose up -d bastion` (recreate). Until then the bastion
   serves member-key auth but cannot resolve session tokens.
6. `rangectl login && rangectl readyz` — readyz reports migration version,
   runner config, `recordings_writable` and safety state.

**Verification status (honest):** the seed script, the bootstrap path and the
volume/env wiring are covered by `tests/test_stage5_bootstrap.py` and the
compose YAML tests in `tests/test_followup_regressions.py`. `docker compose
config` and a fresh-volume boot could NOT be executed in the authoring
environment (docker not installed) — recorded as BLOCKED, not passed.

## 1. One-time setup (control plane host)

1. `.env` from `.env.example` (all variables documented there). `SR_ENV=production`
   refuses to start with placeholder secrets.
2. Postgres 16+: create roles/db per §Database below, then
   `rangectl db migrate` (runs Alembic as `POSTGRES_URL_OWNER` — the ONE
   sanctioned non-HTTP operation; app role has no DDL and cannot
   UPDATE/DELETE/TRUNCATE `events` — trigger + grants).
3. Bootstrap the operator (works only while NO account has a password):
   `rangectl bootstrap` (idempotent full path — see §0) or raw
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
  format, shipper + systemd unit). Scenario host `services` are a VERSIONED
  PREBUILT-TEMPLATE REQUIREMENT (audit N10): the golden template must provide
  the mapped units (`http`→nginx, `mysql`→mysql, `ssh`→sshd — see
  `SUPPORTED_SERVICES`), and `launch` VERIFIES readiness on the owned
  inventory before a session reaches `ready` (unknown/failed readiness keeps
  the session out of `ready` with explicit reasons; dev mode without a
  management channel reports the relaxation in the launch response).
  Unsupported service names are rejected at scenario validation, never
  silently ignored. Or
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
- `docker compose config` + fresh-volume boot of §0: **BLOCKED** in the
  authoring environment (no docker); validated by YAML-parsing tests only.
