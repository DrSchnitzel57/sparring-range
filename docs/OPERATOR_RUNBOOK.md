# Operator runbook and live acceptance gates

Status: **planning runbook, not an accepted production installation guide**.
Updated 2026-10-08; current application baseline `23de4f4` is failing.
See [ARCHITECTURE.md](ARCHITECTURE.md), [ROADMAP.md](ROADMAP.md), and
[FINDINGS_CHECKLIST.md](FINDINGS_CHECKLIST.md). Old instructions requiring runtime
host-root/nft execution or claiming final acceptance are superseded.

The operator owns Proxmox/network setup and approves disposable live fixtures.
Agents prepare artifacts and execute authorized safe automated tests, not mutate
your R740 or unrelated workloads. No model-driven attacks until actual isolation
and emergency-stop gates pass. Windows/AD gates belong to the later milestone.

## 1. Discovery before production configuration

Record these non-secret inputs when their milestone is planned:

- Installed Proxmox version/node, VMID allocations, approved templates, range
  bridge/VLAN and actual routed/bridged paths; management/model/NAS destinations.
- VM disk storage, free capacity, supported full/linked-clone mode, measured
  clone/reset performance and budget for simultaneous lab disks/recordings.
  Approximately 100 GB free on the boot disk is not an accepted VM/evidence store.
  Add SSD storage if needed; do not cut release features silently.
- CPU/RAM/disk/network budgets protecting other R740 workloads and inference.
- Control-plane VM/bastion placement, private web IP/port, ingest/probe/control
  flow allowlist, PVE CA and trusted guest SSH host-key acquisition method.
- Qwen endpoint URL/API model alias, llama.cpp build, quantization/context limits,
  authentication and measured structured-response/latency compatibility. Existing
  inference LXC stays outside the range and is not an attack host.
- Protected persistent storage and backup destination (NAS can be chosen),
  credential storage/rotation, and disposable restore/test environments.

Do not put real values containing credentials in the repository or recordings.
Unresolved version/storage/ACL inputs block deployment, not authorize guesses.

## 2. Identity, secrets and trust

The operator creates/disables member accounts and provisions member SSH **public**
keys. Never request or upload member private keys. Current bastion key format is
one `<username> <algorithm> <base64-public-key>` entry per authorized key; a live
session token binds the SSH login to its owning member. Production onboarding/
disable/rotation steps will be accepted in milestone 10, not assumed from format.

Keep secret files outside Git/image contexts; `.gitignore` alone does not protect
Docker layers or every generated filename. The old `deploy/bastion/` suggestion
is not an assurance that arbitrary files there are ignored. Keep PVE tokens solely
in the private deployment boundary, owner-DB credentials solely in explicit
offline migration/admin tooling, verifier keys in trusted services, and NAS
credentials solely in protected backup tooling. No such secret enters workers,
model prompts, member/browser responses, telemetry, normal logs or casts.

Pin guest SSH identities through a trusted provisioning channel. An unauthenticated
`ssh-keyscan` alone is not verification; fake development pins/TOFU never satisfy
production readiness. Validate PVE HTTPS with its CA. LAN access still requires
password authentication, ownership checks and scoped/revocable producer tokens.

Production member access will be same-origin `https://<private-ip>:<port>` using
a self-signed certificate with the chosen IP SAN. Distribute/verify its fingerprint
out of band and document client trust installation; do not normalize ignoring all
certificate errors. Do not expose the public API, broker, DB or model to the WAN.

## 3. Network setup and restricted automation

Install static default-deny isolation using operator-owned Proxmox administration
tools. Attacker and targets are full VMs with no host filesystem, NAS, GPU or device
mounts/passthrough. The running platform must not SSH to Proxmox as root or execute
host-shell/firewall commands. The existing nft adapter/renderers are legacy code
to preserve/test while redesigning the boundary, not the accepted deployment path.

Deny range access to WAN (including DNS, IPv4/IPv6 and arbitrary TCP/UDP), Proxmox
management, model LXC, NAS, control administration and unrelated workloads.
Allow only exact necessary bastion replies, scoped telemetry ingestion, trusted
probe and guest-management flows. Telemetry ingestion is a narrow endpoint, not
general API administration. Test bridged and routed traffic, established flows,
and new clone NIC placement. No update proxy exception is enabled during matches;
image provisioning occurs outside the active attack environment.

Provision a dedicated non-root automation identity and restricted PVE token for
approved lab resources only. Validate **effective** ACLs, including denials against
unrelated VMs/LXCs, host administration, forbidden config/mount/storage operations
and privilege changes. An assigned resource pool does not prove isolation. The
token is installed ONLY on the broker VM (`SR_PROCESS_ROLE=broker` with
`PROXMOX_TOKEN_*`); the controller/API holds only its mutual-TLS client
certificate (`BROKER_URL`, `BROKER_CLIENT_CERT/KEY`, `BROKER_TLS_CA_FILE`), and
production validation refuses a controller that carries PVE credentials. The
broker additionally validates typed requests against its operator policy file
(`BROKER_POLICY_FILE`: node, templates, bounded VMID range, storage, clone mode,
exact NIC/VLAN, provisioning fields, aggregate CPU/RAM/disk limits) plus exact
ownership/generation in its protected SQLite ledger. If safe ACLs cannot support
required operations on your PVE version, block deployment and revise the design
explicitly; never widen permissions to make a test green.

Broker startup and operations (broker VM only):

```bash
SR_PROCESS_ROLE=broker python -m infra.broker          # daemon: reconciles, then serves
python -m infra.broker.tools status                    # claims/obligations/lease/audit
python -m infra.broker.tools enroll --vmid N --name X --tag srsess-<hex> --operator drew
python -m infra.broker.tools reconcile-legacy --db-url <app-db> [--adopt]
python -m infra.broker.tools stop --yes --reason "incident"
python -m infra.broker.tools release --operator drew   # refused while obligations open
```

Enrollment and legacy adoption require an EXACT PVE identity match (clone name +
session ownership tag); names/tags never auto-adopt. A broker restart with active
claims and an unverified control lease latches and hard-stops BEFORE serving.

## 4. Images, access and installed capture

Milestone 03 must deliver reproducible Linux web and web+MySQL templates with
synthetic seeded business data, usable services, declared vulnerabilities/limited
footholds, defender guest administration, trusted verification channels and stable
baselines. Existing scripts/YAML are not proof those guests exist. Image versions,
template IDs, service/data baselines and host keys are part of accepted inventory.

Install the trusted operation supervisor **inside the disposable attacker VM**,
not on Proxmox. It requires correctly delegated cgroup v2/kernel facilities and
supported namespace protection; a top-level mkdir/chown example is insufficient.
Milestone 02 must specify/prove launcher identities, migration permissions,
bookkeeping protection and safe cancellation. Missing prerequisites refuse work
before command execution. Development `local-dev` is never a production fallback.

Linux capture requires the actual installed `sparring-shipper` systemd unit as
`srshipper`, its declared input/group/sandbox permissions and writable bounded
spool. The deployment provisions a session/host/generation-scoped capability plus
fresh nonce, never a live token baked into an image. Readiness separately proves:

1. Provisioning and service startup.
2. Authenticated delivery from the exact current capability/nonce/generation.
3. A harmless marker command executed on the guest, captured by real auditd, and
   observed through that installed service at the authenticated API/DB boundary.

`systemctl is-active`, fabricated audit stdin or controller-posted callbacks cannot
substitute for capture. With the unit still active, wrong API/path, invalid token
and unreadable audit input must each block readiness visibly and recover after
repair. Migration 0010/current enrollment code exists, but safe legacy-ready/run
upgrade and exact binding remain unverified here. No installing/reconfiguring
auditd or user accounts on this review host; use an explicitly disposable fixture.

Recording bastion and API need an accepted durable same-path storage or transfer
contract; dev Compose uses a shared volume. Replay exposes opaque IDs, never
filesystem paths/tokens. Missing files, truncation and capture/delivery gaps are
visible. Record only synthetic lab activity, never real admin operations.

## 5. Production startup and match behavior — target, not shipped

Milestone 10 will supply executable managed guest-service packaging, same-origin
HTTPS and exact startup/upgrade/recovery commands. Production is not simply dev
Compose pointed at your real infrastructure. Preserve PostgreSQL 16+ UTF8,
separate owner/app roles, forward Alembic migrations, app-role denial of event
UPDATE/DELETE/TRUNCATE and DB trigger enforcement. Current explicit migration
entrypoint is `rangectl db migrate`; inspect/configure it before authorized use.

Accepted startup order must establish storage/DB, role bootstrap and migrations,
private deployment boundary, API readiness/reconciliation, bastion and frontend,
then dependent jobs. HTTP liveness alone is insufficient. No owner DB URL in
runtime services; no attacks automatically resumed after API restart.

The agreed member flow is: login → approved preset/options → Start practice →
provisioning/readiness → per-host SSH instructions → connect → **Begin competition**
→ defend/watch scores/injects → final evidence/report inputs → automatic cleanup
→ reusable range and retained history. Current code does **not** implement all of
this. Current end leaves resources/reservation until separate teardown; do not
tell members the new automatic cleanup exists yet.

- Options: guided/competition; 30/60/120 minutes; low/normal/high intensity;
  injects on/off; explicit network-entry/assumed-breach starts.
- Ready/unstarted expiry: 15 minutes. Running server clock continues on browser
  closure. API restart interrupts/reconciles; it never silently restarts attacks.
- Service checks: every 10s, 5s timeout. Dashboard refresh: 2s. Attack dispatch
  ceilings: 60/30/15s, no overlaps; not guaranteed achieved attack throughput.
- Model timeout: 60s; at most three attempts with 5/15s delays; exhausted recovery
  interrupts. No hidden scripted attacker or foothold fallback.
- Confirmed scorer-infrastructure outage interrupts and preserves partial results;
  actual target failure counts as downtime when scoring infrastructure is healthy.
- Unknown stop/ownership/cleanup retains durable obligations and lease. New users
  see a blocked/recovery state, not an available environment with residual guests.

Effective operator settings are snapshotted per session. Endpoint testing may
require agreeing revised defaults; do not silently alter an in-progress match.

## 6. Emergency stop, recovery and release

**Implemented (milestone 02):** the killswitch persists the latch first, then
attempts three INDEPENDENT layers and reports each truthfully: (a) worker process
groups, (b) the static isolation layer (operator-managed; the runtime executes no
host commands), and (c) the broker's `hard_stop_all` — hard-stopping every owned
lab VM including pending creations, confirming PVE task exit AND stopped/absent
read-back, continuing across failures, and retaining an obligation plus `unknown`
claim for anything unconfirmed. A claim whose VM reads back with a foreign name
(VMID recycled) is NOT stopped; it becomes an operator obligation. API timeout or
worker death is never treated as confirmation. Independently, the broker's
control lease (5 s heartbeat / 30 s expiry) latches and stops the range by itself
when the control plane dies; renewal can never resume a stopped range.

If the platform/broker is unavailable, the operator uses trusted Proxmox UI/API
to stop only the exact identified owned lab guests. If ownership is uncertain,
inspect the approved reservation/creation ledger and actual identities before
mutating anything—no name-prefix sweep. Do not reset disks or change unrelated VMs.

Retain the lease and unresolved operation/resource inventory until verified
cessation and cleanup. Do not edit evidence, mark obligations done by hand, delete
a corrupt latch, or release merely because the attacker worker disappeared.
Record interruption and reconciliation outcomes without secrets. Safe retry is
idempotent; old callbacks/late starts cannot revive the match.

Release is TWO explicit operator actions in order: (1) on the broker, resolve
every obligation (`status`, `stop_and_confirm` reality, `reconcile-legacy`) and
run `python -m infra.broker.tools release --operator <name>` — refused while any
obligation is open;
(2) release the application latch via the operator API and record fresh
isolation/stop evidence bound to the current configuration. It never restores
WAN access or resumes interrupted attacks. A forward upgrade that finds legacy
pre-broker deployments starts LATCHED (migration 0011) until
`python -m infra.broker.tools reconcile-legacy` verifies and adopts or clears
each residual resource.

## 7. Evidence storage, backup and purge

Reports, score evidence, immutable specs/settings and SSH recordings remain until
explicit operator purge. No automatic eviction. Show usage and block new starts
when evidence cannot be stored safely; an active storage failure is surfaced and
handled conservatively, not silently ignored. Finalization must preserve required
inputs before normal VM cleanup; report model work may finish afterward.

Back up PostgreSQL, casts and reference/template/rubric manifests consistently to
operator-selected protected storage. Keep NAS credentials/mounts out of the range.
Test restores in a disposable isolated stack: identity/history, component scores,
recording references/replay and immutable report versions must survive. Restored
operational state must be reconciled, not restart attacks or mutate old VMIDs.

Milestone 10 specifies backup scheduling/consistency, recovery objectives and an
offline scoped archive/purge procedure with confirmation and export/backup first.
Runtime app roles do not gain event-delete/truncate privileges. Missing/removed
recordings are shown honestly. Do not improvise recursive evidence deletion or
volume resets as a recovery action. Indefinite retention requires capacity
monitoring and an operator decision when storage fills.

## 8. Safe validation commands and prerequisites

### Current optional developer baseline

From the repository root (no DB admin selected):

```bash
env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 \
  .venv/bin/python -m pytest -q -ra -p no:cacheprovider
```

This default selection is infrastructure-free (milestone 01): DB/containment/
packet/browser/live are explicit layers, DB and containment membership derives
from the fixture closure, and the default run has zero prerequisite skips.
Per-gate acceptance runs through `python infra/dev/acceptance.py <check>`
(`selection|python|db|containment|authority|packet|frontend|compose|browser`),
which executes the real commands and fails on absent prerequisites, empty
selections or cleanup problems. The `authority` gate (milestone 02) needs no
external service: it exercises the real broker policy, SQLite ledger, mutual-TLS
server and cessation read-back over loopback. `packet` and `browser` remain
CI-only on hosts without root/nft or a launchable pinned chromium.

### Disposable database integration

`python infra/dev/acceptance.py db` starts its own run-owned `postgres:16`
container (unique names/storage, loopback port, synthetic credentials, scoped
cleanup). To point tests at an already-approved disposable cluster instead,
set `SR_PG_ADMIN_URL` or `SR_PG_ADMIN_CMD`; fixtures create/drop unique
`srtest_*` DBs and roles derived from that endpoint and must never target
production. Then run:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -m "db and not browser" \
  -q -ra -p no:cacheprovider
```

With `SR_REQUIRE_DB=1` a skipped DB test is a failure. The absence of DB test
failures due to skipped fixtures is not DB acceptance.

### Containment, installed capture and packet jobs

Containment jobs require correctly delegated cgroup v2, user/mount/cgroup/PID
namespace support and actual harmless containment proof; run them with
`python infra/dev/acceptance.py containment` (sets `SR_REQUIRE_CONTAINMENT=1`,
verifies no run-owned cgroups leak). CI now runs required layers as dedicated
jobs (`SR_REQUIRE_*` per job) — a missing prerequisite, empty selection or
skipped required test fails the job; optional developer skips remain.

The required installed-capture fixture/flag/job is **missing**, to be implemented
in milestone 04. Do not run a nonexistent file and call it a hardware-only gate.
Packet tests (`python infra/dev/acceptance.py packet`) need root + nftables +
iproute2 and apply rules ONLY inside disposable network namespaces the tests
create and remove; never install host firewall rules here or on the R740 merely
to get green tests. The CI packet job runs on a standard GitHub Linux VM for
exactly this reason. Required jobs must execute, not skip/deselect.

### Frontend and browser

From `web/`:

```bash
npm ci
npm run build
npm audit --omit=dev --json    # release gate: zero high/critical
```

Browser acceptance (`python infra/dev/acceptance.py browser`) uses a disposable
DB fixture, the pinned local Playwright CLI (`@playwright/cli` web
devDependency), a run-owned named session, FREE-or-configurable ports
(`SR_E2E_API_PORT`/`SR_E2E_WEB_PORT`) and an isolated `.next-e2e` build — a
developer's `.next`, ports 3000/8010 and other services are never displaced.
The E2E (`tests/test_stage5_browser_e2e.py`, `-m browser`) covers the member
workflow plus replay seek with controlled PVE/model/runner/verifier/datapath
boundaries and synthetic capture. It is not real installed telemetry or R740
acceptance.

### Dev Compose

`python infra/dev/acceptance.py compose` validates the real path: image build,
fresh bootstrap and an idempotent rerun with a run-owned project name, loopback
ports, synthetic `SR_DEV_OWNER_PASSWORD`/`SR_DEV_APP_PASSWORD`/bastion token
and synthetic operator keys, asserting alembic-at-head, app-role-only API
readiness and bastion startup behind the key-seeding gate, then removing only
its own resources. `infra/db/bootstrap.sql` takes the app-role password from
`SR_DEV_APP_PASSWORD` (no committed default dependency). Do not point
unaccepted dev defaults at live infrastructure or delete an existing volume.
Fake pins/dev local runner/datapath relaxations are not production safety
evidence.

## 9. Actual R740 release gates — all open

Each gate needs operator approval, exact evidence revision/environment/commands,
non-secret outcomes and positive controls. Early discovery is useful; attack gates
do not become optional because development tests pass.

- [ ] Effective limited PVE ACLs allow only approved operations/resources and deny
  unrelated VM/LXC, host-administration and privilege-expansion access.
- [ ] Real booted lab VM cannot reach WAN/DNS/IPv6, management, inference, NAS or
  unrelated workloads; authorized bastion/probe/ingest flows work. Cover bridge,
  routing and established flows; management stays usable.
- [ ] Emergency stop stops all owned attacker/target VM traffic and work, including
  background/transport-loss/control-outage cases; latch/release/new-start rules are
  honest and manual PVE stop works independently of the application.
- [ ] Supported template clone/read-back/start/reset/teardown and concurrent launch
  conflict work; failures/unknowns retain ownership/lease; unrelated VMs unaffected.
- [ ] Pinned member SSH, interactive/exec/resize/reconnect casts and durable API
  replay work; revoked/foreign keys/tokens fail.
- [ ] Installed Linux auditd/systemd capture under `srshipper` binds current
  session/host/generation, plus active-service API/token/input negatives recover.
- [ ] Qwen endpoint works through bounded shared gateway: valid tool output,
  measured prompt/context/latency, guided hint priority, paced attacks, retry then
  interruption, honest objective verification and no secret/tool authority.
- [ ] Production HTTPS/IP trust, services/role grants/migrations, boot/restart
  interruption, capacity/quota handling and consistent disposable backup restore.
- [ ] Real service break/restore affects separate scores; technical inject timing/
  verification and written advisory feedback work, including partial results.
- [ ] Both presets/start conditions and guided/competition policies work; operator
  and another member complete unaided browser+SSH sessions, view replay/history
  across sessions, and accept the usefulness/truthfulness of the AAR.

Windows licensing/templates, Sysmon/WEC installed capture, Windows verification
and access are later milestone-12 gates, not marked complete by Linux acceptance.
