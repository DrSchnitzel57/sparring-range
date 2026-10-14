# Plan 13 — Reproducible full-release installation and deployment hardening

Updated 2026-10-14 after repository discovery and operator clarification.
This replaces the overnight fix list; it is an implementation contract, not
a claim that the current code or any live deployment has passed acceptance.

## Steps

- [x] 1. Establish the release contract, fresh baseline, and deployment manifest.
- [x] 2. Repair and prove the Proxmox/broker boundary and recovery contracts.
- [x] 3. Build complete, role-separated, boot-tested guest templates.
- [ ] 4. Establish production configuration, TLS, telemetry, and readiness.
- [ ] 5. Implement durable asynchronous deployment and lifecycle recovery.
- [ ] 6. Complete both presets, match controls, observations, and injects.
- [ ] 7. Complete browser workflows, visibility policy, and honest reports.
- [ ] 8. Deliver and rehearse the operator installer and optional backups.
- [ ] 9. Collect authorized live evidence and reconcile release documents.

Status (2026-10-14, implementation session): steps 1–3 complete and gated
(step 3 by `images` PASS 18/0 + `capture` PASS on the rebuilt role overlays).
Steps 4–6 and 8 are implemented with fast/db/browser/gate evidence recorded
in `docs/FINDINGS_CHECKLIST.md` ("Phases 3–8"); their remaining halves are
live/operator gates (packet CI job, service-VM install evidence, deployed-
lab release workflows), and step 7's new UI beyond the shipped inject inbox
(control builder, safety-panel refinements) remains open. Step 9 is operator
live evidence and stays open by design. Checkboxes are ticked only when the
step's own gate passes — never on implementation presence alone.

Finish phases in order; each has a stop condition below. Independent tests
may run in parallel, but unresolved safety or ownership defects block later
live work. No application implementation or live operation is authorized
merely by saving this plan.

## Goal and scope

Make a fresh installation on the operator's Proxmox host reproducible and
as plug-and-play as the safety boundary allows. After bounded operator setup,
a LAN member can log in, select either approved Linux preset and match
options, launch, connect through recorded SSH, Begin, defend against a paced
AI attacker, receive truthful separate results/replay/history, and leave a
verified clean range for the next member. Installation, reruns, restart,
failure, and recovery must work without improvised ACLs, environment edits,
SQL deletion, ledger surgery, or manual changes inside each clone.

**In:** `mojang-web-01` and `mojang-web-db-01`; one active range; multiple
operator-provisioned accounts taking turns; guided/competition modes;
30/60/120-minute matches; low/normal/high intensity; inject toggle;
network-entry/assumed-breach starts; continuous HTTP/MySQL observations;
technical injects and separately labeled written feedback; production
installation, diagnostics, safety/recovery, and optional backup tooling.

**Out:** concurrent/multi-tenant ranges, shared-team sessions, Windows/AD,
new unrelated scenarios, framework replacement, Hermes/C2 integration,
public hosting, inference-LXC changes, NAS redesign, and paid CI usage.

## Authority, operator decisions, and current deployment

The release requirements and boundaries come from `AGENTS.md`,
`docs/ARCHITECTURE.md`, `docs/ROADMAP.md`, `docs/FINDINGS_CHECKLIST.md`, and
`docs/OPERATOR_RUNBOOK.md`, with these explicit user amendments:

- One combined, phased full-release plan is wanted; the usual 4,800-character
  and one-milestone limits are waived for this plan. Its number is not the
  roadmap's Windows milestone number. Existing acceptance states are not
  silently changed; 03 and 04 retain separate evidence gates.
- The operator removed the old sparring-range installation. **Only the
  network bridge remains.** There is no old service-VM cutover or migration
  requirement. Preserve any unexpectedly discovered resources or evidence;
  do not assume a name or an empty DB establishes safe ownership.
- Scoped, deterministic **operator-run** PVE bootstrap tooling is approved:
  dry-run, reviewed resource manifest, explicit confirmation, and idempotent
  create/reuse of approved service VMs, templates, roles, and ACLs. Agents
  never receive host/root credentials. Runtime authority remains restricted.
- Storage need not be on dedicated non-boot disks. Replace that earlier
  restriction with verified capacity, I/O suitability, quotas, and sufficient
  Proxmox/system headroom. Never wipe or resize unrelated disks to meet it.
- Include automatic backups and a restore procedure, but **backup setup and
  restore verification are not release-blocking**. Unconfigured/unverified
  backups must be conspicuous, never reported as protected recovery.
- The user requested this revision in the actual tracked plan file on the
  current branch. No move to the main checkout or separate knowledge copy
  is required for this planning edit.

Phase 1 records the release amendments in architecture/roadmap during
implementation. The handoff and `deploy/README.md` contain useful historical
inputs, not a current installation specification. Previously reported node
`pve`, bridge `srrange`, VLAN 66, storage `local-zfs`, addresses, VMIDs
9005/9011/9012 and 9100–9199, and model endpoint/alias are **candidates to
verify**, not facts the installer may silently assume. The model LXC and
unrelated workloads remain untouched and outside the range.

## Repository findings and reproducible baseline

Discovery revision: `7b035e3`; clean `focal-mongoose`, equal to locally
recorded `master`/`origin/master`. Research used a fresh ignored `.venv`
with Python 3.12.15 and `requirements.lock`. Research changed no application
files, read no live credentials, and performed no PVE/network mutations.

| Exact command/probe | Fresh result / meaning |
|---|---|
| `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -ra -p no:cacheprovider` | Exit 0: 176 passed, 0 failed/skipped, 206 deselected, 4 warnings, 19.54s. Fast layer only. |
| `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 .venv/bin/python infra/dev/acceptance.py authority` | Exit 1: 16 failed, 8 passed, 358 deselected, 3 warnings. Fixtures use names such as `web01-deadbeef` rejected by the current `sr-` policy. Repair fixtures while preserving negative/race invariants; do not loosen policy. |
| Synthetic `Settings(_env_file=None)` environment probe | `SR_MATCH_SCHEDULER_ENABLED=1` and `SR_MATCH_DEFAULT_DURATION_MINUTES=60` resolve to False/30; field-name `MATCH_*` variables resolve to True/60. Documented names are ignored. |

DB, installed-guest, packet, browser, and production-install acceptance were
not independently rerun in this discovery. Old totals or incomplete CI runs
are not evidence for them. Record the failing authority baseline in
`AGENTS.md` at the beginning of implementation.

| Area and source | Gap the plan must address |
|---|---|
| `infra/proxmox_client.py`, `tests/test_proxmoxer_path_adapter.py`, `docs/audits/pve92-alignment.md` | Several audit fixes already exist: routing-error taxonomy, version GET, token shape, next-ID wording. The path test still uses a recorder rather than real proxmoxer HTTP. Inventory each finding as verified repaired/open, not simply “audit unfinished.” |
| `infra/images/guest_userdata.py`, `guest_build.py`, orchestrator enrollment | Production attacker builder omits auditd/shipper, but deploy enrolls every host. Runner script is installed without an explicit complete cgroup/AppArmor launch setup. Template boot is not proof of readiness or containment. |
| `scenarios/mojang-web-db-01.yaml`, guest setup, `verifiers/library/mojang.py` | Scenario promises separate web/DB guests; image app uses loopback MySQL and reader grants are loopback-only. MySQL verifier invokes a password-protected reader without an explicit credential. Local image checks cannot prove the cross-guest transaction. |
| `Settings`, env examples and systemd units | Ignored `SR_MATCH_*` and unmatched `SR_DATA_DIR`; relative safety-state default under a read-only checkout; runtime env includes owner-DB credentials; bastion shares controller configuration. Need role-specific config and tested permissions. |
| `_provision_command`, shipper and TLS bootstrap | Guest URL inherits public `api_base_url`; urllib validates TLS, but guest certificate trust is not provisioned. Worker/bastion HTTP clients also use the public URL without explicit private-CA setup. |
| `_provision_with_boot_wait`, `management_exec` | SSH 255 means an error, not proof a command never executed. Current retry can replay provisioning; timeout 124 is distinct. Service checks are separate from the boot retry. |
| Orchestrator pin/resume, broker transport | Created-resource resume skips missing pins; publication failure is recorded but not directly a readiness refusal. Most broker RPCs have a 30s client timeout despite longer task waits. Timed-out effects remain possible. |
| `lifecycle.py`, `uptime.py`, session/web/coach APIs | Pilot clock/end paths exist, but durable async deploy, complete controls/injects, MySQL observations, competition filtering, and reliable health/recovery projections remain incomplete. |
| `deploy/README.md`, `web/next.config.js`, `deploy/systemd/` | Next uses standalone output, not documented static export. No committed nginx or `sr-web` service artifact. Users, startup, trust, capabilities, and storage need a real installer rehearsal. |

Framework references checked during discovery:
[OpenSSH exit status](https://man.openbsd.org/ssh.1#EXIT_STATUS),
[Pydantic settings environment names](https://docs.pydantic.dev/latest/concepts/pydantic_settings/#environment-variable-names),
[Python 3.13 urllib HTTPS contexts](https://docs.python.org/3.13/library/urllib.request.html#urllib.request.urlopen),
and [FastAPI background tasks](https://fastapi.tiangolo.com/tutorial/background-tasks/).
Use installed locked dependency behavior and independent tests to verify the
contracts; current web documentation alone is not deployed-version evidence.

## Decisions and why

| Chosen | Rejected / deferred | Why |
|---|---|---|
| Existing FastAPI/SQLAlchemy/Alembic/PostgreSQL, Next Pages Router, asyncssh, proxmoxer, QEMU and supervised worker | Framework rewrite or extra queue service by default | Failures are mismatched contracts/validation, not proof the stack is unsuitable. Keep dependencies minimal. |
| One versioned non-secret manifest; secrets generated/read locally by the operator installer | Repeated editing of drifting env/policy/scripts | Derive consumers from one input and validate actual resolved settings. |
| Durable DB operations with supervised executor and startup reconciliation | HTTP 202 plus ephemeral FastAPI background task | Response decoupling alone cannot survive process death or reconcile uncertain effects. |
| No guest default route; range-IP telemetry-only HTTPS listener | Public API reachability or gateway route as isolation substitute | Guests need same-subnet lab traffic and narrow ingest; controller must not route or expose administration to the range. |
| Separate management/verifier, bastion, runner and emergency-access key roles; capture on every enrolled guest | One key authorized as root/defender/attacker everywhere; disabling enrollment to get green | Match identity boundaries and deployment requirements rather than weakening readiness. |
| Fresh installation plus independently tested rerun and upgrade | Resuming vanished VMs or trusting nightly hand fixes | Operator removed the installation; reproducible setup replaces tribal knowledge. |
| Optional backups with explicit status | Claiming recovery without destination/restore; requiring NAS redesign | User retained tooling but waived it as a release gate. |

## Phase details

### 1. Contract, baseline, and deployment manifest

- Record amendments and fresh test failures; reconcile stale current-state
  prose in authoritative docs without deleting historical evidence. Preserve
  roadmap acceptance until its exact gates are independently met.
- Define a versioned manifest/schema for service VM identities/addresses,
  bridge/VLAN/CIDR, templates/roles/checksums, bounded clone VMIDs,
  storage/full-clone policy, budgets/headroom, public/internal/ingest URLs,
  trust identities, model alias, state paths, and optional backup destination.
  Keep passwords/tokens/private keys out; refer to local protected inputs.
- Installer inventory distinguishes absent, matching, conflicting, and
  unreadable resources. Fail before side effects on conflicts, missing inputs,
  unsupported versions, overlapping addresses/VMIDs, or unsafe capacity. Do
  not claim storage safety from the label `local-zfs` alone.
- Produce a source-of-truth map: manifest -> env/policy/service/template
  config. Commit implementation on the current user-selected non-default
  branch only; never push. Update phase checkboxes as work completes.

**Gate:** amendments/schema recorded; fast/authority baselines reproduced and
failures classified. No live installation inferred.

### 2. Proxmox/broker contracts and recovery

Areas: `infra/proxmox_client.py`, `infra/broker/`, authority tests, audit report.

- Repair stale authority fixtures, retaining foreign-resource, latch, race,
  intent-before-effect, and uncertain-cleanup assertions.
- Exercise the **real pinned proxmoxer client** against local HTTP(S),
  including `/api2/json`, query/form encoding, auth header, version, config,
  next-ID/collisions, clone, start/stop/delete, guest-agent read, UPID status/
  exit and malformed replies. Never substitute `_Recorder` for this boundary.
  Replay source-checked PVE 9.2 error dialects in the fake too.
- Routing/auth/permission/server errors remain uncertain, not absence.
  Match confirmed config absence to the queried resource; never make a
  generic 404/no-such-file answer sufficient proof of complete cleanup.
- Check client/server/task/overall deadlines together. Persist/reconcile
  tasks whose response was lost; retry reads safely, never blind-replay a
  mutation. Test tasks outlasting the previous 30s RPC limit.
- Audit reservation accounting (reserved claims must not be double-counted),
  generation fencing, exact identity checks, and start/config/clone races
  against hard-stop. No late task may revive a latched range. Unknown state
  retains ownership, obligations, and reservation.
- DB/control failure must not indefinitely renew a supposedly healthy lease.
  Distinguish transient failure from unverified control with bounded policy;
  prove fail-closed cessation, idle disarm, restart, release and lost-response
  cases. Latch release remains broker-local explicit operator authority.
- Deliver `deploy/pve_broker_acl.sh` with dry-run/apply/verify and exact
  per-path roles for approved templates, VMIDs, storage, node and bridge.
  Verify effective token permissions and unrelated-resource denials; role
  names alone are not proof. No broad privilege fallback.

**Gate:** authority and new PVE-contract gate execute with zero failures/skips;
audit findings have code/test anchors and remaining live probes are explicit.

### 3. Complete guest/template contract

Areas: `infra/images/`, `infra/cloud-init/`, scenarios and installed-guest tests.

- Unify filesystem/image/PVE inputs so acceptance boots the artifacts actually
  imported. Record resolved packages, build-script inputs, checksums and cache
  keys; moving Ubuntu `current` is not reproducible. Use immutable/retained
  verified inputs; fail on unavailable pins instead of substituting packages.
- Bake only role-appropriate public keys; generate private keys on consuming
  service VMs. Runner key authenticates only to attacker, bastion to defender,
  management to approved provisioning/verifier accounts. Emergency access is
  separate; deduplicate authorized keys.
- Install auditd/shipper on attacker too: deployment requires every guest's
  delivery/capture evidence. Install bounded spool, permissions and units
  identically through the canonical build path.
- Install explicit reboot-persistent runner cgroup delegation/launcher and
  scoped AppArmor profile **inside attacker**. Prove supervised start,
  descendant handling, cancellation and transport-loss recovery under the
  production SSH identity. No global host security relaxation.
- Prove defender passwordless guest administration, least-privilege initial
  network-entry identity and disclosed limited assumed-breach capability;
  no shared root/runner access or hidden foothold fallback.
- Scrub host keys, machine IDs, build capabilities/logs and transient files.
  Boot fresh clones twice to prove new identities, services, capture and
  containment survive cloud-init/restart. Never keyscan/TOFU or silently
  re-pin a compromised generation.
- Define separate web/DB roles. Provision fresh scoped synthetic reader
  credentials, DB listener/grants restricted to owned web/probe sources,
  and web configuration targeting owned DB IP. Do not build a second
  all-in-one app as “DB tier.” No live credential is baked into templates.

**Gate:** images/capture boot actual production-shaped artifacts with synthetic
identities; cross-guest DB transaction and runner boundary pass. Source-text
assertions alone are insufficient.

### 4. Configuration, trust, telemetry, and readiness

Areas: `srplatform/settings.py`, verifier/orchestrator, shipper, bastion and deploy.

- Fix aliases/canonical names with compatibility tests for every shipped
  example. Test non-default values so ignored settings cannot hide behind
  defaults. Reject placeholders, manifest mismatches, dev fixtures and missing
  mandatory configuration before effects.
- Generate separate controller/broker/bastion/worker and offline migration
  config. Owner-DB credentials belong only to offline admin, PVE credentials
  only to broker; worker environment is minimal. Set writable absolute state/
  recording/pin paths outside checkout. Validate user permissions under the
  actual systemd sandbox, not just interactive operator SSH.
- Separate LAN public HTTPS, trusted-process internal API (loopback-only is
  acceptable), and guest telemetry HTTPS on controller's range address.
  Ingest permits only authenticated enrollment/ingest routes/methods and
  bounded bodies, never general API/web/auth/scoring/model/operator endpoints.
- Generate matching SANs and provision **public trust material** into guests;
  use explicit verified SSL contexts for shipper HTTPS. Handle trust for
  internal HTTPS consumers too. Never disable TLS checks for readiness.
- Remove guest default routes through typed policy/config generation; verify
  IPv4/IPv6 behavior. Controller forwarding stays off. Local bridge traffic
  requires local proof; OPNsense logs alone cannot establish isolation.
- Probe pinned SSH harmlessly with bounded backoff before provisioning.
  Bad keys/auth/pins fail distinctly; SSH 255/timeout cannot establish whether
  a command ran. Provision with stable generation/nonce, atomic writes and
  idempotent read-back; retain uncertain outcomes for reconciliation.
- Resume missing pin/publication steps, refuse readiness on unusable required
  pins, invalidate pins on reset/teardown. Confirm declared services, real
  HTTP/DB transactions, runner boundary, authenticated host-originated
  delivery and a real audit-captured marker for every required guest.
- Expose redacted stage/host/code/retry/deadline/error evidence, not secrets
  or full provisioning commands. Distinguish install-ready, lab-ready and
  attack-authorized: absence of a first clone/pin must not create bootstrap
  deadlock or waive later gates. Parse-check configured private keys and
  compare public fingerprints against the role-specific build manifest.

**Gate:** wrong CA/SAN, unreachable ingest, wrong token/input, invalid key,
pin publication failure and delayed boot produce bounded truthful outcomes;
repair recovers without replacing generation evidence or bypassing capture.

### 5. Durable async deployment and lifecycle

Areas: API/orchestrator, `lifecycle.py`, operation models and forward migrations.

- Commit operation identity, owner/fence, generation, phase/deadline,
  progress and outcome before dispatch. Return 202 with operation reference
  only after durable acceptance. Supervised executor uses its own DB
  sessions, not request-scoped dependencies. Prefer PostgreSQL/existing
  components; no Redis/Celery by default.
- Deduplicate launch/reset/end requests; serialize the single range. Polling
  is authorized/redacted. Browser disconnect/504/lost response cannot create
  a second deployment or erase the first operation.
- On restart reconcile provisioning intents/tasks/resources; choose explicit
  interrupted/cleanup outcomes on uncertainty, never unattended attacks.
  Do not clear all claims while another executor could still be active.
  Stale workers/callbacks cannot mutate replacements.
- Preserve shared end/expiry cleanup. Begin alone starts clock/worker;
  duplicates never extend deadline or spawn another worker. Enforce ready-idle
  expiry/server deadlines even when browsers disappear.
- Fence dispatch, confirm cessation, capture required final evidence, revoke
  access and close/settle recording inputs before teardown. Report inference
  can happen afterward; it cannot hold the lease.
- Separate match outcome from cleanup availability: interrupted matches are
  not completed competitions; failed stop/destroy never looks available.
  Reconcile app reservation and broker obligations before reuse.

**Gate:** disposable-DB tests cover commit/effect boundaries, lost responses,
duplicates, restart, deadlines, delayed tasks, failed destroy, recovery and
second launch. No old operation can revive the range.

### 6. Full match, observation, and inject contract

Areas: session/scenario schemas, scoring/uptime, verifiers, trusted inject service.

- Snapshot mode, duration, intensity (60/30/15s maximum dispatch cadence),
  inject toggle, start condition, topology/template/rubric versions and
  effective approved settings. Validate bounded choices. Preserve historical
  snapshots through forward migrations, not reinterpretation.
- Require external HTTP/content and authenticated read-only MySQL business
  transactions every 10s with 5s timeouts. Use owned generation-bound targets
  and protected probe credentials, not target-local claims of health.
- Persist unique scheduled observations. Coverage includes expected schedule
  gaps, not just received samples; never fabricate restart samples or count
  unknown as downtime. Detect unhealthy probe infrastructure separately from
  target failure; confirmed bounded scorer failure interrupts attacks and
  preserves partial results. Test DB failure and stuck/dead probe threads.
- Keep availability, technical-inject and final security scores separate.
  Zero valid coverage is unscored; no invented combined grade. Fix MySQL
  verifier credentials and malformed/ambiguous evidence handling.
- Implement versioned restricted-account, web-restoration, DB-data recovery
  and incident-report injects. Trusted server schedules release/deadline from
  snapshotted duration; identity-bound submission and deterministic technical
  verification are idempotent. Written feedback is advisory only. Define
  incorrect/late/duplicate submission and disabled-inject outcomes.
- Retain sustained sequential attacker/shared gateway. Enforce deadline-aware
  bounded calls/commands/context, retry policy, cancellation and truthful
  exhausted-model interruption. Objective completion never ends the match;
  no scripted “AI succeeded” fallback.

**Gate:** both presets/start conditions/full control matrix pass safe automated
tests; actual business transactions/fault recovery execute, not only unit
presence or mathematical aggregation.

### 7. Browser, visibility, and reports

Areas: `web/pages/`, API/web/coach routes, CLI clients and browser fixtures.

- Navigate to created session immediately and poll operation/session state.
  Include failed/unscored sessions in history; expose retry/cleanup controls,
  safe failure details, lease-holder context and fresh server-served SSH
  instructions. Refresh match/session state as well as live events; transient
  errors must not freeze stale controls.
- Implement control builder, Begin, live service/component scores, inject
  inbox/submissions, degraded/interrupted/cleanup states, AAR/replay and
  per-user history. Begin is the sole normal start; no accidental second-start
  or readiness-bypass path. Operator safety panel shows both latch states
  and the authorized recovery procedure, without moving broker-local release
  authority into a browser endpoint.
- Centralize competition filtering across relevant API/CLI reads: live/raw
  events, objectives, agent memory, verifier results, hints, reports,
  recordings/replay and exports. Members see permitted service/inject data,
  not attack spoilers. Operator diagnostics require explicit authority;
  exposing raw readiness payloads is not an authorization policy.
- Preserve deterministic evidence-linked reports after VM deletion/model
  failure, separate scores and capture gaps/attribution limits. Written
  feedback never awards verified points. Versions/cutoffs remain immutable;
  do not hold DB transactions through model waits.
- Test two members, forbidden/foreign/expired capabilities, disabled accounts,
  close/reload, failure/recovery, modes/presets, genuine backend outcomes,
  cast resize/reconnect and missing recordings. CLI remains an API client.

**Gate:** built-browser flow/API negative matrix pass; hiding a button is
never accepted as authorization or competition filtering.

### 8. Operator installer and optional recovery tooling

Areas: `deploy/`, managed-service artifacts, install fixtures, runbook.

- Deliver one documented entry point with validate/plan/apply/status/
  diagnostics modes and role-specific execution. Operator supplies non-secret
  facts once and secrets locally. Avoid quoting traps, placeholders, printed
  tokens and pasted private keys. Document the few unavoidable operator
  confirmations rather than promising unsafe zero-touch administration.
- PVE bootstrap creates only approved resources after dry-run/confirmation.
  Inspect existing bridge, do not replace it. Isolation stays operator-owned:
  provide exact access matrix/checklist and reviewed scoped setup artifacts,
  never automatically change unrelated host/firewall rules. No destructive
  live acceptance fixtures.
- Package exact release revision/locks/digests for both service VMs. Generate
  users/groups, permissions, persistent directories, DB roles, offline
  migrations, TLS/SSH identities, scoped service capabilities, broker policy,
  nginx listeners, `sr-api`, `sr-brokerd`, `sr-bastion` and `sr-web`. Next
  standalone service includes required static/public assets; remove static
  export instructions. Bind internal services narrowly. Operator creates
  accounts/provisions member public keys; no private-key upload or signup.
- Observe service ordering, schema compatibility, scheduler/watchdog health
  and restart behavior. Preserve private keys/state on rerun; never silently
  rotate a CA or overwrite data. Block mixed revisions. Upgrades use forward
  migration and verified checkpoints, not “commit hash >= c952831.”
- Installation tests boot disposable Ubuntu service VMs with actual systemd/
  PostgreSQL/nginx/Next/SSH and synthetic mTLS/PVE/model fixtures. Test clean
  install, idempotent rerun, reboot, populated forward upgrade and failure.
  Existing Compose acceptance does not prove managed-service installation.
- Add printable normal-operation/recovery guide and redacted diagnostics:
  versions, stages, service errors, topology, config digests and obligations.
  Ordinary operation never needs raw DB administration.
- Optional backups save consistent DB/evidence/recordings/manifests and
  required broker recovery state to a protected operator destination. Keep
  backup credentials outside runtime. Include checksums, failure alerts and
  disconnected disposable restore; restored state never resumes attacks or
  adopts current VMIDs. Missing destination/restore proof is explicit, not
  release-blocking. No automatic evidence purge/retention eviction.

**Gate:** new install gate proves managed services; rerun is non-destructive
and no service-VM shell patch is necessary. Report optional backup/restore
results separately, never silently skip them or mark them accepted.

### 9. Live evidence and documentation reconciliation

- Implementation runs safe synthetic tests only. Operator executes Manual
  checks after reviewing manifest/bootstrap dry-run. Actual safety/stop
  evidence precedes every live model attack.
- Compare release/config/template digests and ACLs to intended inputs; prove
  transport/negative boundaries, then workflows and repeated clean reuse.
  Inspect exact owned VMIDs, ledger/tasks, app leases and capabilities—not
  global `sr-*` sweeps, only `qm list`, or absence of log errors.
- Record exact commands, environment, revision, counts, logs and references
  in `docs/FINDINGS_CHECKLIST.md`. Align audit, `deploy/README.md` and operator
  runbook with tested artifacts. Preserve handoff as historical with a
  supersession pointer; investigate claims instead of copying old totals.
- Last: update roadmap and architecture decisions. Tick milestones only
  against independently satisfied requirements. Storage/backup amendments
  are explicit, not unreported waivers; remaining unverified boundaries stay
  open. Tick plan phases as completed without dropping constraints; report
  failed criteria honestly.

## Validation implementation and stop rules

Keep `infra/dev/acceptance.py` as the single gate entry point. Add
`pve-contract`, `install`, and `release`: these are **planned deliverables,
not existing commands**. Contract uses real proxmoxer over synthetic HTTP(S);
install boots managed-service fixtures; release exercises feature/failure/
authorization matrix. Reuse DB/guest/browser fixtures where appropriate,
classify compound prerequisites correctly, and fail on missing prerequisites,
empty selections, required skips, leaks or incomplete cleanup. No green
result may exclude authority failures or substitute synthetic callbacks for
installed capture. Run relevant gates after each phase and the complete
required matrix at the final evidence revision.

New safety defects get failing regressions and repair in the relevant phase;
never relax boundaries to meet a deadline. Missing live proof blocks attacks.
Missing software prerequisites leave acceptance pending, not “hardware
accepted.” Required CI must use approved free allowance; no paid runs.

## Manual checks — operator only

Necessary human/access steps, not agent-executed live tests:

- Confirm host/PVE version, bridge/VLAN behavior, approved free VMIDs/IPs,
  storage/I/O/headroom, import checksums, model alias/latency and unrelated
  workload inventory. Approve service resources and retained-data location;
  never assume old addresses are free.
- Review bootstrap dry-run, execute scoped setup locally. Create fresh
  credentials and revoke surviving old pasted DB/PVE secrets; no private
  material in chat. Verify effective token allowed operations and denials
  of unrelated VM/LXC, storage, host and privilege changes.
- Validate range IPv4/IPv6, WAN TCP/UDP/DNS, management, model LXC, NAS,
  controller administration and unrelated-workload denial with bounded
  probes and working positive controls. Cover routed, bridged and established
  flows; controller forwarding off, no guest default routes. Ingest works,
  other controller routes/ports do not. OPNsense-only proof is insufficient.
- With disposable owned guests and no attacks, prove latch/stop task
  completion plus stopped/absent read-back, control/API/DB/broker outage
  handling, blocked release on obligations, explicit release with fresh
  evidence, manual PVE stop fallback and unaffected management/workloads.
- Only then validate model through gateway and both presets/start conditions/
  modes. Operator and another member complete unaided browser/recorded-SSH
  practice. Exercise real service break/restore, technical/written injects,
  early/deadline end, idle expiry and restart. Confirm cleanup/next launch,
  retained history/replay and useful AAR.
- Verify free CI allowance/$0-spend protection before expanded hosted runs.
  Optional: select backup destination and run disconnected restore. Missing
  verification is visible but not a release blocker.

## Remaining assumptions and risks

- Only bridge survival is confirmed. Its configuration, PVE version, new
  addresses, budgets, headroom, TLS identities, keys, ACLs and model
  availability require fresh discovery.
- Reuse canonical guest budgets (2 vCPU/2 GiB each; 16/12/16 GiB disks)
  unless a recorded operator-approved decision changes them. Account for
  templates, service VMs, build cache, retained evidence and reserve too.
- Scope is larger than the old rehearsal fix list. Do not make another
  overnight promise or silently drop features. Record software, operator
  and optional-recovery status separately.
- Guest root can forge telemetry; capture is host-claimed evidence, never
  independent scoring truth. Same-host VMs retain hypervisor/contention
  risk. Unknown ownership/cessation/cleanup is never success.
- Single-controller/single-range architecture remains. Installer refuses
  competing controllers over the same reservation/ledger. Backups are not
  HA and must not revive operational work.

## Acceptance criteria

Run required software commands on the final evidence revision in isolated
fixtures/CI. Missing prerequisites/required skips mean FAIL/pending.
Criteria 8–9 require operator Manual checks; implementation agents skip those
live checks and leave them pending. Backup verification is optional and
deliberately absent from mandatory criteria.

1. `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -ra -p no:cacheprovider` exits 0 with zero failures/skips.
2. `bash -e -c 'for gate in selection python authority pve-contract; do .venv/bin/python infra/dev/acceptance.py "$gate"; done'` exits 0; real-client error/URL/task/auth contracts and safety races execute without weakened policy. `pve-contract` is new.
3. `bash -e -c 'for gate in db containment packet; do .venv/bin/python infra/dev/acceptance.py "$gate"; done'` exits 0 in required isolated modes, including forward upgrades, claim/lease races, fencing and honest uncertain cleanup.
4. `bash -e -c 'for gate in images capture; do .venv/bin/python infra/dev/acceptance.py "$gate"; done'` exits 0 with actual production-shaped Ubuntu artifacts, installed delivery/capture, role keys, runner containment and cross-guest web/DB proof.
5. `bash -e -c 'for gate in frontend browser compose; do .venv/bin/python infra/dev/acceptance.py "$gate"; done'` exits 0; production audit has zero high/critical findings and built browser exercises genuine backend workflows and negative access paths.
6. New `.venv/bin/python infra/dev/acceptance.py install` passes clean managed-service installation, idempotent rerun, reboot, populated upgrade and failure recovery; no private-key regeneration/data loss or manual guest fixes.
7. New `.venv/bin/python infra/dev/acceptance.py release` passes both presets/start conditions/modes, approved snapshots, duplicate/crash/timeout recovery, service/inject/security results, scorer/model failures, competition API filtering, reports/history/replay and subsequent reuse.
8. Operator evidence proves effective PVE authority, real transport, isolation with positive controls and emergency/control-loss stop/read-back/release before attacks; service/config/template digests match approved release manifest.
9. Operator and another member complete unaided workflows for both presets; service changes/injects/results/replay are truthful, end/expiry/restart never resume attacks, owned cleanup/obligations/leases settle and another launch succeeds without DB/ledger surgery.
10. Findings, audit, architecture, roadmap and tested runbooks agree with evidence/user amendments; no milestone is ticked on fakes/skips/old totals, unresolved requirements stay explicit and optional backup status is accurate.
