# Architecture — Linux-first CCDC practice release

Status: **agreed release design, not a claim of implemented or deployed behavior**.
Agreed 2026-10-08. Application baseline: `23de4f4`.

Read [ROADMAP.md](ROADMAP.md) for implementation order,
[FINDINGS_CHECKLIST.md](FINDINGS_CHECKLIST.md) for fresh evidence and open risks,
and [OPERATOR_RUNBOOK.md](OPERATOR_RUNBOOK.md) for operator prerequisites.
This document replaces `plan.markdown` and the overlapping architecture/audit
handoffs. Historical evidence remains in Git; old completion checkmarks are not
release acceptance. Full implementation plans are agreed one milestone at a time.

## Release goal and scope

A LAN user opens `https://<private-ip>:<port>`, logs in, selects a bounded practice
configuration, clicks **Start practice**, receives connection instructions, and
SSHs into disposable Linux machines. After clicking **Begin competition**, they
defend while checking service availability, scores, and timed business injects
on the website. At completion they receive verified component scores, a replay,
an evidence-linked after-action review, and separate written-report feedback.
The lab is automatically cleaned up for the next user.

First release:

- One active environment, one owning defender, multiple provisioned accounts and
  persistent per-user history. True team collaboration/concurrent ranges are later
  work; the reserved `players` field is not evidence they exist.
- Two approved Linux presets: web server, and web plus database. HTTP and MySQL
  are supported by the current scenario schema, but their usable baselines must
  still be built. SSH is access, not automatically an availability-scored service.
- Guided practice and competition modes; 30/60/120-minute matches;
  low/normal/high attack intensity; timed injects on/off; explicit network-entry
  or assumed-breach starting conditions.
- Restricted-account creation, required web-content restoration, seeded business
  data recovery in the database preset, and written incident-report injects.
- Service-availability, technical-inject, and final security-state scores shown
  separately. No invented combined weighting or overall letter grade. Written
  AI feedback never changes verified points.
- LAN-only HTTPS with a self-signed certificate containing the selected private
  IP in its subject alternative names, a configurable port, and client trust
  instructions. No internet exposure, external assets, SSO, or public signup.
- Operator-created/disabled accounts and operator-provisioned SSH public keys;
  private keys remain on user devices. The defender has administration privileges
  only within their lab guests.

Windows/AD, RDP/browser terminals, embedding/RAG infrastructure, custom free-form
topologies, multiple concurrent ranges, PvP, C2 integration, adaptive difficulty,
and spaced repetition are not first-release requirements. Storage concerns must
not silently remove agreed features; identify storage prerequisites instead.

## Hardware and deployment context

The operator's R740 runs Proxmox and already hosts the inference LXC. Hardware:
192 GB RAM (approximately 128 GB free), two Xeon Gold 6240 CPUs mostly free, a
4 TB Synology NAS, and a 500 GB boot drive with approximately 100 GB free. More
SSD storage can be added. No Linux templates or attacker VMs are prepared yet.

One operator-provided **Qwen 3.8 Flash Next** model through llama.cpp's OpenAI v1
endpoint serves attacks, summaries, hints, and report feedback. That name is
operator-supplied: verify the actual API model alias, build, quantization, context
limit, and available endpoint before deployment. Do not infer configuration from
the name or historical throughput estimates. No embedding model is required.

Proxmox version, usable VM storage type/clone support, private addresses, network
boundary, resource budgets, and backup destination are deployment-discovery
inputs. NAS capacity does not prove VM-I/O performance or linked-clone support.
Do not deploy lab disks or uncontrolled recordings onto the host boot filesystem.

## Current implementation versus target

| Area | Current code | Remaining release change |
|---|---|---|
| Clients | Next.js Pages Router, Typer, FastAPI | Preset builder, readiness/start flow, complete competition dashboard |
| Sessions | Snapshot YAML, lease, deployments, worker/run-operation rows | Effective settings snapshot, match clock, deadlines, interruption, automatic cleanup |
| Provisioning | API calls `infra/proxmox_client.py` directly | Private restricted deployment boundary; complete Linux image/service/data baselines |
| Safety | Persisted latch, runner supervisor, privileged nft adapter | Validate containment; remove runtime host-root/firewall dependency; hypervisor-backed emergency stop |
| Capture | asyncssh casts, auditd parser/spool/enrollment | Installed-unit command-capture proof and real transport acceptance |
| Scores | Deterministic backend snapshots | Continuous external service transactions and distinct inject/security results |
| Attacker | Supervised worker, one shared model gateway | Sustained paced match behavior rather than 20-step/objective-completion exit |
| Coach | Citable persisted AAR and hints | Separate component scores/written feedback, stricter supported-claim handling |
| Live data | Red phase and recent verifier/detection events | Service observations/injects; server-side competition spoiler filtering |
| Operations | Dev Compose and bootstrap artifacts | Accepted production startup, HTTPS, backup/restore, capacity/recovery procedures |

The fresh baseline is failing; see `AGENTS.md` and the findings checklist. Earlier
repairs are useful and must be preserved, not blanket-reverted. Neither tests
against doubles nor historical reports establish safety on the operator's host.

## Process and authority boundaries

```text
LAN browser / CLI / defender SSH client
    |
    +-- HTTPS reverse proxy --> web + FastAPI --> app-role PostgreSQL
    |                              |
    |                              +--> trusted match / scoring / inject services
    |                              +--> bounded model gateway --> inference LXC
    |                              +--> scoped worker --> fixed attacker-VM channel
    |                              +--> private deterministic deployment broker
    |                                                       |
    |                                                       +--> limited PVE API token
    |
    +-- recording bastion --> owned target VMs

attacker VM <--> vulnerable target VMs       isolated lab network
target telemetry --> narrow ingest boundary --> authenticated append-only evidence
```

Application/business logic remains behind FastAPI; the private broker is an
infrastructure adapter, not another member-facing business API. Retain Python,
FastAPI, SQLAlchemy/Alembic, Typer, asyncssh, OpenAI-compatible calls, YAML presets,
and Next.js unless a milestone establishes a justified necessary change.
Production services use persistent managed guest services; Compose is a dev/test
tool, not silently promoted to production. Exact guest/service layout and proxy
configuration are specified in the relevant milestone plan. Prefer a dedicated
control-plane VM; do not move or reconfigure the existing model LXC without the
operator's approval.

Preserve `srplatform` (avoids shadowing Python's `platform` module), the existing
psycopg2 driver with UTF8 PostgreSQL, stdlib scrypt password hashing, and the
supervised per-run worker process. Durable operational tables are an intentional
exception to immutable evidence, not permission to mutate historical scores.

### Infrastructure authority

- Attacker and intentionally vulnerable targets are **full VMs**, never privileged
  or unprivileged LXCs sharing the Proxmox kernel. No host filesystem/NAS/GPU/device
  mounts or passthrough in lab guests.
- Only a deterministic private deployment service holds a restricted Proxmox API
  token from a dedicated automation identity, not host root. Members and model
  workers never receive it or a general-purpose broker endpoint.
- Milestone 02 uses separate application/control-plane and broker VMs outside a
  new dedicated range VLAN (existing cyber-testing VLAN 30 remains untouched).
  API-to-broker HTTPS is mutually certificate-authenticated; its client key is
  never supplied to model workers. The broker has a protected SQLite ownership,
  intent and latch ledger independent of application PostgreSQL. Offline operator
  tooling enrolls the disposable attacker VM and reconciles legacy deployments;
  names/tags alone never auto-adopt an existing VM.
- Requests are typed operations over approved templates, storage, network,
  resource budgets, and positively owned session VM IDs. No arbitrary PVE paths,
  config dictionaries, host commands, identity changes, or user-specified mounts.
- Test actual effective PVE ACLs against unrelated VMs, the model LXC, host
  administration, storage, and forbidden operations. A pool is an organizational
  scope, not assumed proof of complete permission isolation. If the installed
  PVE version cannot establish the required safe authority, deployment is blocked
  until the operator approves a safer revised design; do not widen permissions.
- Persist creation intent before side effects; wait for UPID tasks, validate
  ownership/NIC placement, reconcile failures, and retain the lease on uncertainty.
  Only positively owned resources may be mutated or removed. Template lookup and
  verifier targets never fall back to arbitrary DNS/user input.

### Network and emergency safety

The operator configures the static boundary once, using Proxmox administration
tools. Range WAN egress is denied, including DNS, TCP/UDP and IPv6. Range-to-host
management, inference LXC, NAS, control-plane administration, and unrelated LAN
workloads are denied. Permit only explicitly required bastion replies, scoped
telemetry ingress, and trusted management/probe flows. Keep inference calls on
the control plane, not from attacker commands. Validate actual bridged as well
as routed traffic and pre-established flows; management must remain available.

The release replaces the requirement that the running application execute
privileged nft commands on Proxmox. Permanent operator-managed isolation is
independent of the API. Emergency stop latches new work, attempts worker/operation
cessation, and independently hard-stops **all owned lab VMs**, including attacker
and targets, through restricted PVE authority. Confirm task/read-back outcomes;
an API timeout or stopped worker does not prove cessation. Keep partial/unknown
outcomes visible and reservations retained. A manual operator PVE stop remains
available if the application/broker fails. Release requires an explicit operator
action and fresh safety evidence; it never restores WAN access.

The milestone-02 broker also monitors a control-plane lease: healthy DB-backed
control renews every 5 seconds; 30 seconds without renewal latches and attempts
owned-VM hard-stop. Broker restart/lost state fails closed. Recovery never resumes
attacks. Broker/PVE unavailability remains an unconfirmed outcome requiring operator
recovery, not a promise that stopped software can stop guests. Normal development
as well as production forbids local model shell execution; harmless local adapters
are restricted to isolated synthetic acceptance fixtures.

Process-group/cgroup/namespace supervision remains useful inside the attacker
VM, but is not the sole authority against guest compromise. Protect supervisor
bookkeeping, track recursive descendants, avoid unsafe bare-PID signaling, fence
late starts, and refuse unsupported containment before executing commands. Root
inside a disposable guest is not root on Proxmox; still, no same-host VM design
can promise zero hypervisor risk. Patch Proxmox and enforce CPU/RAM/disk/output/
network budgets so the range cannot starve the model or other workloads.

### Evidence and identity

PostgreSQL events remain append-only with trigger and application-role denial of
UPDATE/DELETE/TRUNCATE. Reports, settings, preset/rubric/template versions, score
observations, and evidence cutoffs are immutable/versioned. Operational rows may
change for claims, timers, leases, state, capabilities, and resource reconciliation.
Upgrade with forward migrations and test existing data as well as fresh installs.

Authenticate accounts and scoped bastion/telemetry/runner capabilities; enforce
expiry, revocation, ownership, generation, and server-assigned actor/session/host.
Clients cannot submit trusted verifier results. Enrollment requires the exact
current capability plus nonce/generation, distinct host-originated delivery and
capture evidence, and idempotent concurrent confirmation. Old phase-only evidence
must not enable `ready` or `/run` after upgrade.

Auditd command telemetry is evidence of what a compromised host claims, not
independent truth or automatic defender attribution. Terminal casts are replay
byte streams, not reliable parsed interactive commands. Preserve source time,
event-ID cursor ordering, boot/source deduplication, bounded durable spool, gaps,
and crash-safe delivery. Store opaque recording IDs with containment, symlink,
size/frame checks and UUID exclusive creation. The API and bastion must share a
defined durable storage/transfer contract; a missing file is a visible error.

## Session and match lifecycle

1. Authenticate, validate the selected preset/options and platform readiness,
   snapshot effective settings, acquire the single global lease, and record intent.
2. Deploy the approved owned VM topology, provision synthetic services/data and
   per-generation capabilities, verify isolation, service readiness, installed
   telemetry delivery/capture, and bastion access. Failure is visibly unready.
3. Display live provisioning status and real per-host SSH instructions. Do not
   charge provisioning/connection time to the match. The user clicks **Begin
   competition** only after connecting. A ready but unstarted lab expires after
   15 minutes and is safely cleaned up.
4. A durable server-side clock starts scoring, the AI attack schedule and inject
   release/deadline processing together. Browser closure/reconnect never pauses or
   resets it. Duplicate requests cannot spawn duplicate resources/jobs/actions.
5. At expiry or explicit end, stop further dispatch, resolve active operations,
   capture final trusted score/evidence/recording/report inputs, revoke access,
   and automatically clean up owned guests. Model report generation must not
   hold the lease or require live VMs; a deterministic report remains available.
6. Release the lease only after verified cessation and complete owned-resource
   cleanup. A new user sees `busy`, `cleaning up`, or `recovery required`, never
   a misleading available environment. Preserve retryable partial failure state.

Effective states/outcomes must distinguish preparing, ready, running, finalizing,
cleanup, complete, interrupted/failed, and blocked recovery; the milestone plan
maps these concepts to schema/API values rather than falsely asserting current
enums already support them. API restart interrupts an active match, fences old
work, and reconciles durable obligations; it never silently restarts attacks.
Emergency stop prioritizes cessation over report quality and may leave a partial
result. Reports/history survive guest cleanup.

## Scores, service probes and injects

- Probe actual business behavior from a trusted independent vantage point: HTTP
  response/content and read-only authenticated MySQL transactions over seeded lab
  data. A listening port or installed systemd unit alone is insufficient. Keep
  probe credentials out of the attacker environment and member responses.
- Probe every **10 seconds**, with **5-second timeouts**; refresh the dashboard
  every **2 seconds**. Show up/down/unknown, latest observation, freshness, downtime
  history and verified points. An ordinary target failure is downtime only while
  probe infrastructure is demonstrably healthy.
- Store one identity-bound result per scheduled service check; do not award
  duplicate/replayed points or fabricate missed checks after restart. Availability
  scoring derives from recorded valid scheduled checks and the versioned preset
  rubric, with observed coverage explicitly shown.
- A confirmed scoring-infrastructure outage stops attacks, interrupts the match,
  preserves partial results and initiates safe cleanup. Unknown/missing evidence
  remains unknown, not free points or fabricated downtime. Define and test the
  infrastructure-health detector in the scoring milestone; failure of a lab
  service must not be mistaken for failure of the scorer.
- Technical injects have preset-authored release times, deadlines, points,
  requirements and deterministic verifiers. Schedules scale within the chosen
  duration. Record release, submission, verification and deadline outcomes using
  server time, not browser clocks. Disabled injects have no technical-task total.
- Written submissions are text incident reports, stored as evidence with bounded
  size. AI feedback is advisory, evidence-linked and separately labeled; no
  subjective result modifies service, technical-inject or security-state points.
  Treat submitted text as untrusted data, not tool/system instructions.
- Final security-state checks use the owned generation, typed verifier args,
  baseline-aware predicates and explicit expected polarity. Failed execution,
  malformed results and stale inventory produce unknown, never passes. No flag
  based solely on model claims. Use stable seeded artifacts, not a checksum of a
  changing live MySQL file or placeholder hashes/user inventories.

## AI attack behavior and coaching

Network-entry starts without target credentials against deliberately seeded,
documented lab vulnerabilities. Assumed-breach starts with an explicitly
disclosed limited guest foothold. Never silently seed access when network-entry
fails. Guest privilege escalation and lab persistence are permitted within the
approved VM targets; destructive malware, real secrets and external targets are
not. Model failure/success must be reported honestly, not assumed from throughput.

Intensity sets a maximum dispatch rate: at most one new action every **60/30/15
seconds** for low/normal/high, with no overlapping attack actions. Actual rate
may be slower due to commands/model work. Work remains bounded throughout the
selected match; completing one objective must not silently end competition.
Preset objectives, trusted verifiers, command length/output/time limits, action
budgets and current owned inventory remain authoritative. Persist intent before
dispatch and reconcile unknown outcomes; never blindly replay after a crash.

All application model calls share one bounded gateway. Guided hints have priority
over queued attacks, which have priority over report work; an in-flight call is
not preempted. Use bounded prompts/context and schema-valid outputs; unavailable
endpoint or repeatedly unusable attack responses get at most **three attempts**,
**60-second** call timeouts and **5/15-second** retry delays. Show degradation
while the clock continues; exhausted recovery interrupts/preserves the match.
No undisclosed scripted attacker replaces the AI. Verify compatibility and timeout
suitability with the actual endpoint before deployment.

The inference server is inference-only: no llama.cpp built-in shell/file tools,
agent mode, MCP execution, host mounts or infrastructure credentials. No extra
embedding model is needed. Reports retain a deterministic evidence-based path
when narrative generation is unavailable; retries produce versioned outputs.

Retain evidence-linked red/defender timelines, justified MITRE ATT&CK/NIST CSF
mapping, observed misses/wins and a failure-prioritized study list. Declared
techniques are not automatically observed techniques, same-host activity is not
automatically defender investigation, and absence of captured response is not
proof of intent. Real human usefulness remains a release gate, not a text-presence
test or an LLM-authored claim.

Guided mode may offer hints and optional attacker visibility. Competition exposes
service health/scores/injects, but no hidden attack commands, thoughts, objective
progress, agent memory or mid-match debrief. Apply the policy to every relevant
API (including raw events, scenario details, hints, reports, replay and exports),
CLI path and storage access—not merely hidden buttons. Reveal eligible attack
evidence after finalization. Operator-only troubleshooting is explicit authority.

## Operations and acceptance

Retain reports, scoring evidence and recordings until explicit operator purge;
no automatic eviction or retention-driven app-role event mutation. Display usage
and block new sessions when safe evidence storage is unavailable. Purge/archive
is an explicit offline operator procedure with scoped targets, export/backup and
confirmation, not a normal runtime capability. Preserve usable history and make
missing/removed replay artifacts visible.

Back up database, recordings and required manifests together to operator-selected
protected storage; the lab has no NAS credentials/path. Validate consistent
restores to a disposable stack, including recording references and historical
scores. Document startup ordering, service identities, TLS trust, migration,
time synchronization, credential rotation, quotas, interruption, storage/model/
PVE outages, emergency stop/release and boot persistence. Runtime services never
hold owner-DB credentials. Readiness is stronger than HTTP liveness.

Acceptance is layered: infrastructure-free tests; disposable PostgreSQL and
forward migrations; real adapter/SSH/namespace/systemd boundaries; privileged
isolated packet proofs; built-web browser E2E; then operator-approved R740
transport/isolation/clone/telemetry/model/backup gates and unaided human practice.
Required CI gates fail when prerequisites are missing. A skip, fake callback,
fabricated audit record or green helper test never closes a stronger boundary.
Validate dependency advisories and patch supported packages before release.

## Decisions and why

| Chosen | Rejected / deferred | Why |
|---|---|---|
| Canonical AGENTS, architecture, roadmap and current evidence/runbook | Multiple master plans, audit handoffs and completion claims as authorities | One current contract; history remains in Git; no contradictory checkmarks |
| Whole-release docs now, milestone plans one at a time | Writing every detailed implementation plan up front | Validate each plan against the code produced by preceding milestones |
| Linux-first, two presets and bounded controls | Windows-first or free-form topology builder | Deliver a real competition loop without unbounded image/network combinations |
| One active environment; preserve member history | Concurrent ranges and real-time team collaboration | Fits the existing durable lease and initial operator requirement |
| Existing Qwen endpoint for all model work | Separate GPU box assumption, embeddings/RAG requirement | Matches actual R740/LXC deployment and current SQL evidence retrieval |
| Full lab VMs and private restricted non-AI provisioning | Lab LXCs, host-root credentials, model-controlled Proxmox or host nft commands | Stronger separation from the host while preserving one-click practice |
| Permanent operator-managed isolation plus VM hard-stop | Runtime privileged host-firewall automation as the emergency dependency | Keeps host administration with the operator and an independent stop path |
| LAN IP/port, same-origin HTTPS, self-signed trust instructions | Public hosting and browser calls to the visiting user's localhost | Matches first-release network scope and avoids mixed-content/CORS traps |
| Operator-managed accounts/public keys | Self-registration, private-key uploads and key-management UI | User delegated easiest secure onboarding; aligns with existing bastion model |
| Explicit Begin button after readiness | Charging deployment time or unexpected automatic attack start | Defender can connect before the match starts |
| Server clock; 15-minute ready idle expiry; interrupt on API restart | Browser-owned timers and silent automatic restart of attacks | Reconnect-safe accounting and conservative recovery |
| Explicit network-entry and assumed-breach modes | Hidden foothold fallback or fabricated AI exploit success | Preserves realism and honest learning value |
| Guided and competition visibility policies enforced by APIs | Merely hiding attacker UI elements | Hints support learning without leaking competition spoilers through endpoints |
| Separate three verified scores; advisory written feedback | Arbitrary combined weights or LLM-awarded technical points | Deterministic, understandable results without overstating AI judgment |
| Stop/preserve on scoring outage or exhausted model recovery | Quietly continuing an apparently normal match | Avoids misleading completed competitions |
| Capture before automatic cleanup, indefinite evidence by default | Holding VMs indefinitely or silently deleting old evidence | Reuses the one environment while preserving review/history |
| Preserve/retest existing boundary repairs | Framework rewrite or reverting containment to satisfy stale tests | Existing architecture is useful; correctness must be independently demonstrated |
| Fast infrastructure-free pytest default; explicit required integration layers | Broad default with prerequisite skips mistaken for acceptance | Predictable local feedback; required jobs fail for missing prerequisites or empty selection |
| DB/containment layer membership derived from the fixture closure; one acceptance harness (`infra/dev/acceptance.py`) per gate | Hand-maintained markers that can leak a prerequisite; per-gate ad-hoc command lists | A test cannot claim to be fast while using the DB; one real-command entry point developers and CI share |
| Disposable PostgreSQL 16 Docker fixture locally; standard GitHub Linux VMs for privileged tests | Implicit existing DB access or privileged containers on the development host | Own and clean up only synthetic test resources; keep kernel-boundary setup off shared hosts |
| Verify free Actions allowance and a zero-spend blocking budget before expanded CI runs | Authorizing paid usage through the milestone plan | No paid usage approved; unavailable CI leaves acceptance pending |
| Patched stable Next 16, existing Pages Router and React 18 where compatible | Unsupported Next 14, short-lived Next 15 bridge, or UI rewrite | Longer support runway with focused build/workflow/replay validation |
| Zero high/critical frontend production audit findings | Unapproved non-applicability exceptions | Clear dependency gate; document lower-severity applicability separately |
| Isolated browser build, configurable ports and pinned local CLI with run-owned session | Reusing an API-URL-baked developer build or default browser session | Test the intended backend without displacing services or closing another browser |
| Stop milestone 01 acceptance for agreement if a genuine safety defect emerges | Weakening regressions or silently absorbing milestone 02 | Test hygiene cannot conceal defects or expand production safety scope without approval |
| Boundary re-root by **binding** the operation's own cgroup dir onto `/sys/fs/cgroup`; CI's unprivileged boundary runs under a real confined AppArmor profile (explicit allows + `/** rix,`) | Fresh cgroup2 superblock mount inside the userns; `flags=(unconfined)` profile or the global `apparmor_restrict_unprivileged_userns=0` sysctl | 6.8-era kernfs refuses superblock creation from a non-init userns (bind works on every kernel); unconfined-state creators are transitioned into the restrictive `unprivileged_userns` profile, and the sysctl would weaken the whole host |
| asciinema-player 3.17 with explicit `preload: true` | Relying on the legacy load-at-create behaviour | 3.17 made loading lazy — a paused player never fetches the recording without preload, and a seek issued before the driver exists is silently dropped; the replay page and browser gate depend on observable load |
| Separate broker VM, private mutual-TLS API channel and broker-owned SQLite ledger | Shared application/broker VM, app-DB-only emergency inventory, worker broker credentials | Separates host authority and preserves known ownership/stop obligations during application DB outages without another database server |
| New dedicated range VLAN; no range access to inference LXC | Sharing cyber-testing VLAN 30 or opening the model port to attackers | Protects existing lab workloads; model calls originate on the trusted control plane |
| 5-second control heartbeat, 30-second lease expiry then latched owned-VM hard-stop | Operator-only reaction to control loss or automatic attack restart | User delegated the outage choice; prefer interruption to potentially uncontrolled surviving work |
| Offline verified attacker enrollment and legacy reconciliation | Name/tag auto-adoption or requiring deletion of all existing deployments | Includes the fixed SSH attacker in emergency inventory while preserving evidence and deferring real images to milestone 03 |
| Local model shell execution only in isolated harmless fixtures | Normal development local-dev execution on credential-bearing machines | Development mode must not turn model commands into control-plane administration |
| Operator-selected separate SSD or verified suitable NAS with calculated capacity budget | Lab disks on Proxmox boot filesystem or guessed fixed disk requirements | User retained the boot-storage restriction; final sizes depend on image/clone/evidence inputs |

## Risks and explicitly unverified inputs

- Same physical host retains hypervisor/resource-contention risk even with no
  host-root credentials; validate isolation and keep host/guest software patched.
- Real PVE permission/clone semantics, storage performance, bridge topology,
  guest host-key provisioning, protected containment and installed auditd capture
  are not yet accepted. Their milestone plans must specify the verified mechanism.
- Qwen alias/context/structured-response compatibility and reliable attack
  behavior are unverified. Do not equate tokens/second with exploitation skill.
- Milestone-01 tests/dependencies now pass locally and in CI; independent review
  at `27e2624` reopened acceptance for browser-build isolation and an edited
  historical migration. These are plan-compliance gaps, not proof of unsafe
  production migration SQL. Live/hardware boundaries remain unaccepted.
- Exact preset vulnerabilities/baselines, rubric points, inject schedule values,
  action budgets, schema/API changes, health-detector thresholds and deployment
  service/storage configuration will be designed and agreed in their milestone
  plans. They are deliberately not guessed here or presented as existing code.
