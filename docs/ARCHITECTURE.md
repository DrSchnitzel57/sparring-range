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
| Provisioning | Typed broker calls (`infra/broker/`); API holds no PVE credentials (milestone 02) | Complete Linux image/service/data baselines (milestone 03) |
| Safety | Persisted latch, runner supervisor, static isolation + broker VM hard-stop with read-back (milestone 02) | Validate containment on the operator host; live hypervisor-backed emergency gates |
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

### Paired milestones 03+04 (approved 2026-10-12)

This is a specific exception to separate milestone planning, not permission to
combine later work. Plan: `.openchamber/plans/03-04-linux-guests-capture.md`.
Separate image/deployment and installed-capture/access gates remain mandatory.

| Chosen | Rejected / deferred | Why |
|---|---|---|
| Ubuntu Server 24.04 LTS cloud-image provisioning; pinned source checksum, package/artifact manifests and retained build inputs | Repairing the broken optional Packer path; unpinned package resolution treated as reproducibility | One supported build path, rebuilt and boot-tested from recorded artifacts; retire Packer explicitly |
| New `mojang-web-01` and `mojang-web-db-01` IDs; local nginx/Python guest app, PyMySQL for the DB-backed variant | Reinterpreting legacy IDs/snapshots; actual Minecraft server, Microsoft login or proprietary assets | Preserve history and keep the agreed HTTP/MySQL scope; label all business data fictional |
| Three catalogue entries (Minecraft, Dungeons, Legends), twelve fixed fictional purchase records; web-only local data, web+DB reads MySQL | Disconnected web/DB services; raw live MySQL disk hashes | Useful business transactions and stable logical data checks; pinned seed artifact defines exact IDs/rows/prices |
| Deliberately vulnerable diagnostic feature runs as limited web user; misconfigured guest maintenance helper allows guest-root escalation | Old vulnerable OS packages or hidden foothold fallback | Reproducible documented attack paths and defender repairs; patched base packages, no external targets |
| Network-entry has no target capability; assumed-breach has only disclosed web-user access; defender account has full guest sudo | Initial attacker root/DB administrator access; shared defender/verifier keys | Separate role identities and explicit start contracts; control secrets never enter attacker/model execution |
| Fresh attacker clone each session, fixed network destination bound to current ownership/generation | Reusing a potentially compromised attacker disk | Stop/reset/cleanup cover the attacker as well as targets; no stale runner pins or operations |
| Fresh clone host keys/machine IDs; broker reads only `/etc/ssh/ssh_host_ed25519_key.pub` through the PVE guest-agent file-read API during initial provisioning | Shared template host keys, TOFU/keyscan, arbitrary paths, guest exec, host shell or re-pinning after compromise | Trusted hypervisor channel to the positively owned fresh guest; enforce bounded key parsing, exact identity/generation and pin invalidation on reset |
| Require narrowly scoped `VM.GuestAgent.FileRead` on approved lab resources; block unsupported PVE versions/ACLs | `VM.Monitor` or `VM.GuestAgent.Unrestricted` fallback | Current published PVE API supports FileRead separately; actual installed version and effective denial tests remain operator prerequisites, not assumed proof |
| Bake only operator public access keys into protected build inputs, never private keys/live tokens; separate provisioning/verifier and bastion keys | Credential-bearing image builds or relying on implicit SSH-agent identities | Pinned management provisions per-generation secrets; bastion uses explicit guest credentials; guest root can forge guest telemetry, never independent score truth |
| Full and linked clones selected explicitly by operator policy; template/resource/storage/NIC validation before start | Hard-coded linked clones, automatic fallback, declared-but-unused budgets | Test both modes, reject mismatches, reserve aggregate budgets before effects; all uncertainty retains durable obligations/lease |
| Each guest: 2 vCPUs/2 GiB RAM; attacker/web/DB disks 16/12/16 GiB | Assuming live storage capacity or resizing to get green tests | Larger range totals 6 vCPUs/6 GiB/44 GiB disks; templates/control/evidence/reserve are additional; enforce actual PVE read-back and operator-owned CPU ceilings |
| Durable audit-input tracking, spool replay/dedup and visible unrecoverable gaps; 64 MiB spool, 32 MiB/cast | `tail -n 0` restart loss; silent truncation or stronger attribution claims | Installed fixture tests real auditd/systemd under srshipper, rotation, outages/crashes and recovery; preserve source identity/order |
| Protected durable shared recordings directory for API/bastion | New recording-transfer protocol | Fits current shared-volume model; explicit permissions, pinned SSH/revocation/resize/reconnect/restart/replay and missing-file checks; production packaging stays in 10 |
| Required QEMU VM gates: max three VMs/6 GiB guest RAM, 60-minute job timeout; KVM optional, software emulation supported | Shared-kernel auditd fixtures, installing auditd on this host, privileged live-lab testing | Boot actual artifacts with isolated networking, run-owned disks and synthetic secrets; missing prerequisites/skip/cleanup failure blocks acceptance, never touches R740 |

Image builds may fetch pinned inputs in a separate build phase. Practice and
negative-path tests run without general egress; only narrow synthetic control
paths are allowed. QEMU serial-console bootstrap is a test-only trusted transport,
not proof of real PVE guest-agent permissions. Production PVE adapter behavior is
tested with simulated API responses until operator-authorized live checks.
No model-driven attacks precede real isolation/emergency gates. No paid CI usage
is authorized; verify the existing free-allowance/$0-budget operator prerequisite.
Match controls/timers, ongoing availability scores, injects and dashboard changes
remain milestones 05 onward. The attacker start-condition artifact contract is
implemented here; full member controls and sustained AI behavior remain later work.

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
| Broker intent keys carry the deployment generation; ledger claims carry session + generation | VMID- or name-keyed idempotency alone | A reset legitimately re-clones the same VMID; a retry of the same generation must never double-clone, and cross-session mutation is structurally refused |
| Cessation spares a claim whose VM reads back with a foreign name (VMID recycled) and retains an obligation | Blindly stopping everything ever claimed | Stopping a machine that is provably not ours is not cessation; the operator resolves the mismatch |
| Runtime `datapath_controller=nft` removed; `StaticIsolationDatapath` + broker VM stop are the runtime layers; `NftDatapath` stays operator-script/packet-test machinery only | The application executing nft/host commands at runtime | The release decision keeps host administration with the operator; the runtime cannot execute privileged host commands at all |
| Required `authority` acceptance layer (real policy/ledger/mutual-TLS/cessation tests, infrastructure-free) | Mocked broker boundary or CI-only coverage of these invariants | The private-boundary and fail-closed invariants are checkable without PVE and must gate every run |
| FastAPI generator dependencies pinned to `scope="function"` (one shared `DbSession`) | Default request-scope generators committing after the response | FastAPI ≥ 0.142 closes request-scope dependencies AFTER the response is observable; the intermittent CI handoff failures (login 401 after bootstrap 201, launch 404 after create 201, M01-R4) were that race — a 2xx must imply durable writes |

### Tomorrow pilot (authorized 2026-10-13, cross-cutting exception)

Plan: `.openchamber/plans/12-tomorrow-pilot.md`. Accepts no milestone; the
decisions below are pilot-scope and stand unless a later milestone plan
revisits them with evidence.

| Chosen | Rejected / deferred | Why |
|---|---|---|
| ONE durable end/expiry path (`lifecycle.finalize_match`) shared by user end, deadline, idle expiry and startup reconcile; `finalizing` is a durable intent marker the scheduler retries | Request-scoped best-effort cleanup; separate end vs expiry code paths | A crash or blocked step mid-cleanup must leave a retryable intent; unknown cleanup is never reported as success |
| End/expiry destroys owned VMs and releases the lease; a failed destroy keeps the lease and stays visible for retry (R07 invariant retained) | End retaining machines behind a separate explicit teardown (previous pilot behavior) | Take-turns demo needs the range free immediately after a match; the reservation invariant only binds while a machine still exists |
| Server clock is the only match authority: preset/duration/pace SNAPSHOTTED at session creation; Begin binds `started_at`/`deadline_at`; duplicate Begin can never extend | Client-side timers; re-reading preset parameters mid-match | The match must end at a deterministic server deadline and behave identically from every client |
| API restart INTERRUPTS running matches and reconciles cleanup; never resumes | Silent resume of attacks after a restart | Attack workers are children of the API; resuming without supervision would be unmanaged execution |
| Sustained attacker runs to the deadline (objective completion never ends the match); per-action throttle from the snapshot; gateway retry 3×(5 s/15 s, 60 s timeout) then truthful interrupt | Fixed 20-step or complete-then-stop loop; infinite retry | Practice is continuous pressure under a fixed clock; a broken model endpoint must surface as `model_unavailable`, not a hang or a fake success |
| Uptime samples in a dedicated append-only table (app role SELECT+INSERT only); score = % up among VALID checks with unknown first-class; zero valid ⇒ unscored; confirmed probe-infrastructure failure INTERRUPTS the match | Folding uptime into the security scorecard; counting unknown as downtime | Separate honest scores; a broken probe must never fabricate downtime |
| Bastion dials guests as `defender` with its own keypair (public half baked at template finalize, rotated per generation); SSH instructions served by `GET /sessions/{id}/connections` | Implicit root dial default; browser sessionStorage holding connection secrets | Least-privilege guest identity; instructions survive refresh/other devices without browser-resident secrets |
| Scheduler thread + startup match reconcile opt-in (`SR_MATCH_SCHEDULER_ENABLED=1`, production env only) | Always-on background cleanup in every process | Shared-database test processes must never run destructive background cleanup against other sessions' fixtures |

### Plan 13 release amendments (approved 2026-10-14)

Plan: `.openchamber/plans/13-live-deploy-hardening.md`. The user explicitly
amended the release contract as follows; these amendments are authoritative
over older prose in this document and the runbook.

| Chosen | Rejected / deferred | Why |
|---|---|---|
| One combined, phased full-release plan (plan 13); the 4,800-character and one-milestone limits are waived for it; its number is not the roadmap's Windows milestone number; existing acceptance states unchanged and 03/04 keep separate evidence gates | Rewriting the plan as ten separate milestone plans | The operator needs one coherent implementation contract for the end-to-end install/rehearsal goal; splitting would hide cross-phase dependencies |
| Fresh installation only: the operator removed the old sparring-range installation; **only the network bridge remains**; no service-VM cutover or migration requirement; unexpectedly discovered resources/evidence are preserved and never assumed owned from a name or empty DB | Designing a cutover/migration path for the deleted installation | Reproducible setup replaces tribal knowledge; ownership must still be positively established before any mutation |
| Scoped, deterministic **operator-run** PVE bootstrap tooling (dry-run, reviewed resource manifest, explicit confirmation, idempotent create/reuse of approved service VMs, templates, roles, ACLs); runtime authority stays restricted; agents never receive host/root credentials | Fully unattended host administration or ad-hoc ACL editing | Bootstrap needs PVE administration the operator must review and execute; improvising ACLs at runtime violates the boundary |
| Storage suitability proven by **measured** capacity, I/O suitability, quotas and Proxmox/system headroom (installer pre-flight inventory: absent/matching/conflicting/unreadable, refusal before side effects) | Requiring dedicated non-boot disks, or trusting a storage label such as `local-zfs` as capacity proof | User amended the earlier boot-disk restriction; numbers measured at install time are the real safety property, and unrelated disks are never wiped/resized to meet them |
| Automatic backups plus a documented restore procedure, with unconfigured/unverified backups reported conspicuously; backup setup and restore verification are **not release-blocking** | Dropping backup tooling, or reporting unverified backups as protected recovery | User retained the tooling but waived it as a gate; honesty about recovery state is still mandatory |
| One versioned non-secret release manifest (`deploy/manifest.example.json`, validated by `infra/release_manifest.py`) as the single deployment input; every consumer (env, broker policy, services, templates, installer) is derived from it; secrets referenced as local protected paths only | Drifting hand-edited env/policy/script copies | Derivation plus validation makes manifest/consumer mismatch structurally impossible and keeps secrets out of Git and rendered artifacts |

### Plan 13 implementation decisions (2026-10-14, branch `plan-13-implementation`)

#### Review rounds 3–4 (2026-10-15): what changed under reviewer pressure
- Executor liveness = the live `OperationClaim` owner (takeovers never
  touch old rows, so row-fence comparison was vacuous) + conditional
  `UPDATE … WHERE state IN (accepted, running)` for every terminal and
  phase write (identity-map staleness made read-check-write racy).
- Competition filtering is centralized (`srplatform/api/visibility.py`)
  across events/live/scorecard/agent-memory/AAR/hints; replay stays
  unfiltered (first-party shell transcripts, no red internals present)
  and scenario red objectives stay catalog-public (the published threat
  model defenders must know pre-match).
- PVE grants are per-VMID enumerated (templates + bounded clone window;
  destroy has no pool alternative per the PVE 9.2 audit) with a split
  storage role; the `/vms`-wide grant is gone, proven by dry-run output
  assertions.
- The installer renders what the non-secret manifest determines (broker
  policy, topology/URL/model/trust env facts); secrets stay operator-owned
  and the example no longer overrides derived values. TLS identities are
  pair-checked, preserved across reruns, and rotate only explicitly.
- Assumed-breach = snapshot start-phase rewrite + Begin proof executing
  as web-user + worker context seeded via agent_state (the red loop
  restores phase/summary from it at startup).
- MySQL truth is triangulated: loopback business transaction (correctness)
  + web-origin network-path transaction (service path) + controller TCP
  greeting (no guest code runs) + loopback/via count cross-validation.
  Perfect observation of a fully compromised guest is impossible;
  disagreement is reported as integrity failure, never averaged.

| Chosen | Rejected / deferred | Why |
|---|---|---|
| Range guests are **on-link only**: the typed broker policy refuses any `gw=` in `ipconfig0`; every legitimate target (controller range address, bastion, peers) is on-link | Keeping an operator-configurable gateway on clones (a default route is a WAN/management egress path by construction) | Isolation must be impossible to defeat from guest configuration; the plan demands default-route removal via typed policy, not firewall hope |
| Role-scoped template keys (runner→attacker only, bastion→defender guests, mgmt account, separate explicit emergency), deduplicated, private material refused at build time | One operator key baked into every account on every guest | Lateral compromise of one principal must not authenticate to every guest; break-glass stays an explicit decision |
| Web and DB are **separate production-shaped artifacts** (DB payload ships no web app; role-conditional units/firewall/verify; per-role overlay cache keys), wired at deploy time to owned IPs with fresh per-deployment reader credentials | The documented superset overlay running one all-in-one app on both tiers | The plan forbids a second all-in-one app as the "DB tier"; deploy-time grants/listener/firewall narrow to owned sources only |
| Base image pinned to the **dated retained** cloud-image directory with checksum+size enforced; missing pin fails closed | The moving `noble/current` alias | Reproducibility: the artifact a build used is fetchable byte-identically later |
| Settings accept both the bare field name and the documented `SR_*` name; every shipped example key is proven effective with non-default values | Silently ignored example settings (the plan-13 baseline showed `SR_MATCH_*` ignored) | A setting that looks configured but is ignored defeats every downstream gate |
| Telemetry HTTPS with an explicit verified SSL context and the public CA provisioned into guests; production refuses http/localhost/missing-anchor APIs | Disabling TLS checks or trusting a system store nobody provisioned | Enrollment capabilities and audit evidence cross the range; verified trust is the authentication |
| Durable `deploy_operations` rows (identity, fence, phase, deadline committed before effects) + startup reconcile to `interrupted` before claims clear; redacted polling endpoint WITH the completed result. Lifecycle routes return **202** after synchronous durable acceptance (claim + row + lease/preconditions); the supervised executor (`deploy_executor.py`, own DB session, fence-owned) runs deploy/reset + readiness + capabilities, records redacted outcomes (plaintext enrollments NEVER persist), and always releases the claim — a lost response or restart can neither duplicate a deployment nor erase the first attempt | Fire-and-forget synchronous launches whose evidence dies with the response; a half-built async executor changing every client contract in one step | A lost response or restart must never duplicate a deployment or erase the first attempt — that is the safety property; non-blocking UX adds no safety and can land later without migration |
| `install`/`release` gates FAIL without their real fixtures (service VM / deployed lab); sandbox passes are reported as sandbox passes | Accepting a sandbox or a skip as release acceptance | Green must mean the contract ran; prerequisite absence is a loud failure, never a pass |

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
