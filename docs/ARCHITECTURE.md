# Architecture — Linux-first CCDC practice release

## Workflow decision — native OpenChamber (2026-10-28)

Chosen: native planning, saved Plans, Todos and task-selected model roles. The
master chat may coordinate sessions; validation is proportionate to the task.
Rejected: the global procedural rulebook, fixed milestone/plan sizes, prescribed
branches/models/review loops and output formats. These duplicated maintained
platform behavior and accumulated stale exceptions. This supersedes procedural
language below and in historical plans, not product dependencies or safety gates.
Project Knowledge Todos hold actionable work; this document holds design and
the findings ledger holds durable evidence. Old plan identifiers/paths are kept
for traceability, without requiring future milestone numbering. Historical agent
receipts are in [AGENT_HISTORY.md](AGENT_HISTORY.md). No product acceptance was
advanced and no application/live tests were run for this documentation cleanup.

Status: **agreed release design, not a claim of implemented or deployed behavior**.
**Current direction: Ubuntu/KVM appliance, selected by the user 2026-10-20.**
Read [the appliance contract](#ubuntukvm-appliance--2026-10-20) first. It overrides
older direct-Proxmox deployment decisions below; retained release features and
safety invariants still apply. Later implementation and commissioning receipts are
in the findings ledger; approved upgrade plans 18–21 remain outstanding.
Agreed 2026-10-08. Application baseline: `23de4f4`.

Read [ROADMAP.md](ROADMAP.md) for implementation order,
[FINDINGS_CHECKLIST.md](FINDINGS_CHECKLIST.md) for fresh evidence and open risks,
and [OPERATOR_RUNBOOK.md](OPERATOR_RUNBOOK.md) for operator prerequisites.
This document replaces `plan.markdown` and the overlapping architecture/audit
handoffs. Historical evidence remains in Git; old completion checkmarks are not
release acceptance. Saved plans remain implementation agreements, not a required
one-milestone-at-a-time process.

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

Current agreed redesign requirements and unselected framework research are in
[the 2026-10-23 decisions](#j-local-conversation-engine-admin-settings-and-session-review-2026-10-23).
They supersede interim small-output-budget assumptions, not safety authority.

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
| Serve only the FULL broker-pinned key (`host_key_pin`) to the bastion; the truncated `host_key_ref` is display/evidence-only, and a malformed pin is refused before any dial | Serving the display ref (or any unvalidated value) as the dial trust anchor; TOFU or stale copied files | Live find 2026-10-16: an unparseable known_hosts line is silently dropped by asyncssh, so every dial failed `HostKeyNotVerifiable` while the deployment reported ready; a fail-closed refusal makes that class loud, and the real-dial regression test (real server, real host-key verification) makes it unrepeatable |
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

### Plan 20 implementation decisions (2026-10-27, branch `practice-upgrades-18-21`)

| Chosen | Rejected / deferred | Why |
|---|---|---|
| Coach chat rides a durable `kind="coach-chat"` model job; the member message persists BEFORE enqueue, and the evidence cutoff + allowed citation ids freeze AT ENQUEUE (citations outside the window are dropped; prose persists verbatim) | Answering inside the request, or re-reading the live window when the job runs (a later enqueue could cite events the turn never saw) | A reload must never lose an answer, and an answer may only cite the evidence its own turn was authorized to see |
| Timed output capture is a SECOND consumer of the command stream with its own larger quota (`runner_op_capture_bytes`), fed byte-for-byte inside `_bounded_reader`; emit failures and cut-offs become counted gaps, never exceptions; the server re-enforces the quota with unique `(run_id, op_id, seq)` | Raising the model-context bound and "replaying" the first-4000-char action results (they never contained later bytes) | What replay stores must not shrink what the model sees (or vice versa); the worker's honesty can never be the only fence |
| The replay operations track pairs ONLY `action_intent`/`action_result` events by `op_uuid` — attacker provenance by construction | Heuristically attributing telemetry/auditd commands or verifier traffic to the attacker from host-side evidence | Host telemetry can be forged or ambiguous; identity assignment needs the authenticated boundary that emitted the event (plan §implementation), so unknown stays unknown |
| Replay/sessions are cursor-paged projections (timeline page, cast SUMMARIES, per-operation chunk paging) with the sessions list returning honest `interrupted/unscored/cleanup_pending` flags from batched probes | One endpoint that returns the whole audit, every cast blob and per-row scans | A session view must never download the whole evidence store, and the dashboard may only claim flags the database can prove |
| Sealed competition members get NOTHING red through ANY new door (replay timeline phases, `operations: []`, output `{"hidden": true}`, coach sees only visibility-filtered events) | Hiding the replay tab client-side, or filtering only the timeline | Enforcement belongs in the API; tests prove each door leaks nothing |
| Markdown for coach/AAR is a React-node renderer (`web/lib/md.js`): raw HTML is structurally impossible, links are http(s)-only, `#<event_id>` citations deep-link the authorized Activity view | `dangerouslySetInnerHTML` + a sanitizing library (new dependency, and a sanitizer is a denylist) | XSS-safety proven in the real browser (script/onerror/javascript: stay literal text), and citations stay inside the visibility model |

### Plan 20 review-round decisions (2026-10-27, branch `practice-upgrades-18-21`)

The independent review (VERDICT FIX at `28b1f8b`) reproduced eleven
defects; every root fix and its counterexample are receipted in
`docs/FINDINGS_CHECKLIST.md`. The durable design choices:

| Chosen | Rejected | Why |
|---|---|---|
| Coach threads are audience-partitioned: `coach_messages.audience` (`member`/`operator`, server_default `member`, migration 0026) and each principal reads ONLY its own thread — history, pending list (payload `chat_meta` filtered server-side) and reload alike | One shared session thread with role-flavored rendering (the reproduced leak: an operator's sealed coach answer's follow-up prompt could resurface to the member view) | A conversation the other side authored is other-side content; the audience column is append-time and immutable, matching the append-only discipline |
| Capture persistence leaves the pipe reader entirely: a bounded queue + ONE lazily-started daemon consumer with an idle exit and a bounded `finish()`; the reader only enqueues (never blocks on HTTP), producer-side monotonic `seq`, lost-ack retries reuse seq+content, and the endpoint answers `stored/duplicate/conflict/quota/error` idempotently | Feeding capture from the reader (a hung endpoint then stalls the deadline path and the whole loop, as reproduced), or client-side sequence guessing (a retried chunk renumbered and silently overwrote or duplicated a neighbor) | The deadline machinery is safety-critical; capture is durable-bests-effort and must degrade to a counted gap, never to a stuck reader. Idempotency needs an identity both sides agree survives an ack loss — producer seq does |
| The server charges EVERY payload byte (output, gap, truncation marker) against per-op and per-session budgets under a session-row `FOR UPDATE`, with a durable row cap and a unique partial index making the one-time `truncated` marker race-proof | Trusting the client to stop before quota, or checking rows/bytes non-atomically (concurrent writers each passed the check and overshot together — reproduced) | Quota is a server invariant under concurrency; admission control without a lock is a suggestion |
| Citations are an allow-list end-to-end: the server approves only ids present in the RENDERED compressed timeline (what the model was actually shown) and the UI links only per-message `citations`/`approved_citation_ids`; everything else renders as an honest unverified label | Validating against every id that existed in the window but was compressed away (the reproduced defect: the model cited events it never saw), or trusting model prose to only contain real ids | A citation is a claim "this evidence exists and I saw it"; both halves must be enforced by the platform, and rejection must stay visible, not silently rewritten |
| The replay clock is the session clock; the defender player is explicitly EPOCH-OFFSET (`player_time = session_clock − (cast_epoch − t0)`), seek/drift-correct only inside the cast, and the player's own `getCurrentTime()` is surfaced for acceptance | Assuming the cast epoch equals the session start (the reproduced failure: attacker evidence before the cast start shifted the player off every defender frame) | The two clocks coincide only by accident; the offset is a first-class value (rendered in the UI) and browser acceptance asserts the PLAYER's reported time, not bookkeeping |
| Chunk placement uses the observed pipe `read_ts` (persist `ts` is the labelled fallback; merge window 0.25 s with honest `timing_precision_s`/`read_timed` fields) | Placing output at persist time — under any backpressure it systematically renders LATE, and the replay silently lies about when output actually appeared | A review surface is a timing claim; it must carry the timing it actually observed |
| Replay pages are three separate bounded tracks (timeline / casts / operations, each with a server cursor; `/replay` itself carries NO cast bodies and NO operations, only counts) and the panel loads them lazily only as the clock needs them, advancing on the RAW consumed cursor | Fetching every cast and operation per page load (the reproduced O-everything read), or client-side cursors over collapsed rows (a collapsed noise run re-consumed its whole folded range every page) | A bounded view must stay bounded regardless of session size, and a cursor must describe what the SERVER consumed, never what the client displayed |
| The dashboard's `interrupted`/`cleanup_pending` flags derive ONLY from durable lifecycle facts (session status/outcome, `matches.state`, `runs.status='cancel-unknown'`, unresolved `run_operations`) | Prose LIKE-probes over `agent_note` (the reviewer's repro: a completed session with an interrupted match and a durable teardown fact showed no warning because the note text didn't match) | A warning is a fact or it is absent; narrative matching both under-reports and invites wording drift |
| Operations-track provenance is a QUERY-level filter (`actor='red'`, set from the session-bound worker token) — management/system/verifier events carrying or nesting an `op_uuid` stay on the timeline with their real provenance and are never promoted; a lone historical result renders as an explicitly INCOMPLETE operation, and `/replay` replays no cast/operation bodies at all | Pairing ANY event whose payload mentions an `op_uuid` (reproduced: a system event forged into the attacker track), or 500-ing/fabricating on orphan history (pre-capture rows exist) | Attribution follows the authenticated boundary that emitted the event; history that predates capture must display its own absence honestly |

## Ubuntu/KVM appliance — 2026-10-20

### Status, goal and precedence

The user selected **option 2: one Ubuntu VM running KVM/libvirt and the product**,
and authorized a full start-to-finish plan with the fewest manageable milestones.
This supersedes direct-PVE provisioning, the separate broker VM, remote broker
mTLS, per-PVE-VMID ACL maintenance and an outer range VLAN for this release.
The detailed design below and plans 14–16 are drafts for approval; choosing the
architecture does not authorize code on master or live infrastructure changes.

Discovery: `933f6a1`, initially clean master equal to origin/master. Source was
inspected; tests were deferred by the user and the started baseline cancelled.
**Deployed member SSH has never worked successfully**, per the user. Fix commits,
old test totals and ready flags do not prove access. First prove a fresh nested
guest through the real member/bastion/replay chain, then a second fresh deployment.

Complete individual practice remains the product: one active environment, two
Linux presets, all match options, real services, AI attacks, injects, three
separate verified score components, recorded SSH, coaching and persistent history.
No deadline-driven feature cuts. Shared-team sessions, concurrent ranges,
Windows/AD, public hosting, browser terminals and extra scenarios remain later work.

### Decisions and why

| Chosen | Rejected / deferred | Why |
|---|---|---|
| One Ubuntu 24.04 LTS appliance, with hardware-accelerated nested full VMs | Vulnerable containers; Proxmox inside Proxmox; continuing outer-PVE provisioning | Preserve real Linux administration while eliminating outer tokens, clone ACL repair and inter-service-VM trust/storage wiring |
| Existing FastAPI/PostgreSQL/Next application and guest payloads | Framework rewrite, Kubernetes, Redis/Celery, generalized multi-cloud abstraction | Most product logic is reusable; change the infrastructure boundary and integrate existing features |
| Local typed broker, separate OS identity and SQLite ownership ledger | Giving the API/model libvirt access; deleting the broker because it is co-located | Infrastructure effects and fail-closed cessation remain independently supervised |
| Three milestones: working nested access; complete practice; packaged/rehearsed release | One giant coding assignment or many small milestone handoffs | Each model gets a coherent deliverable and independently checkable exit |
| Fresh per-generation qcow2 overlays over immutable flattened bases | Restoring dirty running guests; a general snapshot manager | Cheap reproducible reset; simple ownership, cleanup and disk accounting |
| Public access keys in per-instance NoCloud seeds; private keys stay with their consumers | Baking appliance-specific access keys into every image; shared host keys | Key rotation no longer requires rebuilding guest software; each clone generates its own SSH identity |
| One production pin source: broker-proven current guest host key | TOFU, truncated display refs, stale local-known-hosts fallback | Eliminate competing SSH trust paths and preserve generation binding |
| One canonical operator installer and a checksummed release bundle | Ad-hoc per-host shell repairs; two independently maintained install paths | Install, rerun, upgrade and recovery execute the same artifacts |
| Fixed local isolated bridge plus appliance input/forward filtering | Libvirt default NAT, physical bridging, or relying only on missing guest routes | Guest root can add a route, and an isolated libvirt network still reaches its host |
| Preserved historical records with explicit backend identity | Reinterpreting old PVE VMIDs as libvirt domains; maintaining two production backends | Keep history without carrying the old deployment system into the new product |
| **Fresh installation: the appliance starts from an empty database** (2026-10-20, operator decision) | Importing the old PVE installation's history, sessions, accounts or casts into the appliance | The operator installs from scratch, so there is no old history to reconcile in the new database. The old installation and its history stay exactly where they are and are retired by the operator as a separate, explicit decision; nothing is imported, and no legacy branch is kept in the product code. The new deployments still record their own libvirt domain identity, because that is the new backend's own correctness contract, not a migration. |

### A. Topology, resources and outer-host responsibilities

```text
Existing Proxmox (operator controls one appliance VM; no product API token)
  Ubuntu appliance / L1
    LAN: HTTPS web + API; recorded SSH bastion; operator-only administration
    trusted services: PostgreSQL, controller, model gateway, worker supervisor
    private: typed broker -> local libvirt/KVM; independent broker ledger
    isolated inner bridge: attacker VM <-> web VM [<-> DB VM] / L2
    ingest-only HTTPS on inner bridge; trusted SSH/probes originate on appliance
Existing inference LXC: outside the lab; only trusted model gateway connects
```

Candidate outer sizing: 8 vCPUs, 16 GiB fixed RAM, 250 GiB fast virtual storage;
measure capacity/I/O/headroom before accepting it. This is not a claim about
available R740 storage. Retain guest caps: at most three, each 2 vCPU/2 GiB,
16/12/16 GiB attacker/web/DB disks. Budget OS, bases, maximum overlay growth,
build cache, database, casts and reserve separately. Quotas and minimum free-space
checks protect evidence and control services; sparse files are not free capacity.
Guest CPU/I/O limits must leave control-plane headroom. No GPU/device/host-folder
passthrough to L2 guests; they do not receive nested VMX/SVM or /dev/kvm.

The operator creates the outer VM, exposes supported virtualization CPU features,
and verifies nested KVM. `/dev/kvm` existence alone is insufficient: boot an L2
domain using KVM and record actual capabilities/performance. No silent software-
emulation production fallback. TCG remains useful for some synthetic image tests,
but never satisfies the nested-appliance gate. Do not unload host KVM modules,
reconfigure unrelated VMs, or change outer networking from product automation.
If nesting is unavailable, stop for a deployment decision rather than falling
back to containers or restoring outer-Proxmox credentials.

Outer power-off is the operator's independent emergency fallback. No live outer
VM migration, memory snapshots or suspend/resume are supported during practice;
quiesce first. After restart or detected time discontinuity, interrupt and
reconcile, never silently resume attacks. Same-appliance kernel/hypervisor failure
can affect control and guests together; this is an explicit reduction from
separate-broker-VM fault isolation, not a claim of independent hardware safety.

### B. Process and authority contracts

Use managed services and one codebase. Keep web/API business logic in modules,
thin HTTP/CLI adapters, one PostgreSQL database and a singleton controller.
Refuse a second controller before reconciliation. Supervise deployment/scoring/
scheduler loops; surface failed initialization and stale heartbeats rather than
swallowing exceptions and reporting ready. Keep durable operations/fences and
interrupt-on-controller-restart; no distributed scheduler or HA promise.

| Identity | Allowed authority | Explicitly absent |
|---|---|---|
| controller | app-role DB, typed broker socket, verifier SSH, gateway credentials | owner DB, raw libvirt/KVM, outer PVE |
| broker | local libvirt, owned volume area, protected SQLite ledger | app DB/owner secrets, model tools, outer PVE |
| bastion | scoped API capability, defender guest key, shared cast directory | broker/libvirt, verifier key, DB secrets |
| worker supervisor/children | run-scoped API and fixed attacker SSH | controller files, broker socket, DB/model endpoint credentials |
| ingest | authenticated enrollment/audit handlers, narrow persistence access | controller jobs, deployment/model/admin endpoints or keys |
| offline operator | installation, schema migration, key/backup administration | no credentials passed into model-selected execution |

Replace remote broker mTLS with a private Unix socket: strict mode/group, peer-UID
verification, bounded versioned messages and typed requests. Only controller UID
and explicit broker-local operator tooling may invoke their respective surfaces.
Bastion/ingest/worker use distinct UIDs and cannot read controller environment or
connect to broker/libvirt sockets. Directory traversal permissions are tested as
the actual service users. Co-location alone is never the authorization mechanism.

Run the existing per-match worker under a separate fixed-identity systemd worker
supervisor. It claims a durable assignment through the API with its own limited
service capability, receives only a run capability/owned attacker channel and
spawns the supervised child. It cannot choose arbitrary executable/UID/host paths.
Cancellation, heartbeat loss and controller restart fence assignments; broker VM
stop remains the backstop. Do not grant controller general sudo/systemd control
or build a second queue/database. Preserve process-identity-safe child supervision.

Broker owns libvirt authority on a dedicated appliance; do not pretend libvirt
group membership is per-domain authorization. Its typed API is the enforcement
boundary. Only fixed domain/disk/network profiles may be rendered. No user XML,
QEMU arguments, arbitrary file paths, guest exec/monitor commands, host shell,
storage mounts or NIC changes. Ubuntu libvirt/QEMU confinement stays enabled.
The operator installer creates fixed networking/pools; runtime does not execute
firewall commands. Retain the independent 5-second control heartbeat / 30-second
expiry policy, latched stop and broker restart reconciliation.

### C. Backend replacement, identities and disk lifecycle

Introduce a small typed infrastructure contract and one libvirt production
implementation. Keep policy/ownership/fencing semantics, not PVE-shaped paths,
UPIDs, `net0`, numeric VMIDs or template grants. Requests identify session,
generation, role, approved image and operation UUID. Broker assigns domain UUID,
MAC/IP and owned disk paths; persist intent before volume creation/domain define/
start. Bind domain metadata and ledger to an appliance installation UUID plus
session/generation. Verify metadata, disks and network on every mutation. Names
alone never establish ownership; foreign or unconfirmable resources are untouched.

Use maintained libvirt Python bindings and bounded API operations; narrowly fixed
argument-vector image utilities are permitted behind broker validation, never
shell interpolation. Canonical root-owned flattened base images are hash-pinned
and read-only. Create one fresh overlay per role/generation in an owned directory;
reject symlinks/path escape/backing-chain substitution. Serialize base import,
referencing and retirement. Never delete a base referenced by an active claim.
No domain autostart/managed-save or automatic restoration of guest memory.

Lifecycle: reserve -> create overlay/seed -> define -> start -> pin -> provision
-> ready; stop -> verify inactive -> undefine -> remove owned overlay/seed ->
verify absent -> release. Reset creates fresh disks/identity for every lab role,
including attacker. Libvirt events accelerate observation but are not proof by
themselves: use read-back. A missing response/error is uncertain, not absence;
fence late effects, reconcile partial define/delete and keep the reservation.

Forward migrations add backend/resource identity without rewriting historical
events/specifications. Old PVE resources remain explicitly legacy and cannot be
operated on by the libvirt backend. Port provider-independent regressions before
retiring obsolete production PVE paths/settings/scripts. Preserve history and
reviewable test provenance; do not keep a selectable second production backend.

Add broker-local status/reconcile/resolve commands. An obligation closes only
after fresh matching-generation cessation/absence evidence, with actor/reason/
evidence audit. Handle lost domains, destroyed claims, disk leftovers, ledger
corruption, connection failure and foreign UUIDs without SQLite edits. Latch
release is explicit and cannot discard unresolved obligations. Unknown outcomes
remain visible; application range availability and broker obligations must agree.

### D. Network boundary and first-boot trust

One fixed inner bridge, no physical uplink, no forwarding/NAT, DNS relay, DHCP,
default guest route or IPv6 RA. Use deterministic manifest-derived static
addresses delivered through NoCloud. The operator installer owns narrowly scoped
appliance input/forward/bridge rules and their boot ordering. Guests may contact
only the ingest address/port on the appliance and replies to trusted initiated
SSH/probe flows. Deny appliance LAN/loopback-bound services through every interface,
admin SSH, PostgreSQL, web/business API, model endpoint, outer management, NAS,
WAN/DNS/IPv6 and unrelated workloads. Interface-aware rules must resist spoofed
source addresses and guest-added routes; preserve intended guest-to-guest traffic.

Do not use libvirt's default NAT network. An isolated network's label does not
protect host input: libvirt/firewalld defaults may allow host SSH/DNS. Prove
effective rule ordering with real packets, both bridge and routed paths, existing
flows, IPv6 and positive controls. Bind libvirt locally; expose no TCP management
socket. No guest host mounts, socket forwarding or reachable metadata/seed service.
Image dependency fetching happens only in a separate build phase, never matches.

Each sanitized base boots with fresh machine/SSH identity. Typed NoCloud seeds
contain only role-appropriate **public** access keys, network, installation/session/
generation identity and fixed setup instructions. Private keys are generated and
retained only in their consuming service's protected state; generation secrets are
provisioned after pinned management SSH is established. No application secrets or
private host keys in images/seed ISOs. Attach/detach/delete seeds through owned,
reconciled operations; avoid persistent shared build credentials.

Initial SSH trust uses the domain-bound QEMU guest agent through libvirt, not the
network. Broker implements only read-only guest-file open/read/close of two fixed
paths: `/etc/ssh/ssh_host_ed25519_key.pub` and a fixed first-boot completion record
emitted by the image. Bound sizes, handles, decoding and total deadlines; no
caller-supplied path or raw guest-agent command. Completion identifies current
generation; verify domain ownership before/after, stable full key and completed
key generation. Persist the full pin once; later disagreement blocks access.
Never re-pin after exposure/compromise. QGA data is guest-originated, appropriate
for trusted first boot only, never independent scoring truth.

### E. SSH/access is milestone 14's hard promotion gate

Deliver a redacted diagnostic for each hop: member reachability/bastion host key;
member public-key authentication; capability owner/expiry/generation; API callback;
owned-target resolution; full guest pin; guest reachability; defender login key;
PTY/exec/sudo; cast creation/registration/replay. Keep the four identities distinct
in instructions: member key, bastion server key, guest login key, guest server key.
Never suggest disabling SSH verification. The sole production pin comes from
current broker evidence; remove fallback to copied known_hosts files.

Readiness exercises actual bastion-origin pinned guest SSH with its actual UID/key,
recording permissions and installed telemetry. A fixed harmless diagnostic uses
only owned targets and cannot expose arbitrary destinations/commands. It does not
impersonate a member: an actual SSH client must separately prove personal-key login,
interactive/exec/resize/reconnect, sudo and browser replay of known synthetic text.
Reject foreign/revoked/expired keys/capabilities and stale pins; end revokes and
closes active access. Preserve opaque recording IDs, source times, bounded casts,
missing-file/truncation visibility and a protected local API/bastion shared path.

Ship a minimal usable install/access path in 14, not a throwaway boot probe. Its
operator rehearsal is fresh launch -> SSH/sudo/reconnect/replay -> cleanup ->
second fresh launch with different keys/domain identity and no manual key edits.
Nested acceleration/isolation/stop are proved before that rehearsal; attacks stay
disabled. Do not promote to 15 until the operator records this result. Developers
skip manual checks and hand off the blocked promotion explicitly, not waive it.

### F. Full practice behavior retained for milestone 15

Both `mojang-web-01` and `mojang-web-db-01`: patched Ubuntu, fictional catalogue
and twelve fixed purchase records; local-data web or genuine separate web/MySQL
tiers. Preserve documented diagnostic flaw -> limited web-user -> guest-root
maintenance flaw, and verifiers proving repairs preserve business services.
Install systemd/auditd/shipper on every required guest and supervised containment
inside attacker; prove real capture, delivery, permissions, spool rotation/replay/
dedup/overflow/outage recovery. Host telemetry is forgeable, not automatic actor
attribution. Publish scenario/rubric/image/seed versions and defender objectives.

Snapshot approved options: practice/competition; 30/60/120 minutes; low/normal/high
(60/30/15-second sequential action ceilings); injects on/off; network-entry or
disclosed limited assumed-breach. Fixture acceleration/zero pacing is not a member
production option. Launch returns a durable operation; Begin alone starts server
clock, attacks/probes/injects. Ready expiry is 15 minutes; refresh never changes
deadlines. End, expiry, failures and restart share fenced finalization: stop and
confirm, capture trusted inputs/close casts, revoke, destroy, release only after
all owned resources and obligations settle. Report inference cannot hold VMs.

Probe business HTTP/content and authenticated read-only MySQL from the trusted
appliance every 10 seconds with 5-second timeouts. Use maintained PyMySQL instead
of the homegrown SQL wire protocol (justified locked dependency). Preserve
cross-path integrity diagnostics without treating guest stdout as independent
truth or counting multiple legs as extra availability checks. One scheduled result
per service/generation, expected-slot coverage, up/down/unknown/missed, separate
availability/inject/security results, zero-valid unscored, no invented combined
grade. Probe transport/auth/loop/DB failures must be distinguished from service
failure; stale/dead scorer interrupts within a documented bounded health window.

Version restricted-account, web restoration, DB-data recovery and written-report
injects, server-scaled release/deadline/points and deterministic technical checks.
Bounded submissions have defined correct/incorrect/late/duplicate/advisory results;
disabled injects produce no phantom total. Final security predicates are baseline-
aware and generation-bound; errors/ambiguous evidence never pass.

Retain sustained AI pressure until deadline, one command at a time, fixed owned
attacker channel, bounded context/output/actions and verifier-only achievements.
Shared gateway priority: hints, attacks, reports (no in-flight preemption). Three
attempts maximum, 60-second call limits, 5/15-second retry delays, deadline-aware
cancellation; exhausted recovery interrupts honestly. Actual endpoint capability/
latency and useful attack behavior require operator proof. No hidden scripted
attacker/foothold fallback. AAR/hints/written feedback are cited and advisory;
deterministic reports remain available without the model after guest deletion.

Complete browser builder, launch progress, SSH copy instructions, Begin, 2-second
health/score/inject updates, submissions, hints, busy/recovery states, end, history
and replay. Central API policy seals hidden red internals during competition
across events, memory, reports, hints, exports and CLI. First-party defender casts
and published scenario threat descriptions may remain visible as agreed; do not
leak hidden red timeline details through their metadata. Test two separate users,
logout/disable/revocation, foreign capabilities, reload and interrupted history.

### G. Installation, migration, recovery and support

One supported production OS: Ubuntu 24.04 LTS x86-64, distribution Python 3.12,
compatible pinned libvirt/QEMU/native dependencies and locked app dependencies.
Development's existing Python matrix remains unless separately revised. A
versioned appliance manifest describes LAN/inner subnets, public/internal/ingest
URLs, broker socket, image digests, resource/state budgets, model alias and optional
backups. Secrets are local protected file references. Canonical renderers generate
everything; reject duplicate/conflicting overrides, placeholders and mixed releases.
Schema-version PVE->appliance conversion is explicit, never silent reinterpretation.

New `deploy/appliance.py` is the canonical operator entry point: validate, plan,
apply, status, doctor, upgrade and recovery subcommands. Fixed packaged operations,
reviewed diff/confirmation before privileged effects; no arbitrary manifest shell.
14 supplies a complete minimal installer for the access gate; 16 completes release
bundle production, upgrades/export/import/backup and operator documentation using
that same entry point. A prebuilt outer qcow2 distributor is not required: creating
one ordinary Ubuntu VM and running the installer is the supported starting path.

Install native packages/venv, users/groups, private directories, immutable release
files, PostgreSQL owner/app roles and forward migrations, nginx/TLS/Next standalone
assets, all service units, network rules, images and scoped capabilities. Generate
secrets once; safely resume partial installation without rotating keys or erasing
data. Bootstrap operator/member accounts and public keys locally; no private-key
upload, public signup or normal-operation SQL administration. Fix migration resource
lookup for installed packages. Startup orders storage/network/libvirt/DB/broker
reconcile/controller/bastion/web; readiness includes worker/scheduler/scorer health.

Expose operator diagnostics as installation/config, virtualization/network, guest
access/capture, model, storage and recovery states with actionable codes. Bind
evidence to release/config/image identity; a boolean alone cannot authorize attacks.
No secrets in diagnostics, normal logs, manifests, recording metadata or reports.

Existing service VMs 201/202/203 and any PVE guests require read-only operator
inventory first; names/old notes establish neither existence nor ownership.
Deploy the appliance alongside them. Provide a read-only export/import of closed
history/accounts/recordings with integrity/reference checks and a forward schema
upgrade; archive legacy infrastructure obligations separately. Never import PVE
tokens, active capabilities, old VMIDs as live claims or active match state.
Old resources must be reconciled by the operator's old authority before cutover.
Do not delete old VMs/data/bridge or revoke infrastructure credentials automatically.
Keep the old installation available for explicit rollback until approved retirement;
rollback never rewinds a migrated DB or silently resumes attacks.

Preserve evidence indefinitely; capacity blocks unsafe starts. Explicit offline
export/purge requires scoped selection, checkpoint and confirmation, never runtime
event-delete privileges. Implement optional scheduled backups of DB, recordings,
manifests, protected trust/secret recovery material and broker ledger consistently
while quiesced. Restore disconnected, invalidate capabilities, keep guests off,
reconcile old obligations and require fresh authorization. Synthetic backup/restore
tool tests are required; choosing a real destination and live restore proof remains
optional/non-blocking and prominently unverified when absent. Outer snapshots are
not a substitute for consistency or a claim that nested running state restores safely.

### H. Acceptance and implementation discipline

The original three-plan split is retained as product history, not a standing
branch/session policy. Changed runtime contracts still need evidence;
16 is final packaging/release proof, not deferred product testing.
Do not mark requirements complete from implementer claims, source-string tests,
HTTP 200s without results, environment attestations, skips or old totals.

Extend `infra/dev/acceptance.py`: **new** `hypervisor` and `access` in 14, **new**
`journey` in 15, **new** `appliance` aggregation in 16; strengthen existing
`install` and `release`. `authority` covers the new Unix/UID/typed boundary;
`hypervisor` uses actual libvirt/KVM, not libvirt's test driver; `access` uses
actual SSH through installed services and reads replay bytes; `journey` exercises
the full isolated product with a deterministic model fixture; `release` uses the
operator-approved appliance and real model. A fixture is never advertised as AI
exploitation success. `install` must run real clean install/rerun/reboot/populated
upgrade/failure recovery, not trust `SR_INSTALL_VM_EVIDENCE=1`.

Keep fast/selection/python/db/containment/packet/images/capture/frontend/browser/
compose gates. Images and capture retain separate evidence. Port relevant PVE
contract invariants to hypervisor/authority; legacy PVE tests can remain isolated
historical compatibility coverage, not the appliance acceptance authority. 16's
`appliance` gate runs the mandatory software set and emits revision/digest-bound
results; live `release` is separate and never runs implicitly.

Native KVM tests prove the adapter; the operator's actual PVE->Ubuntu->L2 proof
establishes nesting. Required CI needs an adequate disposable worker with KVM;
confirm availability/free allowance, otherwise record pending rather than a fake
pass or paid runner. Existing image/capture jobs retain max 3 guests/6 GiB/60 min.
New appliance fixtures cap at one 16-GiB outer VM containing at most 3 L2 guests,
one run at a time and 90 minutes per job; account for host overhead/storage before
launch. Reuse verified caches, never shared mutable run disks. Split gate jobs if
these caps are exceeded. No host auditd/firewall/libvirt installation on a shared
developer machine; use an explicitly disposable VM. No live attacks before real
isolation/stop acceptance. Manual checks belong to the operator, not the model.

Documentation references checked during planning (not hardware acceptance):
[nested KVM](https://docs.kernel.org/virt/kvm/x86/running-nested-guests.html),
[libvirt network isolation and host access](https://libvirt.org/formatnetwork.html),
[QEMU guest-agent file operations](https://www.qemu.org/docs/master/interop/qemu-ga-ref.html).
Implement against the appliance's pinned versions; web documentation alone does
not prove that installed capabilities, security profiles or performance work.

### I. Milestone 15 implementation decisions (2026-10-20, branch `15`)

The appliance design above was translated into running code on the user-selected
branch. These are the decisions that changed the shape of the product, and why.

| Chosen | Rejected | Why |
|---|---|---|
| The broker listens on a Unix socket and authenticates the caller with `SO_PEERCRED` (one permitted service UID) | Remote mutual TLS between two processes on one host; a bearer token on the socket | The kernel proves the caller's UID; a token would be a second, weaker identity to leak. Legacy mTLS stays available for the old path only. |
| Production workers are started by a **separate-UID supervisor** that claims a durable queued run; the API only records heartbeats and outcomes | The API spawning the worker and owning a kill switch | A separate UID cannot be signalled by the API at all, so the "API can stop the worker" claim stops being aspirational. The assignment is durable, so a supervisor that dies mid-claim is reclaimable after the claim timeout and cannot strand a run. |
| The supervisor capability is a file with a strict mode, compared with `hmac.compare_digest`; the API stores only the SHA-256 of a worker's one-shot run token | Passing the worker token in the assignment body and trusting the process environment alone | A leaked token must not become a durable capability, and a stale supervisor must not be able to act on a rotated token. |
| The golden image carries ONE netplan entry whose interface key (`range-nic`) is the SAME key the per-instance seed writes | Two differently-keyed netplan files (one in the image, one per seed); relying on cloud-init `network-config` alone | Netplan merges by key, so the later seed file overrides the build-time DHCP fallback leaf by leaf. The cloud image disables cloud-init network rendering, so `network-config` alone is not sufficient; two different keys would define the same device twice. |
| Readiness is a marker file read through the guest agent, not "the domain is running" | Treating a started VM as ready | A running kernel proves nothing about keys, users, network or services. The same fixed-path contract the production backend uses is what the test gate exercises. |
| An obligation is released only after the backend is read AGAIN and no longer owns the resource | Timestamps, operator assertions, or a ledger edit | A stale or wrong evidence file must never release a reservation while the guest still exists. |
| Controller MySQL reads go through locked PyMySQL while the existing integrity diagnostics stay | The hand-written wire protocol it replaces | A pinned, reviewed client removes protocol code we would otherwise own; the diagnostics (typed errors, integrity checks) are the valuable part and are retained. |
| New acceptance layers `hypervisor`, `access` and `journey` fail closed when a prerequisite is missing, and the journey drives the INSTALLED appliance over HTTPS | A journey that runs against fakes and calls itself end-to-end | A fixture proves the harness, not the product. The journey layer refuses to run without a real appliance and real member credentials. |

Not changed by this milestone: the outer Proxmox remains operator-only, the
appliance holds no outer credential, guests stay on the isolated inner bridge,
and no host firewall/auditd/host-shell capability was added to the product.

### Live-practice repair decisions (2026-10-23, branch `15`)

- Completion budgets are role-specific configuration (red 2048, coach 3072 by
  default), with the existing bounded call deadline retained. Rejected: a shared
  hardcoded 600 tokens or unlimited output. Thinking can consume the same budget
  as visible text; empty, truncated, and abnormal-stop completions are explicit
  failures, not success. Identical rejected completions are not gateway-retried;
  transient transport failures keep the bounded recovery policy. Optional coach
  text falls back to labeled deterministic guidance/reporting, never fake advice.
- Worker schema errors use the existing runner-owned `agent_note` capability.
  Rejected: widening event producer permissions to let a worker forge system
  events. A summary checkpoint advances only with usable text.
- Match clock, attacker status/progress, and service availability are separate
  projections. Rejected: interpreting a running match or healthy HTTP endpoint as
  successful AI activity. The browser polls terminal transitions and fetches
  filtered, API-authorized event details; competition redaction remains server-side.
- Cron cleanliness requires trusted content pins and safe file metadata, not
  familiar filenames. Missing trusted maintenance baselines remain UNKNOWN;
  accepting package metadata from a compromised target as its own authority was
  rejected. Existing image artifacts do not acquire trusted pins retroactively.
- Availability coverage counts unique current-generation service/time slots,
  including the first immediate probe. Duplicate/excluded observations are
  reported separately; clamping an inflated sample count to 100% was rejected.

These repairs were subsequently installed (see current findings), not full
model/security acceptance. The
operator's AppArmor containment qualification, full useful model run, image
baseline consolidation, and permanent post-killswitch cleanup repair remain open.

### J. Local conversation engine, admin settings and session review (2026-10-23)

Agreed requirements for the next planning discussion, **not implementation
approval or a new plan**. Commissioning checks for the supervised AI run were
completed; later practice exposed product defects. Receipts: [findings](FINDINGS_CHECKLIST.md).

| Chosen | Rejected | Why |
|---|---|---|
| Replace conversation engine; retain execution/control plane | General agent replacing broker, runner and scoring | Context loss is the defect, not a reason to discard working safety authority. |
| Structured conversation/tool history and durable API checkpoints | Last few raw telemetry events as memory; provider caches as persistence | Preserve evidence-linked facts, attempts/results, failed hypotheses, plan and next experiment. |
| Token-aware pressure and reasoning/answer headroom for ~262k local context | Compaction after a handful of events; tiny output caps as containment | Context and output limits differ. Coordinate model-aware resource limits and real deadlines. |
| One main model through the shared slot | Mandatory auxiliary or unscheduled background calls | Optional small model only after measuring resource/latency benefit, never for authorization/scoring. |
| Repository design/evidence plus native Project Knowledge | Duplicated detailed backlogs or chronological journals in every prompt | Design and evidence travel with code; native Todos hold actionable work and Plans hold implementation agreements (workflow revised 2026-10-28). |

**Agent boundary:** retain separate worker UID, API-only model credential, fixed
pinned attacker VM, durable operation UUID/intent before dispatch, sequential
bounded commands/pacing/deadline, independent supervisor/broker stop, append-only
evidence and deterministic verifiers. Unknown cessation retains obligations and
blocks progression. Only expose the approved range tool: no local shell, arbitrary
SSH/backend/destination, host files, installs, plugin discovery or infrastructure
credentials. Tool filters are not an OS boundary. Every main/summary/coach/report/
retry request uses gateway admission; disable duplicate SDK retries and external
tracing. Coroutine cancellation does not prove remote cessation or GPU slot release.

The worker's `{system,user}` endpoint is not general OpenAI chat: a framework
needs a scoped structured adapter/protocol, typed tool calls and usage/finish
metadata. Current text-only finish parsing rejects native tool-call completions.
Persist versioned run/deployment-bound history via API/forward migrations, not
shared worker-local memory. Checkpoints do not silently resume attacks on restart.
Failed compaction retains history/cutoff and uses bounded backoff, not identical
window retries every turn. Separate useful action progress from model activity.

**Admin-only GUI:** endpoint, model (discovery when supported), masked/write-only
API key, thinking **none / low / medium / high**, context size, generation/time
limits and connection/model test. Validate actual server capabilities; report
unsupported thinking settings, never silently ignore them. Protect keys API-side;
never return saved secrets or include them in browser state, prompts, normal logs
or worker environments. Snapshot settings for new runs; do not silently change
an active match. Local OpenAI-compatible transport does not prove model competence.

**Session UX:** authenticated home active/recent/history cards; Overview / Activity /
Replay / Report navigation and back links; safely rendered Markdown, not `<pre>`.
Filter/group lifecycle/member/security events by host/actor/type, collapse MOTD/
provisioning/verifier noise, retain expandable raw audit. Synchronize defender
recordings and attacker command/output tracks with evidence/operation IDs and
timestamps; existing action records are not historical PTY casts. Future streaming
must label origin. API-enforced competition visibility applies to history/replay.
Ground narrative in authoritative provenance: verifier probes are not attacker
behavior; AI cannot turn UNSCORED into fail or award points. AAR narrative is not
agent-memory compaction.

**Research only; no framework chosen/installed:**

- [Pydantic AI history](https://ai.pydantic.dev/message-history/),
  [deferred tools](https://ai.pydantic.dev/deferred-tools/),
  [OpenAI models](https://ai.pydantic.dev/models/openai/): slim OpenAI extra 2.60.0,
  MIT/Python >=3.11; recommended small embedded prototype, not selected. Structured
  history/custom external tools fit; dependency compatibility requires testing
  (research release needs OpenAI >=3.26 versus lockfile 3.24). Platform durable
  checkpoints/cancellation remain integration work.
- [OpenAI Agents SDK models](https://openai.github.io/openai-agents-python/models/):
  0.24.0, MIT/Python >=3.10; viable custom Chat Completions/tools/sessions option.
  Disable external tracing; do not assume hosted Responses compaction works locally.
- [Hermes integration](https://hermes-agent.nousresearch.com/docs/developer-guide/programmatic-integration),
  [snapshot dc579a5](https://github.com/NousResearch/hermes-agent/tree/dc579a5a0319861e0cde4a9606d4c8d0053ef523):
  full headless loop/history/recall/custom tools/compression, but broader runtime,
  plugin/background surface. Source says supported Python 3.14 despite permissive
  older-version metadata. Stock SSH uses `accept-new`/file sync, not our pinned
  per-operation containment. Candidate only as restricted separate runtime with
  custom range adapter, never unrestricted appliance Hermes. Main-model compression
  possible; auxiliary calls still need shared admission. Footprint and actual Qwen
  tool/reasoning compatibility unmeasured.

### K. Agreed upgrade design — 2026-10-24

Plans 18–21 approved by the user; implementation waits for their new worktree.
The user authorized planning the entire sequence here on branch `15`,
then validating/committing the existing memory fix separately, committing agreed
docs and merging all branch work into `master` in the main checkout, never
pushing. They will create the next implementation worktree. This is an exception
to main-folder/one-milestone-at-a-time planning, not to safety/live-operation rules.

| Chosen | Rejected | Why |
|---|---|---|
| Pydantic AI slim conversation engine behind the existing API | Further open-ended framework comparison; stock general-agent shell tools | Structured history/tools without replacing the working authority/containment plane. Require actual Strata compatibility before switching production. |
| Shared named model profiles with attacker, coach/report and summarizer overrides | Only environment variables or a single inflexible model | Supports the local main model and optional auxiliary; all generations including probes/retries use one slot. |
| Editable thinking-level mappings and allowed generation fields | Hardcoded universal low/medium/high semantics | Strata is the actual server; support its per-request fields and additional model-specific levels without allowing message/tool/auth/destination overrides. |
| Pin configuration for the whole session | Coach/reports silently adopting newer models | Reproducible session behavior. Record profile revisions per generation/report. Secret replacement/revocation invalidates old keys immediately, including pinned sessions; do not silently substitute. |
| Interrupt after bounded exhausted attacker retries | Quietly continuing a match without attacker pressure | Preserve truthful practice/competition outcomes. Remote cessation and server-request cancellation remain separate obligations. |
| Conversational coach, guiding hints then explicit direct help | Permanently forbidding answer commands | Member can request explanations/examples in practice; coach remains advisory, never executes commands. Competition-safe evidence/policy remains enforced. |
| Modern dark dashboard and synchronized timed replay | Cosmetic links only; command-result dump as full future replay | Readable proportional UI/report/chat text, monospace terminals, responsive session navigation; timed capture for new runs plus command navigation, honest old-run step-through. |
| Supported in-place upgrade AND corrected fresh install | Throwaway reinstall or leaving installed workarounds undocumented | Preserve users, history, casts, pins/keys and unrelated apps; reuse unchanged valid images, rebuild only when changed evidence/artifacts require it. |

**Initial editable defaults:** 262,144 context tokens; 32,768 maximum completion
tokens including thinking; 900 s per-request ceiling, bounded by remaining match
time. Compact near 80% context pressure with completion reserve accounted for;
never equate event count/characters with exact token usage. Use server token counts
where supported, conservative explicitly labeled estimates otherwise. Record actual
usage/finish reason and truncation. Existing long synchronous HTTP waits need durable
job/status/stream APIs for coach/report/admin probes, queue visibility and reload
recovery. Do not promise immediate hints while a long generation occupies the slot;
hint priority applies to queued work, not preemption. Close/cancel active requests
and verify endpoint cessation where supported; unknown release must not be called
confirmed or permit overlapping requests.

**Strata research limitation:** upstream
[`7ddc17a`](https://github.com/Niko1221/Strata/blob/7ddc17a38fe7f31637e895ecfba58c2cd43d65ec/serve/server.py)
accepts per-request `reasoning_effort`/template kwargs and reasoning-budget fields,
and watches disconnected clients. This is not proof of the installed version's
behavior. Do not mutate shared Strata global settings, restart its service or run
unrestricted tools. Discovery/test requests require explicit admin action, must
use configured destinations/credentials and share gateway admission. Redirects
must not carry secrets to another origin; saved configuration responses/logs must
exclude keys. Treat server/model content as data, not instructions.

Conversation/checkpoint storage and timed output are separate from raw event
audit. Bound per-operation/session capture and storage; drain without unbounded
memory, label truncation/gaps, retain final result/containment even if capture
fails, and never infer success from playback. Forward-only schema additions and
append-only artifact/checkpoint revisions preserve historical reports; legacy
unknown attribution/timing stays unknown. New provenance is authenticated at the
controller/operation boundary, not asserted by compromised guest audit alone.
No model reasoning text is required to establish scores or trusted evidence.

### Plan 18 second review-round decisions (2026-10-25, branch `practice-upgrades-18-21`)

Second independent review at `41d8df9` returned FIX with six findings;
the root dataflow (not the test inputs) changed in each row.

| Chosen | Rejected | Why |
|---|---|---|
| Scoring reads the baseline FROZEN into the immutable deployment resource at clone time (files + integrity reference + version), integrity-gated on every read; the CURRENT pin document only gates REVOCATION via identity binding — drift or absence degrades to UNKNOWN, same-digest edits change nothing | Re-reading `pins[role]['files']` at scoring time (the round-1 design, superseded row above); trusting a root-controlled mutable file as a session snapshot; post-launch baselines for already-deployed sessions | Reviewer reproduced: editing only `pins[role]['files']` under an unchanged role/template/digest turned a persisted FAILED (0 pts) into PASSED (10 pts) on rescore of the SAME bytes. Immutable scoring authority means the definition of clean is frozen before first use; replacement may revoke, never adopt. (HIGH.) |
| The CLONE AUTHORITY answers artifact identity over the typed broker boundary (`artifact_for_template` — the broker's own loaded manifest, whose SHA-256 the clone-image verification enforces; service validates the shape; no manifest path/secret/libvirt access crosses) | The API re-reading the on-disk manifest at clone time (superseded round-1 row); any API-side manifest path setting | Reviewer reproduced config drift: backend loaded manifest A, disk replaced with B — the old resolver recorded B while the broker would deploy A. A separately re-read config is not proof of deployed bytes. Absence (legacy adapters) is honest UNKNOWN, never a guessed identity. (MEDIUM.) |
| The un-rendered `SR_APPLIANCE_MANIFEST_FILE` setting and its resolver are DELETED; tests drive renderer → real Settings → real deploy flow without patching a nonexistent knob | Rendering the knob into the API environment (round-1 gap: it was never rendered, so the resolver silently returned nothing on the appliance) | Wiring that exists only under monkeypatched tests is not wiring. Identity now travels the broker boundary, so the API needs no manifest access at all — narrower, not broader. (HIGH functional gap.) |
| `_ensure_dirs` provisions the supervisor's `<state>/worker` directory itself (dedicated 0750 `srworker:srworker`, exactly once, drift-repairing), and the unit is rendered with `ReadWritePaths` bound to the configured state path | 0751 on the shared state parent "creating" the child; leaving the template's hardcoded path to drift from a configured state_dir | The unit has no `-` optional marker and no `StateDirectory=` — a missing directory fails the mount namespace before ExecStart. Parent traversal is not child provisioning. (HIGH.) |
| `node_runtime_plan()` selects ONE Node binary (dedicated pinned runtime, else a real candidate ≥ floor; `require` refuses, `auto` provisions); build, the actual unit `ExecStart`, and per-UID verification all name that exact path; provisioning never clobbers a foreign `/usr/local/bin/node` | Provisioning Node 22 while the unit exec'd `/usr/bin/node` (round-1 gap); PATH-dependent probes; `ln -sfn` over whatever another application installed there | Reviewer finding: fresh Ubuntu's Node 18 stayed the service binary despite green provisioning and probe — rendered checks were certifying a different runtime than the unit ran. Selection must be executable truth, and the appliance owns its dedicated tree. (HIGH.) |
| Pin `schema` must be an explicit non-bool integer at document top level AND per pin | Python equality (`True == 1`, `1.0 == 1`) as a format check | A hostile/malformed document must degrade to UNKNOWN like an absent one; implicit numeric coercion silently accepted `true` and `1.0` as schema 1. (LOW.) |

### Plan 18 review-round decisions (2026-10-24, branch `practice-upgrades-18-21`)

Independent review at `168a9e1` returned FIX with seven findings; each
repaired decision is recorded here (replacements are explicit — the
superseded row above stays as history).

| Chosen | Rejected | Why |
|---|---|---|
| Netrules loader has NO stop teardown: the table outlives unit stop; reload is the single atomic `nft -f` batch; removal is operator-only in the maintenance window | `ExecStop=nft delete table inet sr_appliance` (superseded row above) | Stopping the unit (package upgrade, maintenance, crash-restart ordering) while guests were alive DELETED the range's isolation — the exact hazard the loader exists to remove. A stop must never open a window. |
| Broker daemon exit drains ONLY with active claims: same latched, read-back-confirmed cessation (`drain_on_shutdown` wired into brokerd's finally BEFORE the libvirt handle closes); clean idle exit does not latch | Silent exit (range outlives its watchdog); latching every restart (poisons idle maintenance) | The broker is the only lease watchdog and libvirt holder; a live guest must never survive its daemon unwatched, but an idle appliance stop is ordinary. |
| Cron-pin trust binds to the artifact the deployment RUNS ON: deploy freezes role+template+image-digest from the installer manifest into the immutable resource (`appliance_manifest_file`, unset ⇒ record nothing ⇒ UNKNOWN); injection (both `check_objective` and `build_scorecard`) requires pin==recorded identity; malformed pin values (type-checked before any regex) behave exactly like an absent pin | Template-ID-only trust (superseded row above); caching a digest-pinned config at predictable shared paths; trusting pre-existing `$TMPDIR` content | A template number survives rebuilds, so template-only trust honoured hashes for bytes never deployed (a wrong-digest pin passed the real verifier). Frozen deploy-time identity means replacing the pin file can only REVOKE, never forge, a pass. (Reviewer-reproduced.) **SUPERSEDED below:** the freeze stopped at the identity — content hashes were still read live, letting a same-digest edit rewrite history; identity also came from an API-side manifest re-read. |
| TLS material per-file ownership: ingest pair root:sringest 0640 (group default, missing group fails loud at chown), public CA/anchors 0644, CA signing keys 0600; `ensure_tls` VALIDATES per-identity POSIX readability after bootstrap (real owner/group/other math, never root-os.access) and fails closed; sandbox defers loudly | Blanket `chmod 0600 *.key / 0640 *.crt` (installed nobody could actually read what its units served); os.access as root | The blanket chmod made the install internally inconsistent for every identity but root; anchoring the bastion/controller on api-ca while nginx presents the self-signed https.crt failed every API callback — anchors now name the surface actually presented (telemetry keeps api-ca for the ingest cert it signs). |
| Shared state directory installed EXACTLY once: 0751 srbroker:srrange — write for its one writer (broker ledger journals there), traverse-without-enumeration for every other identity; a ledger outside state gets its own dedicated entry | Two `_ensure_dirs` entries fighting over the ledger parent on every apply; 0750 srrange (blocked the very clients reading published 0644 pins) | Ownership must converge, not oscillate; narrow traversal is not group-widening (no service group changes). |
| Private owned staging for every root-fetch-then-verify download and every CLI config: `mkdtemp` 0700 staging for the Node tarball (removed whatever happens), per-invocation `mkstemp` 0600 alembic config with guaranteed cleanup | Predictable `/tmp/node-v<VER>.tar.xz` written through before hashing (root); shared `$TMPDIR/sr-alembic-<digest>.ini` cache trusting planted content | A predictable shared-temp path invites symlink/overwrite attacks and cross-application collisions; content in someone else's file is never trusted. |

### Plan 18 implementation decisions (2026-10-24, branch `practice-upgrades-18-21`)

| Chosen | Rejected | Why |
|---|---|---|
| Own-table nftables loader unit (`sr-appliance-netrules`, root oneshot, validate-then-load ONE rendered file, `Requires=` by the broker) plus a render-time own-table scope parser | Runtime firewall API; operator-applied rules only; `flush ruleset` convenience | Reboot used to silently lose range isolation (live find 2026-10-23). The loader can only load the installer's own render; the parser refuses flush-ruleset, foreign tables and includes at render time, and the broker cannot start before isolation. |
| Latched destroy allowed ONLY with positive re-identification (ledger claim + session match + backend identity re-read; exact name match or confirmed absence), resolving only cessation-class obligations with audit; foreign identities retained as `vmid-recycled-no-destroy` | Blanket 423 refusal (stranded every latched teardown, `lease_released:false`); unconditional destroy | End could never complete under cessation, and the only exit was unaccepted manual hypervisor surgery. Starts/clones/lease renewal stay refused; a foreign machine is never destroyed on belief. |
| Offline `brokerctl resolve --id` requires an independent backend read-back (absence, or a provably foreign name for recycled obligations) | Editing ledger rows; resolving on operator assertion | Resolving is evidence, not a belief; refusals stay open and audited. |
| Trusted cron hashes captured from the CLEAN BUILT ARTIFACT (verify-boot serial marker / tree capture) and pinned to {digest, version, template_id}; injected only while the deployment's template matches | Filename-only trust; learning baselines from any running or compromised guest; scenario YAML carrying hashes | v3 correctly refused filename-only "clean". The artifact is the only honest source of clean; every mismatch degrades to UNKNOWN, never a pass. |
| Model credential is an API-only file reference (`SR_LLM_API_KEY_FILE`, root:srrange 0640), unreadable/empty failing loudly naming the file | Literal env credential shared into worker environments | Workers call models through the API gateway and never hold the key. |
| Runtime host pins live in the state tree (`/var/lib/sparring-range/known_hosts/range_hosts`) read by runner/verifier/bastion | Pins under /etc | `ProtectSystem=strict` makes /etc read-only for the API writer; one file, one authority. |
| Pinned Node 22.23.4 (digest-checked) with explicit `auto\|require\|provision` mode, ABI-matched libvirt binding symlinks, and per-UID `runuser` execution verification in `apply` | `--system-site-packages` venv; trusting rendered units as proof | Ubuntu 24.04's Node 18 cannot build Next 16; the umask-027 venv passed every rendered check and still died 203/EXEC. Apply must prove the real identities execute what their units exec. |
| Shared bounded SSH policy (`ServerAliveInterval=5`/`CountMax=3` + `stdin=DEVNULL`) on every platform diagnostic call | Outer timeout only | A wedged guest with an established TCP connection hangs ssh forever without keepalives; the timeout alone did not save the 2026-10-23 run. |
| `rangectl db` materializes an ABSOLUTE-path alembic config (with a complete synthesised fallback) | Relative ini + CWD assumption | Outside a checkout Alembic resolved `script_location` against the process CWD; the installed CLI failed with a path error that looked like a broken install. |
| Storage-headroom refusal BEFORE any apply effect (placed images + operator floor vs free) | Discovering ENOSPC mid-clone | A nearly-full appliance accepted the copy then failed later with generic I/O errors. |

### Plan 19 implementation decisions (2026-10-25, branch `practice-upgrades-18-21`)

| Chosen | Rejected | Why |
|---|---|---|
| ONE admission slot as a DATABASE invariant: every model admission (turns, hints, AARs, compaction, probes, retries) is a durable `model_jobs` row; a partial UNIQUE index forbids a second `running` row in ANY process; the scheduler claims at most one job and executes it inline | In-process gateway thread (one process's courtesy); SELECT-then-INSERT without the index; post-claim duplicate check | The gateway serialized only within one process; the browser/worker paths cross processes. Provider-side proof (max_concurrent==1) now holds across every caller. |
| Retries are NEW visible rows (attempt+1, parent_job, 5/15 s backoff via future `requested_at` honored by the claimer); non-retryable rejections never re-hit | Hidden re-send inside one row; exponential background retries | Every admission and attempt is auditable exactly as the plan requires; "the model gateway is the single bounded retry authority" survives as "the queue is". |
| Cancellation is an obligation: queued → cancelled un-run; running → `cancel_requested`, slot releases only when the live call RETURNS (result then discarded); orphan `running` at startup → `cessation_unknown`, never replayed | Killing the thread/socket; releasing the slot on cancel; replaying interrupted calls | A provider call that may still be live is never pretended stopped, and a request whose wait bound elapsed never has its late answer consumed (wait-bound expiry requests cessation). |
| No DB session across waits: claim/execute/terminal-write are separate short transactions; waiters `commit()` between polls | Holding a request session open through the wait bound | The pool (size 5) would starve on the first long wait; snapshots must not outlive their purpose. |
| Versioned profiles (immutable rows; rotation = NEW version + demote old + visible cancellation duty over its queued jobs; role overrides in their own table); per-session PIN frozen at first use; sessions on a replaced/revoked version FAIL visibly (503 "rebind") until an explicit operator rebind | Editing a live profile in place; automatic re-pin on rotation; env role selection | "Rotation never silently swaps the model mid-session" — history and scoring stay attributable to the exact version that served them. Demote-before-create ordering respects the one-ACTIVE index mid-transaction. |
| Profile bootstrap (env → DB, once) runs on EVERY process start, race-safe via unique indexes; crashed-live reconciliation stays controller-only | Bootstrapping under the controller advisory lock | Full-gate runs showed lock-race losers serving NO profiles (red turns 503). Creating identical bootstrap rows is idempotent; stamping another process's live rows is not — the two duties have different safety classes. |
| Structured turns on the pinned SDK (ONE native `range_command` tool, typed returns, finish reasons, provider usage); forged tool names/parallel calls refused at the boundary with every call id answered; text answers still pass the SAME strict action schema; loop uses `llm.turn()` only `if hasattr` | Free-form shell tools; plugins/MCP/subagents; dropping the strict-schema path | Execution authority stays where it was (intent-before-dispatch, fixed runner, operation UUID); legacy doubles/tests keep their exact semantics, so the protocol change is provably behavior-preserving. |
| Compaction = a SEPARATE visible summarizer job after a turn; checkpoint COVERS a revision range (append-only history still replays); deferred while a tool call stands unanswered; authoritative provider usage preferred, 0 counts never masquerade as real, estimates labeled | Rewriting/deleting history in place; inline compaction inside the turn; trusting unset usage as zero | An answer must be reconstructible exactly as given; compaction mid-tool-call breaks provider protocol; an absent count reported as real 0 would silently disable pressure. |
| Scheduler starts LAZILY on first enqueue; startup only bootstraps + reconciles | A polling thread in every process (including workers that only POST) | A process that never queues model work never touches the queue; tests control the runner deterministically. |
| Graceful shutdown releases the controller advisory lock; middleware stack rebuilds per lifespan | Leaking the lock on the pooled connection until process exit; once-per-process CORS origins | Both were exposed by second lifespans in one process: startup duties were silently skipped, and the second web origin was refused. Production single-boot semantics are unchanged. |
| Admin surface operator-only; keys write-only (`masked()`/`public_config()` the only read shapes); generation kwargs allowlisted server-side; probe = queue member | Member-visible profiles; a UI kwargs blob; out-of-queue liveness pings | Nothing here may hand a credential or an unvalidated wire body to a caller; a ping that bypassed the slot consumed an admission without being one. |

#### Plan 19 review round (2026-10-25): semantics reopened and re-fixed

An independent review (VERDICT: FIX at `2bb5305`) proved ten behaviors
absent. Each repair is proven by a real-HTTP / real-DB regression:

| Chosen | Rejected / deferred | Why |
|---|---|---|
| The admission slot covers `running` **and** `cessation_unknown` (one partial unique index, migration 0021); an uncertain cessation (timeout, mid-stream close, watcher-cancel, crash reconcile) HOLDS the slot until a bounded, audited operator `resolve-cessation` releases it | Auto-expiry of obligations; treating a closed socket or client timeout as proof the provider stopped; releasing the slot while generation may run | A socket closing is not cessation. Concurrent live requests to a pinned provider are exactly what the slot exists to forbid; "unknown" must never silently become "stopped". |
| Provider failures split on TWO axes: `retryable` (protocol/credential errors never retry) × `uncertain` (only a complete HTTP error or never-opened connect is definite). Classification walks the FULL `__cause__/__context__` chain and matches connect errors by NAME+MODULE because this deployment rides **httpx2/httpcore2** — `isinstance(x, httpx.ConnectError)` NEVER matches | One bool; SDK-wrapper-type-only checks; plain-`httpx` identity checks | The review reproduced a dead endpoint misclassifying as uncertain (obligation storm) because the real exception chain terminates in `httpx2.ConnectError`. Wire truth, not local type identity, decides. |
| Provider credentials live ONLY in `model_profile_secrets`, granted to one dedicated DB identity (`SR_PG_SECRET_URL`); 0021 copies keys forward, EXPLICITLY REVOKES the owner's table auto-grant, then DROPS `model_profiles.api_key`; the app role is never granted; probes prove both directions (app can't read secrets; the secret role reads nothing else) | Column-level REVOKE (table grants made that impossible); app-role fallback when the secret URL is unset; per-process encryption claims | 0020's plaintext column was readable by the ingestion plane because roles are shared; the auto-grant default-privilege nearly reintroduced the identical hole (caught by the real role probe, not by reading the migration). |
| A session freezes ALL role versions at its first use; a NON-secret edit SUPERSEDES (pinned sessions keep running on the old version); only credential replacement/revocation invalidates; rebind is refused while the session has queued/running model work | Per-role lazy first-use binding (let a late override move an in-flight session); cancelling pinned work on every edit; rebind under queued work | Editing a thinking level must never break a match; a revoked credential must never keep serving; no flip may occur while a call could still dispatch. |
| Compaction is evaluated BEFORE the request; the summarize job captures `covers_through` and `used_at_enqueue` AT ENQUEUE, the turn is gated via `depends_on`, and the gated turn RECONSTRUCTS its messages at execution time (checkpoint now committed) so the request goes out compacted; a failed compaction defers with a 5%-growth backoff; `last_usage` stops counting pre-checkpoint provider totals | Post-hoc compaction (the over-budget prompt already went out); coverage = "max revision when the summary finished" (silently covers rows written mid-summary); trusting a stale authoritative count as a floor forever | Coverage must describe exactly what the summary saw, and the point of gating is that the next request never carries the bulk. |
| Durable async surfaces: turn/hint/AAR `wait=false` → job id + own-scope status; results persist through handlers in the JOB'S terminal transaction (exactly once, reload-recoverable); the member job list shows state/timing only | Request-lifetime coupling (a reload loses the answer); returning sealed turn payloads to members | The review proved hints/reports answered or died with the HTTP request; durability must include the outcome, and competition visibility must not leak through a status endpoint. |
| The SERVER's match row caps deadline at admission, and run finalization cancels the session's queued/live model work; a watcher (0.25 s) closes the LIVE SDK call on cancel/deadline | Trusting the worker-supplied deadline; a 900 s generation continuing after the match ended; "cancel" as a flagged row while generation runs | Remaining match time must bound queue, start AND generation; cancellation that cannot reach the wire is not cancellation. |
| This turn's INPUT messages persist WITH its outputs; replay re-prepends the permanent system framing after checkpoints; checkpoint digests ride as LABELED user parts; wire failures redact credentials AT SOURCE (and again at every display surface) | Persisting only model responses (inputs vanish from replay); promoting model-generated summaries to system authority; relying on one redaction layer | The ledger must reproduce exactly what the wire saw — rules, tool returns, all of it — and a leaky 401 that echoes the Authorization header must surface the key NOWHERE. |

#### Plan 19 review round 2 (2026-10-25): thirteen reopened findings, fixed at root

A SECOND independent review (VERDICT: FIX at `1d19c16`) reproduced thirteen
defects in the round-1 repairs. Each was re-fixed at the behavior level and
is pinned by a real-wire / real-DB / real-browser regression
(`tests/test_plan19_review_round2*.py`, `tests/test_plan19_browser_admin.py`);
applied migrations 0020/0021 stayed BYTE-UNCHANGED — all schema work is
forward migration 0022.

| Chosen | Rejected | Why |
|---|---|---|
| Compaction boundaries are PAIR-SAFE: the ledger depth-scans for the newest assistant tool call without its return and the coverage boundary sits strictly BEFORE it; while a pair is open the turn proceeds with a visible deferral, never a split | Trusting "latest revision" as coverage (the reviewer's orphan tool RESULT → strict-provider 400); dropping the pending call from replay | A checkpoint that splits a call from its return corrupts EVERY later request. The deferral is honest; the split is silent data loss. |
| `model_profiles.credential_digest` (0022, one-way, NULL=legacy-never-matches): credential REPLACEMENT revokes every version carrying the replaced digest — queued jobs cancelled, running ones cease, `profile.lineage_revoke` audited; explicit per-version revocation stays scoped | Revoking only the version ACTIVE at rotation (the reviewer's repro: non-secret edits copy the key forward and pinned sessions keep the "compromised" credential); making every explicit revoke cascade (operator revokes ONE version for its OWN compromise) | "Replace this credential" is a statement about the SECRET, not about a row. Version rows are the unit of editing; the credential is the unit of compromise. |
| Failure diagnostics carry NO provider text: class + HTTP status only, plus a fixed "provider diagnostic body withheld" marker; redaction uses the credential CAPTURED AT DISPATCH (`_dispatch_credential` contextvar) and has no length floor | Carrying provider error bodies (real 500s echo the request — including the Authorization header and the sealed conversation); re-fetching the key after a mid-failure revocation; a 6-char minimum that let short keys through whole | The reviewer saved `uvxyz` and watched it leak through the 502 AND the admin row. A diagnostic we cannot sanitize is a diagnostic we never display. |
| Definite HTTP failures retry ONLY on 408/429/5xx; member job surfaces (list/detail/stream, sealed or not) structurally exclude raw errors — `error_kind` is the neutral classification — and sealed matches hide attacker job KINDS entirely (404, not decorated) | Retrying 400/404/422 forever behind a one-slot queue; "redacted" text as member-visible content; filter-everywhere string matching | Competition visibility is enforced IN THE API (standing rule); a diagnostic can echo sealed material even after secret redaction, so members get classification, operators get the redacted detail. |
| The LOGICAL REQUEST is the unit: `cancel()` cascades root+ALL descendants regardless of the target's state (backoff-queued retry children die before dispatch; a watcher-closed LIVE child lands `cessation_unknown`, never a fake "cancelled"); status/admin-detail/streams resolve the chain's FINAL outcome from any attempt id (`chain_view`, one shared serializer) | Cancelling a terminal parent and leaving its queued child to dispatch; reporting attempt 1's stale failure as the request's outcome | The reviewer cancelled a root, watched attempt 2 fire anyway, and polled a "failed" id whose chain had already succeeded. Both are the same confusion of row and request. |
| Member-visible OUTCOMES (hint/AAR) persist once per logical request: only a QUIESCENT chain may persist, and the claim is an atomic guarded UPDATE on `model_jobs.outcome_persisted` (0022) called from every terminal path | Persisting per ATTEMPT (the reviewer saw the fallback hint written by the failed attempt and the real hint by the retry); trusting in-process flags across retry chains | A provider 500 that answers a member twice is a scoring-integrity bug, not a log-noise bug. |
| Deadline expiry at ADMISSION is terminal at the ONE enqueue gate (state `cancelled`, "deadline elapsed before admission — nothing was sent to the provider"); `/internal/model/complete` carries the server-authoritative match deadline and caps its wait | Per-route deadline memory; checking expiry only at dispatch (the reviewer completed an expired match through the text endpoint) | There is exactly one admission point; safety properties belong there, not in every caller. |
| Thinking LEVELS are wire-distinct by preset (`capabilities.thinking.wire_preset`, default `llama.cpp`): `none` → `chat_template_kwargs={"enable_thinking": false}`, graded → distinct `reasoning_effort`; unknown presets are refused BEFORE the request; `override:<level>` refines a preset partially | The round-1 boolean collapse (all four levels produced identical bytes on llama.cpp — the reviewer ran it); guessing per-provider encodings; claiming Strata compatibility | Encoding is a per-provider FACT. We declare what we verified over the real wire and refuse the rest loudly; Strata stays a manual gate. |
| The documented `SR_PG_SECRET_URL` resolves via `AliasChoices` (bare + mechanical names keep working); `ensure_database` PROVISIONS the `sr_secret` role and the API-only 0640 `secrets/db-secret.env`, passes only the role NAME to Alembic, and ONLY `sr-api.service` loads the file; compose's bootstrap creates the role 0021 grants to | Requiring an operator SQL ritual before 0021 can even run (compose proved it: `role "sr_secret" does not exist` at GRANT); putting the URL in `control-plane.env` (every service would load it) | A migration that GRANTs to a role nobody provisions fails at install time on the operator's box. Provisioning belongs to the installer, and the blast radius stays one unit. |
| Secret writes happen LAST after full validation; a per-session rollback guard deletes written secrets and RESTORES deleted ones (values recorded at deletion) on ANY rollback — route-level included (explicit `db.rollback()` in `except`) | Compensating by hand inside `revise` (route-level failures after return skipped it); trusting FastAPI teardown to roll back (empirically it did not reach the guard) — and, decisively, SQLAlchemy 2.1 dispatches `after_rollback` with ONE argument: a two-argument listener made `Session.rollback()` itself raise, silently killing the compensation | The reviewer destroyed a working key with an INVALID rotation. The guard's contract is now pinned by tests at both failure points, and the 2.1 arity trap is documented where it bit. |
| 0022 replaces `uq_model_jobs_slot` with `uq_model_jobs_occupied` — a UNIQUE expression index on the CONSTANT 0 for occupying states, NULL otherwise — and REFUSES to upgrade a database currently holding running+cessation_unknown together | Keeping UNIQUE(state) restricted to two values (two DIFFERENT values are unique against EACH OTHER — the advertised one-slot invariant was false at the DB level); auto-resolving an obligation to make the migration pass | The index must enforce the invariant we advertise, and silently dropping protection for one row is exactly the fail-open the slot exists to prevent. |
| Bounded authenticated SSE streams for worker and members (`job_event_stream`): every state/attempt transition pushes, the terminal event is ALWAYS replayable from the durable row (reconnect-safe without a server window), window close leaves the job untouched — and DISCONNECT IS NOT CANCELLATION; member streams are state/timing-only | Polling-only UX; WebSocket sessions with server-side state; cancelling on disconnect (a network blip silently killing a live engagement turn) | The durable row is the resume cursor. The moment a closed socket changed job state, flaky WiFi would be an attacker's cancellation primitive. |

### Plan 19 review round-3 decisions (2026-10-26, branch `practice-upgrades-18-21`)

The THIRD independent review (VERDICT FIX at `e311ff9`) reproduced six
defects — two HIGH races against the slot contract, a dependency that
followed an attempt instead of the logical request, a terminal path that
bypassed the outcome protocol, a self-revoking revision, and an OS
identity that was not actually an access boundary. Each was re-fixed at
the root and pinned deterministically
(`tests/test_plan19_review_round3*.py`); applied migrations
0020/0021/0022 stayed BYTE-UNCHANGED — all schema work is forward
migration 0023.

| Chosen | Rejected | Why |
|---|---|---|
| Cancellation is LOCK-THEN-ACT over the whole logical chain: `_lock_chain` takes FOR UPDATE on every chain row in a deterministic order (walk up to root, then attempt-ascending), re-enumerating until the closure stops growing; a live row only ever receives `cancel_requested`, never a stale `cancelled`; the claim statement carries an outer `state='queued' AND NOT cancel_intent AND NOT cancel_requested` CAS | Read-then-overwrite from a queued snapshot (the reviewer's production-claim repro: the row became `cancelled` while the provider request stayed live — the constant occupied index protects nothing for a row a stale writer made terminal); per-process locks (multiple processes exist) | Two writers of one row must serialize in the database. Whoever loses the race re-reads the COMMITTED truth and acts on that — the invariant "a live or uncertain slot never goes terminal without cessation evidence" then holds at every interleaving, not most of them. |
| `model_jobs.cancel_intent` + `chain_root` (0023, indexed, NULL chain = unknown = conservatively blocks): cancel stamps the intent on EVERY chain row under the lock; the terminal write locks its row FIRST, treats `cancel_requested OR cancel_intent` as cessation, and REFUSES to birth a retry child for a fenced chain; the claim skips intent rows; late-born children are killed by the locked re-enumeration | Snapshot-then-cancel against a race window (the reviewer's live-500 repro: the executor committed a fresh queued backoff child AFTER "cancelled" committed — the logical request respawned); an operational-state table beside the rows (lifecycle intent belongs with the chain, like `outcome_persisted`) | "Cancelled" must mean NO future attempt is ever born or dispatched. That is only durable if every point where the chain can grow or dispatch consults the fence UNDER THE ROW LOCK — which is exactly what `chain_root` makes one indexed lookup. |
| Dependency admission is CHAIN-aware and quiescence-based: a gated job waits at admission while ANY attempt of its prerequisite chain may still dispatch (claim gate checks `chain_root`), is admitted once quiescent, and the EXECUTOR then decides — requeue on a still-in-flight prereq (race won after admission), truthful `prerequisite logical request did not succeed (final attempt N: state)` on genuine exhaustion | Admitting after the first attempt merely TERMINAL (the reviewer's wire repro: caller 502'd "prerequisite job did not succeed (failed)" while the summary's queued retry was about to succeed — three provider requests where the logical chain never got its chance); failing at admission (would strand the dependent queued forever or double-decide) | The dependency is on the LOGICAL request, so the wait and the verdict follow the whole chain through bounded retries. Quiescence is what the slot decision needs; success/failure is the executor's locked decision. |
| Every terminal path is the SAME durable outcome protocol: profile revocation/replacement routes through `model_jobs.cancel()` (intent + locked cascade + the one guarded outcome claim); `reconcile_startup` and `resolve_cessation` persist the logical outcome; the profile-unavailable branch cascades and persists before returning | Hand-writing row states in `model_admin` (the reviewer's repro: queued hint revoked → `cancelled`, `outcome_persisted` false, ZERO events — the member's honest fallback silently vanished); one protocol for "real" cancellations and another for admin ones | A terminal transition that skips the outcome claim is an engagement that quietly loses its member evidence. One protocol means exactly-once holds for revocation, restart recovery and operator resolution by construction. |
| A resubmitted credential whose VALUE matches the current one (digest or plaintext match, checked BEFORE any effect) is a NON-SECRET edit — lineage stays, nothing is revoked; the sibling sweep additionally skips `new.profile_id` structurally | Treating any supplied `api_key` as a replacement (the reviewer's repro: the GUI resaving the whole form revoked the brand-new version its own sweep was performing and deleted the secret seconds after writing it — a 200 response for an unusable profile); refusing with 4xx (a resave is not an error, it is the form's normal submit) | The secret axis decides revocation duty, so "the secret did not change" must decide "no revocation duty". A genuine rotation still invalidates the whole replaced lineage immediately; nothing resurrects a revoked credential. |
| The credential-store file is an OS boundary, not an EnvironmentFile annotation: `sr-api-ingest.service` runs as its own `sringest` identity (only the API is `srrange`), `ensure_database` creates `secrets/db-secret.env` ATOMICALLY at 0600 (O_CREAT|O_EXCL, fsync, link-publish — never replaced) with post-verify toward 0600 root:root that FAILS CLOSED, and the service contract forbids two units sharing a uid and any non-API reference to the file | Same-uid services with "API-only" comments (same uid reads `/proc/<pid>/environ`, ptraces, and opens the other's group files — the old 0640 root:srrange made the credential URL readable by the ingest process directly); `write_text` then `chmod check=False` (a permissive window and a silent failure) | Only a different uid is access control between processes. The API reaches the content through systemd reading it as root BEFORE privileges drop — so 0600 root:root and zero service-readable bits are the design, and the contract computes exact POSIX readability for every identity (math, never claimed as installed-OS qualification). |
| The secret-store guard is honest IN-PROCESS COMPENSATION, not crash atomicity: `after_commit` clears pending entries (a committed unit of work owns its secrets — session reuse can never make a later rollback vandalize them), a restore re-checks the row's COMMITTED status through a FRESH session (a session inside its own `after_rollback` is inactive and refuses SQL — proven by this guard's own regression), and a FAILED compensation records a durable `model_admin.profile.secret_compensation_failed` admin event | Claiming two-store XA without XA (power loss between the stores leaves a bounded divergence — documented and auditable now, not hidden); reading status on the rolling-back session (silently fails the restore); swallowing a failing compensation (the divergence must become an operator-visible repair obligation) | Separate stores commit separately; the honest contract is "compensate what we can, record what we cannot". The audit item became three pinned tests. |

### Plan 19 review round-4 decisions (2026-10-27, branch `practice-upgrades-18-21`)

The FOURTH independent review (SOURCE-ONLY, VERDICT FIX at `b7ea7cd`)
reopened three roots — the round-3 compensation itself had a
check→write TOCTOU, the 0023 fence could not reach chains that PRE-dated
it, and an operator's cessation resolution was being consumed as a
compaction RESULT — plus two test-quality gaps. Fixed in `069491f` +
`12ecbcb`; applied migrations 0020–0023 stayed BYTE-UNCHANGED and the
new work is forward, data-only migration 0024.

| Chosen | Rejected | Why |
|---|---|---|
| Restore compensation SERIALIZES: hold the profile row `FOR UPDATE` across committed-status check + secret write + commit (bounded `SET LOCAL lock_timeout`; a timeout records the durable repair obligation) | Reading the committed status, closing the session, then writing the secret separately (the reviewer's window: a revoke commits between our two statements and the compensation recreates a credential for a profile just revoked); skipping compensation whenever revoke MIGHT race (would vandalize legitimate rollback restores) | A status check is not serialization. Locking the same row revocation locks to change status makes the order total: restore-then-revoke (revoke's delete is final) or revoke-then-restore (restore sees `revoked`, skips). The positive control pins that the fence never becomes a silent refusal. |
| Fence RECONCILIATION forward: data-only migration 0024 stamps `cancel_intent` on every row of any chain CONTAINING a cancelled row, cancels `queued` members with an honest note, keeps `running`/`cessation_unknown` states (obligations hold the slot); PLUS the same chain fence inside `_CLAIM_SQL` and an executor pre-dispatch reconciliation for shapes no migration can foresee; `downgrade` a deliberate no-op | Editing applied 0023 (immutable history — it truthfully recorded what IT could know); leaving escaped children "for runtime to notice" only (the reviewer's populated-upgrade repro: after 0023 the queued child of a cancelled root still had clean flags and dispatched); reviving/erasing on downgrade (would re-arm the exact defect) | Upgrading must not resurrect a cancelled engagement. "Chain contains a cancelled row" means the logical request WAS cancelled — but a FAILED parent with a queued retry is the ordinary bounded-retry shape and is explicitly untouched, and an uncertain cessation stays an obligation, never a silent success. |
| Dependency success = the chain-final attempt GENUINELY `succeeded` AND, for a summarize prerequisite, its durable checkpoint with the exact covered range EXISTS; `cessation_resolved` is honest `failed-final` (new `no-checkpoint` verdict when a summary "succeeded" without one) | Accepting `cessation_resolved` as prerequisite success (the reviewer's repro: after an audited resolve the gated turn dispatched the uncompacted over-budget context — resolution created NO summary and NO checkpoint); trusting the `succeeded` state label alone (an attempt can end succeeded with no checkpoint artifact) | `resolve_cessation` proves a SLOT was released, not that a RESULT exists. The dependent consumes the compaction ARTIFACT, so the artifact is consulted — its absence refuses with the truthful reason and zero provider calls; the 500→retry→checkpoint→dispatch-once positive keeps legitimate recovery flowing. |
| Concurrency proofs are DATABASE-OBSERVED: tests wait until `pg_stat_activity` shows the victim backend parked on a lock wait (and event-gated fake-model servers for provider interleavings) — replacing the round-3 `t.join(timeout); is_alive()` guess; pin proofs freeze the pin at FIRST role use, then edit (dead URL + same-key resave) and serve a real subsequent turn | Sleeping then asserting a thread is alive (proves scheduling, not the lock); creating the session AFTER the revisions and calling that a pin proof (proved serviceability, not that v1 stayed usable — the pre-fix test failed exactly when made honest) | A race test must demonstrate the interleaving from the database's own view. The corrected pin proof fails loudly against unfixed behavior — that is what makes it a proof. |

### Plan 19 review round-5 decision (2026-10-27, branch `practice-upgrades-18-21`)

The FIFTH review (VERDICT FIX at `e07c52a`, one blocker) showed the
audit of a failed compensation was itself leaking: `str(exc)` from a
secret-store failure carries PostgreSQL's `DETAIL: Failing row
contains (...)` — the credential — into app-role-readable append-only
evidence. Fixed in `db36809`; no migration touched.

| Chosen | Rejected | Why |
|---|---|---|
| Compensation/audit records carry STRUCTURE ONLY: exception class names + 5-char SQLSTATE codes along the bounded cause/`orig` chain (`safe_error_shape`); the obligation-write failure logs safe shapes and says the durable record is missing; the outcome-handler failure note (API-visible) follows the same convention | Persisting `str(exc)` (the reproduced leak: a deliberate fixture CHECK made the restore's INSERT fail, and PG's own diagnostic quoted the credential into the app-readable event); pattern-based redaction of the text (short opaque keys and provider keys of unknown shape defeat every pattern — redaction that must catch everything secret is catch-anything logic, which is exactly what this codebase bans elsewhere); silent `except: pass` on the obligation write (a divergence with NO evidence is worse than a loud structural record) | A diagnostic's text is attacker/DB-controlled content; class names and codes are library structure that cannot carry a value. The failure stays fully actionable (op, profile, code, action_needed) while the value can never ride along because nothing value-bearing is ever read. Regression pinned by real-PG fault injection asserting absence across event rows read as the app role, payloads and every log record |

### Review-round evidence

`docs/FINDINGS_CHECKLIST.md` — "Plan-19 independent review round" sections
record the reproduced original failures, the corrected proofs, and every
gate receipt for all five rounds.

### Plan-21 upgrade-compatibility decisions (2026-10-27, branch `practice-upgrades-18-21`)

The second plan-20 review proved two upgrade-breaking facts: applied 0026
cannot complete over valid 0025 data (its unique truncation-marker index
hits pre-fix duplicate markers), and 0026's `audience` backfill silently
labelled every legacy coach row member-visible. Applied migrations are
immutable and no historical row may be deleted or rewritten, so the
compatibility story lives in the forward path plus the engine.

| Chosen | Rejected | Why |
|---|---|---|
| Explicit SUPPORTED PREREQUISITE in the upgrade engine: walk the chain ONE revision at a time; tolerate ONLY the failure where 0026 raises on `uq_operation_outputs_truncated_once`, the step provably rolled back (heads re-proven unchanged), and duplicate markers are PROVEN in the data — stamp past that one index statement, journal the prerequisite, and let forward 0027 re-apply 0026's other effects with `IF NOT EXISTS` (both paths converge on identical columns) and install the legacy-safe guard `uq_op_outputs_truncated_once_forward` (`ts >= cutoff`), leaving legacy duplicate rows untouched and readable | Deleting or rewriting the legacy duplicate markers (destroys append-only evidence); editing applied 0026 or hand-running operator SQL (immutable history, and manual steps are not a tested installer path); a plain `upgrade head` with try/except (a skipped step must be a PROVEN named condition, never a swallowed failure); a forward migration alone (0026 runs first and fails before 0027 exists) | The upgrade is the product: the exact condition, the exact statement, and the retained data are each verified from the database before anything is stamped, the exception is recorded in the attempt journal, and any other failure still propagates with data and config untouched. The bounded guard makes NEW duplicates a database impossibility without erasing the historical ones. |
| Fail-closed audience for unknowable history: forward 0027 relabels every coach row existing at migration time to `audience='legacy'` — never member-visible, never in a provider prompt, renderable only in the operator thread labelled legacy — with the relabel performed as explicit schema maintenance (append-only trigger disabled ONLY around that one UPDATE, re-enabled before the step commits), plus a runtime fence that refuses coach threads with 503 while the schema head is exactly 0026, and metadata-less pending jobs resolving `legacy` | 0026's `member` default (the leak: sealed operator history surfaced in member GETs and next provider prompts); deleting or hiding old rows (they are the operator's own history); relying on 0027 alone (the API could serve between 0026 and 0027 — the fence closes that window); silently relabelling to `operator` (guessing audience would seal data that is actually member-owned — `legacy` fails CLOSED) | Unknown must mean closed, not guessed. The trigger refusal of the first relabel attempt proved the runtime guarantee held THROUGH the failure; the bracketed exception is single, auditable, and reversible — and downgrade deliberately never relabels legacy back to member, because that would recreate the leak. |
| Bundle = the upgrade artifact: MANIFEST carries an `upgrade` contract (engine, migrations dir, revision, command) and BUNDLE_VERSION 2 refuses pre-21 payloads for upgrade by construction; the CLI `upgrade` runs journal→backups→staged verify→atomic activation→proven migrations→restart, with resume for a named in-progress attempt and a config-only restore issuing ZERO service actions | Re-rendering config and calling it an upgrade (the old stub: no backups, no migrations, no journal — rejected outright); accepting unversioned payloads "for now" (an unversioned artifact cannot prove which schema it migrates to); restore restarting services (a restored box must never be un-paused into an engagement) | The operator carries one sealed artifact; what gets activated, migrated and refused is exactly what `bundle.py verify` digested. Interrupted work is retained and RESUMED, never raced or discarded. |

### Plan-21 review-round-2 upgrade-safety decisions (2026-10-28)

| Decision | Rejected alternatives | Why |
|---|---|---|
| Admission fence is a STATE FILE (`/var/lib/sparring-range/maintenance`) checked by API middleware: NEW work → 503 while login, internal callbacks, health and ingest flow; the engine raises it before consuming quiescence and drops it only on COMPLETION | DB maintenance-mode column (a dead service can still race admission before its own DB check; a file stat cannot); blocking internal callbacks too (in-flight runs would be stranded UN-terminalized, converting the fence into data loss); process-level flags (lost on restart, invisible across services) | The fence must hold across per-file activation and migration exactly when the process doing the work is not the process making decisions; existing obligations must still terminalize. Fail-closed on stat errors. |
| Quiescence reads EVERY durable authority (runs, model jobs incl. `cessation_unknown`, dispatched-command inventory, broker ledger) and a missing ledger is a REFUSAL unless `--allow-fresh-install` attests a provably never-claimed box; quiescence is RE-proved under the fence before the first mutation | Ledger-only (round-1: the API's own durable work was invisible — proven flaky-passed); missing ledger = quiesced (absence of evidence); trusting one check (a job admitted between check and fence would be upgraded under) | `cessation_unknown` means provider-side work nobody can confirm stopped — restarting over it is the exact failure the ledger exists to prevent. |
| The owner DB credential travels environment→private 0600 `PGPASSFILE`→child environment; `--db-url` is REMOVED (CLI refuses it); argv carries endpoint flags only | A URL argument (world-readable in the process table for the whole upgrade — the review found this); `PGPASSWORD` env to children (same-uid readable); prompt UI (unscriptable for the installer contract) | Secrets that appear in argv cannot be unsent; the gate's pg_dump wrapper FAILS (exit 47) if the fixture secret ever appears in its argv, so the passing gate is the inspection. |
| The version stamp is the LAST durable fact, written only after a CHECKED restart (every unit restarted AND `is-active`-verified); provisioning (locked deps + entrypoint import + frontend build, same service helpers as install, installed venv runs migrations) is a journaled stage BEFORE migration; an unfinished attempt outranks any no-op answer | Stamping before restart (advertised a release that never executed); `check=False` restarts (failure looked like success); relying on the invoking interpreter (a green migration proved nothing about what the UNITS execute); no-op bypassing resume (round-1 probe: `--resume` on an unfinished attempt returned "already at revision") | "Upgraded" must mean the services RAN the verified release with its locked dependencies. Anything less leaves the fence up, writes no stamp, and stays resumable. |
| Config backup EXCLUDES the journal tree entirely and records ORIGINAL mode/uid/gid; restore validates the COMPLETE inventory before writing a single file and restores ownership where entitled (root full; non-root only own files) | Backing up live mutable journals (mkstemp-replaced during the backup — the reproduced digest-mismatch defect); writing valid files then discovering a late corrupt one (half-restored config); privacy-masked restore (broke a 0640 service-readable file) | A restore is the failure path; it may not itself become the second failure, and permission guessing is privilege invention. |

### Plan-21 review-round-3 upgrade-compatibility decisions (2026-10-28)

| Decision | Rejected alternatives | Why |
|---|---|---|
| Quiescence is TABLE-AWARE against the live schema (each durable authority is checked only per its introducing revision; absence below it is truth, at/above it a missing table is a refusal), and the 0021 credential-store role + API-only 0600 `secrets/db-secret.env` are bootstrapped by the ENGINE before migration through the installer's own local-superuser channel (honor existing file/`SR_PG_SECRET_URL`; generate+ALTER only when missing) | Refusing every old box until the operator runs SQL to add the role (the reproduced real failure: 0019→head dies in 0021's GRANT); pretending absent newer tables are "unreadable" (an old schema legitimately has no `model_jobs`); manual chmod/file creation (untested operator ceremony) | The shipped upgrade must work from the real deployed revision (52ae355 = 0019) with zero manual prereqs, at the same minimal boundary the installer uses, preserving existing keys and profiles. |
| The barrier against an OLD running API is stopping the admitting services (`sr-api`, `sr-worker-supervisor`) and proving them inactive before the authoritative durable recheck; new-generation admission is additionally refused AT the transaction boundary (`model_jobs.enqueue`, run insert raise `AdmissionFenced` → 503) and `/internal/model/*` is no longer middleware-exempt (only terminality callbacks are) | A fence file alone (the old process never reads it — proven: 200 + queued job under the fence); blanket `/internal/` exemption (let completion callbacks enqueue NEW generations); killing remote providers to "cease" them | Whatever the running code knows, the stop covers; the transaction boundary covers new code and races; unknown/cessation-unknown obligations are refused, never discarded, and no remote cessation is ever claimed. |
| Restart = `daemon-reload` (units were rewritten) + checked restart + BOUNDED REAL-HTTP readiness (`/readyz` — which binds schema head to the installed package — and the frontend) before the stamp; failure keeps fence+journal+resumability | `is-active` alone (an active unit serving 503 passed the old check — reproduced); stamping then hoping | The stamp is a durable claim that the release RAN and serves; health is proven over a socket, not inferred from a unit state. |
| `--restore-config` KEEPS the fence while an attempt is unfinished (and issues zero service calls regardless) | Unconditional fence-drop on restore (reproduced: unfinished attempt, fence gone, "service_actions: []" misread as "services stopped") | A config rollback cannot undo the activated runtime or the forward-only schema; re-opening admission over unknown state is exactly the failure the fence exists for. |
| Owner URL is parsed with SQLAlchemy `make_url` (accepts the installer's `postgresql+psycopg2://`) and validated at PREFLIGHT; owner/secret env vars are STRIPPED from every inherited child environment (explicit call-site channels win, `PGPASSFILE` for the pg tools) | Rejecting the installer's own URL format at backup time (after the fence — reproduced); letting venv/frontend/native children inherit the owner URL (the reproduced child-env leak) | The operator exports exactly the credential `hand_off.sh` wrote; secrets travel only their one authorized channel, and format pain surfaces on --dry-run with zero mutation. |
| The payload must carry a versioned REQUIRED_RUNTIME_CONTRACT (lock, alembic config, migrations, unit entrypoints, frontend inputs) checked against the payload, not against its own MANIFEST list | Hashing whatever the untrusted manifest declares complete (removing `requirements.lock` from disk AND manifest passed — reproduced) | An upgrade payload that cannot provision what the units exec is not an upgrade; completeness cannot be self-declared by the artifact being verified. |

### Plan-21 review-round-4 decisions (2026-10-28, branch `practice-upgrades-18-21`)

| Decision | Rejected alternatives | Why |
|---|---|---|
| Readiness is the PARSED `/readyz` JSON contract: exact `ready is True`, empty `issues`, and `migration_version` equal to the payload's schema head; malformed bodies (non-JSON, HTML, missing fields, non-bool truthiness, ready-with-issues) and stale processes reporting `ready:true` at an old head all fail closed | Accepting any HTTP 200 (reproduced: the installed `/readyz` answers 200 with `ready:false` and the CLI stamped 0027 over an unhealthy 0019); inventing a 503-only model the real API never produces | The stamp is a claim about THIS release serving; only the endpoint's own structured verdict, bound to the payload's head, proves it — status codes cannot express "wrong version, still healthy-looking". |
| The admission fence records its owning attempt; completion clears only its own fence, and `--restore-config` releases a fence ONLY when the selected attempt is done, NO other attempt is unresolved (corrupt journals count as unresolved) and the fence identity is verifiably the restored attempt | Per-attempt-status fence-drop on restore (reproduced: completed A's restore cleared unfinished B's fence, exit 0); pattern-matching or "most recent" attempt ownership | A config rollback can never roll back the runtime or the forward-only schema; releasing an obligation the restore cannot see re-opens admission under unresolved work — exactly what the fence exists to prevent. Unknown identity is fail-closed retained. |
| The SELECTED `--db-url-env` name is REGISTERED for the process and every unauthorized child environment is scrubbed by the explicit name set (`credential_env_names()`), never by fixed-name or pattern filtering | Fixed OWNER_ONLY_ENV filtering (reproduced: `--db-url-env REVIEW_PRIVATE_OWNER` reached pg_dump and provision children); blanket env sanitization by substring (breaks legitimate variables, hides intent) | An arbitrary operator-chosen name must be as safe as the built-in ones, and proof requires an explicit registered name — proven by the wrapper's exit-48 tripwire and the installer-channel env capture (54 keys, zero credential names). |
| REQUIRED_RUNTIME_CONTRACT is derived from the actual EXECUTION SURFACE: dependency/build locks + `alembic.ini` + migrations `env.py` + every unit's ExecStart module | A hand-maintained "obvious files" list (reproduced: dropping `env.py` or `worker_supervisor.py` from disk AND inventory passed); hashing every repo file (stamps, docs and tests are not the executable contract) | The contract is what the services must be able to RUN after activation; deriving it from the units and migration runner makes omission a refusal instead of an accident. |
| The runbook's post-upgrade check separates journal RETRIEVAL from interpretation: private `mktemp` file, exit-checked `journalctl`, grep only on success; retrieval failure prints a distinct message and exits 1 | The one-pipeline `journalctl … \| grep … || echo "clean boot"` (reproduced: journalctl failure exited 0 printing "clean boot") | "No error lines" is only evidence when retrieval actually succeeded; a false clean boot admits members onto an unverified appliance. The documented script is itself under test (extracted verbatim and executed against fakes). |

### Plan-21 review-round-5 decisions (2026-10-28, branch `practice-upgrades-18-21`)

| Decision | Rejected alternatives | Why |
|---|---|---|
| The admission fence is an identity-bearing MUTEX TOKEN validated at every boundary: classified before mutation at acquisition (foreign/anonymous/unreadable → refused and kept byte-exact), acquired only from ABSENT via `O_CREAT\|O_EXCL` exclusive create, re-required at finalization before the stamp, and cleared at completion only when owned EXACTLY by the completing attempt; a resume proceeds only over its own verified fence identity | Overwriting or "taking ownership" of an existing fence at upgrade start (reproduced: foreign fence replaced, `{}` stripped during the readiness window then removed — both stamped done); clearing fences whose `attempt` key is missing at completion (absence is never consent); journal-absence as authority over a fence | Check→write on a shared token is a race an operator can hit; the CAS plus identity validation at acquisition, finalization and completion means no upgrade can silently assume an obligation it cannot see, and an ownership change mid-run blocks success instead of minting a false release. |
| The gate's second payload is built in a PROPER ISOLATED git fixture (its own ancestry), keeping the distinct-revision requirement deterministic under every TMPDIR | Extracting the tree inside the checkout and letting git DISCOVER the parent repo (reproduced: disk-backed `TMPDIR=$PWD/.cache/tmp` made rev2 == candidate HEAD, the gate failed at 403.7 s and every later cross-attempt probe silently stopped running); relaxing the distinct-revision assertion or special-casing "unknown" | A required acceptance gate must fail or pass truthfully in the documented operator environment; determinism comes from the fixture's ancestry, not from weakening the property under test. Production packaging verification is untouched. |
| §7 drives the upgrade CLI as `cwd = payload tree` + `/opt/sparring-range/.venv/bin/python deploy/appliance.py …` with an explicit bootstrap-import preflight (`deploy.appliance`, `deploy.upgrade`, `sqlalchemy`, `alembic`) | Unqualified `python3` or an old checkout (no dependency guarantee for the CLI's imports — the exact shape the acceptance gate does NOT test) | The installed venv is the provisioned, lockfile-verified interpreter the services and migrations use; the tested invocation contract and the documented one must be the same thing. |

### Installed-practice repair decisions — 2026-10-29

The user authorized plan 22 and autonomous Qwen-high implementation/review on the
existing implementation branch. This consolidates the installed test findings and
retained plan-20 review defects; it does not authorize agents to update the VM.

| Decision | Rejected alternatives | Why |
|---|---|---|
| Separate configuration/contract-bound commissioning qualification from bounded automatic non-disruptive admission health; qualification age is displayed, not by itself treated as a failed test | Repeating manual commissioning every 24 hours or every session; silently increasing TTL; minting new passed receipts from old observations; disabling safety wholesale | Observations do not become false at midnight. Ordinary use must remain practical while changed, failed, incompatible or unknown safety state still blocks. Original evidence and its scope remain explicit; legacy compatibility must be proved, not assumed. |
| Preserve latch/unknown-cessation/ownership fences and invalidate qualification for relevant changes or safety transitions; automatic checks use fixed typed existing authorities | Model/worker host-shell or firewall privileges; destructive killswitch exercises on every Begin; unobserved automatic attestations | Usability cannot weaken containment, manufacture proof or interrupt other active work. No extra privileged operator service is authorized implicitly. |
| Repair installed identity/configuration paths and verify a real browser login after upgrade; preserve old receipts and version new verified baselines | Manual world-readable secrets, account reset, receipt overwrites to hide drift, HTTP-200-only release claims | The installed test exposed production-path omissions despite green sandbox gates. Actual identities and client routing are acceptance inputs. |
| Ground coaching in phase and authenticated actor provenance, with explicitly unknown telemetry attribution | Calling member setup commands attacker actions because of a host label or citation; accepting user assertions as verified scores | Hints must be useful without inventing attribution or authority. Subjective feedback remains separate from deterministic scoring. |
| API credential access is a NAMED POSIX ACL (traversal on the secrets directory, read on the key) computed by a deterministic pure-codec and provisioned at install AND repaired before readiness on upgrade; ownership and key bytes stay untouched | `chmod 0640` group widening, world-readable secrets, rotating the credential, or letting readiness fail until an operator hand-patches the ACL | A named ACL grants exactly one identity one operation; the upgrade that broke on this fault must self-heal the same way a fresh install provisions it, verified against real kernel DAC decisions on distinct UIDs. |
| Account-bound bastion enrollment is an API-managed PUBLIC-key-only file under the state tree, merged with the never-rewritten operator commissioning file and hot-reloaded by mtime; SHA256 fingerprints are the display currency | Rewriting the operator file, a privileged restart/signal to apply enrollment, transmitting private keys, or letting an enrollment mistake evict another account's working key | The installed failure was an unenrolled account nobody could see; diagnosis and enrollment must be possible through the API/CLI/UI with public material only, and taking effect without privileges. |
| ONE deterministic host-role classifier decides what connections ADVERTISE (launch and re-fetch share it); a runner-only attacker guest advertises no member SSH string | Advertising SSH for every host and letting the member discover `Permission denied`; client-side role guessing | The platform must never offer a capability it itself refuses to use; advertisement is policy, authentication stays with the guest image. |
| Citations are the timeline compressor's CANONICAL accounting of events actually rendered (chat allow-list and the AAR narrative validator both consume it), not a regex over rendered text | Parsing `#<id>` out of the rendered timeline, where a command payload like `echo reference #99999999` launders a non-existent id into the approved set | A citation is a pointer to an evidence RECORD; only the renderer knows which records it showed. Forgery resistance must not depend on what command text happens to contain. |
| Replay takes ONE server-sourced canonical session-clock anchor (the session's first event, unfiltered); worker-claimed pipe-read instants are window-bounded at ingest, dropped when implausible while their bytes persist, and the projection labels which timing is shown | Deriving t0 client-side from whatever the current filters show (the cast offset moved mid-view); trusting `read_ts=1`; letting a bad timestamp silently masquerade as observed timing | A clock claim that moves with a filter or survives a 1970 epoch is not evidence; completeness outranks a timestamp, and the surface must say what it is showing. |
| Capture idempotence is exact equality on (seq, kind, text, claimed read time, drop count); any divergence at a known seq answers 409 with the worker transport keeping its typed `conflict` classification | A silent HTTP 200 on conflict; same-text-only equality that lets a retried body rewrite timing claims | The capture stream is append-only evidence: a divergent re-delivery means the producer's stream forked, and that must be loud, typed, and never a silent overwrite. |

## Risks and explicitly unverified inputs (historical baseline; see reevaluation above)

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
