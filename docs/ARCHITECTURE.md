# Architecture — Linux-first CCDC practice release

Status: **agreed release design, not a claim of implemented or deployed behavior**.
**Current direction: Ubuntu/KVM appliance, selected by the user 2026-10-20.**
Read [the appliance contract](#ubuntu-kvm-appliance--2026-10-20) first. It overrides
older direct-Proxmox deployment decisions below; retained release features and
safety invariants still apply. Plans 14–16 are implementation drafts awaiting approval.
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

Three plans only, implemented sequentially on a user-selected non-default branch.
Their checklists are internal coherent commit checkpoints; no subagents or new
sessions unless requested. Each delivers tests of changed runtime contracts and
records precise results; 16 is final packaging/release proof, not deferred testing.
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
| Versioned repository docs | Project Knowledge debugging journal | Findings/decisions/backlog travel with code. Migrate/delete notes, retain existing todo/plans. |

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
