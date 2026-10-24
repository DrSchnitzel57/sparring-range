# Roadmap — first deployed Linux CCDC practice release

Design: [ARCHITECTURE.md](ARCHITECTURE.md). Baseline/open evidence:
[FINDINGS_CHECKLIST.md](FINDINGS_CHECKLIST.md). Operator work:
[OPERATOR_RUNBOOK.md](OPERATOR_RUNBOOK.md).

## Current completion sequence — draft 2026-10-20

User-approved direction: a complete individual-practice product in **one Ubuntu
appliance using KVM/libvirt for nested full lab VMs**, with a separate local broker
service and no outer-Proxmox credentials. No deadline-driven scope reductions.
The user authorized planning the full sequence together;
the three plans below were drafts; subsequent branch implementation and operator
commissioning are recorded here, not proof of full milestone acceptance. Their
numbers follow
plan 13 and are completion milestones, not a renumbering of historical 01–12.
Tests were deferred for that original planning pass; later evidence is dated below.

- [ ] **14 — Nested appliance foundation and working SSH.**
  [Plan](../.openchamber/plans/14-nested-appliance-foundation.md).
  Deliver the minimal real appliance installer, libvirt broker, isolated network,
  clean guest images, actual member SSH/replay and recoverable resource lifecycle.
  **Promotion gate:** independent automated hypervisor/access/install proofs AND an operator
  fresh-launch → member SSH/sudo/reconnect/replay → cleanup → second-fresh-launch
  rehearsal with real nested KVM/isolation/stop. **Update 2026-10-23:** actual
  deployed SSH/sudo/replay and scoped isolation/stop commissioning succeeded;
  a ready flag alone was not the evidence. See current findings. No attacks are
  needed for this milestone.
  *Status 2026-10-20 (branch `15`):* the software half exists — typed libvirt
  broker behind a peer-UID Unix socket, manifest-derived policy, the operator
  installer with evidence-bound recovery, a golden-image builder and the
  `hypervisor`/`access` layers. At that historical checkpoint the gate was open:
  nested KVM was unavailable in this environment, so the operator's fresh-launch → member
  SSH → replay → cleanup → second-launch rehearsal with real isolation and stop
  evidence had not yet been produced.
- [ ] **15 — Complete integrated individual practice.**
  [Plan](../.openchamber/plans/15-complete-practice-product.md).
  Complete both presets, durable lifecycle, honest service/inject/security results,
  sustained AI behavior under a distinct worker identity, browser/CLI authorization,
  reports and history. Reuse
  existing functionality; repair missing end-to-end behavior rather than rebuild.
  *Status 2026-10-20/21 (branch `15`):* separate-UID worker dispatch, the
  appliance installer, the controller MySQL client, the release bundle and the
  `hypervisor`/`access`/`journey`/`bundle` layers are implemented, and
  `selection`/`python`/`db`/`authority`/`install`/`hypervisor`/`access`/`bundle`
  pass here, and the aggregate `appliance` gate runs the whole software matrix
  in one pass. The `journey` layer requires the INSTALLED appliance, so it cannot
  be closed in a developer environment; the real-model and human gates stay open,
  and `images`/`capture` need a KVM runner (their image builds exceed the
  serial-marker timeout under software emulation).
  *Status 2026-10-21 (review round, branch `15`):* an independent review
  returned **VERDICT: FIX**. Its findings are fixed: the supervisor's
  callbacks are fenced by their own claim credential, the API no longer
  signals a worker in another UID, the controller stops acting when its lock
  dies, the schema-owner credential no longer travels in a runtime
  environment, the TLS artifacts and the credential ownership are complete,
  the bundle carries the role artifacts, and the aggregate attempts the
  operator gates instead of omitting them. The evidence is in
  `docs/FINDINGS_CHECKLIST.md` ("Review round") and the reviewer's map is in
  `docs/HANDOFF-15.md`.
- [ ] **16 — Installable appliance and qualified release.**
  [Plan](../.openchamber/plans/16-appliance-release.md).
  Finish the checksummed release bundle, upgrade/history-import/recovery tooling
  and operator guide; prove the complete software matrix at a pinned candidate,
  then collect operator/human acceptance. Backup destination/live restore remain
  optional. Runtime practice features and their tests are delivered in 15.
- [ ] **17 — Appliance hand-off in the operator's own VM.**
  [Plan](../.openchamber/plans/17-appliance-handoff.md).
  Added 2026-10-20 at the user's request: deliver a deployable product the
  operator can install and test in their own virtual machine. This is also
  where milestone 14's promotion gate closes for real — nested KVM, isolation,
  emergency stop and member SSH rehearsed on hardware instead of asserted.
  It consumes 15 and 16; it does not replace them. The hand-off path is
  implemented (the release bundle, the rendered operator manifest, the
  installer and the `firstboot` health check); the rehearsal itself is the
  operator's, in their own VM.

Three milestones are the minimum useful split: an accessible/recoverable platform,
a complete practice product, then a qualified release. Each has internal coding
checkpoints and its own tests. Implement one at a time on a user-selected
non-default branch; commit coherent changes, never push. Reviewers run the relevant
gates independently. Any requirement not met stays open, regardless of plan ticks.

### Post-commissioning backlog — 2026-10-23

Commissioning for the supervised AI run is complete: readiness, SSH/sudo/replay,
scoped network denial/spoof/IPv6 probes, boot persistence, API/broker VM stop,
control-loss watchdog and real runner component cancellation. Do not repeat these
as if no evidence exists. Full automated `packet`/`journey` command acceptance,
adversarial qualification and whole-release acceptance are distinct claims.
The source patch is installed; eight later commands establish dispatch but not
useful sustained practice. Milestone checkboxes are not advanced by this cleanup.

Retain this scope for the next fixes/improvements discussion, not a new plan:

- Conversational history/checkpoints, token-aware ~262k local context and reasoning
  headroom, bounded compaction recovery, real progress and cancellation. Framework
  unselected; Pydantic AI slim prototype recommendation only.
- Admin endpoint/model/write-only key/thinking none-low-medium-high GUI, capability
  testing and run-snapshotted protected configuration.
- Honest coach/AAR provenance/scoring, trusted image-bound cron hashes, useful
  real-model behavior and complete preset acceptance.
- Home active/history dashboard, session navigation, Markdown reports, filtered
  timelines and separate honest attacker/defender replay tracks.
- Permanent installer/native/UID/trust/firewall/config repairs replacing operator
  workarounds; cessation-safe teardown/accurate cleanup UI and audited recovery,
  including open obligations; independent adversarial AppArmor acceptance.

Details: [findings](FINDINGS_CHECKLIST.md#consolidated-deployment-and-product-status--2026-10-23).
Requirements: [architecture](ARCHITECTURE.md#j-local-conversation-engine-admin-settings-and-session-review-2026-10-23).
No runtime replacement, new plan or live operation is authorized by this cleanup.

### Agreed upgrade sequence — planning 2026-10-24

The user approved all four plans on 2026-10-24 after full-sequence planning here.
The whole backlog remains in scope; these supplement, not falsely complete,
historical 14–17. Implementation waits for the user's new worktree:

- [ ] **18 — Permanent appliance and recovery repairs.**
  [Plan](../.openchamber/plans/18-permanent-appliance-repairs.md). Installer/native/UID/
  TLS/config/firewall reproducibility, packaged CLI migrations, cessation-safe
  teardown/obligation tooling, trusted cron image pins and adversarial containment
  regression fixtures. Preserve completed commissioning evidence.
  *Status 2026-10-24 (branch `practice-upgrades-18-21`, implementation —
  independent review pending):* all seven plan acceptance criteria were
  reproduced or repaired with automated evidence: fast 604/0/0; `install`,
  `authority` (32), `containment` (26, incl. five new inside-boundary
  adversarial negatives), `db` (184, incl. installed-CLI migrate/status
  reaching head outside the checkout) and `selection` PASS; `images` PASS
  (19) with the artifact-bound cron-pin test under TCG (software emulation,
  no `/dev/kvm`). Commits `2a162d9`…`9885f87`; decisions in the architecture
  and exact attempts in the findings checklist. Pending operator gates stay
  open and are NOT claimed here: `packet` (root+`nft`), `journey` (installed
  appliance), the installed UID/TLS/boot/KVM rechecks affected by these
  changes, and independent adversarial qualification of the broader
  AppArmor profile `9e03696`.
- [ ] **19 — Conversational agent and model administration.**
  [Plan](../.openchamber/plans/19-conversation-and-model-admin.md). Pydantic AI slim,
  protected versioned profiles/role overrides/thinking mappings, context-aware
  history/checkpoints, one-slot async scheduling/cancellation and admin GUI.
- [ ] **20 — Conversational coach and session review.**
  [Plan](../.openchamber/plans/20-coach-dashboard-and-replay.md). Grounded coach/AAR,
  modern home/history/session navigation, filtered audit and synchronized new-run
  timed attacker/defender replay with honest historical fallback.
- [ ] **21 — Upgrade and qualified integrated release.**
  [Plan](../.openchamber/plans/21-upgrade-and-integrated-release.md). Supported preserving
  in-place upgrade, corrected fresh-install bundle, changed-artifact rebuilds,
  installed/aggregate proofs and explicit real-Strata/manual acceptance.

Architecture section K records choices/defaults. Do not restart cancelled
DB/selection runs as though they failed; future acceptance may run them when needed.
The fast planning baseline is recorded in findings. No deployment or new feature
implementation was performed during planning. After agreement, validate/commit
the pre-existing memory fix separately, commit plans, merge `15` into `master`
without pushing; user creates the new implementation worktree.

### Carry-forward map (no requirements silently dropped)

| Existing contract | Completion owner |
|---|---|
| Plan 13 phase 1: manifest, settings, baseline, amendments | 14; final reconciliation 16 |
| Phase 2: authority, deadlines, ownership and cessation | 14, translated to libvirt/Unix-UID contracts; old PVE ACL/UPID work superseded |
| Phase 3: role-separated pinned artifacts, runner, guest identities/data | 14 access prerequisites; 15 both-preset installed behavior |
| Phase 4: trust, role config, network planes, capture/readiness | 14; local broker socket replaces remote mTLS, public/ingest HTTPS retained |
| Phase 5: durable async deploy/recovery | 14 deployment; 15 match/finalization integration |
| Phase 6: controls, probes, injects, attacker | 15 |
| Phase 7: browser, visibility, reports | 14 connection/diagnostic UI; 15 complete journey |
| Phase 8: real installer, consolidation, persistence, backup/restore tools | 14 minimal working appliance install; 16 bundle/upgrade/import/recovery |
| Phase 9 and criteria 1–10: final matrix, live/human proof, documents | Per-milestone tests plus 16 final evidence; live SSH is an earlier 14 gate |
| Original 03/04 separate image/capture acceptance | Separate gates in 14/15/16; never collapsed into a single image claim |
| Original 05–09 functional acceptance | 15, confirmed by 16 release evidence |
| Original 10–11 operational/live acceptance | 14 and 16; original checkboxes require their own evidence |

### Explicit substitutions, not hidden scope cuts

The architecture's [appliance contract](ARCHITECTURE.md#ubuntu-kvm-appliance--2026-10-20)
is authoritative for the new backend. Plan 13's product/evidence/failure requirements
carry forward, but its PVE-specific mechanisms are replaced as follows:

| Old mechanism / acceptance | New equivalent |
|---|---|
| Separate service VMs + broker mTLS | Appliance service UIDs, private peer-authenticated broker socket, local cast storage |
| PVE token/ACL/VMIDs/UPIDs/template import | Typed libvirt domain UUID/owned overlay operations, durable intent and read-back; no outer authority |
| PVE range bridge/VLAN | Operator-installed inner bridge + appliance host-input/forward/bridge filtering |
| PVE guest-agent FileRead pin | Fixed domain-bound QGA read-only key/first-boot operations; identical no-TOFU/generation invariants |
| `pve-contract` mandatory release gate | `hypervisor` actual libvirt/KVM plus `authority` UID/policy/ledger gate; legacy tests retained as appropriate |
| Full/linked PVE clone alternatives | One immutable flattened base + fresh per-generation qcow2 overlay mode |
| Appliance-specific keys baked into templates | Public keys injected into typed per-instance seed; no private keys or live capabilities in image/seed |
| Deleted-installation assumption | Preserve/discover old VMs; import closed history only; operator reconciles/retires old infrastructure |

No old plan is retrospectively marked complete. Historical 03–11 checkboxes can
close only with recorded equivalent appliance evidence, explicitly naming changed
mechanisms; there is no need to reimplement the superseded PVE design to tick them.
No automatic PVE ACL maintenance task or separate broker VM belongs to this plan.

### Execution and handoff

1. Review/approve these drafts, then commit the agreed documentation on master.
2. User selects the implementation branch. Start 14; inspect current code and
   reproduce safe baselines then, recording genuine failures before repairs.
3. Finish each plan's internal steps with coherent commits, exact test evidence
   and an acceptance table. No speculative future-milestone changes.
4. Operator supplies the manual 14 promotion evidence. Models do not run live
   host changes or infer success from old notes. Resume 15 only after that gate.
5. Complete 15, then 16. Failed proof stays open; narrow fixes return to their
   owning modules and rerun affected gates, not a new open-ended remediation plan.

## Historical release milestones and acceptance ledger

The sections below preserve the original sequence and evidence. Statements about
then-missing code are historical, not a fresh inventory; use the completion
sequence above and current findings to direct new work.

These are **new release milestones**, not retroactive completion of the old
M0–M7 plan. Milestone 01 is accepted (reopened by independent review, then
closed by the repair round recorded in the findings).
Architecture and ordered scope are agreed; write the full implementation plan for **one milestone at a
time**, inspect the then-current code, and obtain agreement before implementing.
Plans go in `.openchamber/plans/NN-short-name.md`; do not write them all now.
Exception approved 2026-10-12: milestones 03+04 share one paired plan,
[03-04-linux-guests-capture](../.openchamber/plans/03-04-linux-guests-capture.md),
because guest construction, access and installed capture share the same fixtures.
Their acceptance gates and checkboxes remain separate; no other milestone is combined.

Each milestone requires independently executed acceptance, not old reports or
unchecked implementer claims. Its plan ends with at most ten command/behavior
criteria and separates operator-only `Manual checks`. A missing software fixture
is implementation work, not a hardware-only gate. Preserve existing useful fixes.

## 01 — Reproducible baseline and release dependency hygiene

- [x] Accept milestone 01 (re-accepted after the independent review's repair round, 2026-10-08).

**Goal:** trustworthy tests/CI and a reproducible developer stack before expanding
the product. **Depends on:** the agreed release contract.

Approved implementation plan: [01-reproducible-baseline](../.openchamber/plans/01-reproducible-baseline.md)
(2026-10-08). **Implementation acceptance recorded, then reopened (2026-10-08):** all locally executable gates pass
(infrastructure-free default 114/0/0; selection/python 3.11–3.13/db/
containment/frontend/compose via `infra/dev/acceptance.py`), and the required
CI jobs — including the kernel-boundary packet and real-browser replay gates
that cannot run on this host — all passed in run 37852029894 at `3539667`
(ten jobs green). Evidence: [findings checklist](FINDINGS_CHECKLIST.md).
Independent review at `27e2624` reproduced safe local gates and checked hosted
logs, but found a shared/reused browser build directory and an edit to migration
0010 contrary to the approved plan. CI follow-up also found intermittent browser
command-observation failure at the same commit (M01-R3).
**Re-accepted (2026-10-08, `62939f7`):** M01-R1/R2/R3 repaired (fresh run-owned
build dirs with override rejection + cleanup and 14 new fast isolation
regressions; migration 0010 restored byte-exact with the test passing a
transaction-bound Connection; bounded wait for the ingested command event).
CI run 37855269245 passed all ten jobs on the initial attempt and again on a
repeat-run stability check (attempt 2), browser-e2e included. Requirements
were unchanged by the review. Milestone-02 planning is recorded below. **Open finding
M01-R4:** a docs-only push then exposed an intermittent db-layer failure
(discarded error body on the login→session handoff); instrumented at this
revision, tracked in the findings until classified.

Investigate the ten fresh failures (including the prose-coupled readiness test),
namespace/PID semantics and DB marker leakage; do not restore unsafe containment just to make old assertions
green. If a real safety defect emerges, retain its failing regression and obtain
agreement before widening scope; milestone 01 cannot be accepted with that gap.
Configure explicit disposable PostgreSQL, forward-upgrade tests, reliable
layer selection, required prerequisite failures, and exact result reporting.
Triage/patch frontend advisories and check Python lock resolution; validate the
actual Compose config/bootstrap/build path. Reconcile legacy documentation
references in package metadata, source comments and historical probe tooling
without deleting regressions. Establish isolated browser/packet fixtures without
displacing other services.

Agreed defaults: infrastructure-free pytest; local PostgreSQL 16 Docker fixture;
required privileged gates on standard GitHub-hosted Linux VMs after verifying
free allowance and a zero-spend blocking budget; patched stable Next 16 retaining
Pages Router/React 18 where compatible; zero high/critical production audit
findings; isolated browser build with configurable ports and run-owned CLI session.
Unavailable required CI leaves acceptance pending, not waived.

**Areas:** `tests/`, `.github/workflows/ci.yml`, dependency manifests/locks,
`docker-compose.yml`, `infra/dev/`, source documentation references.
**Exit:** agreed test layers and fresh-stack build commands genuinely execute;
failures/skips are explained; applicable release-blocking advisories are resolved.

## 02 — Host-safe deployment authority and fail-closed cessation

- [x] Accept milestone 02 (software acceptance 2026-10-12; live/operator gates stay open — see below).

Approved implementation plan (2026-10-09):
[02-host-safe-authority](../.openchamber/plans/02-host-safe-authority.md).
First repair/classify remaining milestone-01 CI failures: latest run 37860676959
at `9393a36` fails two DB tests despite a prior green run at the same revision.
Authority implementation requires that prerequisite resolved, not waived.
Implementation must use a user-created non-default worktree/branch; none started
by this planning session.

**Implementation record (2026-10-09, `71507bb` on `quick-dingo`):** the M01-R4
prerequisite was root-caused and repaired (`a87e83b`), the private broker
authority, fail-closed cessation and containment proofs landed (`e896b10`), and
the new required `authority` gate is wired into CI. All locally executable gates
(fast default, selection, python, db, containment, authority, frontend, compose)
pass at `71507bb`; packet and browser remain CI-only gates on this host. Exact
evidence: [Milestone 02 implementation evidence](FINDINGS_CHECKLIST.md#milestone-02-implementation-evidence-2026-10-09).
**Still open:** every operator/live gate — real PVE ACL denials, VLAN/isolation proofs,
identity/stop evidence on the R740 host, and the $0 CI budget check.
**Accepted (2026-10-12, `e6a1d4d` on `quick-dingo`):** all locally executable
gates pass (criterion table in the findings evidence section), and required CI
run 38264738484 is green on all eleven jobs at the same revision — including
the CI-only packet and browser gates. Software acceptance only; live gates
remain explicit operator work.

**Goal:** model execution cannot administer the R740, and successful stop cannot
hide surviving work. **Depends on:** 01.

Introduce the private deterministic restricted-PVE boundary; remove credentials
from public API/model-worker execution paths and runtime host-root/nft dependency.
Define operator-installed network isolation and evidence/start gating. Implement
independent latched emergency VM hard-stop/read-back with an offline operator
recovery path. Repair/prove protected recursive containment, every signal's safe
identity, start/cancel fencing, and all registration/terminal-writer races.
Unresolved work on any run must block release, including inconsistent terminal
rows, local-dev compatibility and PVE/control outages. Define approved resource
budgets, templates/storage/network operations; no privilege broadening fallback.

**Areas:** `infra/proxmox_client.py`, new private infrastructure adapter/service,
`srplatform/api/{deps,app,runs}.py`, `srplatform/safety/`, `red_agent/runner.py`,
`infra/runner/`, settings, migrations and boundary tests.
**Exit:** harmless boundary/race/stop tests pass; model/guest cannot reach host
authority; exact live ACL and isolation proof remains an explicit operator gate.

## 03 — Real Linux preset templates and owned deployment

- [ ] Accept milestone 03 (reopened 2026-10-12: review found the images/capture QEMU gates boot a synthetic boot sector, not the Ubuntu guests; software acceptance is redone under the strengthened gate, live/operator gates stay open).

Paired 03+04 plan approved 2026-10-12 (linked above). Software work only;
real PVE version/storage/ACL/isolation acceptance remains deferred operator work.

**Goal:** web and web+database presets have reproducible, defendable guests—not
just YAML claiming services exist. **Depends on:** 02.

Create the attacker/full-VM and Linux image build contracts, synthetic service/
business data, documented network-entry vulnerabilities and limited assumed-
breach footholds. Replace placeholder integrity/user baselines. Define defender
and trusted verifier access, guest key pins, clone mode supported by selected
storage, CPU/RAM/disk quotas and actual readiness probes. Repair and validate the
optional Packer path or explicitly retire it in favor of the supported image
build path. Preserve exact ownership, intent/task waiting, lease conflicts,
partial-deploy recovery, reset and unrelated-resource protection.

**Areas:** `infra/images/`, `infra/cloud-init/`, `scenarios/`, loader/orchestrator,
Proxmox adapter/settings, verifier baselines and deployment tests.
**Exit:** approved images can be built from documented artifacts; both preset
inventories/services/data match their specification; isolated deploy/reset/cleanup
works without relying on unavailable reads as proof of absence.

## 04 — Installed telemetry, bastion access and durable recordings

- [ ] Accept milestone 04 (reopened 2026-10-12 with 03 under the same review finding; separate gates remain mandatory).

Paired with 03 under the approved exception, not absorbed into image-only acceptance.

**Goal:** a real command through the installed service reaches the correct current
session and is replayable. **Depends on:** 03.

Complete exact token/nonce/generation enrollment and safe legacy-evidence upgrade;
prove distinct delivery and capture using an actual disposable systemd/auditd
host under `srshipper`. Active unit + bad API/token/unreadable input must stay
unready and recover truthfully. Make capture required in its acceptance job.
Exercise SSH member keys/token revocation/host pins, reconnect/exec/resize capture,
shared durable recording access, audit ordering/dedup, spool crash/outage recovery,
attribution limits and visible gaps. Do not use fabricated stdin as installed proof.

**Areas:** `telemetry/`, `bastion/`, auth/ingest routes, orchestrator,
verification service, migrations, isolated fixture/CI and recording storage.
**Exit:** installed Linux capture and bastion/recording integration execute;
stale capabilities and phase-only enrollment cannot enable readiness/run.

## 05 — Immutable session configuration and durable match lifecycle

- [ ] Accept milestone 05.

**Goal:** one configurable, timed match survives browser reconnects and cleans up
truthfully. **Depends on:** 04.

Snapshot approved preset, mode, duration, intensity, inject toggle, attacker start,
rubric/template identities and effective operator settings. Implement durable
provisioning progress, explicit Begin, 15-minute ready-idle expiry, server clock,
deadlines and duplicate-request protection. End/expiry/interruption captures
evidence before automatic cleanup; emergency prioritizes stop. API restart
interrupts/reconciles rather than restarts attacks. Lease release requires
confirmed owned cleanup; report generation must not hold VMs/lease.

**Areas:** scenario/session schemas, API lifecycle and session projections,
DB models/forward migrations, durable scheduling/recovery, CLI wrappers/tests.
**Exit:** timed and early-ended sessions, idle expiry, restart, browser disconnect,
late/duplicate callbacks and failed cleanup produce correct durable outcomes.

## 06 — Continuous business-service observations and separate scores

- [ ] Accept milestone 06.

**Goal:** credible live uptime and separate verified score components.
**Depends on:** 05.

Build independent HTTP/content and authenticated read-only MySQL transaction
probes (10-second cadence, 5-second timeout), identity-bound append-only samples,
freshness/coverage/downtime projections and versioned availability rubrics. Define
and test scorer-infrastructure health versus ordinary service failure; confirmed
scorer outage interrupts/preserves. Preserve final deterministic security checks,
unknown/polarity semantics and immutable score history. Expose separate service,
technical-inject and security-state results; no arbitrary overall grade/weights.

**Areas:** new scoring/probe services, scenario rubrics, `verifiers/`,
verification service, event/API/progress projections, migration and failure tests.
**Exit:** stopping/restoring real fixture services changes observations/points;
duplicate or missed checks cannot create points; scorer failure is not target
downtime; partial/interrupted history is honest.

## 07 — Timed technical injects and written submissions

- [ ] Accept milestone 07.

**Goal:** a small complete business-inject workflow. **Depends on:** 06.

Author restricted-account, web-content, seeded-data recovery and incident-report
tasks, with versioned release/deadline/point/check definitions scaled to match
duration. Implement durable release/inbox/submission/verification/expiry and
idempotent retries. Technical success requires verified correct state plus timely
submission; written text is bounded untrusted evidence, with no automatic verified
points. Disabled injects produce no phantom tasks/denominators. Deterministic
environment changes, if required, are approved lab-only operations, never model
commands with infrastructure authority.

**Areas:** preset schema/catalogue, trusted inject service, API/event projections,
verifier checks and deadline/concurrency tests.
**Exit:** correct/incorrect/late/duplicate submissions and disabled tasks behave
as declared; task scheduling does not depend on browser or model liveness.

## 08 — Sustained bounded AI attacks and evidence-grounded coaching

- [ ] Accept milestone 08.

**Goal:** useful paced attacks throughout a match and honest feedback.
**Depends on:** 07.

Replace 20-step/objective-finish match termination with bounded sustained
preset-scoped work, no overlapping actions, 60/30/15-second dispatch ceilings,
strict tool schema, actual target inventory and deterministic objective truth.
Keep both explicitly selected start conditions; no hidden foothold/scripted
fallback. Bound context/commands/output and reconcile intents without replay.
All model work uses the one gateway; hints outrank queued attacks, then reports.
Validate Qwen/llama.cpp output/latency; use 60-second timeout and at most three
attempts with 5/15-second delays, then interrupt on failed recovery. Written-task
feedback and AAR narrative are advisory/cited; deterministic separate results
remain usable when report inference is unavailable.

**Areas:** red loop/worker/transport/schema/LLM, model gateway, coach/report
services, settings and real-worker/model-boundary tests.
**Exit:** paced full-duration safe fixture practice, objective completion,
malformed responses, outages, queue contention and cancellation are truthful;
no model output creates verified scoring facts or infrastructure requests.

## 09 — Browser-led competition experience and visibility policy

- [ ] Accept milestone 09.

**Goal:** the agreed website-to-SSH-to-review journey. **Depends on:** 08.

Build the preset/control builder, launch progress, instructions, Begin button,
live 2-second refresh, service health/history, component scores, inject inbox and
submissions, degraded/interrupted/cleanup states, guidance, review/replay/history.
Enforce competition spoiler policy on all APIs/CLI reads, raw events, scenario
details, hints, reports/replay and exports—not only UI elements. Keep authentication,
ownership, logout/revocation and operator access explicit. Remove localhost/
mixed-content assumptions; update score/progress display for separate components.
Browser E2E must test both presets/modes, two sessions, failure states and actual
backend outcomes rather than submitting fabricated scores.

**Areas:** `web/pages/`, `web/lib/`, styles, session/live/coach/replay/progress
routes, auth/serialization and browser/authorization tests.
**Exit:** an authenticated user completes practice without CLI administration;
competition cannot retrieve hidden attack state mid-match; post-match replay,
component scores and history are correct.

## 10 — LAN production packaging, persistence and recovery

- [ ] Accept milestone 10.

**Goal:** a documented maintainable deployment without host-root application
authority. **Depends on:** 09.

Provide managed guest-service startup/health ordering, same-origin IP/port HTTPS,
self-signed IP-SAN certificate/trust, operator account/public-key setup, migrations,
PVE CA validation and private broker/model/ingest exposure. Define protected
persistent DB/recordings/manifests, NAS backup inputs, consistent disposable restore,
time sync, resource/storage limits, indefinite evidence retention and explicit
offline purge/archive procedure. Show storage pressure and block unsafe starts;
do not silently evict evidence or grant runtime event-delete permission. Verify
fresh bootstrap, boot persistence, upgrades, rotation and failure/recovery on an
isolated stack; do not claim Docker YAML parsing proves actual boot.

**Areas:** deployment/guest-service/proxy artifacts, settings/bootstrap/readiness,
backup/restore tooling, ignore rules, runbook and operational acceptance tests.
**Exit:** isolated fresh deployment and restore work using documented artifacts;
safe credentials/persistence/HTTPS do not depend on ad hoc host-root access.

## 11 — Operator infrastructure gates and unaided release acceptance

- [ ] Accept milestone 11 and first release.

**Goal:** verified deployment on the actual R740, not merely passing simulations.
**Depends on:** 10 and operator authorization for each disposable live gate.

Discover/record PVE version, storage/clone performance, addresses and real budgets;
install operator-owned isolation/templates and least-privilege ACLs. Prove denied
WAN/DNS/IPv6/management/model/NAS access with positive controls, emergency stop,
safe release and unaffected management. Exercise real clone/reset/ownership/
concurrent conflict, SSH/background/transport loss, installed telemetry negatives,
model context/latency/recovery, persistent restart, and backup restore. Then run
both presets and start modes, guided and competition workflows, real service
break/recovery and timed injects. One operator and a different member complete
unaided browser-plus-SSH sessions; judge AAR usefulness and history across sessions.

**Areas:** operator deployment and evidence only; narrowly scoped fixes go back
through the appropriate milestone plan rather than skipping its tests.
**Exit:** exact live evidence, no unresolved release blocker, human usefulness
accepted and the roadmap/evidence/runbook accurately reflect the deployed revision.

## Later roadmap — not first-release blockers

- [ ] 12 — Windows/AD services, complete installed Sysmon/WEC pipeline, Windows
  baselines/verifiers/access and operator licensing/image/live acceptance.
- [ ] Revisit true team collaboration, independent concurrent ranges, richer
  service presets and difficulty adaptation only after release-01 evidence.
- [ ] Consider embeddings/RAG only for an identified retrieval need; not because
  spare VRAM exists.

## Planning and acceptance discipline

Milestone 01 has recorded acceptance at `62939f7`, with the intermittent DB
finding still open. Milestone 02's approved plan begins by resolving that CI
prerequisite. No milestone implementation
session is authorized by this roadmap alone. Implement code only on a user-selected
non-default branch. Each accepted milestone ticks its checkbox and updates the
architecture if its design changed; record reasons rather than hiding deviations.
Early operator discovery may de-risk storage/PVE/model inputs, but no real
model-driven attacks are authorized before the safety gates pass.

**Authorized cross-cutting exception (2026-10-13):** the user approved
`.openchamber/plans/12-tomorrow-pilot.md` — a combined overnight pilot plan
(attack-chain repair, PVE template build, sustained AI attacker, durable
match lifecycle, optional uptime scoring, browser flow, deployment artifacts)
to demo a web-only AI-defense practice. It is an explicit exception to
one-plan-per-milestone and its plan number does NOT refer to roadmap
milestone 12 (Windows/AD) below. It accepts and ticks NO milestone: milestones
03–11 keep exactly the acceptance states recorded in
`docs/FINDINGS_CHECKLIST.md`, and anything the pilot plan did not verify
stays explicitly open. Implementation ran on the user-selected branch
`openchamber/tomorrow-pilot`; evidence is recorded under "Tomorrow-pilot
implementation evidence" in `docs/FINDINGS_CHECKLIST.md`.

**Authorized cross-cutting exception (2026-10-14):** the user approved
`.openchamber/plans/13-live-deploy-hardening.md` — one combined, phased
full-release implementation plan (reproducible installation and deployment
hardening). It is an explicit exception to one-plan-per-milestone and to the
4,800-character plan-length limit, and its number does NOT refer to roadmap
milestone 12 (Windows/AD). It accepts and ticks NO milestone by itself:
milestones 01–11 keep exactly the acceptance states recorded in
`docs/FINDINGS_CHECKLIST.md`, and its phase checkboxes track implementation
progress only. The user's release amendments recorded with this plan (fresh
installation with only the bridge surviving, operator-run scoped PVE
bootstrap, measured storage suitability, optional non-blocking backups, one
versioned release manifest) are authoritative over older prose; see
"Plan 13 release amendments" in `docs/ARCHITECTURE.md`. Implementation runs
on the user-selected branch `plan-13-implementation`; live/operator gates
stay open and evidence is recorded in `docs/FINDINGS_CHECKLIST.md`.
