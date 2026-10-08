# Roadmap — first deployed Linux CCDC practice release

Design: [ARCHITECTURE.md](ARCHITECTURE.md). Baseline/open evidence:
[FINDINGS_CHECKLIST.md](FINDINGS_CHECKLIST.md). Operator work:
[OPERATOR_RUNBOOK.md](OPERATOR_RUNBOOK.md).

These are **new release milestones**, not retroactive completion of the old
M0–M7 plan. No implementation milestone is accepted yet. Architecture and ordered
scope are agreed; write the full implementation plan for **one milestone at a
time**, inspect the then-current code, and obtain agreement before implementing.
Plans go in `.openchamber/plans/NN-short-name.md`; do not write them all now.

Each milestone requires independently executed acceptance, not old reports or
unchecked implementer claims. Its plan ends with at most ten command/behavior
criteria and separates operator-only `Manual checks`. A missing software fixture
is implementation work, not a hardware-only gate. Preserve existing useful fixes.

## 01 — Reproducible baseline and release dependency hygiene

- [ ] Accept milestone 01.

**Goal:** trustworthy tests/CI and a reproducible developer stack before expanding
the product. **Depends on:** the agreed release contract.

Approved implementation plan: [01-reproducible-baseline](../.openchamber/plans/01-reproducible-baseline.md)
(2026-10-08). **Implemented (2026-10-08, incl. review fixes):** all locally
executable gates pass (infrastructure-free default 114/0/0; selection/python
3.11–3.13/db/containment/frontend/compose via `infra/dev/acceptance.py`);
packet and browser fail closed on this host for missing prerequisites and are
accepted only when their required CI jobs pass after the operator pushes.
Evidence: [findings checklist](FINDINGS_CHECKLIST.md). Acceptance stays
pending until CI is green — not waived.

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

- [ ] Accept milestone 02.

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

- [ ] Accept milestone 03.

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

- [ ] Accept milestone 04.

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

Next: jointly write `.openchamber/plans/01-baseline.md` after checking this
baseline against current code. It does not yet exist. No milestone implementation
session is authorized by this roadmap alone. Implement code only on a user-selected
non-default branch. Each accepted milestone ticks its checkbox and updates the
architecture if its design changed; record reasons rather than hiding deviations.
Early operator discovery may de-risk storage/PVE/model inputs, but no real
model-driven attacks are authorized before the safety gates pass.
