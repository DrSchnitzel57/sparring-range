# 15 — Complete integrated individual practice

> Workflow normalized 2026-10-28: the [native-workflow decision](../../docs/ARCHITECTURE.md#workflow-decision--native-openchamber-2026-10-28) supersedes old procedural rules in this record, not product requirements or acceptance gates. Retained status is not fresh verification.

## Steps
- [ ] 1. Integrate lifecycle and isolated workers.
- [ ] 2. Complete presets, capture and defender workflows.
- [ ] 3. Complete scoring and injects.
- [ ] 4. Integrate AI, coaching and visibility.
- [ ] 5. Finish browser/CLI and journey proofs.
- [ ] 6. Record evidence; tick 15 on its gates; update architecture.

## Goal and context
Draft 2026-10-20; approval required. Requires 14's software AND operator nested-
KVM/SSH/isolation/stop evidence. Binding design: docs/ARCHITECTURE.md “Ubuntu/KVM
appliance”, docs/ROADMAP.md and findings. Reproduce safe baseline; preserve
accepted repairs. User-selected non-default branch; coherent commits, no push.

## Scope
In: both presets, all controls, lifecycle/scores/injects/AI/coaching, API/CLI/web,
recordings/history; reuse modules. Out: concurrent/shared-team ranges, Windows,
public hosting, new scenarios/frameworks, outer-host automation.

## Implementation
1. Consolidate lifecycle.py/runs.py/deploy_executor.py transitions behind API.
   Durable operation/fence before effects; duplicate/late replies cannot revive
   work/extend clocks. Singleton controller; supervised jobs expose failures.
   Separate-UID sr-worker claims API assignments/supervises children: scoped
   API/attacker only, no DB/broker/libvirt/controller files. Begin alone starts
   jobs/clock; ready expires in 15m. End/deadline/failure/restart fence attacks,
   confirm cessation, capture final evidence/close casts, revoke/destroy/release.
   Unknown retains reservation; no restart resume; reports never hold guests.
   Test crash/cancellation/takeover/transport-loss races.
2. Complete mojang-web-01/mojang-web-db-01 with real attacker/web/DB roles,
   catalogue/12 purchases, cross-guest SQL and fresh scoped reader credentials.
   Prove diagnostic foothold/root path and service-preserving defender repairs.
   Real systemd/auditd/shipper; containment under actual attacker SSH identity.
   Prove spool/rotation/crash/overflow/API/token/input negatives, generation
   binding/recovery; no fabricated capture evidence.
3. Snapshot mode, 30/60/120m, low/normal/high, inject toggle, network-entry/
   disclosed assumed-breach and artifact/rubric/seed/settings versions. No member
   fixture acceleration. Trusted HTTP/content/read-only SQL every 10s, timeout
   5s; locked PyMySQL replaces custom wire code, retaining integrity diagnostics.
   Unique service/generation/schedule results; coverage includes gaps, unknown
   is not downtime, zero-valid unscored. Distinguish scorer/auth/DB faults from
   target outage; bounded health interruption. Separate availability/inject/
   security scores, baseline-aware final predicates; errors never pass.
   Version account/web/data/written injects, scaled deadlines, deterministic
   technical checks and correct/incorrect/late/duplicate outcomes. Disabled
   injects have no denominator; writing feedback earns no verified points.
4. Sustained sequential AI, 60/30/15s ceilings, bounded commands/context/output,
   owned inventory. No hidden network-entry credentials/scripted fallback.
   Hints > attacks > reports; 3 attempts, 60s calls, 5/15s delays, cancellation/
   honest interruption. Cited advisory AAR/hints; deterministic report survives
   model loss/cleanup. Immutable cutoffs/versions; no DB transaction across model
   waits. Central competition filtering covers API/CLI/events/memory/hints/
   reports/exports/replay metadata; authenticated verifiers alone award success.
5. Finish builder/launch/SSH/Begin/2s dashboard, freshness/coverage, submissions,
   hints/recovery/end/replay/history (including interrupted/unscored). Test two
   users, logout/disable/foreign/revoked capabilities, reload/cleanup/missing casts.
   New journey gate: installed appliance, real guests/SSH/browser, labeled model
   fixture; actual break/repair, submissions, scores, cast bytes and next-user reuse.
6. Record evidence/manual items; tick 15 on its gates; update roadmap/architecture.

## Manual checks
Operator validates actual model alias/schema/latency and useful sustained attacks
only after safety gates. Rehearse both presets/modes/start conditions, service
repair and injects. Final unaided human acceptance belongs to 16.

## Acceptance criteria
From root, define `gate() { .venv/bin/python infra/dev/acceptance.py "$@"; }`.
Journey is new; required skips/missing prerequisites fail.
1. AGENTS.md fast pytest passes, zero skips.
2. `for g in selection python db authority hypervisor containment; do gate "$g" || exit; done` passes.
3. `for g in images capture access; do gate "$g" || exit; done` passes.
4. `for g in frontend browser compose; do gate "$g" || exit; done` passes; zero high/critical audit findings.
5. `gate journey` proves workflows/failures with actual backend effects.
6. Journey covers presets/modes/start conditions/controls, bounded failures, immutable history/reuse; accelerated fixtures are labeled.
7. Findings/roadmap retain real-model/human gates; fixtures cannot prove AI effectiveness.
