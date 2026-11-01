# 21 — Preserving upgrade and qualified integrated release

> Workflow normalized 2026-10-28: the [native-workflow decision](../../docs/ARCHITECTURE.md#workflow-decision--native-openchamber-2026-10-28) supersedes old procedural rules in this record, not product requirements or acceptance gates. Retained status is not fresh verification.

## Steps
- [x] Inventory installed overrides and define versioned upgrade/preflight contract.
- [x] Deliver preserving in-place upgrade and corrected fresh-install bundle.
- [ ] Prove real install/upgrade/failure/recovery sequences and integrated journeys.
- [ ] Reconcile full backlog, evidence, manuals and handoff.
- [ ] Tick 21 only on its gates; update roadmap/architecture and retained manual status.

## Goal and context
Ship 18–20 as preserving upgrade and clean install. Binding docs:
ARCHITECTURE J/K, ROADMAP, FINDINGS_CHECKLIST, plans 18–20. Approved 2026-10-24;
implement using current task execution choices. Historical baseline 571 fast
passed/267 deselected/4 warnings is not future acceptance. Cancelled DB/selection
commands were not failures; run later only for needed acceptance.

## Scope
In: upgrade, sealed artifacts, packaging/docs and integrated proofs. Out: automatic
live deployment, destructive tests, repeated unchanged commissioning, broad rebuilds,
outer-PVE authority/firewall, Windows/new scenarios or legacy PVE restoration.
No retained installer/legacy/product requirement may disappear.

## Implementation
1. In deploy, infra/appliance services/manifest and packaging, validate versions,
   overrides,
   quiescence, exact owned resources/obligations, schema, native ABI/dependencies,
   model-profile bootstrap, path ownership, artifact signatures/digests and disk
   headroom. Reject unsupported drift/unknown work before mutation; never clear
   latches or equate uptime/readiness. Preserve admin/member users,
   password hashes, keys/pins, service identity, closed sessions, audit, casts,
   historical reports and unrelated apps/config. No secrets in bundle/backup logs.
2. Implement resumable/idempotent upgrade with private source/config backups,
   durable database/storage backup manifest, forward migrations,
   verified staged files/dependencies and ordered service reload only when safe.
   Retain unknown obligations and supported recovery. No reverse migrations or
   old binaries on incompatible schema; restore is quiesced/verified, never resumes attacks.
   No silent key rotation. CLI shows stages/errors.
3. Build fresh-install/upgrade artifacts, locked dependencies and per-file manifests.
   Reuse unchanged verified role images;
   rebuild only modified roles needed for trusted cron pins/profile/capture and
   verify their digests/contracts. Final images contain no live secrets/history.
   Confirm supported Node/libvirt/venv, own-table boot loader and per-service
   access without manual post-install chmod/env workarounds. Reconcile runbook,
   legacy ingest wording/packaged CLI docs and live-practice/handoff chronology.
4. Add required-mode `upgrade` gate: actual fresh/rerun/populated upgrade,
   interruption/drift/repair/restore in disposable fixtures. Prove user/history/
   cast/key continuity, no resume; missing systemd/KVM stays pending, not mock PASS.
   Extend installed journey for both presets, modes/start conditions, controls,
   real SSH/casts, authenticated break/repair/scoring, coach, replay and next-user
   reuse. Label protocol/model fixtures: they do not prove actual AI competence.
5. Run the pinned release matrix; clean only run-owned fixtures. Record exact
   commands/counts/prerequisites/revisions and baseline comparison. Map every
   defect to fix/test or unresolved manual gate. Missing mandatory evidence cannot
   PASS. Never displace OpenChamber/services or repeat unchanged live gates.

## Manual checks
Operator approves live upgrade and actual Strata thinking/tools/token/latency/
cancellation, useful practice/coaching, both presets and unaided workflow. Recheck
isolation/stop/KVM/profile only for changed contracts; retain completed evidence.
Implementation agents do not perform or authorize these manual operations.

## Acceptance criteria
1. AGENTS.md fast pytest command passes, zero failed/skipped.
2. `.venv/bin/python infra/dev/acceptance.py upgrade` passes actual disposable upgrade/restore and negative cases, preserving history/keys.
3. `.venv/bin/python infra/dev/acceptance.py appliance` attempts the full matrix, including new agent/upgrade gates; missing mandatory prerequisites prevent PASS.
4. `.venv/bin/python infra/dev/acceptance.py bundle` verifies shipped base/roles/upgrade payload and rejects tampering.
5. `.venv/bin/python infra/dev/acceptance.py journey` proves installed effects and failure/reuse paths, never silently substitutes a mocked deployment.
6. Fresh install/upgrade needs no manual permission/config fixes; no unknown work is discarded/resumed.
7. Findings/handoff map every defect to evidence or unresolved gate; never fabricate model/hardware/manual passes.
