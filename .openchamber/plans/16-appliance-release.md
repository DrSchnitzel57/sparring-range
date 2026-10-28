# 16 — Installable appliance and qualified release

> Workflow normalized 2026-10-28: the [native-workflow decision](../../docs/ARCHITECTURE.md#workflow-decision--native-openchamber-2026-10-28) supersedes old procedural rules in this record, not product requirements or acceptance gates. Retained status is not fresh verification.

## Steps
- [ ] 1. Package pinned release/installer.
- [ ] 2. Complete upgrade/import/recovery.
- [ ] 3. Deliver release fixtures/operator guidance.
- [ ] 4. Run software matrix; prepare live/human qualification.
- [ ] 5. Update architecture/docs; tick 16/release on matching evidence.

## Goal and context
Draft 2026-10-20; approval required. Requires 14/15, including real SSH promotion.
Binding design: docs/ARCHITECTURE.md “Ubuntu/KVM appliance”, docs/ROADMAP.md and
findings. Deliver reproducible installation/maintenance. Reproduce baseline on
the user-selected non-default branch; coherent commits, never push.

## Scope
In: checksummed app/guest bundle, installer/update/recovery/history, diagnostics,
operator docs/final proofs. Out: outer-PVE automation, old-install deletion,
HA/live migration, new features, mandatory backup destination, paid CI/shared-host changes.

## Implementation
1. Extend deploy/appliance.py: Ubuntu 24.04/Python 3.12, compatible pinned native
   libvirt/QEMU, locked Python dependencies, Next standalone/static assets,
   hash-pinned flattened guests. Bundle binds source/config/schema/images.
   Validate/plan/apply/status/doctor reject drift, fake hashes, unsafe capacity,
   conflicts/permissions before effects; rerun preserves keys/data. Installer
   configures only the operator-created appliance; no outer-PVE credentials/SSH.
2. Quiesced upgrade/checkpoint, forward migrations/compatibility checks; failures
   retain recoverable state. No DB downgrade/attack resume. Prove installed
   resources, boot order, ownership/grants. Read-only legacy export and closed-
   history/account/cast import validate hashes/references; identifiers stay legacy.
   Refuse active matches/uncertain cleanup; never adopt PVE tokens/capabilities/
   claims. Preserve old deployment until operator-approved retirement.
   Complete obligation recovery/storage-pressure handling and scoped offline
   export/purge; runtime cannot delete append-only evidence. Optional scheduled
   consistent DB/cast/manifest/protected-key/ledger backups; disconnected restore
   invalidates capabilities, keeps guests off, requires fresh authorization.
   Synthetic tool tests required; real destination/restore optional, visibly unset.
3. Real install fixture: clean/rerun/reboot/populated-upgrade/partial-failure/
   wrong-permissions/config/recovery; never SR_INSTALL_VM_EVIDENCE attestation.
   Release checks actual SSH/cast bytes, repair/scoring, injects, failures and
   repeat reuse. Required CI, separate image/capture gates; port PVE invariants
   before retiring paths. Native KVM proves adapter, operator proves PVE nesting.
   Enforce architecture budgets/owned cleanup; no skips-as-passes or paid runner.
   Finish quick-start/onboarding/trust/topology/start/stop/recovery/update/storage/
   backup/purge and redacted diagnostics. Replace active PVE instructions; retain
   historical evidence. Supply operator scripts/positive controls/evidence forms.
4. New acceptance.py appliance aggregates fast, selection, python, db, authority,
   hypervisor, containment, packet, images, capture, access, frontend, browser,
   compose, install, journey. Record revision/environment/config/image digests,
   every result and cleanup. Live release never implicit. Run pinned candidate;
   changes invalidate affected evidence, requiring targeted repairs/reruns.
5. Reconcile README/AGENTS/architecture/roadmap/findings/runbook and plan-13 map.
   Tick 16/release only with matching software/live/human evidence; distinguish
   pending manual gates/optional backups. Handoff ends with acceptance table.

## Manual checks
Operator proves resources/nesting, IPv4/IPv6/routed/bridged/established-flow
isolation, authority denials, control/DB/broker outages, stop/read-back/release
and outer power-off; then real model schema/latency/failure. Operator AND another
member complete unaided browser/SSH practice: both presets/modes/start conditions,
repair, technical/written injects, early/deadline/idle end, restart, replay/history
and reuse without key/DB/ledger edits. Normal-duration match and fresh cycles;
separately approved history cutover; optional real restore.

## Acceptance criteria
Root commands; appliance is new. Missing required proof blocks release.
1. `.venv/bin/python infra/dev/acceptance.py appliance` passes all software gates.
2. Install rerun/reboot/upgrade/recovery preserves keys/data; import cannot revive claims/attacks.
3. Synthetic backup/restore/export/purge passes; real backup status is visible, non-blocking.
4. Operator runs `.venv/bin/python infra/dev/acceptance.py release` with real model after safety proof; passes.
5. Manual safety/model/human evidence matches candidate/config/images.
6. Next member launches after cleanup without key/ACL/DB/ledger edits or unknown leftovers.
7. Docs/roadmap match evidence; unresolved gates remain open, no relabeled PVE/fixture passes.
