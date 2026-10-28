# 14 — Nested appliance foundation and working SSH

> Workflow normalized 2026-10-28: the [native-workflow decision](../../docs/ARCHITECTURE.md#workflow-decision--native-openchamber-2026-10-28) supersedes old procedural rules in this record, not product requirements or acceptance gates. Retained status is not fresh verification.

## Steps
- [ ] 1. Establish baseline, manifest and backend identity contracts.
- [ ] 2. Implement local broker, libvirt lifecycle and recovery.
- [ ] 3. Deliver isolated networking, images and first-boot trust.
- [ ] 4. Install real services and complete member SSH/replay.
- [ ] 5. Prove boundaries/reuse and prepare operator rehearsal.
- [ ] 6. Record evidence; tick milestone 14 on its gates; update architecture.

## Goal and context
Draft 2026-10-20; approval required. Inspected 933f6a1; user cancelled/deferred
tests. Reproduce baseline on the user-selected non-default branch; record
failures in AGENTS.md. Commit coherent steps; never push. Deployed SSH has never
worked. Binding design: docs/ARCHITECTURE.md “Ubuntu/KVM appliance” and
docs/ROADMAP.md, replacing Plan 13's PVE mechanisms.

## Scope
In: one Ubuntu 24.04 appliance, typed local broker, nested full VMs, isolation,
recordings, real installer/access. Out: outer-host automation, live attacks,
complete match integration (15), release distribution/legacy cutover (16).

## Implementation
1. Version manifest/renderers: install UUID, URLs/subnets/socket, image hashes,
   state/budgets, protected secret references. Reject conflicts/placeholders/drift.
   Forward-migrate backend/domain UUIDs; preserve PVE history without adopting
   VMIDs. Inventory adapter callers.
2. Reuse infra/broker ledger/policy/fencing with Unix peer-UID authentication.
   Only controller gets runtime typed operations; other UIDs lack broker/libvirt/
   KVM access. Libvirt adapter renders fixed XML, persists intent before effects,
   creates fresh owned overlays over immutable bases and validates UUID+install/
   session/generation/disks/network/caps. No arbitrary XML/path/command/device/NIC.
   Bound/reconcile late or uncertain effects. Stop/read-back/undefine/remove/
   read-back precede release; foreign/unknown retains obligations. Local inspect/
   reconcile/resolve requires fresh evidence, including destroyed claims/disk
   leftovers. Retain 5s/30s lease, latch/restart recovery; no autostart/managed-save.
3. Fixed bridge/static IPs; no NAT/uplink/DNS/default route. Installer input/
   forward/bridge rules deny management/WAN/IPv6/model/NAS despite spoofing or
   added routes; permit ingest/trusted replies. Preserve confinement. Sanitize/
   flatten/hash Ubuntu bases; typed NoCloud injects public role keys only.
   No launch package fetching. Fixed domain-bound QGA key/first-boot reads with
   bounded stability establish generation trust before exposure. No guest exec,
   TOFU or re-pin. Private keys stay with consumers.
4. Add deploy/appliance.py validate/plan/apply/status/doctor: native dependencies,
   venv, separate UIDs/env, DB grants/migrations, nginx/TLS/Next, API/broker/
   bastion/minimal ingest, protected shared casts and local account/key onboarding.
   Fix installed migration lookup; singleton controller/visible health; no outer
   PVE secrets. Preserve keys/data on rerun/reboot/upgrade. Wire launch/progress/
   connections to libvirt. Before ready, prove capture and pinned SSH as actual
   bastion UID/key. Diagnose member reachability/key/capability, API callback,
   pin, guest auth, PTY and casts. Remove local-pin fallback. Prove sudo, exec/
   interactive/resize/reconnect/revocation and browser replay of known bytes.
5. New hypervisor/access gates use real libvirt/KVM/SSH/services. Strengthen
   install: actual clean/rerun/reboot/populated-upgrade/failure sequences, never
   env attestation. Port race/denial regressions; separate images/capture gates.
   Bounded disposable fixtures only; no shared-host changes/paid CI. Deliver
   operator commands and redacted evidence forms.
6. Record findings/runbook/roadmap and architecture decisions. Tick 14 only
   when its gates pass; manual evidence stays pending until supplied.

## Manual checks
Operator provisions outer VM and proves nested KVM/headroom. Attacks off:
isolation with positive controls; stop/read-back/control loss/outer power-off;
fresh launch → member SSH/sudo/reconnect/replay → cleanup → second fresh launch.
No manual key edits, pin bypass or ledger surgery. This blocks promotion to 15.

## Acceptance criteria
From root, define `gate() { .venv/bin/python infra/dev/acceptance.py "$@"; }`.
New gates: hypervisor/access. Missing prerequisites fail.
1. AGENTS.md fast pytest command passes, zero skips.
2. `for g in selection python db authority; do gate "$g" || exit; done` passes.
3. `gate hypervisor` passes real lifecycle/fault/ownership proofs.
4. `for g in containment packet images capture; do gate "$g" || exit; done` passes.
5. `gate access` passes SSH/replay/denial/reuse proofs.
6. `gate install` passes real managed-service sequences.
7. Matching revision/config/image Manual evidence exists, or promotion is blocked.
8. Findings/roadmap separate software/manual evidence; PVE results cannot substitute.
