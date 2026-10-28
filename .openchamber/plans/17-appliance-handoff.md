# 17 — Appliance hand-off: install and rehearse in the operator's own VM

> Workflow normalized 2026-10-28: the [native-workflow decision](../../docs/ARCHITECTURE.md#workflow-decision--native-openchamber-2026-10-28) supersedes old procedural rules in this record, not product requirements or acceptance gates. Retained status is not fresh verification.

> **Deferred 2026-10-20 at the user's instruction: milestones 14, 15 and 16 are
> executed first. This plan is not started and nothing in it has been built.**
> It is kept because it records the request for a deployable product the
> operator can install in their own virtual machine; it becomes actionable only
> after 14–16.

## Steps
- [ ] 1. Produce the signed, checksummed appliance bundle.
- [ ] 2. One-command install plus first-boot health in a fresh VM.
- [ ] 3. First real match end to end, with recorded evidence.
- [ ] 4. Rehearse the milestone-14 promotion gate on real nested KVM.
- [ ] 5. Record evidence; tick 17 and the gates it closes.

## Goal and context
Drafted 2026-10-20 on the user's request: after milestone 15 they want a
DEPLOYABLE product they can install and test in their own virtual machine.
The user's reporting VM is the first real appliance, so milestone 14's
promotion gate (fresh launch → member SSH → sudo → reconnect → replay →
cleanup → second fresh launch with real nested KVM, isolation and stop
evidence) can finally be closed there instead of being asserted in prose.
Requires 15 and 16. Binding design: docs/ARCHITECTURE.md "Ubuntu/KVM
appliance", docs/ROADMAP.md, docs/FINDINGS_CHECKLIST.md and plans 14–16.
Work on the user-selected non-default branch; coherent commits, never push.

## Scope
In: release bundle and digests, installer path for a fresh operator-created
Ubuntu 24.04 VM, first-boot health/doctor output, a first real match with
recorded evidence, the milestone-14 rehearsal, operator quick-start and
evidence forms. Out: outer-Proxmox automation, deleting any old
installation, HA/live migration, new scenarios or frameworks, automatic
model-quality claims, unattended remote installation.

## Implementation
1. Bundle: pinned application source, the locked dependency set, the
   flattened guest base images with their digests, the manifest/policy
   templates, the systemd units, the fixed network artifacts and the
   installer. One manifest records every digest; the installer refuses a
   bundle whose digests, target OS/Python, capacities or file modes do not
   match the operator's machine. The bundle carries no secret, no outer
   credential and no host-specific value.
2. Install path: `deploy/appliance.py validate|plan|apply` against the
   operator's own VM, plus an explicit `first-boot` check that proves the
   broker socket, the API, the ingest listener, the bastion and the worker
   supervisor are all healthy under their own UIDs, and that the isolated
   bridge and its rules are in place. A rerun is idempotent; a partially
   applied install is reported as such and repaired, never silently
   reconfigured.
3. First real match: with a labeled model fixture, create a session, launch
   the nested guests, connect as the member over the real bastion, take the
   recording, submit an inject, read the scorecard, end the match and prove
   the range is released and the second session reuses it. The evidence
   files are the ones the `journey` gate and the milestone-16 release gate
   consume, so the rehearsal is machine-checked rather than narrated.
4. Milestone-14 promotion rehearsal on the operator's VM: nested KVM
   actually used by an inner domain (not TCG), guest denial of appliance
   administration/LAN/model/NAS/WAN, working authorized flows, broker
   stop/read-back/control-loss, and outer power-off as the independent
   emergency fallback. Every step is recorded with its exact command and
   outcome; anything not observed stays open.
5. Reconcile README/AGENTS/architecture/roadmap/findings/runbook with the
   observed installation, tick 17 only on matching evidence, and state
   plainly which gates remain operator-only.

## Manual checks
The operator performs the nested-KVM, isolation, emergency-stop and
outer-power-off rehearsal in their own VM and records the exact commands and
outcomes. The real model alias/schema/latency and useful sustained attacks
are validated separately, after the safety gates. Final unaided human
acceptance by a second member stays with the operator.

## Acceptance criteria
1. `python infra/dev/acceptance.py bundle` verifies the bundle's digests,
   completeness and secret-freedom.
2. `python infra/dev/acceptance.py install` runs a real install/rerun/
   reboot/upgrade/recovery sequence in the operator's VM and preserves
   keys, data and history.
3. `python infra/dev/acceptance.py journey` passes against the INSTALLED
   appliance with real guests, real SSH and a labeled model fixture, and its
   evidence is recorded in docs/FINDINGS_CHECKLIST.md.
4. The milestone-14 promotion rehearsal is recorded with exact commands and
   outcomes, including nested KVM (not TCG), isolation denials, broker
   stop/read-back and outer power-off.
5. A second member completes a practice session unaided, and the range is
   reusable afterwards without key, ACL, database or ledger edits.
6. Documentation matches the observed installation; unresolved gates remain
   open and no fixture result is presented as hardware acceptance.
