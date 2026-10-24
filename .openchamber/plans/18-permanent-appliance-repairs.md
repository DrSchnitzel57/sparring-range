# 18 — Permanent appliance and recovery repairs

> Review round (2026-10-24): review at `168a9e1` → FIX, seven findings, all
> repaired with regressions in `806d239`…`dfaa954`; evidence in FINDINGS
> "Plan-18 review round". Milestone 18 UNTICKED pending re-review.

## Steps
- [x] Reproduce baselines and reconcile retained defects.
- [x] Repair bootstrap, native/runtime provisioning, identities and trust.
- [x] Implement safe latched teardown and audited obligation recovery.
- [x] Bind clean cron evidence to images; qualify scoped containment.
- [x] Run acceptance; update findings, tick 18 on its gates and update architecture if changed.

## Goal and context
Replace operator workarounds with reproducible source fixes. Binding references:
docs/ARCHITECTURE.md J/K, docs/ROADMAP.md and current docs/FINDINGS_CHECKLIST.md.
Plans 18–21 approved 2026-10-24. Implement
on a user-selected non-default worktree, coherent commits, never push. Planning
baseline: 571 fast passed/267 deselected/4 warnings; focused memory 37 passed/1
deselected. Cancelled DB/selection commands were not failures. Separately validate
and commit the existing memory fix before the agreed merge; do not overwrite it.

## Scope
In: retained installer/config/permission/firewall/recovery/legacy CLI defects,
trusted cron baselines and AppArmor regression gaps. Out: agent/UI (19–20), new
scenarios/Windows/outer-host automation or repeating completed commissioning.
Preserve histories/casts/keys, unrelated apps, latches and unknown obligations.
No broad chmod, root runner, AppArmor disable or SQL/ledger surgery.

## Implementation
1. Inspect deploy/appliance.py, hand_off.sh, bootstrap_tls.sh; infra/appliance
   manifest/appliance_services/backend/seed/netrules and installed-contract tests.
   Reconcile legacy ingest-unit wording and installed rangectl/commands/db.py
   root/config lookup. Conflict markers are already absent; ref-only PVE recovery
   stays obsolete. Inventory actual overrides before declaring fixes complete.
2. Fix TLS IPv4Address conversion, sysctl invocation, executed usage line, early
   model-key preflight and staged firstboot. Provision supported Node and native
   libvirt/same-ABI venv visibility; explicit runtime modes/storage headroom.
   Test actual UID execution/import/TLS/listener, not momentary service uptime.
   Preserve API-only model secret, per-role 0640 credentials, public CA trust,
   narrow traversal/QEMU/recording ACLs, writable state pins and LAN bastion.
   Ship own-table firewall loader/broker dependency, parser/first-run/order tests;
   never flush unrelated rules. Retain focused fixes f1eafab/9b1744d/712f69f/
   cff590f/21ad727/5930c9d; replace installed workarounds, not working boundaries.
3. In infra/broker service/ledger/tools, appliance recovery and srplatform
   lifecycle/deployment APIs, permit only typed ownership-checked cessation-safe
   teardown under latch. Serialize against broker writers; retain unknown/foreign
   claims and reservations. Audited obligation resolution requires independently
   confirmed exact identity/cessation/absence; missing proof remains blocked.
   No blanket unlatch or start/clone permission. Expose honest cleanup/retry
   states. Bound diagnostic SSH stdin/keepalives; host exit is not remote proof.
4. In infra/images, runner profile/setup and verifiers, build clean trusted cron
   hashes bound to artifact digest/version and immutable scenario snapshot.
   Missing pins stay UNKNOWN, never learn from compromised guests/filenames.
   Rebuild only changed artifacts. Exercise parser/load and actual attacker-UID
   namespace/cgroup/descendant positive and adversarial negative cases. Broad
   9e03696 is not certified by functional cancellation. Never loosen containment.

## Manual checks
Operator approves installed UID/TLS/boot/KVM checks affected by changes and real
adversarial profile qualification. Retain completed scoped SSH/network/VM-stop/
watchdog/runner-cancel receipts; do not automatically repeat or deploy anything.

## Acceptance criteria
1. AGENTS.md fast pytest command passes with zero failed/skipped.
2. `.venv/bin/python infra/dev/acceptance.py install` passes fresh/rerun/drift and identity contracts without workaround flags.
3. `.venv/bin/python infra/dev/acceptance.py authority` passes latched teardown, foreign/unknown retention and obligation-resolution regressions.
4. `.venv/bin/python infra/dev/acceptance.py containment` passes positive controls and new adversarial negatives.
5. `.venv/bin/python infra/dev/acceptance.py images` proves changed artifacts carry bound cron pins; absent/tampered pins never pass.
6. Installed-package migration/status works outside checkout; recovery reaches absent/released only with confirmed readback, never SQL edits.
7. Findings record exact attempts/prerequisites; roadmap retains pending manual gates rather than invented acceptance.
