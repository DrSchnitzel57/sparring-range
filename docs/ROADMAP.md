# Roadmap — first deployed Linux CCDC practice release

This is the retained product scope, not a required milestone workflow.
OpenChamber Todos hold actionable work and saved Plans hold agreements. The
[native-workflow decision](ARCHITECTURE.md#workflow-decision--native-openchamber-2026-10-28)
supersedes old branch/model/planning/reporting rules, including dated exceptions.
Dated acceptance ledgers are historical receipts; Git history preserves them
(`git log -- docs/ROADMAP.md`).

Design: [ARCHITECTURE.md](ARCHITECTURE.md). Baseline/open evidence:
[FINDINGS_CHECKLIST.md](FINDINGS_CHECKLIST.md). Operator work:
[OPERATOR_RUNBOOK.md](OPERATOR_RUNBOOK.md).

## Current completion sequence — draft 2026-10-20

User-approved direction: a complete individual-practice product in **one Ubuntu
appliance using KVM/libvirt for nested full lab VMs**, with a separate local
broker service and no outer-Proxmox credentials. No deadline-driven scope
reductions. The numbers follow plan 13 and are completion milestones, not a
renumbering of historical 01–12. Implementation and commissioning receipts are
recorded in the findings ledger and Git history, not proof of whole-milestone
acceptance.

- [ ] **14 — Nested appliance foundation and working SSH.**
  [Plan](../.openchamber/plans/14-nested-appliance-foundation.md).
  Deliver the minimal real appliance installer, libvirt broker, isolated network,
  clean guest images, actual member SSH/replay and recoverable resource lifecycle.
  **Promotion gate:** independent automated hypervisor/access/install proofs AND
  an operator fresh-launch → member SSH/sudo/reconnect/replay → cleanup →
  second-fresh-launch rehearsal with real nested KVM/isolation/stop.
  *Status 2026-10-23:* deployed member SSH/sudo/replay and scoped
  isolation/stop commissioning succeeded (branch `15`; see findings ledger);
  the software half — typed libvirt broker, installer, golden-image builder,
  `hypervisor`/`access` layers — exists. Whole-milestone acceptance stays open
  with the model/human gates below.
- [ ] **15 — Complete integrated individual practice.**
  [Plan](../.openchamber/plans/15-complete-practice-product.md).
  Complete both presets, durable lifecycle, honest service/inject/security
  results, sustained AI behavior under a distinct worker identity, browser/CLI
  authorization, reports and history.
  *Status 2026-10-21:* separate-UID worker dispatch, the installer, controller
  MySQL client, release bundle and all local-software acceptance layers pass;
  `journey` needs the installed appliance, and the real-model and human gates
  stay open. Independent review round findings fixed on branch `15`
  (receipts: `git log -- docs/ROADMAP.md docs/FINDINGS_CHECKLIST.md`).
- [ ] **16 — Installable appliance and qualified release.**
  [Plan](../.openchamber/plans/16-appliance-release.md).
  Finish the checksummed release bundle, upgrade/history-import/recovery tooling
  and operator guide; prove the complete software matrix at a pinned candidate,
  then collect operator/human acceptance. Backup destination/live restore remain
  optional. Runtime practice features and their tests are delivered in 15.
- [ ] **17 — Appliance hand-off in the operator's own VM.**
  [Plan](../.openchamber/plans/17-appliance-handoff.md).
  Deliver a deployable product the operator can install and test in their own
  virtual machine; milestone 14's promotion gate closes for real here. The
  hand-off path is implemented (bundle, rendered manifest, installer,
  `firstboot` check); the rehearsal itself is the operator's, in their own VM.

The original split distinguishes an accessible/recoverable platform, a complete
practice product and a qualified release. These product dependencies remain;
they do not prescribe branches, model roles or a future milestone process.
Any requirement not met stays open, regardless of plan ticks.

### Installed-practice repair batch — authorized 2026-10-29

- [ ] **22 — Installed practice repairs and usable safety admission.**
  [Plan](../.openchamber/plans/22-installed-practice-repairs.md).
  Consolidates LIVE-01–10 and retained plan-20 F5–F9: permanent credential/client
  routing fixes, truthful upgrade diagnostics/receipts, account-bound SSH
  onboarding, configuration-bound commissioning with automatic non-disruptive
  admission checks, grounded coach/citations and remaining replay/output repairs.
  LIVE-08's operator-resolved external outage is not a product regression.
  *Status 2026-11-01:* implementation and five review rounds landed on branch
  `practice-upgrades-18-21` and merged; the work is frozen as an unfinished
  development checkpoint (`c398eab`), not release acceptance — see the findings
  ledger. Milestones 20/21 are not retroactively marked accepted by this batch.
- [ ] **Underpressure live AI defense range** — persistent 12-guest team lab
  with real-service checks and autonomous offense. Contract layer and durable
  lab aggregate validated; guest builds, lab API/CLI, segment-lane wiring and
  every installed/live gate remain open. Scope and status:
  [architecture](ARCHITECTURE.md#underpressure-live-ai-defense-range--2026-11-01-implementation-in-progress).

### Post-commissioning backlog — 2026-10-23

Commissioning for the supervised AI run is complete (readiness, SSH/sudo/replay,
scoped network denial/spoof/IPv6 probes, boot persistence, API/broker VM stop,
control-loss watchdog, real runner cancellation); do not repeat it as if no
evidence exists. Full automated `packet`/`journey` acceptance, adversarial
qualification and whole-release acceptance are distinct claims.

Retain this scope for the next fixes/improvements discussion, not a new plan:

- Conversational history/checkpoints, token-aware ~262k local context and
  reasoning headroom, bounded compaction recovery, real progress and
  cancellation.
- Admin endpoint/model/write-only key/thinking GUI, capability testing and
  run-snapshotted protected configuration.
- Honest coach/AAR provenance/scoring, trusted image-bound cron hashes, useful
  real-model behavior and complete preset acceptance.
- Home active/history dashboard, session navigation, Markdown reports, filtered
  timelines and separate honest attacker/defender replay tracks.
- Permanent installer/native/UID/trust/firewall/config repairs replacing
  operator workarounds; cessation-safe teardown/accurate cleanup UI and audited
  recovery, including open obligations; independent adversarial AppArmor
  acceptance.

Requirements:
[architecture](ARCHITECTURE.md#j-local-conversation-engine-admin-settings-and-session-review-2026-10-23).

### Agreed upgrade sequence — planning 2026-10-24

The user approved all four plans on 2026-10-24 after full-sequence planning.
The whole backlog remains in scope; these supplement, not falsely complete,
historical 14–17.

- [x] **18 — Permanent appliance and recovery repairs.**
  [Plan](../.openchamber/plans/18-permanent-appliance-repairs.md).
  Installer/native/UID/TLS/config/firewall reproducibility, packaged CLI
  migrations, cessation-safe teardown/obligation tooling, trusted cron image
  pins and adversarial containment regression fixtures.
  *Accepted 2026-10-25 (SOFTWARE, `c58ef6a`)* after two review rounds;
  operator gates (packet/journey/installed UID/TLS/boot/KVM, adversarial
  AppArmor qualification) remain open and are carried into 21's promotion
  checks.
- [x] **19 — Conversational agent and model administration.**
  [Plan](../.openchamber/plans/19-conversation-and-model-admin.md).
  Pydantic AI slim, protected versioned profiles/role overrides/thinking
  mappings, context-aware history/checkpoints, one-slot async
  scheduling/cancellation and admin GUI.
  *Accepted 2026-10-27 (SOFTWARE, `1348b10`)* after five review rounds;
  operator gates and installed UID/proc/systemd/Strata/nested-KVM
  qualifications remain open and are carried into 21's promotion checks.
- [ ] **20 — Conversational coach and session review.**
  [Plan](../.openchamber/plans/20-coach-dashboard-and-replay.md).
  Grounded coach/AAR, modern home/history/session navigation, filtered audit and
  synchronized new-run timed attacker/defender replay with honest historical
  fallback.
  *Status 2026-10-27:* two independent review rounds fixed at root with
  real-HTTP/PG/browser counterexamples; the second review kept 20
  **unaccepted** — release blockers were fixed inside 21, polish items F5–F9
  were retained and consolidated into 22. Receipts in Git history.
- [ ] **21 — Upgrade and qualified integrated release.**
  [Plan](../.openchamber/plans/21-upgrade-and-integrated-release.md).
  Supported preserving in-place upgrade, corrected fresh-install bundle,
  changed-artifact rebuilds, installed/aggregate proofs and explicit
  real-Strata/manual acceptance.
  *Status 2026-10-28:* the preserving-upgrade engine and five review rounds
  landed (engine contracts in the runbook §7; per-round receipts in Git
  history); pinned guest package images rebuilt from live mirrors (`3000361`).
  21 stays UNTICKED — its operator-machine gates (packet/journey/release,
  installed systemd/Strata/nested-KVM) remain pending.

Architecture section K records the upgrade/conversation choices and defaults.
No deployment or feature implementation is implied by this roadmap alone.

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

The architecture's [appliance contract](ARCHITECTURE.md#ubuntukvm-appliance--2026-10-20)
is authoritative for the new backend. Plan 13's product/evidence/failure
requirements carry forward, but its PVE-specific mechanisms are replaced as
follows:

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
close only with recorded equivalent appliance evidence, explicitly naming
changed mechanisms.

### Acceptance boundaries

Use the current findings ledger rather than repeating the historical execution
instructions. Operator/live evidence remains separate from software checks;
documentation cleanup does not authorize host changes or satisfy release gates.
Failed or missing proof stays open. Native Plans and task instructions determine
the working approach without dropping these product/safety requirements.

## Historical release milestones and acceptance ledger

Milestones 01–11 (reproducible baseline, host-safe authority, guests/capture,
lifecycle, scoring, injects, AI attacks, browser experience, packaging,
operator gates), the later Windows/AD item, and the dated 2026-10-13/14
cross-cutting-exception prose are preserved in Git history:
`git log -- docs/ROADMAP.md`. Their recorded acceptance states remain truth
at those revisions; no milestone is retroactively completed or reopened by
this slim-down. Milestone 12 (Windows/AD services, Sysmon/WEC pipeline,
Windows baselines/licensing) and post-release work (team collaboration,
concurrent ranges, embeddings/RAG only for an identified need) stay
not-first-release scope.

**Standing discipline:** retained acceptance states and design decisions must
stay truthful, and no real model-driven attacks are authorized before the
safety gates pass.
