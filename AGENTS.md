# Agent instructions — sparring-range

## Authoritative project documents

- [Architecture and release decisions](docs/ARCHITECTURE.md).
- [Ordered milestones](docs/ROADMAP.md).
- [Current findings and validation evidence](docs/FINDINGS_CHECKLIST.md).
- [Operator runbook and live gates](docs/OPERATOR_RUNBOOK.md).
- Milestone plans belong only in `.openchamber/plans/NN-short-name.md`, unless
  `.openchamber/project.json` explicitly sets `plansDir`.

These documents replace the original master plan and accumulated audit handoffs.
Historical reports, probes, commit messages, and completion claims are evidence
to investigate, not current instructions or proof of acceptance.

## Workflow

- Work only on the current branch; never push. This is a solo-owned repository:
  agreed documentation may be committed on `master`; application implementation
  requires the user to select a non-default branch. Do not create/switch branches
  or start another session without authorization.
- Before planning, check Git status, read the documents above, inspect the actual
  code, and reproduce the relevant baseline safely. Preserve unrelated work.
- The architecture and roadmap describe the whole release. Write and agree one
  milestone implementation plan at a time; do not manufacture plans for later
  milestones. Each plan is self-contained, under 4,800 characters, and ends with
  at most ten command-based or observable acceptance criteria. Hardware/access
  prerequisites go under `Manual checks`. Its last step updates the roadmap and
  architecture if needed. Commit agreed plans on `master`.
- Implementation follows an agreed plan, with small commits, explicit decisions,
  and automated acceptance. Skip its manual checks; they belong to the operator.
  End the handoff with an acceptance-criterion PASS/FAIL table and nothing after.
- Reviews do not edit code. Find the plan, independently run its commands and
  the suite, and start with `VERDICT: SHIP`, `VERDICT: FIX`, or `VERDICT: RETHINK`.
- Use relative paths, stay in this checkout, and use the patch tool for edits.
  Ask before restructuring further or resolving conflicting instructions.

## Non-negotiable boundaries

- No AI/model-selected command receives Proxmox credentials, host SSH/root,
  controller/owner-DB secrets, verifier keys, NAS credentials, or GPU devices.
- Attacker and vulnerable targets are full VMs, not host-kernel-sharing LXCs.
  The existing inference LXC is inference-only and outside the attack network.
- A deterministic private deployment boundary may use a restricted Proxmox
  token for approved lab resources only. Never broaden privileges to get a green
  test. No runtime host-shell or arbitrary host-firewall execution.
- Operator-configured isolation denies range access to WAN, Proxmox management,
  the model LXC, NAS, and unrelated workloads. Necessary control paths are narrowly
  allowlisted. No attacks until real isolation and emergency-stop gates pass.
- API is the business-logic front door. CLI/web are clients; migration and offline
  operator administration are explicit exceptions. Infrastructure credentials
  must stay behind the deployment boundary, not in model workers or the browser.
- Scores require deterministic, authenticated evidence. Subjective written-task
  feedback cannot award verified points. Enforce competition visibility in APIs,
  not just the UI. Host telemetry can be forged by a compromised host.
- Events are append-only; reports/specifications are versioned. Apply forward
  migrations, not edits to applied migrations. Only mutable operational metadata
  stores locks, leases, and lifecycle state.
- Unknown ownership, containment, readiness, stop, or cleanup is not success.
  Retain durable obligations and the range reservation until genuinely resolved.
- No secrets in Git, images, prompts, normal logs, or recordings of real admin
  operations. Use synthetic lab data. Keep dependencies minimal and justified.
- No destructive live tests, host firewall changes, auditd installation, volume
  resets, or mutations of unrelated VMs. Use explicitly disposable fixtures.

## Baseline recorded before release planning changes

Date: 2026-10-08. Application baseline: `23de4f4` (`master`, clean and equal to
`origin/master` before documentation work). Existing venv: Python 3.13.

Command (no database administration configured):

```bash
env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 \
  .venv/bin/python -m pytest -q -ra -p no:cacheprovider
```

Exit 1: **9 failed, 107 passed, 115 skipped, 1 deselected, 4 warnings**, 61.13s.
This is not database, privileged-packet, browser, or live acceptance.

Failures:

- `tests/test_fifth_followup_acceptance.py`: same-UID escape, nested membership,
  unreadable membership (three tests).
- `tests/test_fourth_followup_containment.py`: cleared-environment descendant,
  ordinary zero/nonzero exit survivor handling, unreachable completion authority
  (four tests).
- `tests/test_third_followup_lifecycle.py`: descendant surviving leader exit.
- `tests/test_followup_regressions.py`: release invalidating old safety evidence;
  this unmarked test requires PostgreSQL, unavailable in this baseline.

Do not equate these failures with nine established production vulnerabilities.
The new PID namespace changes child IDs and leader-exit behavior; tests must
observe real host identities and desired safety invariants, not restore an older
unsafe execution model merely to satisfy old assertions. Database/route races
and enrollment upgrades still need independent verification with an explicitly
configured disposable PostgreSQL instance.

Frontend command: `npm audit --package-lock-only --json` from `web/`, exit 1:
four affected packages, **three critical / one high** (Next, PostCSS, Seroval,
Solid). Package-level audit severity is not proof each advisory is exploitable
in this Linux Pages Router deployment. Triage applicability and patch before
release; do not run a blind major-version audit fix.

Missing installed-systemd/auditd capture acceptance fixture and incomplete
required-containment CI wiring are software gaps, not merely hardware gates.
Legacy source comments/package metadata may still name removed docs; reconcile
them in milestone 01 without changing historical tests' safety intentions.

### Fresh milestone-01 planning baseline

At `7368782` (clean `master` before this rerun), the same no-admin pytest command
above exited 1: **10 failed, 106 passed, 115 skipped, 1 deselected, 4 warnings**,
61.76s. The original nine failures remain; the documentation consolidation adds
`tests/test_followup_regressions.py::test_r12_golden_image_calls_the_real_installer`,
which checks obsolete literal runbook wording. Preserve the service/readiness
contract while repairing that prose-dependent assertion in milestone 01.

The fresh lockfile audit still exits 1 with **three critical / one high** across
four affected packages. Docker is now available: Compose 5.6.0, daemon 29.8.2.
No disposable DB admin, browser CLI or nft binary was configured, and no Docker
fixture or live/privileged gate was started during this planning baseline.

### Superseded by milestone-01 implementation (2026-10-08, `ac5a61b`)

The ten baseline failures and the frontend audit findings above are repaired:
the no-admin default is now **114 passed, 0 failed, 0 skipped, 139 deselected**,
and `npm audit --omit=dev` reports 0 vulnerabilities. Layer membership derives
from the fixture closure; per-gate acceptance runs through
`python infra/dev/acceptance.py <check>`. Exact results are recorded in
`docs/FINDINGS_CHECKLIST.md`; the CI-only gates (packet, browser) passed in
run 37852029894 at `3539667`. Independent review at `27e2624` reopened
milestone 01 for shared browser-build isolation, the edit to migration 0010,
and an intermittent browser command wait; all three were repaired at
`62939f7` (run-owned fresh builds + fast isolation regressions, byte-exact
migration restore, bounded event wait) and CI run 37855269245 passed all ten
jobs on two attempts. Green gate results do not waive plan requirements.

## Validation commands and safety

- Fast baseline: the pytest command above (infrastructure-free since `ac5a61b`:
  0 failed, 0 prerequisite skips); integration layers are db/containment/packet/
  browser/live, and `python infra/dev/acceptance.py <check>` runs each real gate.
- DB tests require `SR_PG_ADMIN_URL` or `SR_PG_ADMIN_CMD` for a disposable cluster;
  fixtures create unique `srtest_*` databases/roles. Never select production.
- Containment/packet/systemd tests need isolated fixtures and explicit required
  modes; a skip/deselection is never acceptance of that boundary.
- Frontend uses `npm ci` and `npm run build` from `web/`; browser acceptance is
  separate. Do not displace OpenChamber or another user's service to free a port.
- Record exact commands, environment, exit status, pass/fail/skip/deselect counts,
  and evidence revision in `docs/FINDINGS_CHECKLIST.md`. Never copy old totals.
