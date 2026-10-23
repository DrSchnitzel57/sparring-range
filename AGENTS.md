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
- The user approved one specific planning exception on 2026-10-12: milestones
  03 and 04 share `.openchamber/plans/03-04-linux-guests-capture.md`, with
  separate acceptance gates and roadmap checkboxes. All other milestones remain
  separately planned. This does not authorize implementation or live testing.
- On 2026-10-20 the user authorized drafting the full completion sequence together,
  using the fewest manageable milestones, with no deadline-driven feature cuts.
  Plans 14–16 are the proposed three-milestone sequence in the roadmap; they await
  approval. This supersedes one-at-a-time *planning* for that sequence only, not
  branch, implementation, safety, or live-operation restrictions. The user deferred
  tests during this planning pass and cancelled the started fast baseline; do not
  claim a new passing/failing baseline. Deployed member SSH remains unaccepted and
  is the first promotion gate, regardless of historical pin-fix test results.
- The user subsequently selected **one Ubuntu/KVM appliance with nested full VMs**
  (2026-10-20). The architecture's appliance section supersedes the direct-PVE,
  separate-broker-VM, remote-mTLS and per-VMID ACL design for the new release.
  Plans 14–16 cover foundation/access, complete practice, and packaged release.
  Retain the typed deployment boundary as a separate local OS service, worker
  identity isolation, append-only evidence and fail-closed recovery. No outer
  Proxmox credential enters the appliance. Plans are drafts pending approval;
  architecture selection alone does not authorize implementation/live operations.
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
- The appliance's deterministic private broker alone may use local libvirt for
  approved inner full VMs; API/model/bastion/ingest cannot access libvirt or /dev/kvm.
  Outer Proxmox remains operator-only. Old restricted-PVE tooling is legacy, not
  a production fallback. Never broaden privileges to get a green test. No runtime
  host-shell or arbitrary host-firewall execution; fixed appliance network rules
  are installed by the operator on the dedicated appliance, never on outer PVE.
- Operator-configured isolation denies range access to appliance management,
  WAN, Proxmox management, the model LXC, NAS, and unrelated workloads. Necessary control paths are narrowly
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

### Plan-13 implementation baseline (2026-10-14, revision `44a712a`)

Fresh reproduction on this branch (`plan-13-implementation`, clean at start,
fresh uv `.venv`, Python 3.13.5):

- `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 \
  .venv/bin/python -m pytest -q -ra -p no:cacheprovider` — exit 0:
  **176 passed, 0 failed, 0 skipped, 206 deselected**, 4 warnings, 19.43s.
- `.venv/bin/python infra/dev/acceptance.py authority` — **FAILED**:
  **16 failed, 8 passed, 358 deselected**. All 16 failures are
  `tests/test_authority_boundary.py` fixtures using the pre-policy name
  `web01-deadbeef`, rejected by the current `sr-` name policy. Repair the
  fixtures; never loosen the policy.
- Settings probe: `SR_MATCH_SCHEDULER_ENABLED=1` /
  `SR_MATCH_DEFAULT_DURATION_MINUTES=60` resolve to **False/30** — the
  documented `SR_*` names are ignored by the current settings model.

These are the plan-13 starting failures to repair; the fast default remains
green and infrastructure-free.

### Milestone 15 review round (2026-10-21, branch `15`)

After the independent review (**VERDICT: FIX**) every reproduced finding was
fixed on the branch. The fast default is now **413 passed, 0 failed, 0
skipped** (261 deselected, 4 warnings, ~65 s) and the gates pass:
`selection`, `python`, `db` (177), `authority` (25), `containment` (21),
`install` (the real sequences **plus** the new managed-service contract
check), `hypervisor` (2, needs `sh .cache/libvirt-debs/start-session.sh`
first), `access`, `images` (18 passed / 1 skipped), `bundle` (the role
artifacts are carried), `frontend`, `browser`, `compose`. The aggregate now
ATTEMPTS the two operator gates and reports them pending with the exact
prerequisite: `packet` needs root + `nft`, `journey` needs the installed
appliance with the member's SSH key, the pinned bastion host key and the
browser login.

The release bundle in `.cache/bundle/sparring-range-appliance` carries the
appliance base **and the three role images** (306 files, 4 images); rebuild
it with `deploy/bundle.py build --base-image ... --role-image ROLE=PATH`.

### Milestone 15 implementation baseline (2026-10-21, branch `15`)

Reviewer entry point: **docs/HANDOFF-15.md** — the plan/commit map, the exact
verification commands, what is claimed versus what is not, and the places a
critical reviewer should look hardest.

Reproduced on the branch, in a Debian 13 container with **no `/dev/kvm`**, no
root and no installed appliance. Guest boots are software emulation and are
labelled as such; they are **not** nested-KVM acceptance.

- `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 \
  .venv/bin/python -m pytest -q -ra -p no:cacheprovider` — exit 0:
  **395 passed, 0 failed, 0 skipped**, 254 deselected, 4 warnings, ~59s.
- `.venv/bin/python infra/dev/acceptance.py selection` — **PASS**
  (all tests classified; fast default clean).
- `… python` — **PASS**; `… db` — **PASS** (171 tests, disposable
  PostgreSQL 16); `… authority` — **PASS** (25); `… containment` — **PASS** (21).
- `… install` — **PASS**: the REAL install sequences (clean, rerun, reboot,
  populated upgrade, drift + repair) in a sandbox root. The old
  `SR_INSTALL_VM_EVIDENCE=1` environment attestation is **removed**; the
  managed-service half in a real VM stays the operator's.
- `… hypervisor` — **PASS**: real libvirt clone/start/QGA readiness/host key/
  ownership/stop/destroy (accelerator: explicit TCG).
- `… access` — **PASS**: a real Ubuntu guest; guest-agent readiness marker and
  fixed host key, real SSH, the real recording bastion, `.cast` bytes, `sudo`
  for the management identity, an interactive PTY with a recorded resize, a
  reconnect, and the refusal of an unauthorized key.
- `… bundle` — **PASS**: the release bundle verifies, the operator manifest
  renders from it and validates, and a tampered bundle is refused.
- `… frontend` — **PASS** (zero high/critical audit findings); `… browser` —
  **PASS**; `… compose` — **PASS**.
- `… images` — **PASS** (1793 s, 19 tests) and `… capture` — **PASS** (751 s, 11
  tests). On a COLD build cache the role-image build alone exceeds the 1500 s
  serial-marker timeout under software emulation (the serial logs show `apt`
  still fetching); the gate passes with the cache warm, and a KVM runner
  removes the distinction.
- `… packet` — **FAILED (environment)**: it needs root and `nft`; it fails
  closed with the exact missing prerequisite and was not simulated.
- `… journey` — **FAILED (prerequisite)**: it needs the INSTALLED appliance and
  operator/member bearer tokens; it fails closed by design.

Plan 13's recorded authority failures (the pre-policy `web01-deadbeef` fixture
names) and the `SR_MATCH_*` settings probe are **repaired**: the authority
gate passes and the settings names resolve.

## Validation commands and safety

### Live-practice repair baseline (2026-10-23, `5930c9d`)

The infrastructure-free command below exited 1: **448 passed, 1 failed,
262 deselected, 4 warnings**, 80.25 s. The sole failure is
`test_m0_partial_engagement_is_reported_truthfully`: it expects the obsolete
literal "Datapath drop FAILED" instead of the current static-isolation warning
"Datapath action FAILED" and independent appliance power-off instruction.
This is a prose assertion mismatch, not evidence the emergency mechanism passed.
The repair investigation follows a real supervised run with empty model hints,
600-token truncation, one failed dispatched command, and a suspected clean-cron
false positive. Do not treat service uptime as AI progress or software fixtures
as deployed acceptance.

Source repairs through `52ae355` supersede that failing baseline: the selection
gate now runs **567 fast tests, 0 failed, 0 skipped** (267 deselected). The
disposable PostgreSQL gate passes **183 tests**, and browser/authority/containment/
frontend gates pass separately. Exact attempts, counts and limitations are in
`docs/FINDINGS_CHECKLIST.md`; deployment constraints and the small source patch
are in `docs/HANDOFF-LIVE-PRACTICE.md`. Operator installation subsequently
succeeded on 2026-10-23. Commissioning for supervised practice (SSH/replay,
scoped isolation, boot, VM stop/watchdog and real runner cancellation) completed;
do not reopen these from older pending notes. Sustained useful AI, trusted cron
pins, permanent teardown and adversarial safety remain separate open work.
Current receipts/backlog are consolidated at the top of
`docs/FINDINGS_CHECKLIST.md`; use repository docs, not Project Knowledge journals.

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
