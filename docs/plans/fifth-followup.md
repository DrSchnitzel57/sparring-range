# Fifth follow-up: finish containment and enrollment acceptance

## Goal and review baseline

Close the remaining safety and telemetry acceptance failures without adding product
features. A successful cessation response must mean that **all operation work is
gone**. A ready deployment must have authenticated delivery and real command-capture
evidence from the **exact enrollment of its current host generation**.

This is the builder's complete handoff. Review baseline is
`2357730222844561f091754f7f5be53f8aa1386a` (one commit in `master..HEAD`, parent
`3b681be97428db4b4440f9b3be734861b51e2670`). The fourth handoff was
`docs/FOURTH_FOLLOWUP_REVIEW.md`, originally reviewing `213246e`.

**Not accepted.** The checked-in software suite is green, but additional production-
boundary probes reproduced the failures below. Completion-report checkboxes are
not evidence that these invariants hold. No application code was changed by this
review; this plan is the only repository file created.

## Findings, in priority order

### F1 — P0: cgroup membership is not yet authoritative containment

References: `infra/runner/runner_supervise.sh:100-117,165-176,220-225,250-275`;
`srplatform/red_agent/runner.py:469-485`;
`docs/OPERATOR_RUNBOOK.md:71-77,216-228`.

Three real Linux probes reproduced false cessation, using the actual supervisor
and, for the first two cases, actual `SshRunner` with only the SSH executable seam
replaced by `/bin/sh -c`:

1. **Escape:** the command runs as the same UID that owns the delegated parent
   cgroup. A redirected background child executes `env -i /bin/bash -c ...`, writes
   its own PID to the parent's `cgroup.procs`, then sleeps. The runner returned
   `exit_code=0, cancel_state=None, note=None`; supervisor status was `not-found`;
   `cancel_remote()` returned `True`; the child remained alive after that ack.
2. **Nested membership:** a child creates a nested cgroup under the operation,
   moves itself there, clears its environment and sleeps. The operation's direct
   `cgroup.procs` is empty, but `cgroup.events` says `populated 1`. Runner success
   and supervisor `gone` were returned while the nested child was alive.
3. **Unreadable membership:** while an environment-cleared sleep remained inside
   its operation cgroup, removing read permission from `cgroup.procs` made `status`
   return exit 0 / `gone`. Restoring permission showed the same live PID. A failed
   read is currently indistinguishable from empty membership.

Each probe killed only its own explicitly recorded child after observations. The
normal-exit check is a useful repair, but it trusts an unsafe authority. Commands
also share access to supervisor bookkeeping; that is not a trusted boundary.

### F2 — P0: registration can commit an active operation on a completed run

References: `srplatform/api/app.py:828-877`;
`srplatform/api/runs.py:61-68,343-347,438-456`;
`tests/test_fourth_followup_containment.py:486-536`.

The registration route locks the run row, but completion's single guarded UPDATE
is **not** a fresh child-table check after acquiring that lock. Under PostgreSQL
READ COMMITTED, its statement snapshot can predate a registration commit.

A barrier-pinned probe used independent request DB sessions and actual routes:

1. Register via `POST /internal/runs/{id}/operations`; pause immediately before
   `INSERT INTO run_operations`, after the route has acquired `FOR UPDATE`.
2. Call `POST /internal/runs/{id}/complete` with `{"outcome":"complete"}`.
   Its remote pass sees no committed operation. Verify via `pg_stat_activity`
   that its guarded terminal UPDATE is actually waiting on the registration lock.
3. Release registration. Registration returns 201; completion returns 200 with
   `status=completed`. Fresh DB inspection finds an **active** operation.
4. `POST /runs/{id}/stop` returns 200, `ok=true`, `note=already finished`, without
   resolving that operation.

The existing five simultaneous-start attempts do not pin this interleaving or
exercise completion racing registration. Other terminal writers still bypass
the new guard: spawn/latch paths at `runs.py:224-268`, watchdog at `309-334`, and
startup reconciliation at `485-548`. Lifecycle release looks only for active runs
(`srplatform/api/app.py:283-297`), so corrupt terminal rows can hide obligations.

### F3 — P1: pre-upgrade "confirmed" bypasses new enrollment evidence

References: `srplatform/scenario_engine/orchestrator.py:292-294,479-483`;
`srplatform/verification_service.py:155-162`;
`srplatform/db/migrations/versions/0009_fourth_followup_acceptance.py:30-38`.

Migration 0009 adds nullable evidence fields but does not invalidate old
`telemetry_enroll.phase=confirmed`. Deployment skips such resources; readiness
trusts the JSON phase alone. A probe representing a pre-upgrade deployment, with
all nonce/generation/delivery/capture fields null, relaunched through the actual
API: 200, enforced readiness `ok=true`, **zero enrollment/capture commands**.
The prior `systemctl`-only claim remains sufficient after upgrade. Existing ready
sessions also need a safe upgrade/run policy, not just a new-launch fix.

### F4 — P1: evidence is not bound to the authenticated token and generation

References: `srplatform/api/auth.py:59-67,115-119`;
`srplatform/api/app.py:1288-1298,1359-1379`;
`srplatform/scenario_engine/orchestrator.py:215-228,256-277,304-318`.

Authentication discards the exact ServiceToken identity. Confirmation and capture
select the newest non-revoked enrollment by session/host, not the authenticated
token. Token recovery/evidence polling also ignore deployment generation.
`enrollment_deployment_id` is stored, but not enforced by these paths.

A production-route probe issued two same-session/same-host enrollments with
different deployment UUIDs. The **older capability + newer nonce** returned 201
and set the newer token's delivery timestamp; an audit batch authenticated by that
older capability set the newer capture timestamp too. The old row stayed
unconfirmed. This is a binding defect, not a claim that compromised-host telemetry
can become trustworthy ground truth. The test supplied the newer nonce deliberately
to verify that the required capability/enrollment pair is enforced.

### F5 — P1: not every signal has a safe process identity

References: `infra/runner/runner_supervise.sh:108-117,157-176`.

The recorded-leader start-time check is progress, but cgroup and marker loops still
signal bare PIDs. Processes can exit and PID numbers can be reused between scan
and signal. The PGID check and later kill are also separate, racy operations.
The wrong-start-time fixture proves only one already-mismatched leader case, not
the handoff's "guard process identity for every signal" requirement. This finding
is source-confirmed; this review did not force real kernel PID reuse.

### F6 — P1 acceptance gap: no installed-service capture/identity fixture

References: `tests/test_fourth_followup_enrollment.py:153-211,259-282,296-402`;
`telemetry/sparring-shipper.service:12,23-28`;
`docs/FOURTH_FOLLOWUP_COMPLETION_REPORT.md:121-136,164-167`.

The subprocess test runs the source Python file as the test caller, not the
installed executable/unit as `srshipper`. It writes a fabricated EXECVE/SYSCALL
record to stdin; it does not execute the harmless command and capture its audit
event. The capture-negative uses a channel double that simply omits the POST,
not an actually unreadable input. API/token negatives immediately close stdin
and do not demonstrate a still-active service blocking the actual readiness path.
Useful adapter tests must remain, but they do not satisfy the required disposable
Linux installed-service fixture. The report correctly leaves real auditd/Sysmon
VM gates open, but overstates the automated fixture's installed identity/capture.

### F7 — P2: local-dev regressions from the shared reader and terminal guard

References: `srplatform/red_agent/runner.py:268-269,504-541`;
`srplatform/api/runs.py:113-116,387-408,452-454`.

The reader's new leader-exit behavior applies to LocalDevRunner without the SSH
runner's subsequent containment check. A real local-dev probe returned exit 0
with no cancellation/error while its background sleep remained alive.

The new terminal guard considers both local and remote unresolved rows, but the
resolution pass handles remote rows only. A production-route probe registering
an unresolved `kind=local` operation on a dead/no-PGID worker returned stop 200 /
`ok=false, status=cancel-unknown`; the local row stayed active. Repeated remote
passes cannot resolve it. This is a dev-mode regression, not a request to enable
local-dev in production. Also, `SshRunner.health()` at `runner.py:487-491` still
reports healthy for an exit-zero result with `cancel_state=unknown` (adapter probe).

### F8 — P1 test reliability: CI delegation can silently skip containment

References: `.github/workflows/ci.yml:41-58`; `tests/helpers.py:97-144`;
`docs/OPERATOR_RUNBOOK.md:71-77`.

CI creates a top-level cgroup and chowns only its directory. Non-root migration
requires write permission on destination **and common-ancestor** `cgroup.procs`;
merely owning that directory does not grant migration from the runner's existing
systemd scope. The helper turns rejected migration into a skip, preserving a green
job. The runbook's top-level mkdir/chown example has the same omission. This is a
source/kernel-contract finding, not a claim that this review ran GitHub Actions.
See the kernel cgroup-v2 documentation's "Delegation Containment" section:
<https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#delegation-containment>.

## Fourth-handoff checklist, verified against code

Legend: **done** = implemented and the specified software behavior exercised;
**partial** = useful implementation/evidence but not the entire requirement;
**missing** = required evidence/test absent; **wrong** = reproduced invariant failure.

| Requirement | Status | Evidence / remaining gap |
|---|---|---|
| Blocker 1: ordinary zero/nonzero exit consults containment | done | `runner.py:469-485`; fourth containment tests:234-295 passed. |
| Blocker 1: completion/stop/end/teardown cannot hide surviving work | wrong | F1/F2; terminal runs are skipped by later stop and lifecycle lookup. |
| Environment-independent cleared-environment tracking | partial | Real cleared-env test:99-128 passes; same-UID migration/nested membership escape remains (F1). |
| Unsupported execution mode explicitly refused | done | Supervisor:199-201,239-242; refusal test:131-146 passed. Secure isolation/authority is not yet part of that refusal. |
| Inaccessible process/containment state stays unknown | wrong | F1 unreadable-membership probe; no inaccessible-state regression in the new suite. |
| Identity guarded for every signal | partial | Wrong-leader identity test:209-227 passes; raw PID paths remain (F5). |
| Actual start/cancel overlap, not only sequential cancel | done | Lock:202-234,259-275; lock-held hook/barrier test:163-206 passed. Retain it. |
| Registration rejected for stopping/cancel-unknown | done | `app.py:859-863`; test:460-482 passed. |
| Registration serialized with all terminal transitions | wrong | F2 pinned completion race; unguarded terminal writers remain. |
| Prompt 1: worker -> operation-done -> actual stop/end regression | partial | Real loop/runner/supervisor/routes/DB at test:329-373 passes; no hand-made operation row. SSH is a seam; command does not explicitly redirect child output; prior failing run/order is not evidenced in this single commit. |
| Prompt 2: success/failure exit gating; unresolved rows persist; unknown stays unknown | partial | Ordinary result handling and unknown-chain test:375-453 pass, but F1/F2 break authoritative finalization. |
| Prompt 3: non-environment containment, every signal identity, atomic start/cancel | partial | cgroups/flock implemented; F1/F5 remain. |
| Prompt 4: production-route DB races, both sides, no unresolved terminal/release | partial | Stop-vs-register test uses independent request sessions, but simultaneous thread starts do not pin both orders or completion (F2). |
| Blocker 2 / Prompt 5: fresh nonce and deployed shipper callback | partial | `_enroll_telemetry`:139-156, provision:238-253, shipper:495-550,643-649; host subprocess sends callback. Exact token/generation binding and legacy readiness are wrong (F3/F4). |
| Startup/delivery/capture evidence distinct; timeouts visible | done for fresh enrollments | Orchestrator:323-368; tests:234-282 passed. Old confirmed phases bypass these checks (F3). |
| Capture acceptance: execute harmless command, observe through installed service | missing | Production probe exists at orchestrator:350-368; automated proof fabricates stdin (F6). No actual installed identity/input capture run here. |
| Prompt 6: active service with unreachable API, bad token, unreadable input blocks readiness | partial | Fresh phase-machine negatives pass; subprocess API/token tests pass, but actual active-unit/input/identity negatives are missing (F6). |
| Prompt 7: existing T regressions, new full paths, unit/DB/browser/packet suites | partial | Software counts below verified. Browser/packet/hardware remain blocked/skipped; CI fail-on-skip is missing (F8). |
| Prompt 7: exact completion report; do not declare final hardware acceptance | partial | Report explicitly leaves hardware gates open; several software-acceptance claims overstate proof (F1-F6). |

## Scope and repairs to preserve

Keep snapshot-based deployment, explicit production readiness, telemetry
provisioning, durable operation records, lifecycle claims, strict firewall policy
and topology checks, bounded byte reads, spool repair, and existing CI coverage.
Keep the fourth branch's ordinary-exit check, unknown-state propagation, durable
detail, cgroup refusal, per-operation locking, host callback, phase evidence,
timeouts and all useful regressions. Do not revert these repairs wholesale.

In scope: F1-F8; minimal supporting runner installation/privilege configuration,
API/DB lifecycle and enrollment fixes, an upgrade migration if needed, focused
tests, correct CI prerequisites, operator instructions and truthful completion
evidence. Fix the local-dev regressions only as compatibility repairs.

Out of scope: product/UI/scenario features, new scoring behavior, GPU/model changes,
network redesign, unrelated refactors, broad dependency upgrades, or changing
user VMs without explicit operator approval. Parser JSONB/NUL handling and the
old topology-test marker/mechanism repair are adjacent, justified changes, not
material feature scope creep. The shared reader's dev impact is unintended and
needs repair, not a new execution mode.

Additional security observation, **pre-existing and outside this branch diff**:
`npm audit --json` reported 4 vulnerable dependency entries (3 critical, 1 high)
in Next/PostCSS/Seroval/Solid. The frontend is a Pages Router app; advisory
applicability/exploitability was not established here. Record a separate security
triage need, rather than silently performing a major frontend upgrade in this pass.

## Builder steps

### 1. Add failing regressions before repairs

Add focused `tests/test_fifth_followup_acceptance.py` tests. Record the failing
baseline commands/outcomes before implementing fixes; assertions must require the
desired invariant, not assert that the current bug occurs. Reuse the real loop,
runner, routes and disposable DB fixtures. For full worker tests, do not hand-build
operation rows; let registration and operation-done run normally.

Cover redirected background children after leader exits 0 and nonzero, cleared
environment, attempted parent/sibling migration, nested membership, unreadable or
missing authoritative state, supervisor-control loss, and bookkeeping tampering.
Assert actual child identities/liveness, not just the same potentially faulty
cgroup query used by production. Cleanup is after assertions and limited to the
fixture's own processes/cgroups.

Pin F2 with the row-lock/INSERT/blocked-UPDATE sequence described above. Test both
orders of registration vs stop **and completion**, independent DB sessions, and
worker crash/watchdog, startup recovery and spawn/latch transitions. Verify
stop/end/reset/teardown cannot overlook an unresolved operation on a terminal row.

Add legacy phase-only upgrade tests, stale token/generation tests, exact
capability/nonce pairing tests, resumed-enrollment tests and local-dev stop/crash
regressions. Keep existing fourth and prior T tests.

### 2. Establish a trusted, fail-closed containment boundary

Run arbitrary/model-selected commands under a boundary that cannot alter the
trusted supervisor's state, migrate out of its operation, change containment
permissions, or control other operations. Prefer a trusted launcher/controller
and separate unprivileged command identity, with appropriate namespace/capability
restrictions. Do not run model commands with controller/root privileges. Document
the exact installation and privilege model. If a host cannot supply that boundary,
refuse dispatch visibly **before executing any command**.

Read recursive liveness (for cgroup v2, `cgroup.events`' populated state includes
descendants). Distinguish known-empty from failed/missing/unreadable authority;
unknown must retain durable state and block completion/release. Do not clean up
records merely because a membership read failed. Protect operation identity and
avoid accepting missing control state as proof for previously dispatched work.

Use kernel-scoped cancellation (`cgroup.kill` over the protected operation tree)
or stable process handles/identity mechanisms for any necessary individual
signals. Eliminate unsafe marker/bare-PID fallback signalling; an environment
marker may be diagnostic, not authority. Retain deterministic start/cancel
locking and durable late-start refusal. Ensure successful registration into the
containment boundary is acknowledged before releasing start coordination.

Only report operation done once this authority confirms the entire tree gone;
otherwise persist cancel-unknown. Preserve zero/nonzero command exit results and
truthful containment details. Make runner health reject an unknown cessation
result. Do not apply SSH-only stream assumptions to local-dev without its own
completion/cessation handling.

### 3. Serialize lifecycle obligations, not just one UPDATE

Use one coherent run-row lock/fence protocol for registration and **every**
terminal writer. Acquire serialization before taking the operation-inventory
snapshot, and use a fresh query after lock acquisition. Account for the existing
per-operation commits in remote cancellation: they release locks, so a check
whose protection has been surrendered is not a terminal invariant.

Fence new registration during finalization, resolve all obligations, then perform
the terminal transition under the same protocol. Audit completion, stop, spawn
failure/race, latch recheck, watchdog and startup paths. Completed/cancelled/failed
must not hide unresolved operations. End/reset/teardown must check durable
obligations independently of an active-run-only lookup; repair or block existing
inconsistent rows without fabricating cessation.

Resolve local operations through actual local cessation evidence when their
worker dies/stops. Do not merely remove the local guard or mark local rows done
because the worker exited: LocalDevRunner creates independent command groups.
Unconfirmed work remains retryable with the reservation retained.

### 4. Bind enrollment evidence to the exact current enrollment

Carry the authenticated ServiceToken identity through auth/dependencies and
update/read evidence for that exact token and deployment generation. Recovery
must resume the current deployment's same token/nonce, not whichever matching host
row happens to be newest. Reject wrong nonce, wrong capability, wrong session,
wrong host, revoked/expired token and obsolete generation; stale evidence must
not satisfy current readiness. Keep confirmation idempotent without duplicate
events; add a concurrent-repeat test as well as the existing sequential one.

Treat a pre-0009 phase-only confirmed resource as **not evidence-confirmed**.
Safely re-enroll existing resources, without gratuitously deleting/recloning them.
Readiness must derive from valid current enrollment evidence, not JSON phase
alone. Handle already-ready sessions on upgrade so `/run` cannot bypass the new
requirements. Keep provisioning, service-running, delivery-confirmed and
capture-verified observations distinct. Successful retries must clear stale
failure-stage/error metadata without inventing new timestamps.

### 5. Prove installed capture, including negative paths

Add `tests/test_fifth_followup_installed_capture.py` for an explicitly disposable
Linux/systemd/auditd fixture. Install the real artifact with `telemetry/install.sh`
on that disposable host, provision its actual env contract, run the real unit as
`srshipper` with its declared sandbox/group access, execute `/bin/true` with the
fresh probe marker, and observe the kernel-originated audit event through that
unit and the actual API/DB readiness workflow. No fabricated stdin record or
synthetic controller-side callback can satisfy this fixture's acceptance.

While the unit is active, break the API address/path, provision an invalid token,
and make the real input unreadable in separate negative cases. Each case must
visibly time out/fail at the correct stage, stay out of ready, and recover after
repair with appropriate current evidence. Tests must assert that the service
really remained active, not that a subprocess exited immediately on EOF.

Never replace or reconfigure the review host's auditd/users/rules for this test.
Use an explicitly disposable VM or suitably isolated fixture with required
permissions. If unavailable, report this gate blocked rather than call the
stdin adapter test an installed-service acceptance pass. Retain separate final
Linux golden-image and Windows Sysmon/WEC tests on the user's VMs.

### 6. Make CI prerequisites executable and required

Provision proper cgroup delegation **and** place the trusted launcher/test
process in a hierarchy from which migration is allowed. Do not chmod the system
cgroup root or permit untrusted commands to migrate arbitrarily. Check a real
process move and the non-escape boundary under the intended identities.

Add `SR_REQUIRE_CONTAINMENT=1` semantics to the fixture/test harness: in required
CI/acceptance jobs, missing or unusable containment is a **failure**, not a skip.
Keep explicit optional skips for ordinary developer hosts. Apply equivalent
required-gate behavior to the disposable installed-capture fixture, e.g.
`SR_REQUIRE_INSTALLED_CAPTURE=1`. Wire the appropriate dedicated job/fixture and
keep Python 3.11/3.12/3.13, disposable PostgreSQL, build, browser and privileged
packet coverage. Correct the runner setup example in the runbook.

### 7. Execute acceptance and report evidence honestly

Publish exact command, exit status, pass/fail/skip/deselect counts, prerequisite
configuration and environment for each gate. Correct prior overclaims; explicitly
separate simulated SSH/PVE/model boundaries from real transport, installed
auditd/systemd identity and hardware. Do not declare either software acceptance
or final infrastructure acceptance solely from completion-report wording.

## Acceptance commands and required observable behaviors

Use a fresh venv with `requirements.lock`; run from the repository root except
frontend commands. Set `SR_PG_ADMIN_URL` (or `SR_PG_ADMIN_CMD`) explicitly to a
**disposable test** PostgreSQL admin. Tests create unique `srtest_*` DBs/roles.
Set `RUNNER_CGROUP_ROOT` to the correctly provisioned protected test hierarchy.
Never use a production database or kill unrelated processes. `PY` below means
the selected venv interpreter; repeat Python jobs on 3.11, 3.12 and 3.13 in CI.

```bash
python -m venv .venv
.venv/bin/pip install -r requirements.lock
.venv/bin/pip install --no-deps -e .
export PY="$PWD/.venv/bin/python"
export SR_REQUIRE_CONTAINMENT=1
"$PY" -m pytest -q -ra
"$PY" -m pytest -m "not db and not adapter" -q -ra
"$PY" -m pytest -m "not db and not browser and not live" -q -ra
"$PY" -m pytest -m "db or adapter" -q -ra
"$PY" -m pytest tests/test_third_followup_*.py -q -ra
"$PY" -m pytest tests/test_fourth_followup_containment.py -q -ra
"$PY" -m pytest tests/test_fourth_followup_enrollment.py -q -ra
"$PY" -m pytest tests/test_fifth_followup_acceptance.py -q -ra
bash -n infra/runner/runner_supervise.sh telemetry/install.sh
"$PY" -c "import srplatform.api.app"
"$PY" -c "import srplatform.bastion.proxy"
"$PY" -c "import telemetry.shipper"
"$PY" -c "import rangectl.cli"
```

Every command must exit 0; DB and required containment tests must actually run.
Existing optional packet/browser/live gates are separately required below;
their skips in the default suite must not be reported as acceptance passes.

On the dedicated privileged disposable Linux CI/fixture host:

```bash
sudo env "PATH=$PATH" "$PY" -m pytest \
  -m "not db and not browser and not live" -k "real_nft or netns" -q -ra
SR_REQUIRE_INSTALLED_CAPTURE=1 "$PY" -m pytest \
  tests/test_fifth_followup_installed_capture.py -m live -q -ra
```

The builder must mark the installed-fixture tests `live` and provide an explicit
disposable-host fixture configuration; the second command must run, not skip,
when that required flag is set. Do not interpret an empty/deselected suite as a
pass. Packet tests must execute with nftables/iproute2 and required privileges.

With Node 22, free ports 3000/8010, and Playwright's Chromium prerequisites:

```bash
cd web
npm ci
NEXT_PUBLIC_API_URL=http://localhost:8010 NEXT_TELEMETRY_DISABLED=1 npm run build
cd ..
npm install -g @playwright/cli
npx playwright install --with-deps chromium
"$PY" -m pytest tests/test_stage5_browser_e2e.py -m browser -q -ra
```

Build and browser commands must exit 0 with the browser test **passed**, not
skipped. Use an isolated acceptance host; do not stop the user's OpenChamber
server to free port 3000.

Required behavior assertions, regardless of test organization:

- Full worker/runner normal completion cannot persist completed while a recorded
  child identity is still alive. Zero/nonzero leader exits and redirected child
  output are both covered. Actual stop/end/reset/teardown succeeds only after all
  work is gone; unknown retains operations and lease and blocks new dispatch.
- Cleared environment, nested descendants, migration attempts and permission/
  state-read failures cannot produce false gone. An unsupported isolation setup
  refuses the harmless command before any side effect. Unrelated victim processes
  are never signalled in injected scan-to-signal identity races.
- Barrier-driven start/cancel and DB registration/finalization tests explicitly
  observe each required ordering. Fresh DB inspection never finds an unresolved
  operation on a terminal run. A pre-existing inconsistent terminal row blocks
  release until cessation is genuinely repaired/confirmed.
- Legacy phase-only confirmation and evidence from another capability/generation
  cannot enable ready/run. Correct fresh callbacks and real installed capture
  enable readiness; resume and concurrent duplicate confirmations are idempotent.
- A still-active unit with bad API/token/input stays visibly unready. The harmless
  command's actual kernel audit record, shipped as srshipper, is the capture proof.
- A local-dev background child cannot silently outlive completed operation state;
  stop/crash reconciliation resolves it truthfully or visibly blocks, rather than
  leaving an unresolvable row. Production continues to reject local-dev mode.
- Required CI containment/capture jobs fail when prerequisites are unavailable.

### Final infrastructure gates — separate, not waived

On explicitly operator-approved infrastructure, execute and record these observable
behaviors before final acceptance:

1. R740 runner: installed trusted supervisor/launcher, protected delegation and
   real SSH normal exits/background children, transport loss and control-channel
   failure; a successful cessation response leaves no recorded operation work.
2. PVE/R740: clone/read-back/launch, concurrent-launch conflict, reset and teardown;
   unresolved work prevents resource/lease release. Real VM egress/killswitch and
   bastion/recording proofs remain required; GPU/model operation is a separate gate.
3. Golden Linux VM: real auditd + installed systemd shipper as srshipper captures
   the harmless marker, passes enrollment/readiness, and exercises the three
   negative delivery/input cases. Windows VM: actual Sysmon/WEC events arrive with
   correct host/session/generation attribution and documented capture acceptance.
4. Compose, on an isolated fresh stack with supplied keys and safe dev config:
   `docker compose config` exits 0; `docker compose up -d` completes role bootstrap,
   migrations and key seeding; `rangectl bootstrap` is idempotent;
   `rangectl login` and `rangectl readyz` succeed. No destructive volume reset is
   authorized by this handoff. R740 boot/persistence must also be observed.

If any gate cannot run, list it as **blocked/unverified** with the reason. Do not
substitute controller attestations, fabricated telemetry, mocks or skipped tests.

## Independent review command results at 2357730

Review environment: non-root Linux, Node 22.23.3/npm 10.9.9; external venv
`/tmp/opencode/fifth-review-venv` using Python 3.12.15 and the locked requirements.
Real PostgreSQL 16.2 on localhost was explicitly selected via
`SR_PG_ADMIN_URL=postgresql+psycopg2://postgres@127.0.0.1:5432/postgres`; the fixtures
created/dropped their own unique DBs and roles. Real delegated cgroups were
available in the caller's systemd user-service scope (not the proposed CI
top-level directory). No sudo password, nftables, Docker or user hardware/VMs.

For pytest rows below, the command prefix was
`PATH=/tmp/opencode/fifth-review-venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1`;
DB-bearing rows additionally used the explicit admin URL above. All pytest
invocations included `-p no:cacheprovider` to avoid repository cache writes.

| Executed command | Exact result |
|---|---|
| `pytest -q -ra` (before configuring DB admin) | Exit 0: 105 passed, 105 skipped, 1 deselected, 4 warnings; not a DB acceptance pass. |
| `pytest -q -ra` (explicit DB admin) | Exit 0: **206 passed, 4 skipped, 1 deselected, 4 warnings**, 103.25s. |
| `pytest -m "not db and not adapter" -q -ra` | Exit 0: **92 passed, 4 skipped, 115 deselected, 3 warnings**, 31.12s. |
| CI unit command: `pytest -m "not db and not browser and not live" -q -ra` | Exit 0: **92 passed, 4 skipped, 115 deselected, 3 warnings**, 31.07s. |
| `pytest -m "db or adapter" -q -ra` | Exit 0: **114 passed, 1 skipped, 96 deselected, 4 warnings**, 86.75s. Browser skip: CLI initially absent. |
| `pytest tests/test_fourth_followup_containment.py -q -ra` | Exit 0: **14 passed**, 2 warnings, 20.19s. Real cgroups, not skipped. |
| `pytest tests/test_fourth_followup_enrollment.py -q -ra` | Exit 0: **7 passed**, 2 warnings, 15.52s. |
| `pytest tests/test_third_followup_*.py -q -ra` | Exit 0: **42 passed, 1 skipped**, 2 warnings, 31.90s. Skip: root+nft+iproute2. |
| `pytest -m browser -q -ra` | Exit 0: **1 skipped, 210 deselected**, 3 warnings, 10.11s; playwright-cli initially absent. |
| `pytest tests/test_stage5_browser_e2e.py -m browser -q -ra` after external CLI/Chromium installation | Exit 0: **1 skipped**, 3.19s; checkout web/node_modules absent. External build did not modify checkout. Port 3000 is also occupied by the user's OpenChamber server; not displaced. |
| `pytest -m "not db and not browser and not live" -k "real_nft or netns" -q -ra` | Exit 0: **3 skipped, 208 deselected**, 3 warnings, 3.82s; needs root+nft+iproute2. |
| Privileged CI packet command with `sudo -n env ... python -m pytest ...` | Exit **1**, `sudo: a password is required`; tests did not execute. |
| `npm ci` on an unchanged copy of web under `/tmp/opencode/fifth-review-web` | Exit 0: 31 packages added; audit reported 4 vulnerable entries. |
| `npm run build` on that external web copy | Exit 0; Next 14.2.35 compiled and generated all 9 static pages. |
| `npm audit --json` on that external copy | Exit **1**: 4 vulnerable entries, **3 critical / 1 high**; pre-existing dependencies, not introduced in this diff. |
| `bash -n infra/runner/runner_supervise.sh telemetry/install.sh` | Exit 0. |
| Combined imports of API app, bastion proxy, telemetry shipper, rangectl CLI | Exit 0; all four entrypoints import. |
| AST parsing every changed `.py` in `master..HEAD` | Exit 0; **17 changed Python files** parsed. |
| `docker compose config` | Exit **127**, `docker: command not found`. No Compose boot attempted. |

Four default-suite skips: three privileged packet tests at
`test_followup_regressions.py:629,693` and `test_third_followup_firewall.py:296`,
plus nft-absent validation at `test_m0_acceptance.py:37`. Default suite deselects
the browser test. Warnings are FastAPI startup deprecations, TestClientTransport
collection warning, and the non-async test marked asyncio in M2.

Additional probes (not committed tests) reproduced F1 escape/nesting/unreadability,
F2 locked-snapshot race, F3 legacy readiness, F4 old-capability attribution, and
F7 local behavior/health. The inline DB probe harnesses reported 1 and 3 passing
**bug-reproduction assertions**, respectively; those are evidence of failures,
not passing acceptance tests. The first unreadable-state probe returned false
`gone`, then cancellation actually killed the child and its cleanup attempt found
the removed cgroup (script exit 1); the corrected status-only probe separately
confirmed the same PID alive after `gone` and cleaned up successfully.

Python 3.11/3.13 CI jobs, GitHub's actual delegation, privileged packet flows,
browser workflow, installed auditd/systemd identity, real SSH, R740/PVE/GPU,
Sysmon and Compose boot were **not independently verified** here. A green
software suite does not close F1-F8 or these gates.
