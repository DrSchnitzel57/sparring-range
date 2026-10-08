# Current findings and validation evidence

Updated: 2026-10-08. Application revision inspected/tested: **`23de4f4`**
(planning baseline); milestone-01 implementation evidence recorded at **`ac5a61b`**.
Release contract: [ARCHITECTURE.md](ARCHITECTURE.md); ordered work:
[ROADMAP.md](ROADMAP.md); operator gates: [OPERATOR_RUNBOOK.md](OPERATOR_RUNBOOK.md).

**Not release-ready.** This replaces accumulated remediation checkmarks. Existing
repairs and regression tests are valuable, but historical green totals and reports
are not fresh acceptance. No release milestone has been accepted, no live attacks
are authorized, and documentation changes do not repair the application.

## Evidence labels

- **Reproduced:** executed here at the stated revision/environment.
- **Inspected:** current source/artifacts support the observation; not a passing
  production integration test.
- **Missing software:** a required mechanism or acceptance fixture is absent.
- **Unverified:** required boundary has not been independently executed here.
- **Historical:** prior revision evidence/claims, recoverable from Git; not current
  acceptance. Reproduction assertions proving a bug are not acceptance passes.

## Fresh planning baseline

Checkout was clean on `master`, equal to `origin/master`, before documentation
work. Linux, existing `.venv`, Python **3.13.5**, Node **22.23.3**, npm **10.9.9**.
No disposable PostgreSQL admin configured; no user-approved live PVE/templates,
installed systemd/auditd fixture, packet or deployed-browser acceptance performed.

Executed in the repository root:

```bash
env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 \
  .venv/bin/python -m pytest -q -ra -p no:cacheprovider
```

Exit **1**: **9 failed, 107 passed, 115 skipped, 1 deselected, 4 warnings**,
**61.13s**. Default pytest selection excludes browser/live. DB cases mostly skip;
an unmarked case leaks a DB requirement. This is not DB, real SSH, installed
capture, privileged packet, browser or R740 acceptance.

| Failing test | Interpretation to investigate, not assumed vulnerability |
|---|---|
| `tests/test_fifth_followup_acceptance.py::test_f1_same_uid_escape_to_parent_cgroup_is_impossible` | Namespace-local child PID / changed leader-exit behavior; retain no-escape invariant |
| `tests/test_fifth_followup_acceptance.py::test_f1_nested_membership_is_running_not_gone` | Nested-survivor premise must match protected namespaces and actual host identities |
| `tests/test_fifth_followup_acceptance.py::test_f1_unreadable_membership_is_unknown_not_gone` | Current leader exit can remove the survivor; establish real live-authority failure before asserting unknown |
| `tests/test_fourth_followup_containment.py::test_t04_cleared_env_descendant_is_visible_and_contained` | Observe host identities and valid survivor conditions under new PID namespace |
| `tests/test_fourth_followup_containment.py::test_t04_normal_zero_exit_with_survivor_is_contained_not_blind` | Namespace PID 1 exit may terminate children; verify cessation, not an obsolete note alone |
| `tests/test_fourth_followup_containment.py::test_t04_failed_normal_exit_is_also_gated_on_containment` | Same issue for nonzero completion; preserve truthful exit and cessation |
| `tests/test_fourth_followup_containment.py::test_t04_unreachable_supervisor_at_completion_is_unknown` | Ensure test actually reaches an unresolved control boundary |
| `tests/test_third_followup_lifecycle.py::test_t01_descendant_survives_leader_exit_status_still_sees_it` | Legacy survivor expectation needs safe current-mechanism fixture |
| `tests/test_followup_regressions.py::test_r04_release_invalidates_previously_valid_evidence` | Unmarked DB dependence; PostgreSQL unavailable, not proof invalidation itself is broken |

Do not weaken containment to satisfy the eight old process assumptions. Fix tests
to independently observe real process identities and safety outcomes; if genuine
production defects emerge, repair them with negative-path regressions. Baseline
failure investigation belongs in milestone 01; full authority acceptance in 02.

Executed from `web/`:

```bash
npm audit --package-lock-only --json
```

Exit **1**: **4 affected packages, 3 critical / 1 high**: Next, PostCSS, Seroval,
Solid. No upgrade performed. Pages Router/Linux deployment applicability must be
triaged advisory-by-advisory; package severity alone is not exploitability proof.
Patch applicable issues and validate build/replay/browser behavior in milestone 01;
do not use blind major-version `audit fix --force`.

No fresh `npm ci`/build, Docker boot, Packer build, DB migration/concurrency,
privileged packet, installed capture or browser result is claimed by this planning
pass. Exact baseline is also recorded in `AGENTS.md`.

### Documentation-only validation

At `23de4f4` with this pass's documentation changes, independently executed:

| Command / check | Result |
|---|---|
| `git diff --check` | Exit 0; no whitespace errors |
| `python3` inline Markdown validator (required documents, relative links, fences, milestone ordering and absence of detailed plans) | Exit 0; 7 Markdown files, 24 relative links, balanced fences, milestones 01–11 in order, no detailed plans |
| `python3` inline Git provenance/scope check using `git cat-file -e 23de4f4:<path>` for every deleted file | Exit 0; all 15 removed documents recoverable; changed/untracked files are documentation and the plans-directory marker only |

These checks validate the documentation consolidation, **not** any application
milestone. The application suite was not rerun after documentation-only edits;
its executed baseline above remains failing and explicitly revision-bound.

### Fresh milestone-01 planning rerun

At clean revision `7368782`, on the same Python 3.13.5 environment, the exact
no-admin pytest command above exited **1**: **10 failed, 106 passed, 115 skipped,
1 deselected, 4 warnings**, **61.76s**. All nine earlier failures remain. The
additional failure is
`tests/test_followup_regressions.py::test_r12_golden_image_calls_the_real_installer`:
the documentation consolidation removed the literal strings
`PREBUILT-TEMPLATE REQUIREMENT` / `VERIFIES readiness` asserted by that old test.
This is a documentation/test coupling regression introduced by the consolidation,
not evidence that the application provisioning code changed. Repair its assertion
without weakening the requirement for usable templates and enforced readiness.

The exact `web/` audit command above again exited **1**, four affected packages,
**three critical / one high**. Read-only prerequisite checks: `docker compose
version` exited 0 (5.6.0); `docker info --format '{{.ServerVersion}}'` exited 0
(29.8.2). DB admin variables remain unset; `psql`, `playwright-cli`, and `nft` are
not on PATH. No Docker resources, DB schema, browser service, live range or host
firewall were created/mutated by these checks. These results supersede assumptions
about Docker availability, not the outstanding acceptance gates.

## Milestone 01 implementation evidence (2026-10-08)

Executed at clean revision **`ac5a61b`** (branch `happy-chipmunk`) on this
developer host: Python **3.13.5** (uv-created pip-less `.venv` from
`requirements.lock`), Node **22.23.3**, npm **10.9.9**, Docker daemon 29.8.2 /
Compose 5.6.0, cgroup v2 with a writable delegated subtree. No Proxmox, live
range, host firewall or unrelated-VM access; all fixtures run-owned.

| Gate (exact command) | Result |
|---|---|
| `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -ra -p no:cacheprovider` | Exit 0: **97 passed, 0 failed, 0 skipped, 139 deselected**, 4 warnings, 14.4s — infrastructure-free default |
| `.venv/bin/python infra/dev/acceptance.py selection` | **PASS**: 236 tests = 97 fast + 139 integration (db 113, containment 25, packet 4, browser 1, live 0 until milestone 11); required modes verified to fail for absent prerequisite, skipped required test and empty selection |
| `.venv/bin/python infra/dev/acceptance.py python` | **PASS**: fresh run-owned venv, locked install without re-resolve, dependency check clean, 4 entrypoint imports on Python 3.13.5 (CI matrix covers 3.11–3.13) |
| `.venv/bin/python infra/dev/acceptance.py db` | **PASS**: disposable `postgres:16` (unique container/volume, loopback port, synthetic creds) — **113 passed, 0 skipped**, 123 deselected in required mode; fresh chain, populated pre-0010 forward upgrade, grants and append-only regressions; no `srtest_*`/`sr_*` leftovers; container+volume removed |
| `.venv/bin/python infra/dev/acceptance.py containment` | **PASS**: 21 namespace/recursive-membership/cancellation regressions in required mode, 0 skipped; no run-owned cgroups leaked (4 db∩containment compound tests run inside the db gate) |
| `.venv/bin/python infra/dev/acceptance.py packet` | **FAIL here (prerequisite)**: missing root + `nft` — this host is not the approved privileged fixture; CI packet job (standard Linux VM, nftables, rules only in disposable netns) is the gate |
| `.venv/bin/python infra/dev/acceptance.py frontend` | **PASS**: `npm ci`, production `next build` (Next **16.4.0**, Pages Router, React **18.3.1**), `npm audit --omit=dev` → **0 vulnerabilities** (baseline was 3 critical/1 high across Next/PostCSS/Seroval/Solid; all were Next-14 transitive and are gone; no lower-severity findings remain to triage) |
| `.venv/bin/python infra/dev/acceptance.py compose` | **PASS**: real image build, fresh bootstrap + idempotent rerun (run-owned project, loopback ports, synthetic passwords/keys) — alembic at `0010`, app-role-only API readiness, app-role schema access, bastion running behind the seed-keys gate; only run-owned resources removed |
| `.venv/bin/python infra/dev/acceptance.py browser` | **FAIL here (prerequisite)**: pinned CLI present but Chromium cannot launch (missing system libraries such as `libglib-2.0.so.0`; no root to install them) — CI browser job (`playwright install --with-deps`) is the gate; E2E now isolated (free/configurable ports, `.next-e2e` dist, run-owned session) and covers replay seek |

Genuine production defects found by the first real DB-layer execution and
repaired with their regressions kept: SQLAlchemy 2.1 `Row` attribute access in
token recovery (`.scalars()`), phase-only JSON trusted by the deploy/idempotent
resume paths (now requires current capability evidence, F3), and migration
0010's helper rejecting an Engine. The supervisor additionally treats a
concurrently-removed operation cgroup tree as confirmed cessation (kernel only
removes empty cgroups). No safety regression was deleted or weakened.

**Review fixes (2026-10-08, post-`ac5a61b` review — VERDICT: FIX, all 8 items):**
Python 3.11 rejected a backslash inside an f-string expression in
`srplatform/coach/aar.py` — rewritten compatibly; the full 3.11/3.12/3.13
matrix now passes `acceptance.py python`. The CI db job now also delegates a
cgroup v2 subtree (the layer includes four DB+containment worker-chain tests),
and delegation is proven by a migration positive control both in the CI step
and inside `acceptance.py containment` (a real process is migrated in and
observed there — ownership alone is not permission). The compose override now
uses `!override` to REPLACE base port mappings (verified via `compose config`),
and the gate holds the default ports 5432/8000/2222 for its whole run. The PG
fixture claims ownership before each create/start, surfaces cleanup failures,
is idempotent, and `acceptance.py db` now runs a failure-path probe (occupied
port → fails and strands nothing). The frontend audit gate fails closed on
error responses/unparsable/missing metadata, and the skip gate read the wrong
count key (`skip` vs pytest's `skipped`) — both fixed with harness unit
regressions (`tests/test_acceptance_harness.py`, 4 tests). Replay coverage now
proves a REAL seek: the player's own polled position (`data-now`) must reach
the clicked event's offset and the rendered frame content must change to match
(bracketing frames at 1s/3600s). Compose verification now checks the exact
alembic head, DB-backed `/readyz`, the API's app-role-only credential env, and
authenticated account operations with idempotent rerun behavior (bootstrap
closed 403, duplicate member 409, login survives rerun).

Post-fix gate results at this revision: fast default **101 passed, 0 failed,
0 skipped, 139 deselected**; `selection` PASS (240 total); `python` PASS on
3.11.17/3.12.15/3.13.5; `db` PASS (failure-path probe + **113 passed,
0 skipped**); `containment` PASS (migration probe + 21 passed); `frontend`
PASS; `compose` PASS with default ports held (exact-head migrations,
credential split, `/readyz`, account ops, idempotent rerun, clean teardown).

**Round-3 review fixes (2026-10-08, post-`13daa88` review — VERDICT: FIX,
all 6 items):** the invalid top-level `x-delegate-cgroup` workflow key was
removed — the anchor now lives on a real step reused via alias, and a
structural workflow-schema test (`test_ci_workflow_is_schema_valid`) rejects
unknown top-level/job/step keys and nested step lists. CI now runs the db and
containment gates **inside** the delegated subtree via
`infra/dev/run_in_cgroup.sh`: root performs the single privileged migration
into the subtree, verifies it took effect, then drops to the unprivileged
user — so source and destination of every test migration are user-owned
(the old step only chowned the destination, which the kernel refuses to
migrate out of). The PG fixture now REFUSES pre-existing container/volume
names (collision = not ours, never removed), claims ownership only after a
name is verified free, and wraps the entire startup in exception-safe
cleanup so timeouts (`TimeoutExpired`) as well as nonzero exits strand
nothing; covered by fault-injected unit tests and a real-docker collision
probe in `acceptance.py db`. The audit evaluator additionally requires the
complete nonnegative-integer severity map and a consistent exit status
(0↔zero findings, 1↔findings; anything else fails). The compose gate now
provisions the stack's bastion token into `service_tokens` and verifies a
scoped target-resolution call authenticates with it (404 authenticated vs
401/403 refused) before AND after the idempotent rerun.

Round-3 gate results: fast default **106 passed, 0 failed, 0 skipped,
139 deselected** (245 total); `selection`, `frontend`, `containment` PASS;
`db` PASS with failure-path + collision probes; `compose` PASS with bastion
capability verified on both attempts.

**Round-4 review fixes (2026-10-08, post-`8ba0764` review — VERDICT: FIX,
all 3 items):** CI delegation now chowns the subtree's **control files**
(`cgroup.procs`), not just the directory — the kernel requires the delegatee
to write `cgroup.procs` for any migration — and `run_in_cgroup.sh` is
self-verifying end to end: after dropping privileges it runs an
**unprivileged migration probe** (create child cgroup, migrate a real
process in, observe, kill+wait, rmdir with retry) and fails before the gate
if any permission in the chain is wrong; the containment gate now runs that
same dropped-phase probe against the real subtree (full wrapper path, not
just `bash -n`), plus fast failure-path tests. The PG fixture distinguishes
inspection **errors** from absence (a daemon error is never a free name),
creates every resource with a run-unique `sr-range-run` **ownership nonce**,
and re-verifies that nonce before any deletion — a raced collision is left
in place and surfaced, never deleted; covered by fault-injected race/error
tests. The collision probe now tracks exactly which resources it created,
verifies its own nonce before removing them, and fails acceptance when its
teardown does not complete.

Round-4 gate results: fast default **111 passed, 0 failed, 0 skipped,
139 deselected** (250 total); `selection`, `containment` (incl. wrapper
dropped-phase probe) PASS; `db` PASS with failure-path + collision probes
(nonce-verified teardown).

**Round-5 review fixes (2026-10-08, post-`b97cfa9` review — VERDICT: FIX,
both items):** `docker volume create` succeeds for an already-existing
volume and keeps its FOREIGN label (re-verified against real Docker here),
so the fixture now verifies its ownership nonce landed **immediately after
creation and before the volume is mounted** into postgres — a raced foreign
volume is refused, never mounted, never removed. `cleanup()` no longer
clears its tracking flags on failure: identity-inspection errors, failed
removals, and foreign-nonce resources RETAIN the claim so every subsequent
`cleanup()` retries and re-reports until the resource is confirmed removed
or absent (only then is the obligation cleared). Regressions: raced-volume
(never mounted, never removed, obligation retained), retained-retry for
foreign containers and unconfirmable identity, and resolution-clears-claim
transitions.

Round-5 gate results: fast default **112 passed, 0 failed, 0 skipped,
139 deselected**; `db` PASS against real Docker (post-create nonce check on
the happy path, failure-path + collision probes, 113 passed required mode).

**Milestone 01 acceptance status:** all locally executable gates pass.
Packet and browser gates fail closed here for missing prerequisites
by design; per the plan they are accepted only when the required CI jobs pass
after the operator pushes. Milestone remains until then.

## Release blockers and missing work

| ID / priority | Current finding and evidence boundary | Milestone |
|---|---|---|
| B01 / P1 | **Repaired at `ac5a61b` (see milestone-01 evidence):** baseline failures fixed on real host identities; DB marker leakage structurally prevented (fixture-closure derivation). Awaits CI green for milestone close | 01 |
| B02 / P1 | **Repaired at `ac5a61b`:** Next 16.4.0 + patched transitive deps; `npm audit --omit=dev` reports 0 vulnerabilities; build/replay/browser validated | 01 |
| B03 / P0 | Inspected API still constructs direct PVE adapter; current safety controller invokes privileged nft machinery. Incompatible with agreed private limited-token/no-runtime-host-root boundary | 02 |
| B04 / P0 | Namespace/cgroup boundary and kernel kill exist, but nine-failure baseline is not containment acceptance. Missing/unreadable authority, recursive membership, bookkeeping protection, unsupported starts and all signal identities need independent proof | 01–02 |
| B05 / P0 | Run-row locking, guarded writers and any-run obligations exist. DB races and every writer/caller (spawn, callback, stop, watchdog, startup, emergency) remain unverified here; never rely on helper docstrings saying every writer is covered | 02 |
| B06 / P0 | Exact effective PVE permissions, static bridged/routed isolation, resource budgets and independent owned-VM emergency stop are not accepted. No attacks before real gates; no permission widening to pass | 02, 11 |
| B07 / P1 | Current image artifacts do not establish usable web/database templates. Service-present checks are not actual transactions; YAML has placeholder integrity/user baselines and seed contracts need completion | 03 |
| B08 / P1 | Enrollment now carries exact capability/generation evidence and migration 0010 invalidation logic. Fresh/legacy upgrades, stale-token rejection, recovery and concurrent confirms require disposable DB acceptance | 04 |
| B09 / P1 | **Missing software:** `tests/test_fifth_followup_installed_capture.py` and required installed-systemd/auditd acceptance. Subprocess synthetic stdin cannot prove `srshipper` reads real audit input or captures a real command | 04 |
| B10 / P1 | **Wired at `ac5a61b`:** required layers run as dedicated CI jobs via `infra/dev/acceptance.py` with `SR_REQUIRE_*` (missing prerequisites/empty selections/skipped required tests fail). Installed-capture fixture still missing (milestone 04). CI execution pending operator push | 01, 04 |
| B11 / P1 | SSH/recording/spool code exists; real pinned SSH, installed identity, input/API/token negatives, shared durable storage, delivery gaps and transport-loss recovery remain unverified | 04, 11 |
| B12 / P1 | **Missing release behavior:** configuration snapshots for new controls, explicit timed Begin, ready-idle expiry, server clock, restart interruption and automatic post-evidence cleanup. Existing end keeps owned VMs/reservation pending separate teardown | 05 |
| B13 / P1 | **Missing release behavior:** continuous independent HTTP/MySQL probes, availability samples/rubric, distinct live component scores, scorer-health detector and outage interruption | 06 |
| B14 / P1 | **Missing release behavior:** timed inject catalogue/deadlines/submissions, deterministic task results and separate written feedback | 07–08 |
| B15 / P1 | Inspected red loop terminates at step budget/objective completion; sustained pacing, both explicit start modes and bounded retry-then-interrupt policy still needed | 08 |
| B16 / P1 | Shared API model gateway exists; actual Qwen alias/context/structured responses, capacity, outage recovery and coaching usefulness remain unverified. No embeddings needed | 08, 11 |
| B17 / P1 | Inspected live UI exposes red phase/objective progress. Competition spoiler policy must be enforced across all API/CLI/event/report/replay reads, not just hidden controls | 09 |
| B18 / P1 | Browser pages exist but not agreed session builder/service scoreboard/inject flow/recovery states. Same-origin LAN HTTPS/IP-SAN trust and visiting-client localhost assumptions need work | 09–10 |
| B19 / P1 | Production packaging, owner/runtime credential separation, storage-pressure readiness, indefinite evidence/explicit offline purge and consistent DB+recording backup/restore are not accepted | 10 |
| B20 / P1 | Real R740 clone/storage/ACL/isolation/stop, installed telemetry, model, restart/restore and unaided operator/member usefulness gates have not run | 11 |

Windows/Sysmon/WEC remains unfinished later work (milestone 12), not a disguised
first-release blocker or claimed implemented pipeline. More storage can be added;
capacity must be discovered, not used to silently remove agreed scope.

## Historical finding coverage retained

The removed reports were at older revisions. The table preserves every finding
family and its requirement/test anchor without reusing its checkmarks. All rows
are **retest/preserve**, not newly accepted. Paths below are current code/test
anchors; detailed historical repros/results remain in Git and `audit/`.

| Historical IDs | Requirement to preserve / test anchor | Release work |
|---|---|---|
| F01, R01, N04 | Remote-only production execution; actual worker auth, minimal resolved env, no controller dotenv/secrets; `tests/test_stage3_telemetry.py`, `tests/test_followup_regressions.py` | 01–02 |
| F02, R03, N05, T01 | Durable operation IDs; local+remote acknowledged cessation, transport loss/crash/restart; `tests/test_stage2_safety.py`, `tests/test_third_followup_lifecycle.py` | 02 |
| F03, R05, N06, T03 | Actual range-scoped bridge/routed/IPv6/established denial, atomic safety, effective topology/policy, management preservation; firewall/netns regressions | 02, 11 |
| R04, N07 | Fail-closed latch/file+DB merge, persistence errors, no stale proof reuse; config identity/freshness/killswitch proof; safety regressions | 02 |
| F04 | Password auth, ownership, producer scopes, actor assignment, revocation; no forged verifier/score events | 02, 04, 09 |
| F05, R06, N01 | Correct PVE verbs/`newid`/UPID waiting, TLS; typed absence vs outage; no mutation without ownership; `tests/test_stage1_safety.py` | 02–03 |
| F06, R07–R08, N02–N03, T02 | Single reservation, intent-before-side-effect, idempotency, generation/ownership, fenced lifecycle/concurrency, uncertain cleanup retains lease | 02–05 |
| F07, R12 | Actual fresh Compose bootstrap, build secret exclusions, no runtime owner URL, real seed/volume wiring; `tests/test_stage5_bootstrap.py` | 01, 10 |
| F08, R02 | Real token→owner key binding, owned inventory and live SSH instructions, access revocation | 04, 09 |
| F09, R11, N08–N09, T05, T08 | Real audit assembly/source time/boot IDs, bounded synchronized crash-safe spool, installed identity/delivery/capture, automatic enrollment; telemetry/spool tests | 04 |
| F10, R09, N10 | Typed/quoted baseline-aware checks, expected polarity, unknown on errors, flag provenance, current owned pinned inventory, historical scores not live SSH to reused IPs | 03, 06 |
| F11 | API-only trusted scoring and finalize, immutable score snapshots; no CLI-submitted facts | 06 |
| F12, F18, R10 | Supported coach labels/citations, unscored ≠ failure, prioritized study; one actual cross-process scheduler, timeout/queue recovery | 08 |
| F13 | Ready/run/end outcomes distinguished from attacker achievement; production-role grants, idempotence, failure reporting | 05 |
| F14 | Ingest/event-ID cursor pagination, prior-summary carry-forward, logged action intent, no blind replay | 05, 08 |
| F15 | Strict nested tool schema, all objective truth independently verified, scenario phase/inventory; no model DONE awarded points | 08 |
| F16–F17 | Opaque UUID exclusive recordings, read/register path and symlink bounds, exec+resize capture; replay epoch/seek/multiple casts | 04, 09 |
| F19, N11, T04 | One strict immutable scenario snapshot drives deploy/reset/worker/score; versioned usable templates, no live YAML divergence | 03, 05 |
| F20 | Chronological per-domain/component history from trusted score snapshots, zero/unknown handling and actual browser workflow | 09 |
| F21 | Supported reproducible Linux image build, real seeded services/key installation; Windows deferred explicitly | 03, 12 |
| F22–F23, T07 | Safe explicit unique disposable DB fixtures, markers/CI/locks/readiness/packaging; bounded nonblocking byte reads and honest layers | 01, 02, 10 |
| Fifth F1 / P0 | Protected non-escapable bookkeeping/recursive authority, no failed reads treated empty; PID-namespace test premises must be repaired | 01–02 |
| Fifth F2 / P0 | Lock before fresh inventory after commits; registration vs every terminal writer; corrupt terminal row cannot hide obligations | 02 |
| Fifth F3–F4 / P1 | Legacy phase-only ready/run invalidated; exact capability+nonce+session+host+generation; idempotent concurrent confirmation | 04 |
| Fifth F5 / P1 | Kernel/stable-identity scoped signals; environment marker diagnostic only, scan-to-signal races/unrelated processes protected | 02 |
| Fifth F6 / P1 | Real installed systemd/auditd capture under `srshipper`; active-service bad API/token/unreadable-input negatives | 04 |
| Fifth F7 / P2 | Local-dev background children/operation rows resolved truthfully; runner health rejects unknown; never enable local-dev in production | 01–02 |
| Fifth F8 / P1 | Executable delegation and required containment/capture CI flags; missing prerequisites fail mandatory jobs | 01, 04 |

The fourth review's two blockers were authoritative completion/cessation and real
delivery/capture enrollment. The fifth review showed its completion report did not
prove them. The new namespace/migration repairs in `23de4f4` must be evaluated on
their merits; neither the prior failures nor report claims are blindly carried
forward as current defects/successes.

## Historical provenance and documentation consolidation

Recover removed tracked documents at the pre-cleanup application revision, e.g.:

```bash
git show 23de4f4:docs/plans/fifth-followup.md
git show 23de4f4:IMPLEMENTATION_AUDIT.md
```

| Historical source (removed from current tree) | Evidence revision / retained meaning |
|---|---|
| `plan.markdown` | Original M0–M7 contract; safety/API/evidence/replay/usefulness retained, new explicit release decisions supersede old GPU/LXC/grade assumptions |
| `IMPLEMENTATION_AUDIT.md`, `LOCAL_AGENT_HANDOFF.md` | `a5b19ab`, F01–F23 |
| `docs/FOLLOWUP_REVIEW.md`, `docs/FOLLOWUP_REMEDIATION.md` | `bd93f0d`, R01–R12 and subsequently corrected completion claims |
| `docs/SECOND_FOLLOWUP_{REVIEW,HANDOFF,COMPLETION_REPORT}.md` | `18377c6`, N01–N11; later addendum acknowledges incomplete original claims |
| `docs/THIRD_FOLLOWUP_{REVIEW,HANDOFF,COMPLETION_REPORT}.md` | `0b0d726`, T01–T08; later repairs/test anchors retained |
| `docs/FOURTH_FOLLOWUP_{REVIEW,COMPLETION_REPORT}.md` | `213246e` / `2357730`, two blockers and seven focused repair requirements |
| `docs/plans/fifth-followup.md` | Review at `2357730`, committed in `7c29c45`; F1–F8, production probes and stronger acceptance boundaries |
| `docs/ARCHITECTURE_NOTES.md` and old checklist/runbook/README | Consolidated into current architecture/roadmap/evidence/runbook; no old “all built” claim remains authoritative |

Prior fifth-review totals (including 206 passes with PostgreSQL 16) belong to
`2357730` and its environment, **not** this revision. Do not copy them as today's
result. Historical probe files/results in `audit/` are preserved, not deleted or
promoted to acceptance. Source/test comments and package metadata still naming
old docs are legacy references to reconcile in milestone 01 without changing
regression intentions; they cannot override `AGENTS.md` or the release design.

## Recording new acceptance evidence

For every gate record: date, evidence Git revision and dirty status, exact command
and non-secret environment, runtime/fixture versions, exit code and all
pass/fail/skip/deselect totals, boundary actually exercised, prerequisite blockers,
and observable live outcomes where applicable. Never record plaintext credentials,
real admin terminal casts or mutable generated files as proof in Git.

Only close a blocker after independently executing its agreed milestone criteria.
No implementation milestone is closed by this documentation pass.
