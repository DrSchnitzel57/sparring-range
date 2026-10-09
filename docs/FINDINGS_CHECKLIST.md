# Current findings and validation evidence

Updated: 2026-10-08. Application revision inspected/tested: **`23de4f4`**
(planning baseline); milestone-01 implementation evidence recorded at **`ac5a61b`**.
Release contract: [ARCHITECTURE.md](ARCHITECTURE.md); ordered work:
[ROADMAP.md](ROADMAP.md); operator gates: [OPERATOR_RUNBOOK.md](OPERATOR_RUNBOOK.md).

**Not release-ready.** This replaces accumulated remediation checkmarks. Existing
repairs and regression tests are valuable, but historical green totals and reports
are not fresh acceptance. Milestone 01 is accepted after independent review
reopened it and a repair round closed the findings (see below). No live attacks
are authorized; later milestones remain
unaccepted. Documentation changes do not repair the application.

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

**Round-6 review fix (2026-10-08, post-`cf98a67` review — VERDICT: FIX,
the item):** the t03 discovery test replaced global `pathlib.Path` with a
lambda, which crashes Python 3.11 (`Path._flavour` INTERNALERROR, reproduced
on 3.11.17 before the fix). The direct `/sys` bridge-port read is now a named
module seam (`_local_bridge_ports` in `srplatform/safety/firewall.py`), and
the test doubles THAT — same trap semantics (a same-named local bridge must
never be consulted while an execution prefix is configured), no global class
replacement. Round-6 gate results: fast suite **112 passed** on 3.11.17,
3.12.15 and 3.13.5 (fresh locked venvs, mirroring the CI matrix); `python`
matrix gate PASS on all three; `selection` PASS; `containment` PASS (21
passed, wrapper probe included).

**First CI run (run 37832124220 at `beae969`) — failures and fixes
(2026-10-08):** selection/frontend/compose green; five distinct causes
behind the rest.
1. `python` matrix (all 3): the gate demanded a `uv` or bare `3.12` binary;
   GH runners have neither. `_interpreter_for` now accepts the RUNNING
   interpreter when it matches the spec — the matrix job's venv already IS
   the fresh run-owned locked install on that version.
2. `containment` (15 failures) + 2 `db` worker-chain failures: the
   supervisor's trusted boundary needs `unshare --user`, which Ubuntu
   24.04+ (GitHub runner images) restricts via AppArmor
   (`apparmor_restrict_unprivileged_userns`); the supervisor correctly
   refused every start (exit 4). The workflow now loads Ubuntu's documented
   SCOPED profile granting `userns` to exactly `/usr/bin/unshare` on the
   disposable runner (never the global sysctl switch), and the containment
   gate gained a boundary pre-probe that names this prerequisite instead of
   failing 15 tests on "command never started".
3. `browser`: Next 16 resolves `distDir` RELATIVE to the project and
   silently treats an absolute path as relative (built into
   `web/home/dev/...`, rc 0), so the baked-URL marker had no directory.
   The fixture now hands next a relative distDir (verified locally: build +
   `next start` serve from `.next-e2e`).
4. `db` hint-jump test: its cross-process client stripped the environment
   to `PATH=/usr/bin:/bin`, dropping `LD_LIBRARY_PATH`, which GitHub's
   hostedtoolcache python needs (its own workflow env exports it) — the
   child died before posting. `_minimal_python_env()` keeps the minimal
   surface but forwards loader variables.
5. Harness diagnostics: the first CI run showed failing test NAMES with no
   reasons (tracebacks above the 1500-char failure tail). Layer runs use
   `--tb=line` and the failure tail grew to 6000 chars.
Still open for the next CI run (tracebacks were invisible): the m2 bastion
and r06 packet failures — both green locally, but neither has ever passed
in CI, so treat them as unresolved until the one-line tracebacks name the
cause.
Round of fixes verified locally: fast default **113 passed** (new
interpreter-resolution regression), `selection`, `db` (113), `containment`
(boundary probe + 21), `python` gate in CI-matrix shape (current-interpreter
match) all PASS.

**Second CI run (run 37835631215 at `7de03cb`) — failures and fixes
(2026-10-08):** python matrix/selection/frontend/compose green and the m2
bastion test passed; four jobs red, three distinct causes — the new
`--tb=line` tails named them.
1. `containment` (12 failures) + `db` (2, "the remote job never started"):
   the scoped profile was `flags=(unconfined)` + `userns,`. That permits
   userns creation (the pre-probe passed), but Ubuntu's kernel treats a
   profile in the *unconfined state* as an unconfined creator and
   transitions it into the restrictive `unprivileged_userns` profile,
   whose `deny capability` then fails the boundary's two inner mounts
   (cgroup2 remount, tmpfs state mask) — exit 96. The workflow now loads a
   REAL confined profile (upstream apparmor's `bwrap-userns-restrict`
   pattern: explicit `allow capability/file/mount/umount/userns/...`;
   exec'd children inherit it), and both the workflow probe and the
   containment gate pre-probe exercise the FULL boundary including those
   mounts. A harness regression pins the profile shape.
2. `packet` (r06, "emergency must sever intra-range traffic"): R1↔R2
   traffic is BRIDGED, and the inet forward hook only sees bridged frames
   when `br_netfilter` is loaded — true on the dev host, false on the
   runner. The test declared `range_bridge_ports=""`, so the bridge-family
   emergency drop matched only the master, which the bridge forward hook
   never shows (the render's own audit-R05 comment says so). The test now
   declares the real veth ports, exercising the production L2-sever
   mechanism independent of any host module.
3. `browser`: the distDir fix worked — built, served and driven by
   Chromium; login failed with "Failed to fetch": `app.py` snapshotted
   `get_settings()` at IMPORT for CORS, while the test sets
   `API_ALLOWED_ORIGINS` after import (and pytest collection imports the
   app module even earlier), so the run's ephemeral web origin was never
   allowed. The CORS middleware now resolves origins when the middleware
   stack is BUILT (app startup) — production behaviour unchanged (read
   once, at boot); verified: a preflight from the configured origin gets
   ACAO, any other origin does not.
Verified locally after the fixes: fast default **114 passed** (new
confined-profile regression), `db` gate PASS (113, real Docker),
`containment` gate PASS (mount-inclusive probe + 21). Packet and browser
remain CI-only gates.

**Third CI run (run 37841594922 at `2bc926a`) — packet GREEN; two causes
left (2026-10-08):**
1. `containment` + `db` died in the workflow probe itself: `unshare:
   failed to execute sh: Permission denied` (exit 126). The confined
   profile had NO execute grant: under `abi <abi/4.0>` (policy v6) the
   file `m` bit is mmap-exec, not execute — exec requires an `x` rule
   with a transition mode. Added `/** rix,` (exec, inherit profile), so
   unshare can exec sh/bash/mount/the command and every child stays in
   the profile (capability/mount remain available inside the namespace).
   The harness regression now pins the exec grant too.
2. `browser`: login worked (CORS fix confirmed); replay failed "player
   never mounted" — asciinema-player 3.17 is the Solid rewrite: it mounts
   as `.ap-player` with the text mirror in `<pre class="ap-term-text">`;
   the legacy `.asciinema-player` class no longer exists, so the test's
   selector could never match. Verified against the installed package:
   `create(src, elem, opts)` API matches the page, unknown opts are
   filtered (not rejected), the vt WASM is base64-inlined (no external
   asset). Test selectors updated to the real DOM.
Fast default after fixes: **114 passed**.

**Fourth CI run (run 37843120582 at `4ace51e`) — exec fixed; boundary
mount + replay seek fixed (2026-10-08):** the confined profile now loads
and execs (the round-3 EACCES is gone). Two causes remained.
1. `containment` + `db` (probe exit 32): `mount: /sys/fs/cgroup: cgroup2
   already mounted on /sys/fs/cgroup` — the mount(2) SYSCALL returned
   EBUSY. On 6.8-era kernels (Ubuntu 24.04) the kernfs superblock layer
   refuses to create/reuse a cgroup2 superblock from a non-init user
   namespace ("reusing existing filesystem in another namespace not
   allowed"); the per-userns kernfs rework that permits it landed later
   (works on this dev host's 7.0 kernel, which is why the boundary always
   passed locally). The supervisor's boundary therefore re-roots
   /sys/fs/cgroup by **BINDING the operation's own cgroup directory**
   (the standard container mechanism — no superblock creation, works on
   every kernel; verified locally that the bind hides the hierarchy above
   and keeps the op subtree writable). The workflow's full-boundary probe
   moved into the delegated-cgroup step (it needs a real bindable cgroup
   dir) and the containment gate's pre-probe binds a run-owned probe
   child under the delegated root.
2. `browser`: the player mounted (selectors fixed) but the timeline click
   never moved `data-now`. Root cause: the 3.17 driver SILENTLY DROPS a
   seek issued while still loading, and the page swallowed load errors.
   The page now surfaces player errors (`data-player-error`) and the
   loaded duration (`data-duration`); the test waits for load, fails
   loudly on player errors, and REISSUES the seek click until the
   player's own reported position moves.
Verified locally after the fixes: fast default **114 passed**, `db` gate
PASS (113), `containment` gate PASS (bind-based probe + 21), web build
OK.

**Fifth CI run (run 37845728116 at `271e6f6`) — replay never loaded
(2026-10-08):** only `browser-e2e` red: "asciinema-player never loaded
the recording (duration stayed empty)", no player error. Instrumented
the page (unhandled-rejection trap, lifecycle-event trace
`data-player-events`, both surfaced as attributes + in the test's
failure message) and root-caused the rest against the REAL library
driver in Node: asciinema-player 3.17 made loading LAZY — `INIT_REQUESTED`
in COLD does nothing unless `preload` (or an npt poster) is set, so a
paused player never fetches the cast and `getDuration()` stays undefined.
The original single-click failure matches too: a seek issued before the
driver exists is queued behind the startup promise and silently
swallowed. Fix: `preload: true` in the page's create options (verified
in `CORE_OPTS`; Node repro: duration 3600 arrives post-init, seek lands,
metadata+seeked fire). With preload the duration wait also proves the
WASM vt came up (the driver only exists after terminalReady).

**Sixth CI run (run 37850316805 at `6841ace`) — browser-e2e GREEN;
two flakes (2026-10-08):** selection, python 3.11/3.12/3.13, frontend,
packet, containment and — for the first time — **`browser-e2e` all
passed**: the preload fix is confirmed in the runner's Chromium. Two
previously-green jobs turned red on a frontend-only diff:
1. `db`: m2 bastion "no input frames" — the two `conn.run` exec sessions
   each write their OWN output-only cast, and the test read `casts[0]`
   from `glob()`: filesystem order decided which cast was checked. Now
   every cast must have an opaque name + v2 header and the BOTH-
   directions assertion searches for the interactive cast (exec casts
   can never carry `i` frames, so this is equivalent, not weaker).
   Verified: `db` gate PASS locally (113).
2. `compose`: "member account creation through app-role API — 401"
   immediately after a successful login. No code path deletes or revokes
   WebToken rows between requests, FastAPI ≥0.106 commits dependency
   teardown before the response is sent, and the gate passes locally
   (both attempts, full stack). Unreproducible; the check discarded the
   response body, which would name the branch ("authentication required"
   vs "token expired or revoked" vs "bad token"). Bootstrap/users/login
   failures now include the body so a recurrence is classifiable.

**Milestone 01 implementation acceptance recorded (2026-10-08), superseded by
independent review below.** All locally
executable gates pass; packet and browser gates fail closed here for
missing prerequisites by design and were accepted through their required
CI jobs: run 37852029894 at `3539667` — selection, python 3.11/3.12/3.13,
frontend, compose, packet, db, containment and browser-e2e all green.

### Independent merged-work review (2026-10-08, `27e2624`)

**VERDICT: FIX.** Safe local results were rerun independently; hosted-only
results were read from GitHub job logs, not independently rerun on a privileged
machine. `3539667..27e2624` changes documentation only, so the hosted application
revision matches the reviewed application. No application code edited by review.

Findings (both P2; acceptance reopened rather than requirements weakened):

- **M01-R1 — browser build is shared, not run-owned.**
  `tests/test_stage5_browser_e2e.py:144–161` defaults to `web/.next-e2e`, reuses
  a build when its marker matches, and never removes the build. Two simultaneous
  runs use the same directory while baking different API URLs; one can overwrite
  the other run's build. `SR_E2E_DIST_DIR=.next` also permits overwriting a developer
  build. An inline mocked fixture probe invoked `web_app.__wrapped__` twice and
  observed `SR_NEXT_DIST_DIR=['.next-e2e', '.next-e2e']` (exit 0; no filesystem or
  real subprocess changes). Use a fresh run-owned build directory, reject unsafe
  path overrides, clean it on failure/success, and test preservation/concurrent
  isolation. This is approved step 8 / criterion 9, not new product scope.
- **M01-R2 — historical migration edited for a test-only calling convention.**
  `srplatform/db/migrations/versions/0010_fifth_followup_enrollment.py:79–91`
  adds Engine handling. `git diff da13e72..27e2624 --` that path confirms the edit;
  `upgrade()` still passes a Connection and the SQL is unchanged. Approved step 4
  and the architecture explicitly prohibit editing applied migrations. Restore
  the historical migration and pass a transaction-bound Connection from the
  helper test at `tests/test_fifth_followup_acceptance.py:978,999`. If production
  migration behavior needs changing, use a new forward revision instead.

Review environment: Linux, existing Python 3.13.5 `.venv`, Node 22.23.3;
Docker fixtures synthetic/run-owned, existing delegated cgroup only, no sudo,
host firewall, Proxmox or unrelated-VM changes. Commands from checkout root:

| Exact command | Independent result |
|---|---|
| `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -ra -p no:cacheprovider` | Exit 0; 114 passed, 0 failed/skipped, 139 deselected, 4 warnings; 16.63s |
| `.venv/bin/python infra/dev/acceptance.py selection` | Exit 0; 253 classified, 114 fast/139 integration; negative prerequisite/skip/empty controls passed; 35.4s |
| `env SR_ACCEPTANCE_PYTHONS=3.11,3.12,3.13 .venv/bin/python infra/dev/acceptance.py python` | Exit 0; fresh locked installs, dependency checks and four imports each on 3.11.17/3.12.15/3.13.5; 13.1s |
| `.venv/bin/python infra/dev/acceptance.py db` | Exit 0; 113 passed, 0 skipped, 140 deselected; failure/collision probes and owned cleanup passed; 102.4s |
| `.venv/bin/python infra/dev/acceptance.py containment` | Exit 0; full boundary/migration/wrapper probes, 21 passed, 0 skipped, 232 deselected; cleanup passed; 11.2s |
| `.venv/bin/python infra/dev/acceptance.py frontend` | Exit 0; npm ci/build and production audit passed, zero findings; 11.0s |
| `.venv/bin/python infra/dev/acceptance.py compose` | Exit 0; fresh build, two bootstrap attempts, exact 0010 head, DB-backed readiness, app-role account/bastion checks, owned cleanup; 41.1s |
| `.venv/bin/python infra/dev/acceptance.py packet` | Exit 1; required prerequisites root/nft missing, no packet test executed locally |
| `.venv/bin/python infra/dev/acceptance.py browser` | Exit 1; initial attempt overlapped npm ci and saw CLI missing; rerun after install: Chromium launch prerequisite unavailable, 1 setup error, no browser test passed locally; owned DB cleaned |
| `gh run view 37852029894 --json conclusion,headSha,jobs,url,headBranch` | Exit 0; success, happy-chipmunk at 3539667, all ten jobs succeeded |
| `gh run view 37852029894 --log \| grep -E 'counts \|passed\|skipped\|acceptance:\|: PASS\|\[PASS\]\|\[FAIL\]'` | Exit 0; logs confirm packet 4 passed/249 deselected, browser 1 passed/0 skipped, Python matrix fast suite 114 passed each, and all acceptance commands executed |

Hosted evidence: [run 37852029894](https://github.com/DrSchnitzel57/sparring-range/actions/runs/37852029894).
Green command results remain valid, but do not prove run-owned build isolation or
waive migration immutability. Close M01-R1/R2 and rerun affected gates before
marking milestone 01 accepted. Billing protection remains an operator manual check.

**CI follow-up after user reported another failure (2026-10-08):**
`gh run list --workflow ci --limit 12 --json databaseId,headSha,headBranch,conclusion,status,createdAt,url,displayTitle`
and `gh run view 37852794770 --log-failed` (both exit 0) confirm
[happy-chipmunk run 37852794770](https://github.com/DrSchnitzel57/sparring-range/actions/runs/37852794770)
failed browser E2E at `27e2624`: `tests/test_stage5_browser_e2e.py:296`,
`assert 'command' in recent`, **1 failed**, 2 warnings, 50.05s.
`gh run view 37852833914 --json conclusion,jobs,url,headSha` (exit 0) confirms
[master run 37852833914](https://github.com/DrSchnitzel57/sparring-range/actions/runs/37852833914)
passed all ten jobs at the SAME commit. These are mixed results, not proof the
intermittent failure is repaired. They supersede any impression of consistently
green acceptance; the user's abbreviated email reference was not identified.

- **M01-R3 / P2 — command assertion does not wait for the command.**
  `tests/test_stage5_browser_e2e.py:293–296` waits for `web01`, already present
  in connection instructions, then immediately asserts `command` before the
  two-second dashboard poll is guaranteed to complete. This is consistent with
  the observed pass/fail at the same revision. Wait with a bounded deadline for
  the newly ingested command event itself, retaining the UI-rendering assertion;
  investigate further if it never appears. Rerun affected browser acceptance and
  check repeat-run stability; do not merely rerun until green or suppress failure.
  This repair falls within the existing browser-fixture step/criterion, not a
  new milestone or permission to change application behavior without evidence.

### M01-R1/R2/R3 repair round (2026-10-08)

- **R2 repaired:** migration `0010_fifth_followup_enrollment.py` restored
  byte-identical to `da13e72` (`git diff da13e72 -- <path>` empty); the helper
  test now passes the transaction-bound Connection (`s.connection()`) at both
  call sites instead of the Engine. `db` gate PASS (113 passed, 0 skipped,
  owned cleanup). No applied migration is edited.
- **R1 repaired:** the `web_app` fixture builds into a FRESH unique directory
  per call under `web/.e2e-builds/` (marker reuse removed), rejects unsafe
  `SR_E2E_DIST_DIR` targets (absolute, `..`, `.next`, `.next-e2e`,
  `node_modules`, project dirs), and removes the run dir on success AND on
  build/serve failure. 14 new fast isolation regressions
  (`tests/test_browser_fixture_isolation.py`): per-call uniqueness, override
  rejection, fresh relative build + teardown cleanup, concurrent-run
  isolation, failure cleanup — mocked npm/next/httpx against a temp WEB, so
  they run in the fast default (now **128 passed**, selection gate PASS).
- **R3 repaired:** the dashboard assertion waits with a bounded deadline for
  the ingested event itself (`_body_has(pw, "command", timeout=20)`);
  verified `command` appears on the session page ONLY as an event
  `action_type` cell (no static text can satisfy the wait early).

Re-accepted 2026-10-08: CI run 37855269245 at `62939f7` passed all ten jobs on
the initial attempt and again on the repeat-run stability check (attempt 2,
browser-e2e included); db/selection/fast gates rerun locally at the repair
revision (113 / PASS / 128 passed).

- **M01-R4 / P2 — intermittent db-layer auth-handoff failure (RESOLVED
  2026-10-09 — root cause and repair under "Milestone 02 implementation
  evidence").**
  Docs-only commit `9a12374` turned CI `db` red:
  `test_stage5_acceptance.py::test_hint_jumps_queued_red_turns_across_processes`
  line 144 `KeyError: 'session_id'` — the POST /sessions response carried no
  session_id, i.e. an error body the test discarded. Same signature as the
  earlier compose "member creation — 401" one-off: the request immediately
  after a successful login intermittently fails, and neither failure
  captured the response. Repairs at this revision: the stage-5 handoff calls
  now go through `_api_json` (status+body in the failure message), and every
  uvicorn readiness loop that silently proceeded on `server.started == False`
  now asserts (a failed port bind names itself instead of poisoning
  downstream requests). Local fast (128) and db gate (113) PASS. Unclassified
  until the next occurrence names the branch (401 vs 5xx vs wrong-server);
  milestone 01 acceptance rests on the twice-green `62939f7` runs, and this
  finding stays open until classified.

### Milestone-02 planning baseline and prerequisite (2026-10-09)

Clean `master` at **`9393a36`**, equal to locally recorded `origin/master` before
documentation edits. Executed:

- `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -ra -p no:cacheprovider`
  — exit 0, **128 passed, 0 failed/skipped, 139 deselected, 4 warnings**, 15.09s.
  This is infrastructure-free, not DB or live authority acceptance.
- `gh run list --limit 4 --json databaseId,headSha,status,conclusion,url`
  — exit 0; run **37858626650** succeeded at `9393a36`, but the later
  **37860676959** failed at the same revision.
- `gh run view 37860676959 --json jobs --jq '.jobs[] | {name,conclusion}'`
  — exit 0; DB failed, all other nine jobs succeeded.
- `gh run view 37860676959 --log-failed` — exit 0; hosted DB suite:
  **2 failed, 111 passed, 154 deselected, 3 warnings**, 104.83s; owned fixture
  container/volume cleanup passed. Failure gate exited 1.

Failures inspected, not yet diagnosed:
`tests/test_followup_regressions.py:1373` assumes login JSON contains `token`
without checking status/body (`KeyError: 'token'`);
`tests/test_stage5_acceptance.py:162` receives HTTP 404 launching a session just
created successfully. Shared state/server/DB lifetime is an investigation target,
not an established cause. Neither a green rerun nor added diagnostics fixes this.
M01-R4 remains open; the approved milestone-02 plan requires repair/regression and
repeat affected acceptance before authority implementation. No software/live
deployment acceptance is claimed by saving that plan.

## Milestone 02 implementation evidence (2026-10-09)

Executed at code revision **`71507bb`** (branch `quick-dingo`; only these
documentation files were dirty during the gate sweep — no code changed after
`71507bb`): Python **3.13.5** (uv-created pip-less `.venv` from
`requirements.lock`), Node **22.23.3**, npm **10.9.9**, Docker daemon 29.8.2 /
Compose 5.6.0, cgroup v2 with a writable delegated subtree. No Proxmox, live
range, host firewall, NAS or unrelated-VM access; every fixture is run-owned.

**M01-R4 prerequisite resolved (`a87e83b`).** Root cause classified: FastAPI
≥ 0.142 finalizes default-scope (`"request"`) generator dependencies **after**
the response is sent, so each request's `DbSession` commit could land after
the client's next request had already begun — exactly the intermittent
r02/stage5/M01-R4/compose signatures (login succeeded, the immediately
following request saw uncommitted state). Repair: one shared `DbSession`
dependency pinned to `scope="function"`, so commit/close complete before the
response; plus `_api_json`/`api_json` helpers that surface status+body on
unexpected responses, and commit-visibility regressions. No test was weakened,
no retry-until-green, no applied migration edited.

| Gate (exact command) | Result |
|---|---|
| `.venv/bin/python -m pytest -q -ra -p no:cacheprovider` | Exit 0: **131 passed, 0 failed, 0 skipped, 164 deselected** — infrastructure-free default |
| `.venv/bin/python infra/dev/acceptance.py selection` | **PASS**: 295 tests = 131 fast + 164 integration (db 117, containment 25, packet 4, **authority 22**, browser 1, live 0 until milestone 11); required modes verified to fail for absent prerequisite, skipped required test and empty selection |
| `.venv/bin/python infra/dev/acceptance.py python` | **PASS**: fresh run-owned venv, locked install without re-resolve, `uv pip check` clean, 4 entrypoint imports on Python 3.13.5 (CI matrix covers 3.11–3.13) |
| `.venv/bin/python infra/dev/acceptance.py db` | **PASS**: disposable `postgres:16` (unique container/volume, loopback port, synthetic creds) — **116 passed, 0 skipped, 179 deselected** in required mode; includes the 0011 upgrade-latch pair (non-torn-down deployments latch `safety_state`; downgrade never unlatches) and writer/terminal-row races; failure-path probe passes; no `srtest_*`/`sr_*` leftovers; container+volume removed |
| `.venv/bin/python infra/dev/acceptance.py containment` | **PASS**: 21 namespace/recursive-membership/signal-identity/cancellation regressions in required mode, 0 skipped; no run-owned cgroups leaked (4 db∩containment compound tests run inside the db gate) |
| `.venv/bin/python infra/dev/acceptance.py authority` | **PASS** (new required gate): **22 passed, 0 skipped** — real operator policy validation, durable SQLite intent-before-effect, restart-with-active-claims latch+stop, lease expiry, cross-session/generation fencing, hard-stop read-back and SPARE-on-foreign-VMID, obligations retention across broker/PVE faults, and mutual-TLS/auth negatives against a live broker over loopback (TLS 1.3 refusal, no client cert, wrong CA all refused) |
| `.venv/bin/python infra/dev/acceptance.py packet` | **FAIL here (prerequisite)**: missing root + `nft` — CI packet job (standard Linux VM, rules only in disposable netns) is the gate |
| `.venv/bin/python infra/dev/acceptance.py frontend` | **PASS**: `npm ci`, production `next build`, `npm audit --omit=dev` → **0 vulnerabilities** |
| `.venv/bin/python infra/dev/acceptance.py compose` | **PASS**: real image build + fresh bootstrap + idempotent rerun (run-owned project, loopback ports, synthetic creds) — alembic at head **0011**, API holds app-role credentials only, `/readyz` at schema head, account ops idempotent, bastion behind the seed-keys gate; fixture mode is explicit env (`ALLOW_LOCAL_DEV_FIXTURE` + `SR_BROKER_FIXTURE`), no production bypass; only run-owned resources removed |
| `.venv/bin/python infra/dev/acceptance.py browser` | **FAIL here (prerequisite)**: no launchable Chromium on this host (per operator instruction nothing was installed) — CI browser job (`playwright install --with-deps`) is the gate |

Boundary actually exercised: the authority gate runs the real broker service
(policy, ledger, mTLS server, cessation supervisor) in-process over loopback
against synthetic PVE fixtures — private deterministic boundary, fail-closed
cessation and durability semantics, not live Proxmox. Live ACL/isolation/stop
proofs remain explicit operator gates (Manual checks in the plan).

**Required CI at the implementation revision:** pending — the operator pushes;
the run URL and per-job conclusions will be recorded here when they appear.
Until then criterion 9 is open, not waived.

## Release blockers and missing work

| ID / priority | Current finding and evidence boundary | Milestone |
|---|---|---|
| B01 / P1 | **Repaired at `ac5a61b`, CI-accepted (see milestone-01 evidence):** baseline failures fixed on real host identities; DB marker leakage structurally prevented (fixture-closure derivation) | 01 |
| B02 / P1 | **Repaired at `ac5a61b`:** Next 16.4.0 + patched transitive deps; `npm audit --omit=dev` reports 0 vulnerabilities; build/replay/browser validated | 01 |
| B03 / P0 | Inspected API still constructs direct PVE adapter; current safety controller invokes privileged nft machinery. Incompatible with agreed private limited-token/no-runtime-host-root boundary | 02 |
| B04 / P0 | Current namespace/cgroup regression gate passes locally and in CI; full production authority, missing/unreadable control, bookkeeping, start/cancel fencing and every signal identity still require milestone-02 boundary/race acceptance | 02 |
| B05 / P0 | Run-row locking, guarded writers and any-run obligations exist. DB races and every writer/caller (spawn, callback, stop, watchdog, startup, emergency) remain unverified here; never rely on helper docstrings saying every writer is covered | 02 |
| B06 / P0 | Exact effective PVE permissions, static bridged/routed isolation, resource budgets and independent owned-VM emergency stop are not accepted. No attacks before real gates; no permission widening to pass | 02, 11 |
| B07 / P1 | Current image artifacts do not establish usable web/database templates. Service-present checks are not actual transactions; YAML has placeholder integrity/user baselines and seed contracts need completion | 03 |
| B08 / P1 | Enrollment now carries exact capability/generation evidence and migration 0010 invalidation logic. Fresh/legacy upgrades, stale-token rejection, recovery and concurrent confirms require disposable DB acceptance | 04 |
| B09 / P1 | **Missing software:** `tests/test_fifth_followup_installed_capture.py` and required installed-systemd/auditd acceptance. Subprocess synthetic stdin cannot prove `srshipper` reads real audit input or captures a real command | 04 |
| B10 / P1 | **CI passed at `3539667`:** dedicated required layers via `infra/dev/acceptance.py` fail closed for missing prerequisites/empty selections/skips. Review M01-R1 reopens browser-build isolation; installed-capture fixture still missing (milestone 04) | 01, 04 |
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
