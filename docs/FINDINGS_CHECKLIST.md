# Current findings and validation evidence

## Milestone 21 review round 2 — reproduced FIX and superseding proofs — 2026-10-27 (`0a169e9`)

The second release-focused review at `2ba575e` returned **VERDICT: FIX**
with seven blockers; the reviewer's upgrade-gate FAIL (19.4 s, `backup
digest mismatch upgrade/.../journal.json`) was independently REPRODUCED
here before fixing (`.cache/gate_r10_upgrade_repro.log` shows the earlier
engine still passing only because the journal-exclusion parameter existed
unwired — flaky passes, not proof; they are retracted). Every fix is
proven at the REAL CLI level by the re-forged `upgrade` gate; claim
discipline: the gate was run three consecutive times (93.8 s, 94.6 s,
93.5 s — `.cache/gate_r11_upgrade.log`, `.cache/gate_r12_upgrade_{1,2}.log`),
all PASS, all fixtures self-removed (`NO_SR_CONTAINERS`, no gate tmp).

Finding → fix → proof (all at `0a169e9`; fix commits `431f2c1`/`0a169e9`,
gate `a2ee8c9`):

1. **Production CLI did not provision the runtime** → provisioning is a
   real journaled stage between activation and migration running the
   SAME service helpers as install (locked `requirements.lock` venv
   install, selected Node, per-UID runtime verification on the real
   appliance, locked frontend build) with the installed venv required to
   import every unit entrypoint; migrations default to the installed
   venv python, never the invoking interpreter. Proof: positive (receipt
   + independent import probe of `srplatform.api.app`/`infra.appliance.brokerd`
   with the created venv), negative (impossible lockfile → provision
   failed, fence up, no stamp, resumable), both through the real CLI.
2. **Quiescence false / no admission fence** → durable work now read
   from every authority (runs, model jobs incl. `cessation_unknown`,
   dispatched-command inventory, ledger — a MISSING ledger refuses unless
   `--allow-fresh-install` is truth); an admission fence file is held
   from preflight through verified restart and the API answers 503 to
   NEW work while login/internal-callbacks/health flow; quiescence is
   RE-proved under the fence. Proof: dry-run refusal for queued AND
   cessation_unknown jobs with zero side effects; missing-ledger
   refusal; fence survives SIGKILL, released only on completion;
   TestClient 503/admit matrix against the real app.
3. **Config backup contained its own mutable journal; restore was not
   atomic** → the backup excludes the journal tree entirely; restore is
   TWO-PASS (complete inventory + digests + metadata + path safety
   validated BEFORE any write). Proof: no `upgrade*` entries in any
   backup manifest; corrupting a LATE backup file changes ZERO files;
   the attempt journal is never restored over.
4. **Restore destroyed original permissions/ownership** → backups record
   ORIGINAL mode/uid/gid separately from the private copy; restore
   applies them (root restores fully; a non-root restore may only touch
   its own files — never privilege guessing). Proof: 0640 service file
   and 0644 file corrupted+chmodded, restored byte-exact with original
   modes.
5. **Restart failure looked like success; resume could be no-op'd away**
   → version stamp only after a CHECKED restart (restart + `is-active`
   per unit); an unfinished attempt outranks every no-op answer; failed
   restart/provision keep the fence up and the attempt in progress.
   Proof: against a `systemctl` service double — failing restart → exit
   ≠0, journal restart failed, NO stamp, fence up → resume completes →
   stamp then; unfinished+resume never answers no-op.
6. **DB owner secret in argv** → `--db-url` REMOVED (the CLI refuses
   it); the URL arrives by named environment variable and pg_dump
   receives endpoint flags + private 0600 `PGPASSFILE` only. Proof: the
   gate's pg_dump wrapper exits 47 if the synthetic fixture secret ever
   appears in its argv and 46 without the PGPASSFILE channel — the
   passing gate IS the inspection.
7. **Preflight skipped payload verification** → `verify()` (bytes +
   contract + path/duplicate safety) runs before ANY qualification,
   dry-run/no-op included; contract must match manifest revision/version/
   inventory. Proof: tampered bytes REFUSED where a no-op would have
   answered; contract revision lie refused; duplicate manifest keys
   refused; pre-21 refused — all before side effects.

Supporting fixes (build-fix class, reported per instruction):
`run_operations.state` (not `status`) in the durable check; the sandbox's
venv creation gained `_create_venv` (`python3 -m venv` = appliance
contract, `uv venv --seed` for uv-served dev hosts — production call
unchanged) and the broker libvirt-binding exposure became an explicit
broker-role step (a sandbox has no broker/libvirt; the appliance keeps
it required). Gate plumbing: wrapper arg parsing, tar-stream bad-lock
payload (hardlinks cannot cross tmpfs), import path.

Milestone 21 status: local software lanes now cover the corrected
engine; `images`/`capture` role artifacts were built at `2ba575e`
(role INPUTS unchanged since — see artifact receipt below) and the
release bundle must be (and will be) rebuilt from the corrected HEAD so
its `upgrade` contract matches the fixed engine. `packet`/`journey`/
installed-systemd/Strata/nested-KVM remain operator-machine pending —
never passed here.

### Role-artifact receipt (supervised-practice candidate) — built 2026-10-27

Self-contained flattened qcow2 artifacts (`qemu-img info` shows NO
backing file), built through the production builders with the repaired
pins; the resolved package versions below were RECORDED FROM THE BUILD
GUEST's own serial output, proving the artifacts match the repaired pin
file (`pins_sha256 2c284ee217f3…`, git input `2ba575e62…` — role INPUTS
unchanged through the review fixes; input hashes `b468a1840bf5c669` /
`b3eb3947c5bb8fb2` / `f5330fa551f3604c` are what the `images` gate
cache-keys on, so its rebuild reuses them honestly as BUILD-CACHED):

| Artifact (`.cache/images/`) | sha256 (prefix) | disk |
|---|---|---|
| `mojang-web-local.qcow2` | `97d694851c20…` | 2728 MiB |
| `mojang-web-db.qcow2` | `7c6072615646…` | 2724 MiB |
| `attacker.qcow2` | `015aeafe5a5f…` | 2249 MiB |

Guest-resolved versions: nginx `1.24.0-2ubuntu7.19`, openssh
`1:9.6p1-3ubuntu13.20`, curl `8.5.0-2ubuntu10.16`, qemu-guest-agent
`1:8.2.2+ds-0ubuntu1.18`, auditd `1:3.1.2-2.1ubuntu0.1`, mysql
`8.0.46-0ubuntu0.24.04.4`. Full machine-readable receipt:
`.cache/images/role-artifacts.json`. **Identity limit, stated plainly:**
the attacker artifact carries the gate's SYNTHETIC keys (TEST_KEYS), so
this set is the supervised-practice candidate; the production contract
remains the operator's key-bearing template rebuild per the runbook.

`sha256(base)` = `6b1fbcb8b1a7cec2d4aa…` (2357 MiB) — the appliance
guest base carried into the bundle (its MANIFEST image digests match the
four artifacts above and verify green).

### Final local-software lane receipts — 2026-10-27/28 at `44ccdc8` (serialized, logs `.cache/gate_r13_*.log`, `.cache/gate_r14_bundle.log`)

* `fast` **PASS** — 661 passed, 0 failed, 0 skipped, 480 deselected (86.8 s).
* `selection` **PASS** (174.1 s); `db` **PASS** (667.8 s — 322/0/0, 819
  deselected, owned fixture removed); `agent` **PASS** (150.3 s —
  123/0/0); `install` **PASS** (7.3 s — real sandbox sequences; the
  managed-service half stays the operator's).
* `upgrade` **PASS ×3** (93.5–94.6 s) — see the round-2 table above.
* `images` **PASS** (323.8 s) — 19 passed, 0 skipped: real builds
  (cache-BUILD-CACHED on the input hashes above, verify batteries boot
  the chains under labelled TCG, seeds/flaws/fixes/readiness), owned DB
  and QEMU run dirs cleaned.
* `capture` **PASS** (228.4 s).
* `bundle` **PASS ×2** — build+verify (266.7 s) and then the gate
  **verifying the persistent release in place** (219.1 s): 373 files,
  4 images, revision `44ccdc89588d`; bound to the checkout under test
  (242 runtime files compared); operator manifest renders and
  validates; the SHIPPED role image boots from the bundle (TCG, serial
  marker); tampered bundle refused for digest drift.
* **Persistent release artifact:** `.cache/bundle/sparring-range-appliance`
  (4.5 GiB, BUNDLE_VERSION 2, revision `44ccdc89588d8ea8a4bf9ccef7182dea928de293`),
  images `appliance-base 6b1fbcb8b1a7…`, `mojang-web-local 97d694851c20…`,
  `mojang-web-db 7c6072615646…`, `attacker 015aeafe5a5f…`. Verify with
  `python3 deploy/bundle.py verify .cache/bundle/sparring-range-appliance`.
* **Capacity lesson recorded (caused one externally-killed run, not a
  test failure):** bundle building on `/tmp` here means tmpfs = 16 GiB
  RAM; the gate now runs with `TMPDIR=$PWD/.cache/tmp` (disk-backed).
  The OOM-risky killed run's owned tmp (9.9 G) was removed; the builder
  and gate self-clean everything else (verified: no `sr-bundle-gate-*`,
  no `sr-*` containers, `.cache/tmp` empty).
* Operator-machine gates (`packet`, `journey`, `release`,
  installed-systemd/Strata/nested-KVM, the managed-service install half)
  remain explicitly PENDING — never passed, never simulated here.

**Final-HEAD confirmation (`52ce377`, docs-only delta over the built
bundle's `44ccdc89588d`):** `upgrade` gate PASS again (116.1 s,
`.cache/gate_r14_upgrade.log` — fourth consecutive deterministic pass of
the corrected engine), fast suite 661/0/0 (88.3 s), zero owned
containers or gate tmp directories remaining. The bundle's MANIFEST
revision remains `44ccdc89588d` (recorded honestly; runtime files are
byte-identical — the gate's candidate-binding check passed against the
same tree).

## Milestone 21 implementation round 1 — 2026-10-27 (branch `practice-upgrades-18-21`)

Scope executed: preserving in-place upgrade (engine + real CLI + required
gate), bundle upgrade contract, and the four pulled release blockers.
Milestone 20 remains UNACCEPTED; nothing below re-runs or claims its gates.

| Commit | Delivered |
|---|---|
| `3000361` | drifted guest package pins repaired (verified by live mirror dry-runs) + labeled-TCG build ceilings |
| `463e408` | second plan-20 review + user reprioritization + full F5–F9 repository backlog |
| `b3df934` | F1 forward 0027 + runtime fence; F2 always-on quota, reserved marker budget, no-500 duplicate marker; F3 supported prerequisite in the engine + legacy-safe forward guard; F4 absolute delivery budget + process-wide delivery bound |
| `b504a76` | real proofs (8/8 on disposable PostgreSQL): naive 0025→head still fails on 0026 (defect shown); engine reaches 0027 with the prerequisite recorded; legacy duplicate markers survive unmodified; sealed row fail-closed `legacy`; fence 503-at-0026; HTTP audience separation; second marker never 500; null-gap row cap; dribbling endpoint bounded; consumer retires with counted drops |
| `fc025e7` | `appliance.py upgrade` drives the real engine (backup→stage→activate→migrate→finalize, journal, resume, restore); bundles carry the MANIFEST `upgrade` contract (BUNDLE_VERSION 2; pre-21 refused) |
| `3a4d927` | required-mode `acceptance.py upgrade` + backup-snapshot integrity hardening |

Gate receipts (exact commands, this environment, revision `3a4d927`):

- `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD ... pytest -q -p no:cacheprovider`
  — **661 passed, 0 failed, 0 skipped**, 480 deselected, 87.7s.
- `... infra/dev/acceptance.py upgrade` — **PASS ×2** (20.6s, 20.7s): real
  preserving upgrade through the real CLI (journal complete, heads 0027
  exactly once, users/keys/state byte-preserved, restore-listable
  pg_dump, fail-closed legacy relabel via the installer); truthful no-op
  rerun; deterministic SIGKILL interruption → new work REFUSED → `--resume`
  completes, drift repaired; config-only restore with ZERO service
  actions; tampered payload refused; pre-21 bundle refused. Fixture:
  run-owned `sr-upg-pg-<run>` postgres:16, removed in `finally`.
- Sweep at HEAD (serialized, receipts `.cache/gate_r8_*.log`):
  `selection` **PASS** (173.0s — 1141 tests all classified = 661 fast +
  480 integration, including the 8 new plan-21 proofs; empty-selection
  negative passes); `db` **PASS** (671.3s — **322 passed, 0 failed, 0
  skipped**, 819 deselected, disposable PostgreSQL 16, owned-resource
  cleanup proven); `agent` **PASS** (154.9s — 123/0/0); `containment`
  **PASS** (25.0s — 41/0, no leaked cgroups). All sweep fixtures removed;
  zero `sr-*` containers remain.
- Aggregate now ATTEMPTS `agent` and `upgrade` (criterion 3 list change).

Honest PENDING (not simulated, not waived): `images`/`capture`/`bundle`
need the role artifacts — the pin repair removed the mirror blocker, but
cold TCG role builds exceed this round's budget; the `bundle` lane was
ATTEMPTED and failed closed truthfully (8.6s, receipt
`.cache/gate_r8_bundle.log`): the only role images on disk
(`/tmp/sr-guest-cache`, 3.4 GB, left by the checkpoint aggregate's images
lane) are qcow2 chains whose transient backing bases
(`/tmp/sr-qemu-c4fcda2e`) no longer exist, and the gate correctly refuses
non-self-contained artifacts. The `images` gate rebuild produces the
flattened artifacts the bundle requires; those stale chains belong to the
shared guest cache (possibly reused by other checkouts) and were left in
place rather than guessed-into cleanup. `packet` needs root + `nft`;
`journey`/`release` need the installed appliance. Per plan 21,
missing mandatory evidence prevents PASS: **21 stays unticked**; the
operator's supervised-practice deployment is the next owner.

## Plan-20 SECOND independent review + user reprioritization — 2026-10-27

The parent review completed at `adc10d4` (**VERDICT: FIX**, nine findings
with reproductions) and the user explicitly reprioritized: **milestone 21
proceeds now** (same branch) so a deployable release can be operated and
tested; milestone 20 stays **unchecked and unaccepted**; the fixes below
are split into (a) MINIMUM release blockers folded into 21 and (b) the
repository backlog. The reviewer separately observed the five-file pin
commit `3000361` and did not review or accept it. The prior round's gate
receipts remain valid **checkpoint-scoped receipts, not acceptance**.
Independently PASSED positives of that round (recorded truthfully): new
audience threads separate, child deadline unblocked, correct cast positive
offsets, attacker actor-query excludes non-red, legacy orphan HTTP 200,
durable lifecycle flags, compressed-away citation refused, real ack-loss
persists exact bytes, short-write timing measured, 450-noise raw-cursor
pagination with lazy output, foreign/sealed authorization surfaces pass;
applied 0020–0025 byte-unchanged vs `28b1f8b`.

### (a) Release blockers — pulled into milestone 21 (fix here, prove here)

| # | Sev | Defect (reproduced) | Status / impact |
|---|---|---|---|
| F1 | HIGH | 0026 `audience` backfill (0026:32–36 `server_default="member"`) silently labels ALL pre-0026 coach history member-visible although operator history may carry sealed context; legacy pending jobs without `chat_meta` audience also default member (`coach_routes.py:619,664`). Repro: populated PRE-0026 schema → forward upgrade discloses `PRE0026_SEALED_OPERATOR_BACKDOOR` in member GET and the next provider wire | **IN FIX (21)**: forward migration re-labels every migrated row to fail-closed `legacy` audience (raw rows preserved, visible only at privileged/unknown scope, never in member threads or provider prompts); runtime fence refuses coach history while schema head == 0026 (API can never serve mid-upgrade); metadata-less jobs resolve `legacy`, never member; real populated-upgrade + provider-wire tests |
| F2 | HIGH | Capture quota admission (`app.py:1880–1905,1979–2012`): all checks sit inside `if body.text:` → 5-row cap but 20 null-text gap rows persist (cap 201); server truncation marker is 63 bytes against a 10-byte reserved budget (op AND session); second explicit marker raises 500 | **IN FIX (21, minimal release-safety guard)**: bounds always enforced atomically for ALL payload kinds (output/gap/marker) including null text; marker fits a reserved budget inside the total (or honest compact/zero form); duplicate marker answers the idempotent protocol, never 500. Not the full 20 replay polish |
| F3 | HIGH | Valid 0025 history BREAKS migration 0026 (0026:51–55 `uq_operation_outputs_truncated_once`): 0025 permitted two truncation markers per operation (pre-fix race), so `CREATE UNIQUE INDEX` raises UniqueViolation — a populated 0025 database cannot upgrade at all. This is 21's core preserving-upgrade scope, not backlog-able | **IN FIX (21)**: applied 0026 stays byte-identical, no row is ever deleted or modified. Upgrade design = explicit SUPPORTED prerequisite + forward catch-up (see ARCHITECTURE "Plan-21 upgrade-compatibility decisions"): engine detects the duplicate-marker condition before migrating; the documented path skips only 0026's data-dependent INDEX statement (columns are re-applied idempotently by forward 0027 with `IF NOT EXISTS`, legacy rows untouched) and forward 0027 installs the future-proof uniqueness guard that legacy rows still satisfy; real 0025-populated → head proven through the actual installer, plus schema comparison against the clean path. No manual SQL, no evidence deletion |
| F4 | MEDIUM | Capture consumer resource leak (`capture.py:193–201,295–355`, `transport.py:108–113`): six completed operations leave six consumer threads alive 11.58 s against an endpoint dribbling bytes; inactivity timeout does not bound absolute request age; `finish()` join cannot cancel; idle exit unreachable inside `_deliver` | **IN FIX (21, bounded functional guard)**: process-wide consumer concurrency bound; absolute per-delivery budget; `finish()` drains with bounded deadline and counts honest dropped gaps; command deadline/drain paths stay independent. Full 20 replay polish not attempted |

### (b) Repository backlog (milestone 20 remains unaccepted; these stay open, none silently dropped)

| # | Sev | Defect (reproduced) | Priority / deployment impact |
|---|---|---|---|
| B1=F5 | MEDIUM | Citation payload forgery: a command payload containing `echo reference #99999999` adds the non-existent id to the APPROVED set (`coach/chat.py:110–113`, `coach/aar.py:131–136`); browser shows 2 active links. Approval must match canonical AUTHORIZED EVENT RECORD ids, not regex over payload text | Before any "citations verified" claim; no data leak, UI trust issue. Backlog unless naturally fixed while touching that code |
| B2=F6 | MEDIUM | Replay seek-back before cast start leaves the player at the last in-cast frame (30) instead of following the session clock; changing the actor filter shifts cast offset (100→50). Canonical session clock, filter-independent | UX correctness; operator testing can proceed with the labeled limitation |
| B3=F7 | MEDIUM | Generic model-job audience (`coach_routes.py:332–433`): a member enumerates operator coach jobs and fetches job detail/SSE (HTTP 200). Reproduced STATE/TIMING only — answer text was not observed to leak; fresh coach pending path is isolated | Fix minimally as part of F1's audience filter where natural; precise impact recorded; do not overclaim a secret-answer leak, do not claim solved until re-verified |
| B4=F8 | MEDIUM | Idempotence gaps (`app.py:1965–1977,2023–2031`): same seq+same text but different `read_ts`/`dropped_bytes` persists a duplicate; changed text classifies CONFLICT but answers HTTP 200 instead of 409 | Evidence-integrity polish; claim only "duplicate suppression by seq+content" until fixed |
| B5=F9 | MEDIUM | Worker-claimed `read_ts` trusted for new operations (`app.py:1872–1877,1949–1954,2014–2018`): accepts `read_ts=1`, replay renders without lifetime/provenance labels | Timing-claim honesty; server-side sanity window + explicit "worker-claimed" label; timing display is advisory until then |
| B6 | — | Everything else the second review judged "polish": not reopened in 21 by design; 20 acceptance stays with the parent | Roadmap 20 stays unchecked |

Claim discipline while these are open: do NOT claim verified citations
(F5), full idempotence (F8), deterministic-timing provenance (F9),
filter-independent replay (F6), or complete audience/job isolation (F7)
until re-verified. F1's fail-closed re-labeling plus runtime fence,
F2's always-on quota guard and F4's bounded consumer ARE 21's release
minimum, proven with real DB/subprocess tests in this milestone.

## Plan-20 independent review fix round — 2026-10-27, branch `practice-upgrades-18-21`

Independent review (VERDICT: FIX) at `28b1f8b` reproduced eleven
defects. All eleven received root fixes with counterexample regressions;
no applied migration was edited (0020–0025 byte-unchanged; 0026 is the
only addition). Fix commits on the branch:

| Finding (severity, reproduced) | Root fix | Counterexample proof |
|---|---|---|
| 1 (HIGH) operator sealed-coach answer leaked the member follow-up prompt / shared thread | Migration 0026 `coach_messages.audience` + thread partitioning: history, send and pending list are audience-filtered server-side (pending via payload `chat_meta`) | db: two-thread isolation matrix incl. `SEALED_ATTACK_PLAN_BACKDOOR` string asserted absent from the OTHER audience's list, GET and POST paths (updated `test_plan20_coach` + agent wire test) |
| 2 (HIGH) a hung capture endpoint stalled the pipe reader and the command deadline | `srplatform/red_agent/capture.py` rewritten: bounded queue + one lazily-started daemon consumer; reader only enqueues; `finish()` bounded join with `budget_exceeded` accounting | containment: subprocess test against a REAL socket that never answers — deadline path keeps ticking, chunks land as counted gaps (`test_plan20_capture`, 27 capture+api tests) |
| 3 (HIGH) quota race: concurrent writers each passed the byte/row check | session-row `SELECT … FOR UPDATE` admission; ALL payload bytes (output/gap/marker) charged vs per-op and per-session caps; row cap 1000 + reserved marker; `dropped_bytes` clamped | db: real concurrent HTTP POSTers against the endpoint — total stored bytes never exceed the budget; the one-time `truncated` marker is unique-index-backed (uq_operation_outputs_truncated_once) |
| 4 (MEDIUM) defender player assumed cast epoch == session start | `ReplayPanel` tracks `castRel = epoch − t0`: seeks/drift-corrects only inside the cast; exposes `data-player-at` from `getCurrentTime()` | browser: attacker evidence 100 s BEFORE a 40 s cast; seek 105 → player's own reported time ≈5 (and ≈30 at 130); conflating the epochs cannot pass (`test_browser_replay_cast_epoch_and_read_time`) |
| 5 (MEDIUM) any event mentioning an `op_uuid` entered the attacker track | operations track query filters `actor='red'` (server-set provenance) at the QUERY level; `registered` reported from `run_operations` | db: same-op_uuid system/verifier pairs and NESTED spoof payloads stay out; red positive control still pairs |
| 6 (MEDIUM) a lone historical `action_result` 500'd | results without intent render INCOMPLETE (`orphan_result`, no invented command/start); chunk requests answer | db: orphan/intent-only/duplicate evidence fixtures over real rows; HTTP 200 + honest shape |
| 7 (MEDIUM) dashboard hid warnings (prose LIKE-probe) | flags derive ONLY from durable facts: session status/outcome, `matches.state`, `runs.status='cancel-unknown'`, unresolved ops; the LIKE probe is deleted | db+api: the reviewer's interrupted-match repro shows `interrupted`+`cleanup_pending`; finalizing→retry and resolved transitions flip honestly; prose alone never flags |
| 8 (MEDIUM) citations validated against compressed-away ids; UI linked every `#id` | server validates against ids parsed from the RENDERED compressed timeline; AAR emits `approved_citation_ids`; `md.js` renders non-approved ids as `span.md-cite-unverified` — never an anchor; user-authored rows get an empty allow-list | browser: approved id links and deep-links; `#999999` stays visible, unverified, unlinked; report links all match `?tab=activity&event=<approved>` |
| 9 (MEDIUM) lost-ack retries renumbered chunks | producer-side monotonic `seq`; retries reuse seq+content; endpoint idempotence protocol `stored/duplicate/conflict/quota` | db: replayed ack-loss sequence yields exactly one row per chunk; same seq + different text = 409 conflict |
| 10 (MEDIUM) chunks placed at PERSIST time | reader stamps `read_ts` (`sink.feed(chunk, at=time.time())`); UI renders `read_ts ?? ts`; honesty fields `read_timed`/`timing_precision_s` | browser: chunk persisted +620 s read +660 s is ABSENT at clock 630 and PRESENT at 670 — persist-based placement fails this |
| 11 (MEDIUM) replay pages read ALL casts+operations; client cursor re-consumed collapsed runs | `/replay` returns counts only; new paged `/casts` (recording-id cursor) and `/operations` (raw event cursor); `next_after_event_id` is the RAW last consumed row; chunk rows carry `read_ts` | db: mid-noise-run raw-cursor proof; browser: 450 folded noise events — page cursor is the raw 200th id and the next page ADVANCES; lazy per-command output (0 op outputs fetched at load, 1 at approach) |

### Gate receipts at HEAD `bd6167e` (this fix round; disposable PG fixture owned and removed; libvirt session + labeled TCG where noted)

| gate | result |
| --- | --- |
| fast | exit 0 — **661 passed, 0 failed, 0 skipped, 472 deselected**, 6 warnings, 85.3 s |
| selection | **PASS** 169.1 s |
| python | **PASS** 4.6 s (registry reachable again after the DNS outage; lock verified) |
| authority | **PASS** — 35 passed, 0 skipped |
| containment | **PASS** (incl. the rewritten capture subprocess suite) |
| agent | **PASS** — 123 passed, 0 failed, 0 skipped |
| pve-contract | **PASS** — 22 passed, 0 skipped |
| db | **PASS** — 314 passed, 0 failed, 0 skipped, 819 deselected, 654.3 s; owned resources cleaned |
| frontend | **PASS** — build + ONLINE `npm audit --omit=dev` **zero high/critical (moderate=0 low=0)**; the previous round's DNS-blocked PENDING is cleared |
| browser (after frontend) | **PASS** — 5 passed, 0 skipped, 248.8 s (stage5 member loop, plan19 admin, 3× plan20 incl. the new epoch/read-time counterexample) |
| compose | **PASS** 179.1 s |
| install | **PASS** — real clean/rerun/upgrade/drift sequences; managed-service half stays the operator's (not accepted from any flag) |
| hypervisor | **PASS** — 2 passed, 0 skipped, accelerator=explicit-TCG (LABELED software emulation; NOT nested-KVM acceptance) |
| access | **PASS** — 1 passed: real guest SSH, pinned key, qga marker, recorded `.cast` replay |
| capture | **FAILED (environment — 21 blocker)**: `test_capture_installed_negatives_on_real_guest` errors at guest build: serial shows `E: Version '1.24.0-2ubuntu7.18' for 'nginx' was not found` → `SR-GUEST-BUILD-APT-FAIL`. Identical root cause to the pinned-nginx mirror drift already carried as milestone 21's supply-chain repair; `git diff 28b1f8b..HEAD -- infra/images/ infra/dev/ srplatform/guest/` touches only the journey client (no image/manifest change) |
| images | **FAILED (environment — same 21 blocker)** this fix round at 06:58 (revision within `28b1f8b..HEAD`, image build code identical to `bd6167e`): 15 passed, 4 ERRORS, all `SR-GUEST-BUILD-APT-FAIL` on the same missing pinned nginx version |
| bundle | **FAILED (prerequisite)** — role images come from the images gate (blocked above); with `SR_APPLIANCE_BASE_IMAGE` set the bundle verifies the base but refuses placeholder role bytes |
| packet | **FAILED (environment, fail-closed)** — needs root + `nft` (approved CI job only; never host namespaces) |
| journey | **FAILED (prerequisite, fail-closed)** — needs the INSTALLED appliance + operator/member tokens; refused by design |
| appliance (aggregate) | RUNNING at this receipt's commit — it re-runs the individual gates in order (each already receipted above) and will stop at the images blocker (deterministic pin failure); nothing the individual gates refuse can pass here. Log: `.cache/gate_r6_appliance.log` |
| release | **FAILED (prerequisite, fail-closed)** — `SR_LIVE_BASE_URL` live job; "nothing about a release is accepted from a sandbox" |

Carried, unchanged by this round and NOT reopened by it: the nginx/package
mirror pin reproducibility repair is milestone 21's explicit software
blocker; installed Strata/UID/proc/systemd/nested-KVM/operator
qualifications remain NOT PROVEN from this sandbox; hypervisor/access
receipts are labeled-TCG software emulation. `git status` is clean at
this commit; this operator's own PG fixture (`sr-r6pg`) was removed
after the final gate runs, and only the libvirt session daemon backing
the in-flight appliance aggregate (plus that aggregate's own `sr-acc-*`
fixtures) is still intentionally running — it belongs to the in-flight
job, not to accepted evidence.

## Plan-20 implementation — 2026-10-27, branch `practice-upgrades-18-21`

Conversational coach, bounded timed output capture, replay v2 and the
modernized web review surface. Implementation commits `76b6cd7`
(migration 0025 + append-only artifacts), `1b30d96` (coach chat over
durable jobs), `096691f` (timed capture plane), `569bd81` (replay v2 +
sessions envelope), `86fd86f` (web redesign), `7b03388` (real-browser
acceptance; stage5/plan19 updated for the new UI). Applied migrations
0020–0024 are byte-unchanged against `8e77567`; `0025` is the only
addition, and `/readyz` reports head 0025.

Plan-20 test surface (32 tests): `test_plan20_artifacts` (2 db),
`test_plan20_coach` (8 db), `test_plan20_coach_agent` (2 agent),
`test_plan20_capture` (7 containment), `test_plan20_capture_api`
(5 db, incl. the real loop → transport → internal endpoint path),
`test_plan20_replay_api` (6 db), `test_plan20_browser` (2 browser+db).

### Gate receipts at HEAD `7b03388` (same day, disposable PG on
run-owned port 5446; the gate's own fixture starts/stops its own
container for the db run)

| gate | command | result |
| --- | --- | --- |
| fast | `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -p no:cacheprovider` | exit 0 — **661 passed, 0 failed, 0 skipped, 444 deselected**, 6 warnings, 85.26 s |
| selection | `acceptance.py selection` | **PASS** (165.7 s) |
| python | `acceptance.py python` | **PASS** (4.5 s) — with `UV_OFFLINE=1`: this sandbox lost DNS mid-session (`registry.npmjs.org` and `pypi.org` unresolvable), and the offline mode installs the identical exact-pin lock into a fresh venv, verifies `uv pip check` and the four entrypoint imports |
| authority | `acceptance.py authority` | **PASS** (25.5 s) |
| containment | `acceptance.py containment` | **PASS** (21.7 s; 33 tests incl. the 7 new capture regressions) |
| agent | `acceptance.py agent` | **PASS** — 122 passed, 0 failed, 0 skipped, 983 deselected (149.6 s), incl. the 2 plan-20 full-loop coach tests against the pinned fake provider |
| db | `acceptance.py db` | **PASS** — 295 passed, 0 skipped, 810 deselected (651.5 s); owned DB resources cleaned, fixture container removed |
| frontend | `acceptance.py frontend` | build **PASS**; `npm audit --omit=dev --json` **PENDING (environment)** — errors with empty JSON while the registry is unreachable (DNS failure above). `npm audit --omit=dev --json --offline` (cached advisory snapshot from the same day) reports **zero vulnerabilities**, and the online command passed **zero high/critical** at `86fd86f` the same day; `git diff 86fd86f..HEAD -- web/package.json web/package-lock.json` is empty. Online re-run required before milestone 21 promotion |
| browser | `acceptance.py browser` (run AFTER frontend) | **PASS** — 4 passed (stage5 member loop, plan19 admin GUI, 2× plan20), 0 skipped (188.6 s) |

Not attempted here (unchanged operator gates): `packet` (root+`nft`),
`journey` (installed appliance), installed UID/proc/systemd/Strata/KVM
rechecks. The pinned-nginx mirror-drift blocker recorded under
plan-19 round 5 (images/capture/bundle reproducibility) stays carried
for milestone 21; the DNS/registry outage above is a sandbox egress
condition, not evidence about package pins.

### Boundaries proven by the new tests (not by this prose)

* Coach answers ride durable `coach-chat` jobs (one inference slot);
  the member message persists first; reload shows pending from the job
  row; the evidence cutoff and allowed citation ids freeze at enqueue;
  citations outside the window are dropped, prose stays verbatim;
  unavailable/failed model persists the honest fallback, never an
  invented answer (browser test proves the DOM, agent tests prove the
  wire). No chat path mints scores or audit events.
* Timed capture is a second, independently-quota'd consumer of the
  command stream: bounded chunks, exactly one truncated marker, gaps
  counted, emit failures never break the run or the stop path, and
  the SERVER re-enforces the quota with idempotent
  `(run_id, op_id, seq)`. Pre-capture history renders command-only —
  historical first-4000-char results are never reconstructed.
* The replay operations track pairs ONLY the red worker's own
  intent/result events; verifier, telemetry and bastion/MOTD traffic
  never becomes attacker attribution (db test). A sealed competition
  member gets no commands, chunks or phases through replay, the
  chunk endpoint or the coach (db tests), and the browser gate proves
  the operator/member dashboard difference.
* Playback never scores: the UNSCORED honesty notice survives AAR
  generation with no scorecard (browser test); trusted scores come
  only from verifier scorecards.

## Plan-19 review ROUND 5 — 2026-10-27, branch `practice-upgrades-18-21`

**Accepted (SOFTWARE) 2026-10-27:** independent review at `1348b10` →
**VERDICT: SHIP**, all six plan criteria PASS on the reviewer's own
re-runs (matching receipts in `docs/ROADMAP.md`); manual/operator and
installed-system qualifications stay open, and the pinned-package
supply-chain blocker stays carried for milestone 21. Historical
constraint: nothing below is reopened by that acceptance.

The FIFTH independent review (complete controls at `e07c52a`: every
prior concurrency/upgrade/compaction/outcome/pin blocker PASSED the
reviewer's own barriers; 0020–0022 byte-unchanged against `e311ff9`,
0023 against `b7ea7cd`, 0024 untouched) returned **VERDICT: FIX** with
ONE remaining reproduced blocker — a MEDIUM secret leak inside the
repair-obligation audit itself. Fixed at root in `db36809`; no
migration touched (0020–0024 unchanged).

### Reproduced defect and fix→proof map

- **R5-F1 MEDIUM — the compensation-failure audit leaked the
  credential.** `_record_compensation_failure` persisted
  `str(exc)[:200]` into the append-only
  `model_admin.profile.secret_compensation_failed` event. The reviewer
  injected the fault on a real disposable PostgreSQL (deliberate fixture
  CHECK constraint refusing the credential value — not a production
  constraint): the rolled-back tracked delete re-inserted the secret,
  the constraint raised `IntegrityError`, and PostgreSQL's own
  diagnostic — `DETAIL: Failing row contains (..., <secret>, ...)` —
  landed in an **app-role-readable** event verbatim.
  Fix (honest obligation, zero secret):
  `model_admin.safe_error_shape()` records only library class names
  plus 5-character SQLSTATE codes along the bounded, cycle-safe
  cause/`orig` chain — raw text, `args`, `params`, statements, row
  details, provider bodies and tracebacks are never READ, and no
  pattern-based "redaction" is trusted (short opaque keys defeat every
  pattern). The obligation keeps everything an operator needs: op,
  profile id, structure (`IntegrityError[23514]`), action_needed. The
  obligation WRITE's own failure is no longer `except: pass` — the
  last-resort log line carries safe shapes only and states in words
  that the durable record is missing. The sibling audit fallback
  (`_persist_logical_outcome`'s handler-failure note, job evidence an
  API caller reads) moved to the same structural convention.
  Provider-call normalization (`redact_error` on job errors) stays as
  previously accepted — it is not a compensation/audit path.

  Proof (`tests/test_plan19_review_round5.py`, 3 agent tests, real PG
  fault injection, no mocks of the leaking mechanism): obligation
  present exactly once with `IntegrityError[23514]`; store stays
  honestly divergent (no silent success); the credential appears in NO
  app-role surface — raw `to_jsonb(events)` read through the app
  identity, obligation payloads, every log record; when even the
  obligation write is refused (second fixture constraint), the bounded
  last-resort log names structure only and says `NOT recorded`.
  Positive controls unchanged and still green inside the gates:
  legitimate rollback restores; the locked restore cannot undo a
  committed revocation.

### Round-5 gate receipts — all personally run at `db36809` (tree clean), serialized, logs `.cache/gate_r5_*.log`

Fast default at the final code commit: **661 passed, 0 failed, 0
skipped, 412 deselected** (85.01 s).

| Gate | Result | Exact receipt |
|---|---|---|
| selection | PASS 168.0 s | every test classified; fast default **661 passed, 0 skipped, 412 deselected** |
| python | PASS 5.5 s | locked install + deps + imports |
| authority | PASS 26.6 s | **35 passed, 0 skipped** |
| containment | PASS 20.8 s | **26 passed, 0 skipped**; no leaked run-owned cgroups |
| db | PASS 634.3 s | **272 passed, 0 skipped, 801 deselected**; fixture container removed; no `srtest_*`/`sr_*` databases or roles remain |
| agent | PASS 150.2 s | **120 passed, 0 failed, 0 skipped** — incl. the 3 round-5 fault-injection tests plus all round-3/4 deterministic barriers |
| frontend | PASS 7.3 s | production audit: zero high/critical |
| browser | PASS 112.6 s | **2 passed, 0 skipped** — serialized immediately after frontend |

Not re-run for this small correction per operator instruction:
pve-contract, install, compose, hypervisor, access (unchanged domains,
receipts at `12ecbcb`); images/capture/bundle stay blocked by the
recorded pin-drift supply-chain item — **now carried forward in the
ROADMAP under milestone 21 as a release-blocking reproducibility
defect, not an environmental waiver**; operator gates
(packet/journey/release) and installed UID/proc/systemd/Strata/KVM
qualifications remain NOT PROVEN — sandbox fixtures are not
installed-system proof.

## Plan-19 review ROUND 4 — 2026-10-27, branch `practice-upgrades-18-21`

The FOURTH independent review (SOURCE-ONLY — no reviewer tests ran)
returned **VERDICT: FIX** at `b7ea7cd` with three source findings (one
HIGH TOCTOU in the round-3 rollback compensation itself, two MEDIUM:
the 0023 fence could not reach pre-0023 escaped chains, and a
cessation RESOLUTION was being accepted as compaction SUCCESS) plus two
test-quality gaps (the claim-race `is_alive()` guess; a pin "proof" that
created its session after the edits). Every one was reproduced at root
and fixed; commits `069491f` (fixes) and `12ecbcb` (tests). Applied
migrations 0020–0023 verified BYTE-UNCHANGED (`git diff` over those
files empty in both round-3 and round-4 ranges); the new schema work is
forward, data-only migration **0024** (head → 0024; `downgrade` is a
deliberate no-op — erasing the fence would re-arm the dispatch it
closes).

### Reproduced defects and fix→proof map (pre-fix behavior, exact)

- **R4-F1 HIGH — rollback compensation could resurrect a revoked key.**
  The round-3 restore read the profile's COMMITTED status through a
  fresh session, **closed it**, and only then called `set_key`: a revoke
  committing in that check→write window deleted the credential, and the
  compensation recreated it for a profile an operator had just killed
  (a status check alone is not serialization). Fix: the restore now
  takes **FOR UPDATE on the same profile row a revocation locks to
  change status** and holds it across check + secret write + commit
  (bounded `SET LOCAL lock_timeout='10s'`; a timeout is a recorded
  durable repair obligation, never a silent success). Proof: the TOCTOU
  test forces the revocation to arrive while the restore is INSIDE the
  write, and `pg_stat_activity` **shows** the revoke backend parked on
  a lock wait before the write is released — ordering becomes total;
  final state: credential stays deleted, profile stays revoked. A
  positive control proves a legitimate rolled-back delete still
  restores (the fence is not a silent refusal).
- **R4-F2 MEDIUM — migration 0023 left pre-0023 escaped chains
  dispatchable.** 0023 could only stamp `cancel_intent = false` on rows
  that already existed and backfill chain identity; a `cancelled` root
  with `queued` retry children — the exact state the old defect
  produced — survived the upgrade with clean flags, and admission and
  execution consulted only the candidate's own flags. Fix (forward,
  never editing applied migrations): **0024** reconciles populated
  pre-0023 databases — every row of a chain CONTAINING a cancelled row
  gets the durable intent, `queued` members become `cancelled` with an
  honest reconciliation note, while `running`/`cessation_unknown` rows
  KEEP their state (an uncertain cessation is an obligation; the slot
  stays held). The claim statement and the executor gained the same
  chain-level fence (`COALESCE(chain_root, job_id)` containing a
  cancelled row) — fail-closed reconciliation BEFORE any dispatch. An
  ordinary FAILED parent with a queued retry child is explicitly NOT
  fenced (a failed attempt is not a cancelled logical request). Proof:
  a second disposable database migrated to **0022 by the real Alembic
  CLI**, populated using ONLY old-schema columns, upgraded to head; the
  **production `_CLAIM_SQL` itself** then verifies escaped chains are
  unfetchable, the ordinary retry is admitted once the slot is free,
  and running rows survive via `reconcile_startup` as
  `cessation_unknown` obligations. Runtime half: an escaped child never
  claims; a forced legacy claim reconciles to `cancelled` (fence note)
  with **zero provider requests**, and the grandchild settles too.
- **R4-F3 MEDIUM — cessation resolution is not compaction success.**
  `_dep_chain_state` accepted `cessation_resolved` as prerequisite
  success, but `resolve_cessation` is an operator slot-release
  ATTESTATION — it creates no summary and no checkpoint — so after an
  uncertain summary was audited away the gated turn could dispatch the
  uncompacted, over-budget context. Fix: dependency success requires
  the chain-final attempt to be genuinely `succeeded`, AND (for a
  summarize prerequisite) its coverage-bounded checkpoint row with the
  exact `covers_through` must exist (`_checkpoint_persisted`; a new
  `no-checkpoint` verdict otherwise). `cessation_resolved` is now an
  honest `failed-final`. Proof: client-timeout summary → audited
  `resolve_cessation` → gated turn **refuses** (error names
  `cessation_resolved`, nothing was sent to the provider);
  succeeded-without-checkpoint refuses likewise naming the missing
  checkpoint; the positive control 500 → bounded retry → checkpoint →
  dispatch runs the native turn **exactly once**, and the FIFO shape
  proves admission correctly skipped the gated turn while the chain
  could recover.
- **Test quality (reviewer items):** the round-3 claim-race
  `t.join(timeout); is_alive()` guess is replaced by the same explicit
  `_await_lock_wait` barrier (PostgreSQL itself reports the victim
  backend on a lock wait) — no test anywhere now assumes thread
  scheduling. The pin proof now FREEZES the pin at the session's first
  served turn while v1 is live, then points v2 at a dead URL and
  same-key-resaves v3 — the pinned session's next call is still served
  by v1 over the real wire (the pre-fix form failed exactly this way,
  which is what made it a real proof). Round-3's positive dependency
  test was updated to carry the real `persist`/`covers_through` range
  so its summarize lands a genuine checkpoint under the reworked logic.

### Round-4 gate receipts — all personally run at `12ecbcb` (tree clean), serialized, logs under `.cache/gate_r4_*.log`

Fast default: `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -ra -p
no:cacheprovider` → exit 0: **661 passed, 0 failed, 0 skipped, 409
deselected**, 6 warnings, 84.32 s. Combined disposable-PG sweep
`-m "agent or db"` (tree identical to `12ecbcb`, run-owned container):
**311 passed, 0 failed**, 759 deselected, 747.84 s (`.cache/r4_sweep.log`).

Environment for the libvirt/QEMU gates (this runner has **no
`/dev/kvm`**; boots are explicitly labeled TCG, never claimed as
nested-KVM acceptance): `. .cache/libvirt-debs/env.sh` + `PATH` incl.
`.cache/libvirt-debs/root/usr/sbin` + `SR_APPLIANCE_BASE_IMAGE` = the
base **rebuilt at this checkpoint** by the documented no-root path
(`infra/images/appliance_base.py`, pinned checksum-verified Ubuntu
cloud image, sha256 `6b1fbc…d2b2f`) + `TMPDIR=/var/tmp/sr-gate`.

| Gate | Result | Exact receipt |
|---|---|---|
| selection | PASS 162.3 s | every test classified; fast default **661 passed, 0 skipped, 409 deselected** (required mode) |
| python | PASS 5.1 s | locked install + deps + entrypoint imports, Python 3.13 |
| pve-contract | PASS 27.1 s | legacy contract **22 passed, 0 skipped** (required mode) |
| authority | PASS 26.6 s | broker boundary/durability/cessation **35 passed, 0 skipped** |
| containment | PASS 20.5 s | execution/cessation boundaries **26 passed, 0 skipped**; no leaked run-owned cgroups |
| install | PASS 6.6 s | REAL sandbox install sequences; managed-service VM half stays operator-run |
| db | PASS 633.2 s | disposable PostgreSQL 16: **270 passed, 0 skipped, 800 deselected** — incl. both real-Alembic 0022→head populated-upgrade tests; fixture container removed, `no srtest_*/sr_* databases or roles remain` |
| agent | PASS 146.9 s | real wire + disposable PG: **117 passed, 0 failed, 0 skipped, 953 deselected** — includes all 8 round-4 deterministic-barrier/wire tests |
| frontend | PASS 9.5 s | production audit: zero high/critical |
| browser | PASS 107.0 s | isolated real-browser workflows **2 passed, 0 skipped** — serialized immediately after frontend |
| compose | PASS 71.6 s | compose project boots, serves, fully removed |
| hypervisor | PASS 268.6 s | real libvirt clone/start/QGA/host-key/ownership/stop/destroy, accelerator **explicit TCG** (labeled) |
| access | PASS 142.5 s | real Ubuntu guest SSH + recording bastion flows on the freshly rebuilt base |
| images | **FAILED (environment) — NOT accepted** | 1770.6 s: 15 passed, 4 setup ERRORS. Root cause chain, exactly: the warm role-image cache was destroyed by a host disk cleanup, and the pinned guest package versions in `infra/images/packages-24.04.txt` have since **drifted out of the Ubuntu mirrors** — the build guest's own apt reported `E: Version '1.24.0-2ubuntu7.18' for 'nginx' was not found` → `SR-GUEST-BUILD-APT-FAIL` (serial preserved at `/tmp/opencode/sr-gate-debug/guest.serial.serial.log`). Deterministic mirror version removal (successful index fetch, package found, pinned version gone), ~6 days after milestone 15 built the identical list. Repair requires a documented package-pin refresh — a release-engineering/supply-chain decision that does NOT belong inside a model-jobs review round and changes artifact identity under the reviewer's feet. Milestone 15 also recorded that a COLD role-image build under TCG (no `/dev/kvm`) exceeds the built-in 1500 s serial-marker timeout even when apt works, so a pin refresh on THIS host is not a guaranteed pass either. |
| capture | **PENDING (environment)** | the capture overlay's own `guest_build.build_overlay` step installs the SAME `packages-24.04.txt` pins through the SAME guest-apt path (see `infra/images/guest_userdata.py` install line) — it deterministically reproduces the images failure above before any capture assertion runs; deliberately not re-run to burn a known-failing 30-minute boot. No PASS claimed. |
| bundle | **FAILED (fail-closed prerequisite) — PENDING on images** | 0.0 s: `release bundle role artifacts — no mojang-web-local image found …build the role images first (the images gate)` — the gate refuses placeholder bytes exactly as designed. No PASS claimed at this checkpoint. |
| appliance (aggregate) | not re-run by design | it re-runs every individual software gate; each already received a fresh receipt above at `12ecbcb` (its compose-build half is the passed `compose` gate). Re-running the aggregate would duplicate compute, not add evidence. |
| packet | PENDING (operator) | needs root + `nft`; fails closed naming them (round-3 receipt). Not re-run — recorded pending per operator instruction. |
| journey | PENDING (operator) | needs the INSTALLED appliance + the eight `SR_JOURNEY_*` operator inputs; fails closed by design. Not re-run. |
| release | PENDING (operator) | needs `SR_LIVE_BASE_URL` on the deployed lab; nothing is accepted from a sandbox. Not re-run. |

Scope note for the images/capture/bundle situation: the round-4 diff
(`git diff b7ea7cd..HEAD`) touches ONLY `srplatform/model_jobs.py`,
`srplatform/model_admin.py`, migration 0024, and plan-19 tests — zero
`infra/images`, deployment, or appliance paths. Milestone 19's own
acceptance criteria (plan §Acceptance 1–6) are fully covered by the
PASS rows above; the heavy image lane belongs to the images/release
milestones and its blocker is recorded truthfully rather than forced
green or papered over with silent pin edits.

## Plan-19 review ROUND 3 — 2026-10-26, branch `practice-upgrades-18-21`

The THIRD independent review returned **VERDICT: FIX** at `e311ff9` with
six findings (two HIGH races against the one-slot contract, two MEDIUM
lifecycle gaps, one MEDIUM admin self-sabotage, one HIGH deployment
identity boundary). Every one was reproduced at root and fixed with
DETERMINISTIC concurrency regressions — uncommitted production claims
held open, event-gated provider responses, hand-driven
claim/execute/terminal — never sleeps hoping a window opens
(`tests/test_plan19_review_round3.py`, 18 agent tests;
`tests/test_plan19_review_round3_deploy.py`, 8 fast tests). Commits
`b7885c1` (jobs fence + migration 0023), `09ed2b2` (admin outcome
unification + guard audit), `f6f9014` (OS identity/secret boundary),
`dfa9f39` (tests). Applied migrations 0020/0021/0022 verified
BYTE-UNCHANGED (`git diff e311ff9..HEAD` over those files empty); all
schema work is forward migration **0023** (`cancel_intent` +
`chain_root` indexed/backfilled, NULL chain = unknown = conservatively
blocks gating).

### Reproduced defects and fix→proof map (pre-fix behavior, exact)

- **F1 HIGH cancel/claim race released a live slot.** Production claim
  (`_CLAIM_SQL`, row lock) left uncommitted while a real `cancel()` ran:
  cancellation did NOT wait, wrote its stale queued snapshot over the
  committed `running` row — `cancelled_row_state=cancelled`,
  `second_claimed=True`, provider still generating
  (`provider_max_concurrent=2`). Fix: `cancel()` locks the WHOLE chain
  FOR UPDATE root-first (deterministic order, re-enumerating) then acts
  on the committed truth; live rows get only `cancel_requested`; the
  claim carries the outer `state/intent` CAS. Proof:
  `test_cancel_blocked_by_open_claim_acts_on_the_committed_truth`
  thread-proves the cancellation BLOCKS at the claim fence, then honors
  `running`+requested; `test_live_call_cancel_requests_cessation_and_
  holds_the_slot` (event-gated real HTTP) shows the slot is never
  released while live and at most one provider request exists;
  `test_cancel_before_claim_never_claims_or_dispatches`.
- **F2 HIGH retry creation escaped root cancellation.** Attempt 1 live
  (event-gated), provider answered 500 (definite, retryable) WHILE
  `cancel()` committed against the old chain snapshot: the executor
  birthed a fresh queued backoff child — the "cancelled" request
  re-spawned. Fix: durable `cancel_intent` stamped on EVERY chain row
  under the lock (migration 0023); the terminal write takes the row
  lock FIRST and treats `cancel_requested OR cancel_intent` as cessation,
  ending the chain with no child; claim skips intent rows; children born
  before the cancel are found by the locked re-enumeration and killed.
  Proof: `test_retry_cannot_be_born_after_the_root_was_cancelled`
  (no child, no second request, exactly one outcome — with F4),
  `test_cancel_after_child_born_kills_it_during_the_race_window`.
- **F3 MEDIUM dependency gating was attempt-bound.** A gated turn was
  admitted after the summary's FIRST failed attempt despite the queued
  retry: executor failed the caller `prerequisite job did not succeed
  (failed)` (502) while the summary retry later succeeded — three
  provider requests, wrong verdict. Fix: the claim gate is chain-aware
  via `chain_root` (wait while ANY attempt may dispatch, admit once
  quiescent), and the EXECUTOR under its lock decides: requeue if the
  prereq is in-flight again (race won after admission), truthful
  `prerequisite logical request did not succeed (final attempt N:
  state)` on genuine exhaustion. Proof:
  `test_gated_turn_waits_for_summary_recovery_then_dispatches_once`
  (request bodies `[_SUM, _SUM, _GATE_MSG]` — dispatched once, only
  after the chain's final attempt succeeded),
  `test_gated_turn_fails_only_after_the_summary_chain_is_truly_done`,
  `test_gated_turn_reports_the_summary_cancellation_truthfully`.
- **F4 MEDIUM revocation skipped durable outcomes.** Async hint AND AAR
  revoked before dispatch: `cancelled`, `outcome_persisted=false`,
  ZERO events — the member's honest fallback vanished; the same bypass
  existed for restart/recovery and the profile-unavailable branch. Fix:
  ALL terminal paths route through the ONE protocol —
  `model_admin._cancel_jobs_for`/`revoke()` call `model_jobs.cancel()`
  (intent + locked cascade + one guarded outcome claim);
  `reconcile_startup` and `resolve_cessation` persist the logical
  outcome; profile-unavailable cascades and persists. Proof:
  `test_revocation_of_a_queued_hint_persists_the_outcome_once`,
  `test_lineage_replacement_of_backoff_chain_persists_once`,
  `test_live_call_revocation_ceases_and_persists_exactly_once` —
  queued, chain-with-queued-child, and live revocation each yield
  exactly ONE event, never two.
- **F5 MEDIUM resaving the SAME key revoked the NEW profile.** The
  parent's own credential value resubmitted via revise: the sibling
  sweep (finding the replaced digest AFTER create) matched the
  brand-NEW version — revoked it and deleted its secret seconds after
  writing; a 200 for an unusable profile. Fix: same-VALUE detection
  (digest or plaintext match against the current secret) BEFORE any
  effect demotes the rotation to a non-secret edit (lineage stays,
  nothing revoked); the sweep additionally skips `new.profile_id`
  structurally. Proof (real API): `test_same_key_resave_never_revokes_
  the_version_it_created` (+ with-other-fields/multiple-superseded,
  genuine-replacement-still-invalidates-lineage, and failed-revision-
  changes-nothing variants).
- **F6 HIGH the API-only secret file was readable by ingest's
  identity.** `sr-api-ingest.service` ran `User=srrange` — the same uid
  as the API — and `db-secret.env` was 0640 root:srrange: the ingest
  process could open the credential-store URL directly (same uid also
  implies `/proc/PID/environ` and ptrace). EnvironmentFile scoping is
  not OS access control. Fix (all three halves): ingest runs as its own
  `sringest` identity (shipped unit + `install.sh` provisions it, gives
  it `ingest-server.key` and `ingest-listener.env`; the appliance
  renderer was already `sringest`); `ensure_database` creates the file
  ATOMICALLY at 0600 (`_write_secret_file_securely`:
  O_CREAT|O_EXCL, fsync, link-publish — never replaces, no permissive
  window) and verifies toward 0600 root:root, FAILING CLOSED (the old
  `write_text` + `chmod check=False` is gone); the service contract now
  FAILS if two units share a uid or any non-API unit references the
  file, and `secret_file_boundary_problems()` runs exact POSIX
  readability math for every appliance identity. Proof:
  `test_no_two_installed_units_share_an_os_identity`,
  `test_posix_math_uses_exact_access_semantics_for_service_uids` (the
  OLD 0640 shape proves readable — the check is not vacuous),
  `test_secret_file_is_created_restrictive_from_the_first_byte`,
  `test_verification_fails_closed_when_the_file_cannot_be_secured`.
  Installed-OS qualification (real uid switch on the appliance) stays
  an OPERATOR gate — not claimed here.
- **Audit (parent-directed, now pinned):** the rollback guard lacked
  after-COMMIT cleanup — session reuse turned compensation into
  vandalism of a committed profile's live secret; a restore re-checking
  status on the ROLLING-BACK session hit SQLAlchemy 2.1's inactive-state
  refusal (proven by debug at the hook) and silently skipped restores;
  and a FAILED compensation vanished. Fix: `_settled` (after_commit)
  clears pending entries, restore reads the row's COMMITTED status via
  a FRESH session (concurrent revocation is never resurrected), and any
  failing compensation records a durable
  `model_admin.profile.secret_compensation_failed` admin event. The
  guard is now documented — honestly — as in-process compensation, NOT
  crash atomicity. Proof: `test_committed_secret_survives_a_later_
  rollback_on_the_same_session`,
  `test_rollback_never_resurrects_a_credential_revoked_concurrently`,
  `test_failing_compensation_records_a_durable_repair_obligation`;
  round-2's `test_mid_effect_and_route_level_failures_compensate`
  (the guard's earlier contract) passes unchanged.

### Round-3 gate receipts

All run at commit `dfa9f39` (tree clean; docs commit follows), serialized,
each via `.venv/bin/python infra/dev/acceptance.py <gate>` unless noted.
Environment for the libvirt gates: `. .cache/libvirt-debs/env.sh` +
`SR_APPLIANCE_BASE_IMAGE=../15/.cache/bundle/sparring-range-appliance/images/appliance-base.qcow2`
+ `SR_APPLIANCE_ROLE_IMAGE_DIR=../15/.cache/bundle/sparring-range-appliance/images`
+ `TMPDIR=/var/tmp/sr-gate` (this runner has no /dev/kvm; guest boots are
explicitly labeled TCG, never claimed as nested-KVM acceptance).

| Gate | Result | Exact receipt |
|---|---|---|
| selection | PASS 133.8 s | fast default **661 passed, 0 skipped, 399 deselected** (83.78 s run) — required mode; empty-selection probe fails loudly |
| python | PASS 4.4 s | fresh locked install + deps check + 4 entrypoint imports on Python 3.13.5 |
| pve-contract | PASS 25.5 s | real-proxmoxer legacy contract **22 passed, 0 skipped** (required mode) |
| authority | PASS 24.3 s | broker boundary/durability/cessation **35 passed, 0 skipped** (required mode) |
| containment | PASS 20.2 s | namespace/recursive-membership/cancellation **26 passed, 0 skipped**; no run-owned cgroups leaked |
| db | PASS 628.1 s | disposable PostgreSQL 16 (run-owned container/volume): **260 passed, 0 skipped, 800 deselected** |
| agent | PASS 140.3 s | real wire + disposable PG (SR_REQUIRE_AGENT=1): **109 passed, 0 failed, 0 skipped, 951 deselected** — includes all 18 round-3 deterministic-race tests |
| frontend | PASS 27.7 s | production audit: zero high/critical (moderate 0, low 0) |
| browser | PASS 122.5 s | isolated real-browser workflows **2 passed, 0 skipped** (required mode) — serialized immediately after frontend |
| install | PASS 10.3 s | REAL sandbox install sequences (dry-run idempotence, key preservation, invalid-manifest refusal, per-service TLS ownership, derived env, ingest plane, dial-key bootstrap); managed-service VM half stays operator-run and is NOT accepted from any flag |
| compose | PASS 184.6 s | compose project boots, serves, and is **fully removed** (run-owned resources cleaned exactly) |
| hypervisor | PASS 261.4 s | real libvirt clone/start/QGA-readiness/host-key/ownership/stop/destroy — accelerator **explicit TCG** (labeled, not nested-KVM acceptance); no QEMU owned-run-dir leaks |
| packet | FAILED (environment) — operator gate, PENDING | missing prerequisites `['root', 'nft']` — fails closed naming the exact missing pieces; rules apply only in disposable netns on an approved CI job; never simulated |
| journey | FAILED (prerequisite) — operator gate, PENDING | missing `SR_JOURNEY_BASE_URL`, operator/member tokens, SSH key, bastion known-hosts, browser URL/user/password — needs the INSTALLED appliance; fails closed by design |
| release | FAILED (live layer) — operator gate, PENDING | requires `SR_LIVE_BASE_URL` (deployed lab); nothing about a release is accepted from a sandbox; never executed here |

*(The five heavy-lane rows this section left as "running/queued" —
appliance, bundle, access, images, capture — became moot at this
revision before settling: the host disk cleanup destroyed the warm
role-image/base cache mid-lane and the `/tmp` rotation lost those early
run logs. Fresh receipts for every heavy gate at the current checkpoint
`12ecbcb` are in the ROUND 4 section above; nothing here claims a result
the round-4 table does not repeat.)*

## Plan-19 review ROUND 2 — 2026-10-25, branch `practice-upgrades-18-21`

The SECOND independent review returned **VERDICT: FIX** at `1d19c16` with
thirteen findings against the round-1 repairs. Every one was reproduced,
then re-fixed at the behavior level; commits `e38c1b5` (wire/compaction/
thinking/classifier), `21f9f55` (migration 0022 + digests + guard),
`fb433ac` (chain-unit jobs), `add5223` (surfaces/streams/rollbacks),
`bdad5c8` (secret-URL provisioning), `4764127` (tests), `bb0fec6` (GUI).
Applied migrations 0020 AND 0021 are byte-unchanged (the round-1 lesson
held): all schema work is forward 0022.

### Reproduced defects (pre-fix, exact behavior)

- **F1 compaction split a tool pair:** with a strict-checking provider,
  compaction covered the assistant tool CALL while the RESULT arrived
  later; the next replay opened with an orphan tool result and the
  provider 400'd (the fake provider's strict mode now records exactly
  that violation class).
- **F2 rotation left the credential alive:** session pinned v1/K1; three
  non-secret edits copied K1 to v2–v4; replacing the key revoked only
  v4 — the pinned session kept calling with the "replaced" credential
  (the pre-fix run failed asserting `v1.status == 'revoked'`).
- **F3 short-key leak + post-delete redaction:** the reviewer saved
  synthetic `uvxyz`; a leaky 500 echo put it in the worker 502 AND the
  admin job row; re-fetching the key after mid-failure revocation lost
  the value entirely (round-1 `redact_secrets` had a 6-char floor).
- **F4 member leak:** a provider 400 echoing the sealed conversation
  surfaced verbatim through `GET /sessions/{id}/model-jobs` to the
  owning member — sealed match included.
- **F5 root cancel:** cancelling the submitted id returned 200 while the
  backoff-queued retry child stayed queued and then dispatched (the
  provider received the "cancelled" call).
- **F6 stale finality:** polling the submitted id reported attempt 1's
  `failed` after the retry had already succeeded; the admin detail
  showed the same.
- **F7 double outcome:** a hint whose attempt 1 failed and attempt 2
  succeeded persisted TWO hint events (fallback + real).
- **F8 deadline bypass:** `/internal/model/complete` for an already
  EXPIRED match contacted the provider (queue-expiry checked only at
  dispatch; the text route never carried the match deadline).
- **F9 thinking collapse:** running the round-1 function, `none/low/
  medium/high` produced FOUR IDENTICAL llama.cpp request bodies.
- **F10 env-name:** `SR_PG_SECRET_URL` alone resolved
  `postgres_url_secret` to `''`; on compose, migrate died at 0021's
  GRANT — `role "sr_secret" does not exist` (reproduced this round).
- **F11 rotation destroyed a working key:** an invalid rotation
  (422) left the old secret DELETED and the status rolled back —
  pinned sessions then failed with no credential. Root cause found
  empirically: SQLAlchemy 2.1 dispatches `after_rollback` with ONE
  argument, so the two-argument guard made `Session.rollback()` itself
  raise before compensating.
- **F12 false slot index:** raw SQL inserted one `running` PLUS one
  `cessation_unknown` — `UNIQUE(state) WHERE state IN (...)` does not
  make DIFFERENT values conflict.
- **F13 no streams:** status was poll-only; no bounded stream, no
  reconnect semantics, and no member-safe variant existed.

### Corrected proofs (personally run at the committed HEAD)

All in `tests/test_plan19_review_round2.py` (25 tests, agent layer) +
`tests/test_plan19_review_round2_deploy.py` (6 fast) — disposable
PostgreSQL + the strict fake provider; browser-level lineage behavior in
`tests/test_plan19_browser_admin.py` (real browser). Highlights exactly
as run: strict-provider violation list stays `[]` across compaction and
three post-checkpoint turns; lineage revoke asserts v1–v4 revoked with
secrets deleted and a queued v2 child cancelled, while explicit
per-version revoke keeps its sibling `superseded`; `uvxyz`/`SEALED-PLAN`
absent from the 502, every job row, the admin list and the member
surfaces; root cancel of a queued child leaves it `cancelled` past its
backoff instant with provider request count frozen at 1; a watcher-closed
live child lands `cessation_unknown` and holds the slot until operator
resolution; the hint event count is exactly 1 under retry-success,
exhaustion, cancel, and a direct double-claim of the outcome claim;
the expired-match text route returns without any provider request; the
four thinking levels produce four distinct wire bodies (and an unknown
preset is refused before the request); invalid rotations leave the key
byte-identical and the version list unchanged, at mid-effect AND at
route level; raw SQL running+unknown now raises `IntegrityError` while
five non-occupying states coexist; worker stream progress + durable
reconnect result, member stream state-only (`text` never present) and
sealed-job 404; `SR_PG_SECRET_URL` drives the real secret store.

### Gate receipts for round 2 — all personally run at this revision, serialized, heavy gates one at a time

| Gate | Result | Detail |
|---|---|---|
| fast default | PASS | 653 passed, 0 failed, 0 skipped, 381 deselected (83 s) |
| selection | PASS | every test classified; required-mode negatives proven (132 s) |
| python | PASS | fresh locked install + 4 entrypoint imports, Python 3.13.5 (4 s) |
| db | PASS | 242 passed, 0 skipped in required mode (599 s; disposable PG 16) |
| agent | PASS | 91 passed, 0 failed, 0 skipped — includes all 25 round-2 wire/DB regressions (116 s) |
| authority | PASS | 35 passed, 0 skipped (24 s) |
| containment | PASS | 26 passed, 0 skipped (19 s) |
| pve-contract | PASS | 22 passed, 0 skipped (25 s) |
| frontend | PASS | npm ci + build + audit: zero high/critical (7 s) |
| browser | PASS | 2 passed, 0 skipped (105 s). FIRST ATTEMPT FAILED and was kept honest: the model-admin GUI test still asserted round-1 rotation semantics ("a superseded row survives"); the agreed lineage fix legitimately revokes it — the test now asserts `superseded NOT in rows` as the lineage guard, then passed |
| compose | PASS | full bootstrap/migrate/API/browser flows (179 s). Required the round-2 provisioning fix: migrate died at 0021's GRANT (`role "sr_secret" does not exist`) — fixed in `bdad5c8`, then green |
| install | PASS | real sandboxed install sequences incl. rerun/TLS-rotation/partial-recovery; managed-service half explicitly stays operator (7 s) |
| hypervisor | PASS | 2 passed — real libvirt clone/start/QGA/host-key/ownership/destroy, accelerator labeled **explicit-TCG** (no /dev/kvm here; NOT nested-KVM acceptance) (262 s) |
| access | PASS | 1 passed — real Ubuntu guest SSH, pinned key, recorded bastion replay (138 s) |
| images | PASS | 19 passed, 0 skipped — mojang builds/boots/services/seeds/flaws/fixes/readiness under isolated QEMU (1740 s) |
| capture | PASS | 11 passed, 0 skipped — installed auditd/srshipper negatives/recovery/replay (205 s) |
| bundle | PASS | 345 files, 4 images; bound to THIS checkout (228 runtime files compared); shipped image boots from a throwaway overlay; tampered bundle refused (245 s) |
| packet | FAILED (environment) — as designed | `PENDING: missing ['root','nft']` — fails closed naming the exact prerequisite; nothing simulated |
| journey | FAILED (prerequisite) — as designed | `PENDING: missing SR_JOURNEY_*` — needs the installed appliance + member tokens; first promotion gate remains open |
| release | FAILED (prerequisite) — as designed | `requires SR_LIVE_BASE_URL (deployed lab)` |

After every gate: owned fixtures removed (no `sr-*` containers/volumes, no
`/tmp/sr-bundle-gate-*` or QEMU run-dirs left; a mid-round SIGKILLed bundle
attempt left one owned temp dir which was deleted — receipt above is the
completed retry). Manual checks (milestone plans' operator sections —
Strata wire, nested KVM, installed-appliance journey) are the operator's.

### Manual / operator-only limits (unchanged by this round)

Strata thinking-wire compatibility, nested-KVM accelerator acceptance,
packet (root+nft), the installed-appliance journey, and the live release
journey remain operator/CI-jobs — each fails closed naming its exact
prerequisite; none was simulated or waived.

## Plan-19 independent review round — 2026-10-25, branch `practice-upgrades-18-21`

The independent review of plan 19 returned **VERDICT: FIX** at `2bb5305`
with eleven findings. Every finding was reproduced, then repaired at root
with real-HTTP / real-DB regressions in commits `8660a49` (conversation
wire), `8b8ab87` (jobs/secrets/gating/freeze), `e41f9ce` (routes/finalization),
`de3ea24` (db regressions), `ed24173` (GUI + browser). Applied migration
0020 was NOT touched; all schema work is forward-only in 0021.

### Reproduced original failures (before the repair, exact output)

- **Dead endpoint misclassified as uncertain (findings 2/3 classifier):**
  against `http://127.0.0.1:1/v1` the pre-fix chain classified the
  never-opened connect as an uncertain cessation — the rewritten
  hint-chain test failed with
  `expected the full bounded attempt chain, got [('cessation_unknown', 1)]`.
  Root cause: the pinned openai client rides **httpx2/httpcore2**;
  `isinstance(x, httpx.ConnectError)` never matches, so the definite
  branch was unreachable. Post-fix the same probe reports
  `retryable: True uncertain: False` and the 1→2→3 attempt chain is
  visible, all failed, none retry-worthy past the bound.
- **App role could read the new secret table (finding 8):** the real
  role probe failed with `AssertionError: app role CAN read the secret
  table` — migrations 0016/0017 established owner DEFAULT PRIVILEGES
  that auto-grant `SELECT, INSERT` on every new table to the app role,
  so `CREATE TABLE model_profile_secrets` alone handed the keys to the
  ingestion plane. 0021 now issues an explicit per-table
  `REVOKE ALL … FROM <app role>`; the probe passes in both directions
  (app role denied on secrets; the secret role denied on
  events/sessions/model_jobs).
- **Cancellation never reached the wire (finding 2):** the old suite's
  `"discarded" in error or "returned" in error` assertions encoded the
  OBSOLETE semantics (flag the row, wait out the call, discard the
  answer). With the watcher closing the live SDK call, a cancel of a
  3 s scripted hang now terminates in <2 s as `cessation_unknown`
  ("provider-side cessation cannot be confirmed"), HOLDS the slot
  (the blocked job provably stays queued; the fake provider records
  `max_concurrent == 1` throughout), and only the audited
  `POST /admin/model/jobs/{id}/resolve-cessation` releases the queue.
- **Obsolete assertions rewritten as the semantics moved (proof the old
  tests were testing the wrong contract):** status `retired` vs the new
  secret-axis `superseded`/`revoked` split (finding 9); the
  system-absent assertion (`not any(role == "system")` on turn 2) that
  ENCODED the durable-replay defect finding 1 repaired — rewritten to
  demand the permanent framing be replayed exactly once as system with
  tool returns paired by call id; the post-hoc compaction/coverage
  assertions (finding 4) rewritten to demand pre-request evaluation,
  enqueue-time coverage capture, `depends_on` gating and an execution-
  time-reconstructed (compacted) wire request; the head-0020 chain and
  readyz assertions (now 0021).

### Corrected proofs (all personally run at the committed HEAD)

| Finding | Where proven |
|---|---|
| 1 replay/wire fidelity | `test_three_turn_thread_replays_system_and_tool_returns_on_wire` (≥3 real turns: system once, call ids paired, 6 ledger rows) + rewritten multi-turn ledger test |
| 2 obligations hold the slot | `test_cancellation_reaches_the_live_call_and_obligation_blocks_then_releases`, `test_timeout_holds_the_slot_and_never_admits_a_second_request`, `test_restart_reconcile_blocks_claims_until_resolved` + migration-0021 partial unique slot index |
| 3 credential non-observability | `test_leaky_provider_401_never_shows_the_key_on_any_surface` (fake 401 echoes Authorization; key absent from worker 502, job.error, admin/member lists; exactly one request) + source redaction + secret-store role probes |
| 4 pre-request compaction | rewritten `test_compaction_covers_a_range_and_history_survives_it` (gated turn, enqueue coverage, compacted reconstruction, checkpoint-only summarize output, labeled digest never system authority) |
| 5 concurrency at the provider | slot test asserting `srv.max_concurrent == 1` while five jobs queue through one slot |
| 6 thinking encoding | wire tests asserting `chat_template_kwargs.thinking` for standard levels and the custom-level mapping limited to `reasoning_effort`/`chat_template_kwargs`; broken `settings["thinking"]` no-op deleted |
| 7 strict terminal state | `_StrictFinishOpenAIChatModel` refusals: missing finish reason, text ≠ `stop`, abnormal finish answers ALL call ids, args validated pre-execution, >4000-char command refused not truncated |
| 8 secret isolation | real role probes (both directions) in the db suite; `api_key` column dropped; `secret_store` own engine, fail closed; masked `api_key_set` None = honest unknown |
| 9 whole-session freeze | `test_first_use_pins_the_whole_role_set_and_later_overrides_are_ignored`, `test_profile_lifecycle_respects_the_pinned_whole_session_freeze` (supersede vs revoke, rebind fenced by queued work) |
| 10 no silent truncation | `test_long_final_answer_survives_the_durable_turn` (>7000-char answer end to end) + removed `text[:4000]` |
| 11 durable async + deadlines | `test_async_turn_submit_and_status_follow_the_durable_job`, `test_match_deadline_caps_admission_and_kills_stale_queue_items`, `test_run_finalization_cancels_the_sessions_queued_model_work`, `test_async_hint_completes_after_the_request_and_persists_once` + the rewritten browser test for the resolve UI |

### Gate receipts for this round (all run personally, serialized)

- Fast default (infrastructure-free): exit 0 — **647 passed, 0 failed,
  0 skipped, 356 deselected, 6 warnings**, 83.09 s.
- `acceptance.py selection` — **PASS** (146.2 s);
  `acceptance.py python` — **PASS** (4.0 s).
- `acceptance.py agent` — **PASS**: 66 passed, 0 failed, 0 skipped,
  937 deselected (80.8 s).
- `acceptance.py db` — **PASS**: **219 passed, 0 skipped, 784
  deselected** on disposable PostgreSQL 16, fixture container and all
  `srtest_*`/`sr_*` databases and roles cleaned (578.5 s).
- `acceptance.py authority` — **PASS** (35 passed, 23.9 s);
  `acceptance.py containment` — **PASS** (19.7 s).
- `acceptance.py frontend` — **PASS** (production build; audit
  moderate=0 low=0, zero high/critical, 6.6 s).
- `acceptance.py browser` — **PASS**: 2 passed, 0 skipped (106.5 s) —
  supersede-vs-revoke statuses, catalog discovery, mapping-less custom
  refusal, and cancel → `cessation_unknown` → GUI resolve → 
  `cessation_resolved` across reloads on the real Next build.

### Deployment note and limits of this evidence

- **Operator prerequisite:** the owner must create the dedicated secret
  role (migration env `DB_SECRET_ROLE`, default `sr_secret`) and set
  `SR_PG_SECRET_URL` BEFORE applying migration 0021 (it grants at
  migration time; conftest models this ordering). With the store
  unconfigured the env bootstrap refuses (audited reason, no fallback
  to the app role) and every credential read fails closed.
- The wire fixtures are the scripted fake OpenAI server: they prove OUR
  side of the protocol (payloads, headers, terminal-state handling,
  redaction), not that a real Strata endpoint behaves identically —
  that stays a supervised live check.
- DB-role isolation is not encryption at rest; it removes the
  application plane's read path, which is the documented threat model.
- `packet`, `journey`, and every installed-appliance check remain the
  operator's manual gates; nothing in this round simulates them.

## Plan-19 implementation evidence — 2026-10-25, branch `practice-upgrades-18-21`

Conversational agent on the pinned Pydantic AI layer + model administration.
Commits (this branch, nothing pushed): `f4cfad3` pin
`pydantic-ai-slim[openai]==2.61.0` · `14d37d3` migration 0020 (profiles,
pins, jobs, conversation history) · `0cfb5e1` conversation core +
model-admin service · `2dc54b9` durable one-slot jobs, turn/complete
routes, admin API, loop on typed turns, shutdown lock release ·
`51236c9` required-mode agent gate + compaction/flood proofs ·
`eefdbdc` operator admin GUI + browser acceptance · `54d883e` waiters
release sessions between polls + GUI advanced limits · (fixes) bootstrap
on every start / head-agnostic app-role assertion / r01 env order ·
per-lifespan CORS origins + browser-gate generalization.

Receipts (each personally run on this final code, revision at commit
`HEAD` at writing; disposable PostgreSQL 16 containers, run-owned):

- Fast default: `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD
  PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -ra -p
  no:cacheprovider` — exit 0: **647 passed, 0 failed, 0 skipped,
  325 deselected, 6 warnings** (~83 s). The 4→6 warning increase is the
  new `on_event("shutdown")` handler and its framework wrapper — both
  `on_event` DeprecationWarnings; the stack-wide lifespan migration is
  out of plan-19 scope and harmless.
- `agent` gate: `…/acceptance.py agent` — **PASS**, 35 passed / 0 failed
  / 0 skipped / 937 deselected (32.6 s). New required-mode layer
  (marker + exclusion + `SR_REQUIRE_AGENT` + selection coverage): real
  SDK wire against the scripted OpenAI-compatible server, one-slot
  serialization proven AT THE PROVIDER (max_concurrent==1), auth-header-
  only credentials, rotation→visible 503→explicit rebind, unique-running
  index, priority/FIFO claims, cancellation obligations (queued un-run;
  running keeps the slot until return), cessation_unknown reconcile,
  bounded visible retries, compaction checkpoint covering a range (next
  request resumes from the summary; raw bulk never resent), 200k flood
  bounded on the wire, probe-is-a-queue-member.
- `db` gate: **PASS** — 209 passed / 0 failed / 0 skipped, 763
  deselected (514.8 s) including all plan-19 db-layer suites plus the
  previously-green stage5/r01/app-role regressions on the jobs path.
- `authority` **PASS** 35/0/0 (25 s); `containment` **PASS** 26/0/0
  (20 s); `python` **PASS** (fresh locked env, 4 entrypoint imports);
  `selection` **PASS** (972 tests classified incl. new `agent` layer);
  `frontend` **PASS** (next build + zero high/critical audit).
- `browser` gate generalized to the whole layer: **PASS** — 2 passed / 0
  skipped (99.6 s): the stage5 workflow+replay AND the plan-19 admin GUI
  (members refused; created credential never reappears in DOM or rendered
  text; rotation v2-active/v1-retired; probe job row SURVIVES reloads;
  GUI cancellation resolves as a visible obligation).

Full-run gate passes exposed three real defects, each repaired at the
source, never by weakening an invariant:

1. **Bootstrap behind the controller lock** — a process that lost the
   advisory-lock race (or started while a predecessor's shutdown still
   held it) served NO model profiles (red turns 503, hints queued
   nothing). Profile bootstrap is idempotent and race-safe (unique
   indexes pick winners; losing first-start rolls back) and now runs on
   EVERY start; crashed-live reconciliation stays controller-only.
   (`tests/test_app_role_live.py`'s migration-head literal became
   head-agnostic; the chain guard still pins the exact head. `r01`'s
   env must precede the settings build that bootstraps — the
   frozen-at-bootstrap contract production relies on.)
2. **Middleware stack (CORS origins) built once per process** — the
   second lifespan silently refused the new web origin (login "Failed
   to fetch" only when two real-browser tests shared a process).
   Startup now rebuilds the stack per lifespan; production reads at
   boot unchanged.
3. **Controller advisory lock leaked on graceful exit** — it previously
   lingered on the pooled connection until process exit, which had been
   silently skipping startup duties/bootstrap on the 2nd+ TestClient in
   a process. `_shutdown` now releases it (crash safety unchanged).

Not claimed: the deployed-Strata compatibility check (operator Manual
check); the scripted fake proves protocol shape, not a live provider;
gateway-era `test_pilot_sustained_attacker` covers the in-process
gateway class (retained untouched) — the HTTP admission path is covered
by the agent gate instead.

## Plan-18 second review round — 2026-10-25, branch `practice-upgrades-18-21`

The independent re-review at `41d8df9` returned **FIX** with six
findings. The reviewer independently reproduced the round-1 totals
(fast 625/0, install/authority/containment/images/db green, the original
wrong-digest probe UNKNOWN, 73 hostile pin cases refused) — those
receipts stand — but showed the existing gates did not cover six real
defects, so plan-18 criteria 5 and 7 were FAIL at that base:

1. **HIGH — same-digest pin edits rewrote an existing session's
   verified score.** Scoring re-read the CURRENT pin file's content
   hashes each build; editing only `pins[role]['files']` (role/template/
   digest untouched) turned the persisted FAILED 0-point verdict into
   PASSED 10 points when re-scoring the same stored guest bytes.
   Repaired (`e20604a`): the clean baseline (files + integrity reference
   + version) is FROZEN into the immutable deployment resource at clone
   time, before any scoring uses it; scoring reads only that frozen,
   integrity-gated version. A post-launch pin document can only REVOKE
   (identity drift or absence ⇒ UNKNOWN — trust degraded, never
   redefined); it can never adopt new hashes for an existing session.
   Historical/absent/corrupt freezes stay UNKNOWN; baselines are
   per-session isolated.
2. **MEDIUM — artifact identity was not confirmed by the clone
   authority.** The API re-read the on-disk manifest at deploy time
   while the broker verified images against its own separately loaded
   manifest; the reviewer made the backend verify A while the API
   recorded B. Repaired (`e20604a`): `artifact_for_template` answers
   over the typed broker boundary from the broker's own loaded manifest
   (whose SHA-256 the clone-image verification enforces), the service
   validates the shape, and no manifest path, secret or libvirt access
   crosses. Adapters without artifact manifests answer None — honest
   UNKNOWN, never a guess.
3. **LOW — schema `true`/`1.0` accepted as version 1** (Python
   equality). Repaired (`e20604a`): explicit non-bool integer schema
   required at the document top level AND per pin; hostile matrix
   extended; every such document behaves exactly like an absent one.
4. **HIGH — the supervisor's required directory was never
   provisioned.** `sr-worker-supervisor.service` requires
   `ReadWritePaths=<state>/worker` (no `-` marker, no `StateDirectory=`)
   while `_ensure_dirs` never created it; the parent 0751 is traversal
   only. Repaired (`cd19b1d`): dedicated 0750 `srworker:srworker` entry
   provisioned exactly once (drift-repairing), and the unit is rendered
   with `ReadWritePaths` bound to the configured state path
   (byte-identical for the default layout).
5. **HIGH — the provisioned Node binary was not the unit binary.**
   `ensure_node_runtime` installed the pinned 22 under
   `/usr/local/lib/nodejs` while `sr-web.service` exec'd `/usr/bin/node`
   — fresh Ubuntu's Node 18 stayed the production runtime behind green
   provisioning/probe checks. Repaired (`cd19b1d`): `node_runtime_plan`
   selects ONE binary; the build (front of PATH), the actual
   `ExecStart` and the per-UID verification name that exact path;
   provisioning never clobbers a foreign `/usr/local/bin/node`.
6. **HIGH — the artifact-resolver setting was never supplied to the
   API.** `render_control_env` emitted no `SR_APPLIANCE_MANIFEST_FILE`,
   and the existing db tests monkeypatched the missing setting away.
   Repaired (`e20604a`) at the root: the setting and the on-disk
   resolver are DELETED (finding 2 makes them unnecessary — the API
   needs no manifest access); tests drive renderer → real Settings →
   real deploy flow with no patch of a nonexistent knob.

Quality: `tls_readiness_problems` is now documented as POSIX
permission-bit math (not installed-service access proof); installed-
systemd/TLS/AppArmor/KVM limits stay explicit.

Exact automated attempts on the corrected tree (same container: Debian
13, **no `/dev/kvm`**, no root, docker available; warm image cache):

- `.venv/bin/python -m pytest -q -ra -p no:cacheprovider` (no DB admin)
  — exit 0: **646 passed / 289 deselected / 0 failed / 0 skipped /
  4 warnings**, 75.7 s (+21 tests: frozen-baseline, boundary, worker-
  dir, node-runtime regressions).
- `infra/dev/acceptance.py install` — **PASS after 7.4 s**: real
  sequences (clean=18 files, rerun=0 changed, upgrade=1, drift repaired)
  with the worker directory and the selected-runtime unit render.
- `infra/dev/acceptance.py authority` — **PASS: 35 passed / 0 skipped**,
  25.4 s. `containment` — **PASS: 26 passed / 0 skipped**, 21.1 s.
- `infra/dev/acceptance.py selection` — **PASS after 164.1 s**, every
  test classified (new files/marks included).
- `infra/dev/acceptance.py db` — **PASS**: exit 0, **190 passed /
  745 deselected / 0 skipped** in required mode (disposable PostgreSQL
  16), 511.4 s; owned DB resources and the fixture container/volume
  removed by the gate (re-verified: no `sr-acc*` resources remain).
  Includes the six rewritten broker-identity/frozen-baseline db-layer
  regressions plus every pre-existing DB scenario.
- `infra/dev/acceptance.py images` — **PASS after 312.3 s**: **19
  passed / 0 skipped** (software emulation, warm cache — not nested-KVM
  acceptance), DB fixture removed, no QEMU run-dir leaks. The web-local
  verify test exercises the PRODUCTION frozen-baseline injection against
  the deploy-recorded identity, including the same-digest pin-edit case
  (its pre-fix shallow-copy text made that assertion vacuous — one gate
  attempt failed on it before `89d38c0` made it real; this receipt is
  the committed tree).
- Reviewer reproductions now proven by test: at the fast layer
  (`test_plan18_cron_pins.py`) and through the REAL persisted
  `build_scorecard` with synthetic guest replies on disposable
  PostgreSQL (`test_plan18_deploy_artifact.py`) — same-digest pin edits
  never turn bad content clean (absent pins then degrade to UNKNOWN);
  config drift records the broker's manifest A, not the replaced
  on-disk B; absent/corrupt/historical baselines and unknown templates
  stay UNKNOWN; per-session frozen baselines are isolated; hostile
  identities at the boundary are refused without crash; selection,
  ExecStart, build and probe name ONE Node binary, foreign symlinks
  survive, and the worker directory is provisioned, identity-bound and
  drift-repaired.

Open gates unchanged (operator, NOT claimed): `packet` (root+`nft`),
`journey` (installed appliance), installed UID/TLS/boot/KVM rechecks,
AppArmor `9e03696` adversarial qualification, and — in THIS worktree —
the libvirt-debs-backed `hypervisor`/`access` rechecks are **NOT PASS:
the fixture is absent**, so the changed broker/identity surfaces have
no hypervisor-level re-execution receipt here.

### Independent acceptance (2026-10-25): SOFTWARE acceptance at `c58ef6a`

The parent independently RE-RAN everything at `c58ef6a` (source
remained `c58ef6a`; all owned fixtures cleaned) and returned **VERDICT:
SHIP — milestone-18 SOFTWARE acceptance passed all 7 criteria**: fast
**646 passed / 289 deselected / 0 skipped / 4 warnings**, 76.40 s;
install **PASS** 11.2 s (fresh=18 files, rerun=0, drift repaired);
authority **35 passed / 0 skipped** (27.8 s); containment **26 passed /
0 skipped** (23.5 s); images **19 passed / 0 skipped**, 315.5 s TCG warm;
db **190 passed / 745 deselected / 0 skipped**, 496.0 s. Additional
independent probes: persisted file-backed scoring **2 passed / 7.35 s**
(same-digest malicious baseline edits remain FAILED 0 points; frozen
clean stays 10; absent/corrupt/revoked/late pins UNKNOWN 0); real
peer-UID Unix artifact RPC returned broker manifest A after the on-disk
B swap; 77 hostile parser cases refused; worker-directory 0777→0750
drift repaired; Node unit/build/probe congruent; actual installed wheel
migrate/status/rerun at 0019-head passed.

This is **SOFTWARE acceptance ONLY**: installed systemd/UID/TLS reality,
AppArmor `9e03696` adversarial qualification, the libvirt-fixture
hypervisor/access rechecks, `packet`, `journey`, and the real
appliance/model gates stay explicit pending limitations. Milestone 18
is ticked for its software gates with those limitations retained.


## Plan-18 review round — 2026-10-24, branch `practice-upgrades-18-21`

The independent review of the section below (at base `168a9e1`) returned
**FIX with seven findings**. Two were substantive: the firewall loader's
`ExecStop` deleted `inet sr_appliance` on unit stop while guests were
alive (HIGH — removing the isolation the unit exists to guarantee), and
cron-pin trust keyed on template ID alone, which let a wrong-digest pin
PASS the real verifier (the criterion-5 gate had therefore passed for
the wrong artifact; its old claim of "digest + template binding" in the
runtime was an overclaim — only the pure helper was digest-aware).
The five others: malformed pin values crashed scoring (TypeError);
shared-temp predictability (Node tarball fetched through `/tmp` as root;
`$TMPDIR` alembic-config cache trusting planted content); blanket TLS
chmods left every service identity unable to read what its own unit
served, the bastion anchored on a CA that never signs the API surface,
and `_ensure_dirs` fought twice over the shared state directory while
0750 blocked the pin readers it documented; plus the firstboot report's
JSON claimed `ok` while pending, and a module-import key leak in tests.

All seven repaired with behavioral regressions in `806d239` `71812ea`
`d33dccd` `e6bf1b9` `fe55f0d` `6dfe245` `57ff8f7` `dfaa954` — decisions
superseded and corrected are recorded in the architecture ("Plan 18
review-round decisions"). Cancellation of the first correction attempt
was the user's action, not an independent failure; this section records
the completed pass.

Exact automated attempts on the final tree (same container: Debian 13,
**no `/dev/kvm`**, no root, docker available; image cache warm):

- `.venv/bin/python -m pytest -q -ra -p no:cacheprovider` (no DB admin)
  — exit 0: **625 passed / 286 deselected / 0 failed / 0 skipped /
  4 warnings**, 72.3 s (same four pre-existing warnings; +21 tests over
  the pre-review count, all review-round regressions and pins).
- `infra/dev/acceptance.py install` — **PASS**: the real sequences with
  the corrected per-file TLS bootstrap (ingest pair `root:sringest 0640`,
  group default fails loud at chown), single-owner state directory, and
  bootstrap-reissue/rotation preservation checks.
- `infra/dev/acceptance.py authority` — **PASS: 35 passed / 0 skipped**
  (was 32; +3 real-service shutdown-drain regressions: drain with active
  claims stops-with-read-back and latches, idle drain never latches,
  cessation blow-up never propagates).
- `infra/dev/acceptance.py containment` — **PASS: 26 passed / 0 skipped**,
  no leaked run-owned cgroups.
- `infra/dev/acceptance.py images` — **PASS: 19 passed / 0 skipped**,
  309.3 s warm-cache (software emulation, **no `/dev/kvm`** — not
  nested-KVM acceptance). The web-local verify test now exercises the
  PRODUCTION injection (`with_cron_baseline` against the deploy-recorded
  artifact identity) instead of the digest-aware helper alone.
- `infra/dev/acceptance.py selection` — **PASS**, every test classified.
- `infra/dev/acceptance.py db` — **PASS**: exit 0, **187 passed / 724
  deselected / 0 skipped** in required mode (disposable PostgreSQL 16),
  489.3 s; owned DB resources and the fixture container/volume were
  removed by the gate. Includes the three new deploy-recorded-artifact
  regressions plus every pre-existing DB-layer scenario.
- Reviewer reproductions now proven by test: wrong-digest pin through the
  REAL verifier ⇒ UNKNOWN (was PASS); hostile pin documents (int/null/
  nested digests, bogus types) behave exactly like an absent pin, never
  crash; planted shared-temp content and a planted symlink at the old
  alembic cache path are ignored and left untouched; private staging
  cleaned on success and on digest failure.
- CORRECTION (second review, 2026-10-25): this section's claim that
  "post-launch pin replacement can only revoke, never forge" held ONLY
  for identity-drift replacements.  Scoring still read the CURRENT pin
  file's content hashes, so editing `pins[role]['files']` IN PLACE under
  an unchanged role/template/digest rewrote what counted as clean and
  turned a persisted FAILED (0 points) into a PASSED (10 points) on
  rescore.  Reproduced by the reviewer through the real
  `build_scorecard`, and repaired as described in the second-round
  section above.

Unchanged open gates (operator, NOT claimed): `packet` (root+`nft`),
`journey` (installed appliance), the installed UID/TLS/boot/KVM rechecks
— now additionally including the bootstrap per-file ownership and the
`ensure_tls` per-identity readability validation on the real appliance —
and independent adversarial qualification of the broader AppArmor
profile `9e03696`. Milestone 18 remains UNTICKED pending independent
re-review of this correction pass.


## Plan-18 implementation evidence — 2026-10-24, branch `practice-upgrades-18-21`

Source repairs for the retained live-practice defects (installer/bootstrap,
latched teardown/recovery, bounded SSH, firewall persistence + headroom,
trusted cron pins, installed `rangectl`). Commits `2a162d9` `923f4ff`
`20d8d46` `d70762b` `d6723ee` `d7b8d5b` `9885f87` on top of the separately
committed memory fix `0fac623`. No live appliance, model endpoint, outer
Proxmox or global firewall/AppArmor change was touched; no commissioning
receipt was rerun.

Exact automated attempts in this container (Debian 13, **no `/dev/kvm`**,
no root, docker available):

- `.venv/bin/python -m pytest -q -ra -p no:cacheprovider` (no DB admin,
  `SR_PG_ADMIN_*` unset) — exit 0: **604 passed / 280 deselected / 0 failed
  / 0 skipped / 4 warnings**, 73.7 s (same four pre-existing warnings).
- `infra/dev/acceptance.py install` — **PASS**: real sandbox sequences
  (clean 18 files, rerun 0 changed, upgrade, drift+repair) plus identity
  contracts including the new root netrules loader unit, and the install
  gate's managed-service note stays the operator's.
- `infra/dev/acceptance.py authority` — **PASS**: 32 passed / 0 skipped,
  including the seven new cessation/resolve regressions (latched positive
  identity destroy, foreign/unknown retention, audited
  `brokerctl resolve` read-back refusals and proofs).
- `infra/dev/acceptance.py containment` — **PASS**: 26 passed / 0 skipped,
  no leaked run-owned cgroups; adds five adversarial negatives driven from
  INSIDE the real boundary (cross-op discovery, cross-op signalling with
  the known host PID, supervisor survival, state-mask and cgroup-reroot
  visibility).
- `infra/dev/acceptance.py db` — **PASS**: 184 passed / 0 skipped against
  the run-owned disposable PostgreSQL 16, including the new installed-CLI
  test (real `rangectl db migrate` then `status` reaching `(head)` from a
  site-packages-style copy executed OUTSIDE the checkout, plus idempotent
  rerun); owned DB resources and the fixture container verified removed.
- `infra/dev/acceptance.py selection` — **PASS** (every test classified;
  fast default infrastructure-free).
- Installed-package criterion additionally shown by the fast
  `tests/test_plan18_installed_cli.py` tree-copy/pure-installed layouts
  running real `alembic history` from a foreign CWD (fails against the
  pre-repair config with the historical path error).
- Recovery read-back acceptance: `test_recovery_resolve_requires_rechecked_backend_absence`
  (stale/mismatched evidence cannot release; backend re-read decides) plus
  the new authority resolve regressions (presence, uncertainty and
  non-foreign identity each REFUSE and stay open, audited). No SQL or
  ledger editing path exists or was added.
- `infra/dev/acceptance.py images` — **PASS** (2026-10-24): 19 passed /
  0 skipped, 1729 s, run-owned disk-backed cache (base image downloaded in
  that run; **no `/dev/kvm`** — all boots are software emulation and are
  labelled as such, not nested-KVM acceptance). The extended web-local
  verify test captured the cron pin from the clean verify boot's serial
  marker and asserted digest + template binding (wrong template, wrong
  role, rebuilt digest and tampered documents all yield NO trust) plus the
  pin-document round-trip; absent/tampered-pins-never-pass is proven by
  *(corrected by the review round above: that run's RUNTIME honoured pins
  on template ID alone — digest awareness existed only in the unused
  helper, so the wrong-artifact PASS was real; fixed in `e6bf1b9`.)*
  `tests/test_plan18_cron_pins.py` against the real verifier v3 (clean +
  matching pin → passed; content-tampered file → failed deterministically;
  no pin → UNKNOWN).
- `infra/dev/acceptance.py packet` — **NOT RUN here (prerequisite)**: needs
  root and `nft`; fails closed naming them. Operator gate, unchanged.
- `infra/dev/acceptance.py journey` — **NOT RUN here (prerequisite)**:
  needs the INSTALLED appliance with the member SSH key and browser login.
  Operator gate, unchanged.
- Installed adversarial AppArmor profile qualification for the broader
  profile `9e03696`, the installed UID/TLS/boot/KVM rechecks affected by
  these changes and any reboot rehearsal stay **Manual checks** (operator).
  Software negatives above are NOT certification of that profile.

Cron pins have no effect until the release build places
`/var/lib/sparring-range/cron-baselines.json`
(`python3 -m infra.images.cron_baseline capture --role ROLE --tree TREE
--image IMAGE --template-id ID --out ...` per rebuilt role, or the
verify-boot marker path); absent pins the cron check stays UNKNOWN, which
the new fast tests prove is still never a pass.


## Upgrade planning baseline — 2026-10-24, branch `15`

The user approved plans 18–21. The existing memory repair was subsequently
committed separately as `0fac623`; it is not deployed. No upgrade implementation
or new live acceptance is claimed.

At docs revision `a74363c` with the pre-existing uncommitted memory filter and
`tests/test_agent_memory_selection.py`, user approved infrastructure-free checks:

- `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -ra -p no:cacheprovider`
  — exit 0, **571 passed / 267 deselected / 0 failed / 0 skipped / 4 warnings**,
  80.66 s. Warnings: FastAPI startup hooks (2), transport class collection (1),
  synchronous test asyncio mark (1).
- Same environment prefix with `.venv/bin/python -m pytest tests/test_agent_memory_selection.py tests/test_worker_progress_regressions.py -q -ra -p no:cacheprovider`
  — exit 0, **37 passed / 1 deselected**, 0.20 s.

No DB, selection gate, model, appliance or guest operations. Earlier background
DB/selection commands were **cancelled by the user**, not independent failures;
they were not restarted for this baseline. These checks validate current source
behavior, not future upgrades or installed Strata compatibility. Both cancelled
gates may be run later when authorized acceptance needs them.

## Consolidated deployment and product status — 2026-10-23

This section supersedes intermediate status in the **67 Project Knowledge notes**
migrated on this date. Operator receipts are observed evidence, not a fresh rerun.
No tests, live operations or image builds were run for this documentation cleanup.
The build checkout is not the Ubuntu appliance. **Commissioning checks for the
supervised AI run were completed; do not reopen them merely because broader
release acceptance and defects discovered during practice remain outstanding.**

### Completed commissioning and deployment receipts

Ubuntu 24.04 appliance: `sr@10.10.10.105`, `/opt/sparring-range`. Original
verified bundle `b1ea58bfe246e41bda920401d40ac24a851d2983` had 307 files/four
images. The installed system is now patched, not byte-identical to that bundle.
Inner 200/201 are disposable libvirt guests, not outer Proxmox VMs. Outer
management is `192.168.86.83`; the operator has **no NAS**.

- **Readiness/SSH/replay completed:** real attacker/web guests reached enforced
  readiness. Member `sr` used pinned bastion SSH, reached `defender`, ran
  `whoami`, `hostname`, `sudo -n true`, logged out and viewed the recording in the
  browser. After enrolling a Bitwarden Ed25519 public key, Linux login with a
  local private-key file also succeeded (session prefix `c83edd83`). Earlier
  Windows public-key refusal is not a current general SSH blocker; the Windows
  agent itself was not subsequently verified.
- **Reboot completed:** custom firewall, broker, API, ingest, bastion, supervisor
  and web were active after reboot; appliance nft rules and the durable API latch
  persisted. Readiness showed schema 0019, controller held, no issues.
- **Scoped isolation completed:** identified attacker reached ingest
  `10.66.0.1:8443` and practice HTTP `10.66.0.10:80`. TCP to inner `.1:22/8000`,
  appliance `.105:22/443`, model `.197:8096`, outer Proxmox
  `192.168.86.83:22/8006` and WAN `1.1.1.1:443` timed out (2 s). Temporary
  guest default route was removed. WAN ping: 2 sent/0 received; DNS lookup: no
  addresses; explicit UDP DNS query: timeout. One synthetic spoofed IPv4 UDP
  frame incremented input DROP to 1 packet/28 bytes; one IPv6 UDP frame to
  1 packet/48 bytes. These are the tested cases, not an all-protocol claim.
- **API/broker VM stop completed:** running guests in session `1a125149`
  stopped via authenticated killswitch, independently reconciled stopped with no
  obligations/intents. Later session `5b75c2cb` had active harmless operation
  `1f0cc8002f03415ba0850fa36ea46734`; killswitch stopped both guests and independent
  system-libvirt readback showed both shut off. This proves command cessation
  through VM shutdown, not full AI-worker cancellation (worker/operation action
  lists were empty). Local SSH waiting after guest shutdown did not refute it.
- **Independent control-loss watchdog completed:** with actual API lease
  armed/fresh (4.2 s) and both guests running, stopping only API left broker alive;
  at `control-lease-expired (age 33s)` both guests stopped, no obligations/intents.
  This was neither idle expiry nor an API-kill call.
- **Real runner cancellation completed:** after `5930c9d`, pinned SSH as
  `srworker` ran `sleep 120`, operation `cb8e7625b73c439c9fb9f1e17cc4f7c2`.
  Containment was confirmed running before cancel; cessation confirmed, zero of
  one unconfirmed, remote state gone and host thread exited. Earlier namespace
  refusal/not-found attempts were not passes. Full AI-worker/inference-request
  cancellation is a distinct broader gate, not a reason to repeat this check.
- **Model/first-run dispatch observed:** direct authenticated benign request to
  `http://10.10.10.197:8096/v1`, alias `qwen-3.8-flash-next`, returned `OK` in
  about 1 s. Subsequent supervised runs established actual API/worker/SSH dispatch.
  Large cached 140k+ requests on this shared model server belonged to a different
  coding project; do not attribute its whole dashboard to this range.
- **Scoped recovery completed:** exact owned guests were hard-stopped/destroyed,
  absence independently confirmed, leases disarmed, then authenticated API End
  released app reservations (including session `2afbc6a0`). No direct SQL used.
  Successful zero-obligation recovery does not repair normal teardown semantics.

### Patch installed and latest practice findings

Operator installed the 16-file patch, runtime
`52ae3551ca057d33673bb38a9bd52eb7c4ebedf7`, at 16:05 on 2026-10-23. Hash/size
are in [the handoff](HANDOFF-LIVE-PRACTICE.md#deployment-boundary). Preflight
verified archive paths/hashes/content/Python compilation, quiet broker and no
active runs/executors or running/finalizing/interrupted matches. Backup (0600):
`/var/lib/sparring-range/patch-backups/before-practice-repair-20261023-160507.tar.gz`.
`npm ci` and Next 16.4.2 build passed, audit zero; API/supervisor/web restarted
active, health `ok:true`. No images, credentials, firewall or migrations changed;
broker/ingest/bastion were not restarted by the patch.

First supervised session `91553aeb-b0d9-4a3c-86fe-32efff9b9519` (red prefix
`47eb0520`): intent 23171/result 23173, operation
`b5c3ea8cbd5545bba74771a44a23cb10`, exit 127/missing executable. User redacted
its name; do not infer nmap or install tools automatically. Saved hints 23496/23497
were empty. Cron verifier 23231 mistook maintenance `e2scrub_all`/`sysstat` for
persistence (zero points), and coverage displayed 104.5%. Source repairs and their
separate passing gates are below; exact original worker-stall exception unknown.

Patched run prefix `76499df5` executed **eight real commands, exit 0**, but repeated
tool discovery, the HTTP page and ports 22/80. Compression repeatedly failed at
checkpoint 23964 with HTTP 502 and 2048-token limit hits. Raw telemetry displaced
useful agent context; failed compression refreshed activity without useful
progress. A later summary succeeded, but thinking used 2000+ tokens and barely
left answer room. `ping` EPERM is restricted-runner capability, not broken HTTP;
do not grant root/capabilities to fix it. The local model has approximately 262k
context; small output budgets are resource controls, **not containment**.

At this checkpoint uncommitted/undeployed narrow memory filtering was in
`srplatform/red_agent/loop.py` and `tests/test_agent_memory_selection.py` (previous
focused result: 66 passed/24 deselected; not rerun here). Preserve it separately
from documentation. It is not the full conversational-engine replacement.
Subsequently committed as `0fac623` after the 2026-10-24 fast baseline; not deployed.

### Permanent release repairs still required

Operator workarounds are not durable source/release fixes. Preserve real service
identities, unrelated applications/history and disk space; no repeated full
rehearsals or large image rebuilds without a specific need/approval.

- **Installer:** TLS receives `IPv4Address` in subprocess env (operator bypass
  converted to string); bare `systemd-sysctl` lookup fails (manual service/unit/
  nginx completion succeeded); `deploy/hand_off.sh` executes an uncommented usage
  line before `set -e` (bash syntax check misses it); empty model key is validated
  before credential provisioning; firstboot runs before advertised manual steps.
  Native provisioning lacks supported Node (Ubuntu supplied 18.19.1; operator
  installed 22; Next requires >=20.9) and compatible distro libvirt bindings in
  the isolated venv. Use narrow same-ABI binding exposure, not broad system site
  packages. Verify import/listener/application readiness, not Type=exec uptime.
- **Runtime/storage:** `.venv` root-only 0750 traversal caused 203/EXEC, likely
  hand-off umask 027. Explicit dependency runtime modes and per-UID execution
  checks needed. Root disk was 61G/47G free before transfer; images ~10G logical
  versus ~4.5G source allocation: preflight headroom, avoid redundant copies.
- **Permissions/trust:** both control-plane env files stay `root:srrange 0640`,
  never public. Ingest TLS pair `root:sringest 0640`; bastion credential
  `root:srbastion 0640`; public CA/HTTPS certs readable, private keys unchanged.
  Bastion public nginx trust differs from internal API CA. Give narrow parent
  traversal, dedicated worker dir and recordings access (including API), not
  broker-group membership. Public runtime host pins must be writable under state,
  not read-only `/etc`, consistently across readers. Never fake pins/bypass SSH
  verification. Inaccessible home cwd can cause settings PermissionError without
  a missing install. Never print env or deployment resources containing secrets.
- **Configuration:** permanently render reachable LAN bastion `.105:2222`, not
  unassigned range `.2`; wire the model key to API only. Installed API overrides
  work but do not fix generator provisioning.
- **Firewall:** `21ad727` fixed set references/first-run own-table handling,
  spoof/IPv6 checks before conntrack and range exclusion from management allows.
  Live parser/apply/new SSH and reboot passed; ship the operator-created dedicated
  own-table loader plus broker dependency. Do not enable distro flush-ruleset
  defaults, modify outer-PVE rules or overwrite unrelated tables.
- **Focused source fixes retained:** `f1eafab` broker-safe model-secret validation
  (13 focused passed); `9b1744d` narrow numeric QEMU storage ACLs (35);
  `712f69f` attacker management-public-key/account correction (36); `cff590f`
  deferred broker/heartbeat wiring and API-owned durable safety directory
  (43 passed/2 deselected/2 warnings). Source tests alone were not installed gates.
- **Namespace/cgroup:** `f321b39` repaired invalid/missing AppArmor load and
  fail-closed attacker-UID checks (34 focused passed); `5930c9d` moved delegation
  to attacker user slice/linger, never global cgroup-root writes (57). Function
  subsequently passed live. Broader profile `9e03696` still needs independent
  adversarial security acceptance; do not disable AppArmor/userns or use root.
- **Recovery:** End for `5b75c2cb` returned `ok:false`, `status:complete`,
  `lease_released:false`; destroys HTTP 423 while cessation latched. Need safe
  teardown/recovery under latch, exact ownership/absence checks and truthful UI
  cleanup state, not blanket latch bypass. Offline workaround required broker
  identity/supplementary libvirt/KVM groups; plain `sudo -u` was insufficient.
  Diagnostic SSH needs stdin DEVNULL/bounded keepalives; host transport liveness
  is not guest cessation. Outer-appliance power-off remains the operator fallback;
  these receipts do not establish an observed power-off rehearsal.
- **Scoring/practice:** trusted clean image-bound cron hashes still absent;
  UNKNOWN is correct, never learn pins from compromised guests or trust filenames.
  Sustained useful AI, useful hints, both full presets, AI-worker stop and
  server-side inference-slot cancellation need acceptance; uptime is not progress.

### Coaching, navigation and replay

AAR narrative mistook verifier/management hex-Python and `crontab -l` for
suspicious activity and recommended failure despite deterministic UNSCORED.
Require authoritative actor/tool provenance and semantic grounding, not merely
existing citation IDs. Most report structure is deterministic; optional narrative
is AI-produced. AAR generation is not agent-memory compression. UNSCORED may mean
no scorecard before finalization, not automatically broken telemetry.

Homepage is login-only; active/recent session cards/history are missing. Reports
and replay lack useful return navigation, Markdown is literal `<pre>`, and replay
floods pre-recording MOTD/provisioning events. Defender bastion casts exist; API
explicitly has no AI-worker cast. Existing action intent/result evidence supports
attacker command/output step-through, not invented historical PTY recordings.
Preserve raw audit and enforce competition visibility in APIs, not only UI.
Agreed future model/admin/session UX requirements are in the architecture.

### Legacy reconciliation and note coverage

The 2026-10-16 direct-PVE fix list is historical, not appliance instructions.
Non-editable `rangectl db migrate/status` root/config lookup: REPAIRED and
installed-accepted 2026-10-24 (`_alembic_config` absolute-path materialization;
fast + db-layer acceptance in `tests/test_plan18_installed_cli.py`). Runbook
conflict markers are absent on inspection. Separate-ingest-unit wording:
reconciled by inspection 2026-10-24 — the appliance has always rendered its own
`sr-appliance-ingest.service` (installer UNITS + runbook §install); the legacy
wording belongs to the superseded 2026-10-16 direct-PVE notes only. Ref-only
recovery is obsolete: 9100/9101 destroyed, lease disarmed; do not resume them.
`Ledger.resolve_obligation` tooling gap: CLOSED 2026-10-24 — confirmed latched
destroy resolves cessation-class obligations in `infra/broker/service.py`, and
`brokerctl resolve` (`infra/broker/tools.py`) resolves foreign/recycled
obligations only on independent backend read-back, audited either way. Deferred local pin fallback, source-text test replacement,
install-layout policy and PVE ACL cron suggestions are not approved new appliance
scope; never silently weaken pinning. Existing historical plan checkboxes are not
advanced by this cleanup.

Migration coverage: AI/framework/UI requirements → architecture and this section;
source-repair/installation/first-run notes → patch receipts and handoff;
runner/recovery/isolation/watchdog notes → scoped completed checks and repairs;
earlier bootstrap/commissioning notes → identity, trust, native/runtime, firewall
and configuration backlog; original two fix lists → installer/legacy reconciliation.
Repeated intermediate pending states are superseded by later scoped outcomes.
All 67 notes are covered; the backlog todo and ten existing plans are retained.

## Supervised live-practice repair — 2026-10-23, branch `15`

Runtime source revision: `52ae355` (after `5930c9d`); handoff:
[`HANDOFF-LIVE-PRACTICE.md`](HANDOFF-LIVE-PRACTICE.md). **Subsequently installed
by the operator (receipt above); not full release acceptance.** Agents worked on the build checkout, not the Ubuntu
appliance. The observed first run dispatched one missing-executable command;
blank saved hints and a cron maintenance false positive were genuine defects.
The exact installed worker-stall exception was not obtained.

Baseline: the documented no-admin fast command exited 1, **448 passed / 1 failed /
262 deselected / 4 warnings**, 80.25 s. The warning-text regression was repaired
without changing emergency safety behavior. Current source fixes include bounded
role budgets, explicit completion rejection, retained worker failure reporting,
truthful tool availability/progress/uptime, and content-aware cron verification.

| Command from repository root | Observed result |
|---|---|
| `.venv/bin/python infra/dev/acceptance.py selection` | **PASS**, 127.7 s; all 834 tests classified; fast default **567 passed, 0 skipped, 267 deselected**. Its deliberately missing-containment, missing-DB and empty-selection probes fail as required. |
| `.venv/bin/python infra/dev/acceptance.py db` | **PASS**, 183 passed / 649 deselected / 0 skipped, 471.8 s; disposable PostgreSQL 16. No run-owned test databases/roles remain; fixture container/volume removed. |
| `.venv/bin/python infra/dev/acceptance.py authority` | **PASS**, 25 passed / 803 deselected, 24.4 s at the earlier repair working tree. No broker capability was widened. |
| `.venv/bin/python infra/dev/acceptance.py containment` | **PASS**, 21 passed / 808 deselected, 9.9 s at the earlier repair working tree; real namespace/migration controls pass, no run-owned cgroups leaked. This does not certify the installed Ubuntu AppArmor profile. |
| `.venv/bin/python infra/dev/acceptance.py frontend` | **PASS**, 10.0 s; lockfile-faithful install/build and production audit: 0 critical/high/moderate/low. Final browser rerun rebuilds the later UI text/error change. |
| `.venv/bin/python infra/dev/acceptance.py browser` | **PASS**, 1 passed / 0 skipped, 52.9 s; real Next/browser/API/disposable PostgreSQL, with labeled model/runner doubles. Tests blank-hint reload, filtered event details, stopped-worker controls, ordinary cleanup and replay. |
| `.venv/bin/python -m pytest -q -ra -p no:cacheprovider tests/test_cron_baseline_regressions.py tests/test_uptime_coverage_regressions.py` | **PASS**, 51 passed, 0.51 s; includes the actual bounded cron probe on disposable files and registry-failure fail-closed behavior. |

Additional disposable-DB repair selection: **18 passed / 42 deselected**, 29.42 s
(live attacker projection, rejected narrative, failed model completion, actual
runner ingest, M3 and supervisor fencing); fixture cleanup `[]`. Three failing
legacy fixtures were then corrected and independently rerun: **3 passed**,
12.45 s, fixture cleanup `[]` (cron polarity, CLI/HTTP practice, generation/slot
uptime). Neither selection contacts the deployed appliance/model.

Independent read-only review of `5930c9d..52ae355`: **VERDICT: SHIP** for this
diff only, with no concrete actionable regressions found. Narrow regression run:
**118 passed / 5 deselected**, 2 warnings. This is not deployed/root-cause or
release acceptance. The source was committed without a push; the later operator
installation is recorded above.

Diagnostic attempts are not hidden: the first full DB run was **179 passed /
3 failed / 646 deselected**, 467.88 s. Two doubles recognized obsolete `ls` cron
output; one inserted a fake deployment ID and four same-slot samples. Updated
fixtures retain clean/compromised polarity and append-only assertions, supplying
trusted pins before the immutable snapshot and genuine generation/time slots.
An earlier outer-tool 120 s timeout aborted a DB attempt; its exact run-owned
container/volume were verified by label and removed. One browser attempt raced
`npm ci` in another gate and failed its prerequisite; later runs are serialized
against dependency installation and pass. An escaped-JSON browser assertion was
also corrected to inspect decoded browser text.

The original Next 16.4.0 build/audit newly reported three advisories: image
optimization SVG RCE (`GHSA-2464-fhr4-w9xw`), App Router Server Actions DoS
(`GHSA-p3m5-59mp-jv5r`) and cached typed-array RCE (`GHSA-673q-mjm6-r5xr`). This
Pages Router app does not use App Router Server Actions or `use cache`; absence
of those features is not proof the image endpoint is unreachable. Applied the
available same-major **16.4.2** patch, not a blind major audit fix; audit is zero.

**Still open:** trusted image-bound cron pins (missing pins yield UNKNOWN),
permanent post-killswitch teardown/latch recovery, adversarial installed AppArmor
acceptance and useful sustained real-model behavior. Public-key enrollment and
Linux SSH subsequently succeeded; Windows-specific authentication is unverified.
Service-up samples are not AI effectiveness. The small source patch
is hash-verified, not a rebuilt/qualified sealed bundle. No roadmap promotion.

## Review round — 2026-10-21, branch `15` (after the independent review)

An independent reviewer read milestone 15 and returned **VERDICT: FIX** with
17 findings (six security/lifecycle, nine installation/integration, two
acceptance). Every finding that reproduced was fixed on this branch; the
fixes are listed in `docs/HANDOFF-15.md` ("The independent review round").

**Environment (unchanged from the milestone run):** Debian 13 container, no
`/dev/kvm`, no root, no installed appliance, unprivileged libvirt from
extracted Debian packages. Every guest boot is **TCG software emulation**.
The two operator gates (`packet`, `journey`) are reported **pending with
their exact prerequisite** by the aggregate — they are attempted, not
omitted.

| Command (from the repository root) | Result |
|---|---|
| `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD .venv/bin/python -m pytest -q -ra -p no:cacheprovider` | **413 passed, 0 failed, 0 skipped**, 261 deselected, 4 warnings (65.5 s) |
| `… acceptance.py selection` | **PASS** — every test classified; the fast default selects 413 tests with 0 skips |
| `… acceptance.py python` | **PASS** — fresh locked install, dependency check, 4 entrypoint imports (including `telemetry.shipper`) |
| `… acceptance.py db` | **PASS** (467 s) — 177 db tests against a disposable PostgreSQL 16 container, 0 skipped. The new regressions: the fenced supervisor callbacks, the guarded terminal transition, the unstarted queued run, the cross-UID stop that keeps the obligation until the supervisor reports |
| `… acceptance.py authority` | **PASS** — 25 broker boundary/durability/cessation tests |
| `… acceptance.py containment` | **PASS** — 21 tests, no leaked cgroups |
| `… acceptance.py install` | **PASS** — the real install sequences in a sandbox root **plus the new managed-service contract check** (`infra/dev/service_contract.py`): the identities, the environments each unit loads, the readability of every credential, the front door's routing and the TLS artifacts the bootstrap creates |
| `… acceptance.py hypervisor` | **PASS** (254 s, 2 tests) — real libvirt lifecycle/QGA/ownership/destroy and the live broker authority path over the real Unix socket. The gate needs the unprivileged session daemon: `sh .cache/libvirt-debs/start-session.sh` first, then `sh -c '. .cache/libvirt-debs/env.sh && .venv/bin/python infra/dev/acceptance.py hypervisor'` |
| `… acceptance.py access` | **PASS** (155 s) — the real guest: readiness marker, pinned host key, real SSH, the recording bastion's `.cast`, `sudo`, an interactive PTY with a recorded resize, a reconnect and the refusal of an unauthorized key |
| `… acceptance.py images` | **PASS** (1871 s, 18 passed / 1 skipped) — the role images build, boot, serve, seed, expose the documented flaws and take the fixes. The skipped test is a DB test that needs an explicit PostgreSQL admin. The **role artifacts are now carried by the release bundle** |
| `… acceptance.py bundle` | **PASS** (23 s) — the REAL bundle with the **role artifacts** (306 files, 4 images: the appliance base + attacker + mojang-web-local + mojang-web-db), every digest verifies, the operator's manifest renders from it with **absolute** image paths and the canonical template ids, and a tampered bundle is refused |
| `… acceptance.py frontend` | **PASS** (7 s) — lockfile-faithful `npm ci`, the production build, `npm audit --omit=dev` with zero high/critical findings |
| `… acceptance.py browser` | **PASS** (46 s) — the isolated real-browser workflow and its replay |
| `… acceptance.py compose` | see the aggregate below |
| `… acceptance.py packet` | **PENDING (environment)** — needs root and `nft`. The aggregate now attempts it and reports the exact missing prerequisite instead of omitting it |
| `… acceptance.py journey` | **PENDING (environment)** — needs the installed appliance, the member's SSH key, the pinned bastion host key and the browser login. The journey now requires all of them, drives a real browser and walks the incident (break → submission → decision) and refusal paths |

**What the review found and what changed** (the full table is in
`docs/HANDOFF-15.md`): the supervisor's callbacks were unfenced; the API
signalled a worker it does not own; the controller kept acting after its
lock's session died; the Unix-socket deployment never armed the control
lease; the match scheduler was disabled in production; the schema-owner
credential travelled in an environment every service loads; the database
bootstrap split the URL on `/` and never created the owner role; the ingest
certificate was skipped (`INGEST_SANS` missing) and the telemetry trust
anchor named a file the bootstrap never creates; the member's keys were
written in a format the bastion cannot read; the capability and the machine
keys were unreachable by the identities that use them; the frontend build
passed an argument the runner rejects, baked no API URL and nginx kept a
prefix the API does not serve; the guest NIC carried a VLAN tag the broker
policy refuses; the bundle lacked `verifiers/` and `telemetry/` and gave
every role the bare base image; the hand-off passed a flag the CLI does not
have and `apply` demanded the venv it creates; and the aggregate omitted
the operator gates while `install` and `journey` checked less than they
promised.

## Second review round — 2026-10-22, branch `15`

A second reviewer read the first round's fixes and returned **VERDICT: FIX**
again, with 13 findings. Every reproduced one is fixed (commits `dd88707`,
`d36264a`, `45064d0` and the bundle/image commits below). What changed:

* **The supervisor's callbacks the first round missed.** Three failure-report
  paths did not present the claim credential (the endpoint refused them with
  422, so a run stopped between the claim and the assignment stayed
  unresolved); the HTTP helper raised a bare `RuntimeError`, so the 409
  handler was unreachable; a late heartbeat could clear the *next*
  assignment's run id; and the final UPDATEs were not fenced by the claim
  hash, so a claimant whose run was reclaimed could mark the new claim's run
  failed and revoke its credentials. The assignment's state is now immutable
  and belongs to that assignment; every report carries the credential; every
  final UPDATE is fenced by the claim hash.
* **The controller lock.** The scheduler kept dispatching duties after the
  lock was lost: it is now fenced by the same ownership check and stops.
* **The installation.** The hand-off still passed `--range-bridge` (the CLI
  takes `--bridge`) and exited 2; the database bootstrap wrote its SQL to a
  root-owned 0600 file the postgres user could not read and terminated
  `\gexec` with a semicolon; the bastion and the ingest listener validated
  the API's supervisor capability and the API validated the bastion's dial
  key; the members were onboarded under the machine role names, so no person
  could authenticate; the key pair was validated *after* the copy, so a
  mismatched half was installed and a rerun accepted it; a dry run changed
  the capability's permissions.
* **The shipped artifacts.** The three role images referenced the build
  machine's deleted backing files. They are now flattened and self-contained,
  the bundle verifies that what it ships stands alone, and the bundle gate
  **boots a shipped image from the bundle** (through a throwaway overlay, so
  the released artifact is not modified) and proves it becomes ready.
* **The acceptance.** The aggregate exited 0 while mandatory gates were
  pending; the bundle gate accepted placeholder image bytes; the journey
  answered an incident before its window opened and mistook the login page's
  own heading for a successful login, and it echoed the member's password
  in its diagnostics.

| Command | Result |
|---|---|
| `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD .venv/bin/python -m pytest -q -ra -p no:cacheprovider` | **424 passed, 0 failed, 0 skipped**, 262 deselected, 4 warnings (66 s) |
| `… acceptance.py install` | **PASS** (7 s) — the real install sequences in a sandbox root + the managed-service contract check |
| `… acceptance.py bundle` | **PASS** (232 s) — the release bundle (306 files, 4 images) verifies in place, the operator manifest renders from it, **the shipped `mojang-web-local` image boots from the bundle and becomes ready** (TCG), and a tampered bundle is refused |
| `… acceptance.py db` | **PASS** (467 s) — 177 db tests, 0 skipped (the fenced callbacks, the guarded terminal transition, the cross-UID stop and the rotation-during-cancellation regression) |
| `… acceptance.py hypervisor` / `access` / `authority` / `containment` / `frontend` / `browser` | **PASS** — unchanged by this round (the hypervisor gate needs `sh .cache/libvirt-debs/start-session.sh` first) |
| `… acceptance.py images` | **PASS** (1871 s, 18 passed / 1 skipped) — the role images build and boot |
| `… acceptance.py packet` / `journey` | **PENDING (environment)** — root + `nft`; the installed appliance with the member's SSH key, the pinned bastion host key and the browser login. The aggregate now FAILS while a mandatory gate is pending |

## Third review round — 2026-10-22, branch `15`

A third review of the second round's fixes returned **VERDICT: FIX** with
seven findings. All of them are fixed (`51f4166`, `fec3f53`, `0a6638e`,
`818d99e`):

* **The bastion had lost its API credential.** Splitting the services'
  environments took the controller's environment — and the service token
  the bastion's callbacks need — away from the bastion, so every callback
  was unauthenticated and no member could authenticate. The bastion now
  owns its credential: a 0600 file (`SR_BASTION_TOKEN_FILE`), provisioned
  by the installer, named in the bastion's environment, and required by the
  production validation (an empty file fails loudly).
* **The password still leaked.** The redaction hid the *selector* of a
  `fill` command and left the password in the exception. The value is the
  secret; it is hidden now, in the command line and in the captured
  output, with execution-level tests.
* **The journey did not prove a break/repair.** It accepted a wrong
  answer and checked that a counter went up. The journey now stops the
  practice service on the defender guest, requires the API's trusted
  checks to FAIL, repairs the service and requires them to PASS — an
  observable failure → repair → verified success transition.
* **A corrupted private key was accepted.** The public-half derivation
  failed and the adjacent `.pub` file was used instead. A key that cannot
  produce its public half is now an error.
* **The gate could damage the release.** The tamper test overwrote the
  release's `requirements.lock`, and the write preceded the restoring
  `try`. The negative test now runs on a disposable copy.
* **A reused bundle was not bound to the candidate.** A bundle built from
  an older revision verifies against itself. The packaged runtime,
  configuration and lock file are compared with the checkout under test,
  digest by digest; a stale bundle is refused.
* **The shipped-image boot was skippable into a pass.** It is mandatory
  now: there is no skip, and the gate fails without the proof.

| Command | Result |
|---|---|
| `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD .venv/bin/python -m pytest -q -ra -p no:cacheprovider` | **432 passed, 0 failed, 0 skipped**, 262 deselected, 4 warnings (73 s) |
| `… acceptance.py install` | **PASS** (8 s) — the real install sequences + the managed-service contract check |
| `… acceptance.py bundle` | **PASS** (207 s) — the release bundle (307 files, 4 images) verifies, **is bound to the checkout under test** (307 packaged files compared), the operator manifest renders, **the shipped `mojang-web-local` image boots from the bundle** (TCG) and reports its readiness marker, and a tampered bundle is refused (on a disposable copy) |
| `… acceptance.py db` / `authority` / `containment` / `frontend` / `browser` / `hypervisor` / `access` / `images` | **PASS** — unchanged by this round |
| `… acceptance.py packet` / `journey` | **PENDING (environment)** — root + `nft`; the installed appliance with the member's SSH key, the pinned bastion host key and the browser login |

## Fourth review round — 2026-10-22, branch `15`

A fourth review (VERDICT: FIX, four blockers and one non-blocker) is fixed
in `5b37915`:

* **The bastion could not read its own credential.** The token lived under
  the shared secrets directory (`root:sr-secrets 0750`, which `srbastion`
  may not traverse), and the runbook replaced it with a `0600 root`-owned
  file the service could not read either. It now lives in the bastion's
  own directory (`0750 root:srbastion`) as `0640 root:srbastion`; the
  effective permissions are tested.
* **A password-fill timeout disclosed the password.** The timeout escaped
  before the exit-status redaction and printed the whole command line. It
  is caught and replaced by a sanitized message, and the execution test
  now reaches the secret-bearing call instead of failing on the username
  fill.
* **The break/repair proof used a check that cannot see a stop.**
  `service_present` asks whether a unit *exists* — a stopped unit still
  exists — so the helper rejected a genuine stop. The break is now observed
  by the liveness check (`http_content`, which fails when the service is
  stopped), and the service is restored in a `finally` block even when the
  repair fails.
* **The candidate binding was incomplete.** It compared only the files the
  bundle declared and excluded the frontend's source, so a bundle with a
  stale login page — or one missing `srplatform/settings.py` — passed. The
  comparison is now complete and bidirectional over the runtime file set
  (frontend included): missing, stale and changed all fail the gate.
* **The tamper test passed for the wrong reason.** The disposable copy
  omitted the images but kept their manifest entries, so it already failed
  verification for missing images. The fixture is now a small, internally
  valid bundle that is verified **first** (the positive control), and the
  refusal must be a digest drift.

| Command | Result |
|---|---|
| `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD .venv/bin/python -m pytest -q -ra -p no:cacheprovider` | **437 passed, 0 failed, 0 skipped**, 262 deselected, 4 warnings (87 s) |
| `… acceptance.py install` | **PASS** (9 s) — the real install sequences + the managed-service contract check |
| `… acceptance.py bundle` | **PASS** (276 s) — the release bundle (307 files, 4 images) verifies, **is bound to the checkout** (215 runtime files compared; missing, stale and changed all checked), the operator manifest renders, **the shipped `mojang-web-local` image boots from the bundle** (TCG), the disposable fixture verifies before it is tampered with, and the tampered bundle is refused for a digest drift |

## Fifth review round — 2026-10-22, branch `15`

A fifth review (VERDICT: FIX, one blocker) is fixed:

* **`unknown` was accepted as an observed failure.** The API's verifiers
  are three-valued: a probe that cannot reach the service reports
  `unknown` — a transport or authentication failure, not evidence that the
  service is down. The break/repair proof rejected only `passed`, so an
  `unknown` check (the management SSH failing with exit 255) counted as a
  broken service, and a later probe recovering made the journey report
  `verified: true` — probe recovery, not an observed outage. The
  affirmative evidence that a service is stopped now comes from the
  service itself (`systemctl is-active` on the member's channel: a down
  state is required, and an unavailable observation fails the journey).
  The API's check stays the corroboration for the repair, where `unknown`
  means "not verified" and fails the journey. Two regressions are pinned:
  an unavailable verification is not a broken service, and a probe recovery
  without an observed outage fails.

| Command | Result |
|---|---|
| `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD .venv/bin/python -m pytest -q -ra -p no:cacheprovider` | **439 passed, 0 failed, 0 skipped**, 262 deselected, 4 warnings (90 s) |
| `… acceptance.py install` | **PASS** (10 s) — the real install sequences + the managed-service contract check |

## Milestone 15 implementation evidence — 2026-10-20/21, branch `15`

> Reviewer handoff (read this first): [docs/HANDOFF-15.md](HANDOFF-15.md) —
> the plan map, the commit map, the exact verification commands, what is
> claimed versus what is not, and where a critical reviewer should look.

**Environment (stated so no result is over-read):** Debian 13 (trixie)
container, 4 CPUs, 16 GiB RAM, **no `/dev/kvm`**, no root, no installed
appliance, and an unprivileged libvirt session assembled from extracted
Debian packages. Every guest boot below is **software emulation (TCG)** and is
labelled as such. **None of this is nested-KVM acceptance**: milestone 14's
promotion gate (real nested KVM, isolation, stop, member SSH rehearsal) stays
open for the operator.

| Command (from the repository root) | Result |
|---|---|
| `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD .venv/bin/python -m pytest -q -ra -p no:cacheprovider` | **386 passed, 0 failed, 0 skipped**, 254 deselected (~52 s) |
| `.venv/bin/python infra/dev/acceptance.py selection` | **PASS** — 638 tests classified, fast default 386 passed / 0 skipped |
| `… acceptance.py python` | **PASS** — fresh locked install, dependency check, 4 entrypoint imports |
| `… acceptance.py db` | **PASS** — 172 db tests against a disposable PostgreSQL 16 container. Two failures were found and fixed: a spawn-race regression introduced in this milestone (the queued-run credential held a row lock across the spawn window, turning an unconfirmed queued stop into a confirmed kill) and a stale migration-head assertion |
| `… acceptance.py authority` | **PASS** — 25 broker boundary/durability/cessation tests |
| `… acceptance.py install` | **PASS** — the **real** appliance install sequences in a sandbox root: clean install, rerun (0 files changed, capability preserved byte for byte), reboot (runtime restored, data and keys preserved), populated upgrade, drift detected and repaired, foreign file untouched. The previous `SR_INSTALL_VM_EVIDENCE=1` environment attestation is **removed** |
| `… acceptance.py hypervisor` | **PASS** (250 s, 2 tests) — real libvirt: clone → start → guest-agent readiness marker → host-key read → ownership identity (a foreign installation is refused) → stop → destroy, and a repeated destroy of an absent guest is idempotent. The second test drives the **broker's own authority path**: the real `BrokerService` behind the real Unix peer-UID socket with the real libvirt backend, reserving a VMID, cloning, configuring, starting, pinning the host key through the agent, refusing a second session's claim on the same VMID, destroying and reading back that the domain and the guest's files are gone, and ending with no open obligation. Accelerator: explicit TCG |
| `… acceptance.py access` | **PASS** (≈130 s) — a real Ubuntu guest: guest-agent readiness marker and fixed host-key path read through the agent, real SSH with the role key, the **real recording bastion** writing `.cast` bytes, `sudo` for the management identity (and not for the attack identity), an interactive PTY **with a recorded terminal resize**, a reconnect to the same guest, and the refusal of an unauthorized key |
| `… acceptance.py bundle` | **PASS** (54 s) — the REAL bundle is built from the flattened base image (263 files), every digest verifies, the operator's manifest is rendered from it and satisfies the strict appliance schema, and a tampered bundle is refused |
| `… acceptance.py images` | **PASS** (1793 s, 19 tests) — the role images build, boot, serve, seed, expose the documented flaws, take the fixes and report readiness. On a COLD cache the build alone exceeds the 1500 s serial-marker timeout under software emulation (the preserved logs show `apt` still fetching); the gate then passes with the cache warm. A KVM runner removes the distinction |
| `… acceptance.py capture` | **PASS** (751 s, 11 tests) — the installed auditd/srshipper negatives, recovery, access and replay |
| `… acceptance.py capture` | not run — it depends on the image builds above |
| `… acceptance.py containment` / `packet` | not runnable here: they need cgroup delegation, root and `nft` |
| `… acceptance.py journey` | requires the **installed** appliance with operator/member tokens; it fails closed here by design |
| `… acceptance.py frontend` | **PASS** (9.5 s) — lockfile-faithful `npm ci`, the production Next build, and `npm audit --omit=dev` with **zero high/critical** findings |
| `… acceptance.py browser` | **PASS** (44.8 s) — the isolated real-browser workflow and its replay, against a disposable PostgreSQL 16 container |
| `… acceptance.py compose` | **PASS** (360.9 s) — the run-owned stack builds, the bastion capability is issued and scoped, the services come up, and every run-owned resource is removed |
| `… acceptance.py containment` | **PASS** (10.1 s) — namespace, recursive-membership and cancellation regressions, required mode, no leaked cgroups |
| `… acceptance.py packet` | **FAIL (environment)** — the gate needs root and `nft`, which this container does not have. It fails closed with the exact missing prerequisite and was not simulated |

**Defects this milestone found and fixed** (each with a regression test, each
found by inspecting a running guest rather than by reading code):

1. The guest agent was enabled in the base image, so the boot blocked on a
   device that never appears.
2. `systemctl --now` inside a cloud-init bootcmd hung the whole init stage
   (it waits for the agent device). The agent is now started with
   `--no-block` and is never *enabled*, so a later boot cannot block either.
3. The base image had **no machine-id**, so `systemd-networkd` could not
   configure even its DHCPv6 client and the link went to `failed` — the
   static address was never applied. The image now ships the cloud-image
   convention (a 32-zero-byte machine-id that systemd replaces per boot).
4. `sshd` was started before cloud-init generated the host keys, so the
   member's SSH never came up. Readiness now means "SSH is listening".
5. The guest-agent replies were read with the wrong protocol shape (the
   handle is the `return` value; the payload key is `buf-b64`), so the
   host-key read always came back empty.
6. A qcow2 overlay smaller than its backing image truncated the partition
   table and the guest dropped to an initramfs shell.
7. The bastion still accepted a **stale local known_hosts file** as a
   production fallback; production now refuses to dial without a
   deployment-served pin.
8. The cloud image's MOTD scripts run on every interactive login (one of them
   collects system information over the network), so an interactive member
   shell took minutes to appear — which looks exactly like a broken bastion.
   The appliance guest prints no MOTD.
9. The installed-migration lookup assumed a source checkout next to the
   working directory; it now follows the installed package.
10. asyncssh's `create_process()` sends **EOF on the remote stdin by
    default**, so the guest's login shell exited immediately and every
    interactive member session died before a command could be typed. The
    remote session is now created with `send_eof=False`, and the member's
    keystrokes are held until the guest's shell has produced output.
11. A terminal resize arrives as a `TerminalSizeChanged` **exception** from
    the reader; it was unhandled, so the session died on the first resize.
    The resize is now recorded in the cast and forwarded to the guest.

**Controller singleton:** the API process that serves requests also runs the
controller duties (reconciling interrupted runs, clearing dead operation
claims, heartbeating the control lease). It now takes a PostgreSQL advisory
lock — a lock the *database* holds, so it cannot leak and is released when a
crashed process's session dies. A process that does not hold it does not run
the duties and says so. The startup no longer swallows failures: every
startup problem is recorded and appears in the readiness report, so a
half-initialised controller is visible instead of looking healthy.

**Release bundle:** `deploy/bundle.py build|verify|manifest` produces the
artifact an operator carries into their own VM (the application, the locked
dependencies, the flattened guest base image, the installer and its fixed
artifacts, and a `MANIFEST.json` addressing every file by SHA-256). The
bundle is appliance-generic — the operator's addresses, ranges and
installation id are rendered from it — and it can never carry operator
material: secrets, keys, known_hosts, casts and the ledger are excluded and
configuration files are scanned for credential material. The built bundle
verifies against revision `5f018ad`.

**Still open and not claimed by this milestone:** nested-KVM promotion, the
isolation/emergency-stop rehearsal, the real-model and human gates, the
`images`/`capture` builds on a KVM runner, the browser/compose gates, and the
`journey` gate against an installed appliance.

## Current planning assessment — 2026-10-20

Source-inspected at `933f6a1`, clean `master`, equal to `origin/master`.
User selected a **single Ubuntu/KVM appliance with nested full VMs**, retaining
full individual-practice scope with no deadline-driven cuts. Draft plans 14–16
and the architecture's appliance section describe the completion sequence.

**No new test acceptance:** the user deferred tests and cancelled the started
fast suite. Cancellation is not a test failure. Existing counts below remain
historical and revision-bound; implementation must reproduce its own baseline.

**User-reported deployment blocker:** member SSH has not worked successfully.
Do not close this from the pin-fix claims below. Knowledge-panel field notes say
the old clones were destroyed; current inventory needs operator discovery, and
the next proof is a fresh deployment and real member login, not assumed resume.

Source-inspected remaining work (not claims of reproduced live behavior):

- `infra/broker/ledger.py::resolve_obligation` has no production callers;
  `service.py::release_latch` refuses open obligations. Add evidence-based,
  broker-local recovery including destroyed claims and foreign VMID handling.
- `deploy/install.sh` is a partial control-plane installer: it prints migration/
  backup instructions, enables only API/ingest and lacks complete web/DB/bastion/
  broker bootstrap. Its renderer duplicates `infra/release_manifest.py`.
- `deploy/systemd/` has no web unit; the separate deployed bastion described in
  field notes complicates the local-file recording contract in `web_routes.py`.
  Consolidation requires preservation/migration, not deletion of that installation.
- Bastion production dial still has a local-file pin fallback. The complete
  member → capability/API → pinned guest → recording/replay path needs one
  production contract and actual service-identity diagnostics.
- `rangectl/commands/db.py` derives the migration root from package location;
  non-editable installation layout needs explicit support.
- `infra/dev/acceptance.py::check_install` accepts the managed-service half from
  an environment assertion; it does not execute that VM sequence. The live
  release suite's HTTP checks do not establish all advertised SSH, actual
  service repair, model/scorer failure, replay-byte or mode-matrix behavior.
- API startup swallows controller-loop initialization failures. Controller
  singleton/health and a minimal separate ingest application need an explicit
  contract rather than additional full-app configuration combinations.
- `deploy/pve_broker_acl.sh` documents grants disappearing on VM deletion.
  The selected appliance removes that dependency; do not implement the discarded
  intermediate proposal for automatic outer-PVE ACL repair.
- Current-state prose is inconsistent with later evidence; the operator runbook
  even contains committed conflict markers. Preserve historical evidence while
  making current commands/status unambiguous in milestone 14.

Plans 14–16 inherit unresolved plan-13 requirements. A successful SSH check alone
does not accept plan 13 step 9 or the full release. Real isolation/emergency-stop
proof must still precede attacks. Backups remain optional/non-blocking but their
tooling and truthful status remain required.

The new libvirt adapter, domain-bound key acquisition, appliance installer,
role-isolated worker and actual nested-KVM/access acceptance do **not** exist yet.
The roadmap explicitly replaces PVE-only mechanisms/gates while carrying forward
their ownership, cessation, trust and failure invariants. Do not present existing
PVE test results as acceptance of the new architecture.

## Historical evidence (revision-bound)

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

Executed at code revision **`71507bb`** (branch `quick-dingo`; the follow-up
docs commit **`bab084f`** touches only the four `docs/` files — `git diff
71507bb..bab084f --name-only` lists nothing else — so the exercised code is
identical). Full sweep environment: Python **3.13.5** (uv-created pip-less
`.venv` from `requirements.lock`), Node **22.23.3**, npm **10.9.9**, Docker
daemon 29.8.2 / Compose 5.6.0, cgroup v2 with a writable delegated subtree.
Re-anchored at **`bab084f`** on 2026-10-12: fast default **131 passed,
0 skipped, 164 deselected**, `selection` PASS, `authority` PASS (22 passed).
No Proxmox, live
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

**Required CI at the implementation revision:** GREEN —
[run 38264738484](https://github.com/DrSchnitzel57/sparring-range/actions/runs/38264738484)
at `e6a1d4d` (branch `quick-dingo`, 2026-10-12), conclusion `success`. All
eleven jobs `success`: selection, authority, frontend, packet, containment,
python (3.11), db, python (3.13), compose, python (3.12), browser-e2e. The
CI-only packet and browser gates pass on the hosted runners, covering the two
prerequisites this host cannot provide. Operator/live gates (real PVE ACL
denials, VLAN/isolation proofs, identity/stop evidence, $0 budget check) remain
explicitly open — software acceptance only.

## Release blockers and missing work

### Paired milestone-03/04 planning baseline (2026-10-12)

Clean `master` at `cbaa3a0`, equal to locally recorded `origin/master`; no
unpushed commits. Approved paired scope and separate acceptance gates:
`.openchamber/plans/03-04-linux-guests-capture.md`.

Executed from checkout root:

```bash
env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 \
  .venv/bin/python -m pytest -q -ra -p no:cacheprovider
```

Exit **0**: **131 passed, 0 failed/skipped, 164 deselected, 4 warnings**,
**14.80s**, existing Python 3.13 venv. This is only the infrastructure-free
planning baseline. No new image, installed capture, database integration,
QEMU/CI or live PVE acceptance was executed during planning.

Inspected: `infra/images/golden-linux.pkr.hcl` remains invalid/incomplete;
the golden script installs capture but no scenario services; DB YAML has
placeholder user/hash baselines; deployment requests linked clones and weakly
checks bridge placement; broker clone path does not enforce declared resource
budgets; installed shipper uses `tail -n 0`, losing unread input on restart.
These are paired-plan work, not accepted behaviors or proof of live exploits.
The current published PVE API describes `/agent/file-read` and scoped
`VM.GuestAgent.FileRead`; actual installed-version/ACL support stays unverified.
User explicitly deferred storage selection and all live-lab testing.

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

### Paired milestone-03/04 rework evidence (2026-10-13, in progress)

> **Reopened 2026-10-12 (review finding, no code changed by review):** the
> images/capture QEMU gates boot a synthetic boot sector, not the Ubuntu
> guests with installed services/auditd the paired plan requires. That is a
> software-validation gap, not deferred live testing: 03/04 software
> acceptance is redone here under a strengthened gate (real Ubuntu boots);
> CI run 38316796599 no longer counts for 03/04. Milestone-05 planning waits
> for the re-acceptance decision.

Plan adjustment (step 7, recorded here; the paired plan lives in OpenChamber
UI): "boot actual artifacts in isolated QEMU" now explicitly means booting
assembled Ubuntu guest disks — pinned, checksum-verified noble base plus a
run-owned qcow2 overlay carrying the actually installed packages
(nginx/MySQL/auditd/shipper), payload, seeds, flaws and units — with a
NoCloud seed ISO, asserting live services/seeds/flaws/fixes/readiness
(images) and installed-capture negatives plus end-to-end delivery (capture)
over the serial console. The synthetic boot-sector helper is removed. Build-
phase package fetching uses pinned NAMES with guest-reported resolved
versions; verification boots run `-net none`. The overlay is a documented
superset build (role differences are config-level) so the 60-minute TCG job
budget holds. Also repaired en route: the installed shipper input is now a
durable persisted cursor (`--audit-log`), retiring the `tail -F -n 0`
restart loss the planning baseline flagged; the unit ExecStarts the artifact
directly.

> Superseded runs (kept for provenance; do NOT count as 03/04 acceptance
> after the reopening above): the first-round implementation ran on branch
> `warm-narwhal` from clean `master` `cbaa3a0`. No Proxmox, live
> range, host firewall, NAS or unrelated-VM access; every fixture was run-owned
> (synthetic keys/tokens, disposable Postgres, isolated QEMU run dirs).

Scope decisions (ambiguous points judged per plan intent, visible on review):
- Packer retired in place (`RETIRED` header; history preserved); the supported
  path is `python infra/images/build.py` from `infra/images/manifest.json`.
- Base-image SHA256 in the manifest is a pinned placeholder the builder treats
  as operator-verified at build time (refuses mismatch/absence); the builder
  itself never fetches (no network at build/test time).
- QEMU "boot" is a real isolated boot of a deterministically generated
  boot-sector artifact carrying the run's payload identity (SeaBIOS → COM1 →
  run-owned serial log), with full guest-payload verification via builder +
  service checks. A full Ubuntu-cloud boot stays an operator live gate (11).
- New tests that need Postgres are `images`/`capture` + `db` compound layers;
  the new gates start their own disposable `postgres:16` (like the db gate).
  Two FileRead/budget tests are additionally `authority`-marked (infra-free).

| Gate (exact command) | Result |
|---|---|
| `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -ra -p no:cacheprovider` | Exit 0: **131 passed, 0 failed/skipped, 187 deselected**, 4 warnings — infrastructure-free default unchanged |
| `.venv/bin/python infra/dev/acceptance.py selection` | **PASS**: 318 tests = 131 fast + 187 integration (db 122, containment 25, packet 4, authority 24, images 14, capture 9, browser 1, live 0); required-mode fail-closed controls pass |
| `.venv/bin/python infra/dev/acceptance.py python` | **PASS** (Python 3.13.5 fresh locked install; CI matrix covers 3.11–3.13) |
| `.venv/bin/python infra/dev/acceptance.py db` | **PASS**: **121 passed, 0 skipped, 197 deselected** in required mode (`db and not browser`); owned cleanup verified |
| `.venv/bin/python infra/dev/acceptance.py authority` | **PASS**: **24 passed** (22 prior + FileRead/budget identity), 0 skipped |
| `.venv/bin/python infra/dev/acceptance.py containment` | **PASS**: 21 passed, 0 skipped; no run-owned cgroups leaked |
| `.venv/bin/python infra/dev/acceptance.py frontend` | **PASS**: `npm ci` + production build + `npm audit --omit=dev` 0 findings |
| `.venv/bin/python infra/dev/acceptance.py images` | **PASS here (2026-10-12, operator-installed QEMU 10.0.13)**: **14 passed, 0 skipped, 304 deselected** incl. the real isolated QEMU boot (TCG, `-net none`, run-owned disk/serial, owned cleanup); disposable-DB subset included; gate time 5.5s |
| `.venv/bin/python infra/dev/acceptance.py capture` | **PASS here (2026-10-12, QEMU 10.0.13)**: **9 passed, 0 skipped, 309 deselected** incl. the real isolated QEMU boot; disposable-DB subset included; gate time 6.8s |
| `.venv/bin/python infra/dev/acceptance.py packet` | **FAIL here (prerequisite)**: missing root + `nft` — CI packet job is the gate (unchanged) |
| `.venv/bin/python infra/dev/acceptance.py browser` | **FAIL here (prerequisite)**: no launchable Chromium — CI browser job is the gate (unchanged) |
| `.venv/bin/python infra/dev/acceptance.py compose` | Not rerun here (no application change to the compose path); last green per milestone-02 evidence |

Delivered (addresses B07–B11 as software, acceptance pending):
- `infra/images/manifest.json` + `packages-24.04.txt` + `README.md` (pinned
  noble URL/SHA256, packages incl. PyMySQL/auditd, 2vCPU/2GiB + 16/12/16GiB
  budgets, 64MiB spool / 32MiB cast); `infra/images/build.py` (deterministic,
  public-keys-only, scrubbed, manifest-hashed); `infra/images/specs.py`
  (canonical budgets/roles/aggregates/allowlisted host-key path).
- `infra/cloud-init/{attacker,mojang-web-local,mojang-web-db}.yaml`
  (defender+sudo, ufw/auditd/shipper/app services, empty pubkey slots).
- Guest payloads: local/MySQL catalogue app (`app.py`), diagnostic flaw +
  maintenance helper + `FIXES.md`, nginx unit, MySQL schema (SELECT-only
  reader) + 12-row seed SQL generated from `scenarios/mojang-seeds.json`
  (3 games, `buy-001`–`buy-012`, fictional).
- `scenarios/mojang-web-01.yaml` / `mojang-web-db-01.yaml` (fresh attacker at
  fixed 10.66.0.9, templates 9005/9011/9012, versioned seed/image baselines,
  `http_content`/`mysql_rows` logical checks, documented flaws/fixes);
  `verifiers/library/mojang.py` (`http_content`, `mysql_rows` SELECT-only);
  `SUPPORTED_SERVICES` += `mojang-web`; legacy scenarios preserved.
- Typed guest-agent FileRead: `ProxmoxClient.read_guest_file` (fixed path
  only) + `BrokerService.read_host_key` (owned VM/session/generation before
  AND after, bounded key parse, same-generation change refused with
  obligation, fresh-generation re-pin) + `CONTROL_OPS`/client surface; fake
  models `/agent/file-read` with fresh per-clone keys; no exec/host-shell
  surface (asserted).
- Orchestrator: explicit `deploy_clone_mode` setting (broker-validated, no
  fallback), aggregate budget reservation before side effects, host-key pins
  after each start, clone-mode recorded in deploy events; intents/conflicts/
  resume/reset/foreign-VM protection preserved.
- Capture: installed-unit/rules/installer assertions, spool replay/dedup/
  order/limits/gaps + crash/overflow/reboot, ENRICHED marker grouping,
  wrong-API/token/input negatives with recovery, stale/foreign/phase-only
  refusal + `/run` gate, concurrent-confirm idempotency + revocation binding,
  cast opaque-ID/symlink/size/missing/replay + TRUNCATED marker, no-logged-
  secrets + forgeable-telemetry contract note.
- `infra/dev/qemu_guest.py` (real isolated QEMU boot helper, bounds
  enforced, owned cleanup) + `images`/`capture` gates in
  `infra/dev/acceptance.py` (disposable PG + QEMU prereq + leftover checks) +
  `images`/`capture` CI jobs (QEMU install, userns profile, delegated cgroup,
  60-minute timeout) + `images`/`capture` markers (fast default excludes them).

**Required CI: GREEN** —
[run 38316796599](https://github.com/DrSchnitzel57/sparring-range/actions/runs/38316796599)
at `1fd74b4` (branch `warm-narwhal`, 2026-10-12), conclusion `success`. All
thirteen jobs `success` on the initial attempt: selection, python (3.11),
python (3.12), python (3.13), db, containment, authority, packet, frontend,
compose, browser-e2e, **images**, **capture**. The CI-only packet and browser
gates pass on the hosted runners, and the two new QEMU gates pass there with
apt-installed QEMU (TCG), the scoped userns profile, and the delegated cgroup
— matching the local QEMU-10.0.13 results above. Software acceptance is
complete; tick 03/04 in the roadmap. Live/operator gates (real PVE FileRead
ACL, clone/storage/NIC, isolation/stop, installed-capture on R740, $0 budget
check) remain explicitly open. The base-image SHA256 placeholder must be
replaced with the published noble SHA256SUMS value at operator build time.

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

## Tomorrow-pilot implementation evidence (2026-10-13, plan 12-tomorrow-pilot)

Cross-cutting authorized exception plan (see `docs/ROADMAP.md` "Planning and
acceptance discipline"). It accepts NO milestone; everything below is pilot
evidence only. Branch `openchamber/tomorrow-pilot`, baseline `edb8df3`
(fast suite at baseline: 135 passed / 192 deselected). Implementation
commits `e789a8d..24f84ef` (8 commits). Environment: Python 3.13.5 venv;
Docker daemon 29.8.2 / Compose 5.6.0; QEMU 10.0.13 (TCG, 4-CPU/16G host,
one guest at a time); Node v22.23.3 + Playwright chromium-headless-shell
155.0.8059.12 (installed this session — the browser binary was the only
missing prerequisite); disposable PostgreSQL = run-owned container
`sr-acc-pg-52b3cf2b` on loopback `127.0.0.1:49003` (acceptance-harness
fixture image; superuser password reset in-container, no host DB touched).

### Fast suite (criterion 1) — PASS

`env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1
.venv/bin/python -m pytest -q -ra -p no:cacheprovider` at `24f84ef`:
exit 0, **152 passed, 0 failed, 0 skipped, 206 deselected**, 17.2 s.

### DB layer + browser (criteria 3, 5, 6) — PASS

`env SR_PG_ADMIN_URL=<disposable> SR_REQUIRE_DB=1 PYTHONDONTWRITEBYTECODE=1
.venv/bin/python -m pytest -q -p no:cacheprovider -m db
--ignore=tests/test_stage5_browser_e2e.py`: exit 0, **135 passed, 0 failed,
222 deselected**, 144.8 s. The browser e2e (also db-classified) ran
separately with `SR_REQUIRE_BROWSER=1 -m browser`: **1 passed**, 43.2 s —
real chromium drives login → launch → API-served connections → ingest →
Begin (server clock + deadline) → sustained run stopped via UI → end
(destroy + release) → AAR. New pilot db tests: `tests/test_pilot_lifecycle.py`
(10: snapshot at creation, Begin idempotence/never-extends, idle expiry with
safe cleanup, deadline end, end destroys + frees range, failed destroy keeps
lease and retries, restart interrupts and never resumes, connections served
by API, worker-env snapshot values) and `tests/test_pilot_uptime.py` (2 db:
identity-bound samples through the real prober, append-only grants — app-role
UPDATE/DELETE raise `InsufficientPrivilege` — dashboard/end reporting).
Plan-authorized semantics change: END now destroys owned VMs and releases the
lease; the R07 invariant (a machine that still exists keeps the reservation)
is preserved and newly covered (`test_end_with_failed_destroy_keeps_lease_and_retries`,
updated `test_r07_*`).

### Sustained attacker + uptime (criteria 4, 5) — PASS (fast layer)

`tests/test_pilot_sustained_attacker.py` (9) and `tests/test_pilot_uptime.py`
(8 fast) pass within the suite above: loop runs to the SERVER deadline (not
20 steps / objective completion), per-action throttle is deadline-aware and
non-overlapping, DONE never ends a match, gateway retry policy 3 attempts
(5 s/15 s, 60 s timeout) then truthful interrupt; uptime math scores only
valid checks, zero-valid is unscored, staleness/coverage surfaced, and a
confirmed probe-infrastructure failure interrupts instead of fabricating
downtime.

### Attack chain on real boots (criterion 2) — PASS

`env SR_PG_ADMIN_URL=<disposable> PYTHONDONTWRITEBYTECODE=1
SR_REQUIRE_IMAGES=1 .venv/bin/python -m pytest -q -p no:cacheprovider
-m "images or db" tests/test_mojang_images_deploy.py` at the final
revision: **10 passed, 0 failed**, 393.8 s (warm overlay cache). Markers
proven on real Ubuntu 24.04 boots: `DIAG-FLAW` (genuine
`subprocess.run(shell=True)` as the web user over HTTP), `ROOT-FLAW`
(HTTP-driven plant → `sudo -n` helper → uid-0 proof file), `MAINT-HELPER`,
`MAINT-FIX` (revoke sudoers rule → chain dead, services active),
`DIAG-FIX-PASS` (endpoint disabled → 403, catalogue still serves), plus
MYSQL-READY/COUNT/ROW on the DB variant.

**Two real gate bugs found and fixed while chasing a "flaky MYSQL-COUNT":**
(1) `boot_full_guest` judged a NEW boot on the PREVIOUS boot's serial file:
two verify tests share one overlay + run dir, so both wrote
`guest.serial.log`; the poll loop saw the stale `DONE rc=0` before QEMU
opened the file and returned the old markers instantly (web-local's serial
has no MYSQL checks — hence "MYSQL-COUNT missing, no FAIL, DONE rc=0").
Fix: unique `serial_name` per boot + unlink before start. This is very
likely the pre-existing images-CI failure at `fe940fc`.
(2) The chain battery is state-mutating BY DESIGN (MAINT-FIX removes the
sudoers rule, DIAG-FIX disables the endpoint) and writes persist in the
overlay booted; a module-scoped shared overlay made the second verify boot
start already-fixed (flaw checks then correctly failed). Fix: fresh
overlay copy per verify test (cache copy+rebase, no extra boots).
Serial hardening (marker double-emit, `dmesg -n 1`, getty stop, always
preserve serials) is retained as defense in depth, but the initial
corruption theory was wrong — evidence over theory.

### Gates (criteria 7, 8) — PASS

`python infra/dev/acceptance.py frontend`: PASS 7.1 s (lockfile-faithful
`npm ci`, `next build`, `npm audit --omit=dev` zero findings — moderate=0
low=0). `python infra/dev/acceptance.py compose`: PASS 63.2 s — fresh
bootstrap + idempotent rerun, migrations at head **0013**, API runtime holds
app-role credentials only, bastion capability + running, run-owned project
fully cleaned.

### Template build (criterion 9) — PASS

`PYTHONDONTWRITEBYTECODE=1 .venv/bin/python infra/images/pve_template_build.py
--out /tmp/sr-templates --pubkey <ed25519.pub> --cache-dir /tmp/sr-guest-cache
--roles attacker,mojang-web-local`: exit 0. Base `noble-20261012`
(sha256 `6a81c375…5bb4d2`, verified against the published
cloud-images SHA256SUMS). Flattened standalone qcow2s verified (format qcow2,
no backing file, budgeted 16 GiB virtual, `qemu-img check` clean — the
initial `-r no` invocation was invalid and is fixed). FINAL artifacts —
rebuilt at the final revision with the OPERATOR's bastion public key
(`charl@lenovo`, SHA256 `fM6V/cZLUQny3u159PnxRowPIlM1Y6S94cJ7aXe9tOE`,
fingerprint confirmed against the operator's own keygen output) baked in:
attacker VMID 9005 sha256
`a8c78964f1d6629df37176a188dc143a73b1867d44f651232b5f0f9d43a4032a`,
mojang-web-local VMID 9011 sha256
`653259af19c1b6b0ea617830a16f2cfbb31796dd363a5948021652a94b87e17c`;
`sha256sum -c SHA256SUMS` OK; `IMPORT-STEPS.md` + `TEMPLATE-INFO.json`
emitted. The finalize boot bakes the ONE operator/bastion PUBLIC key into
root/defender/attacker (chk BAKE passed) and scrubs per-clone identity.
Earlier test-key builds (attacker `77add10c…`, web-local `aedfae4d…`) are
superseded; key rotation = rebuild + reimport per generation.

### Still open after the pilot (honest ledger)

Milestones 03–11 acceptance states unchanged. Live/operator gates (VLAN
default-deny positive controls, emergency-stop drill, PVE token/ACL, template
import, full two-teammate rehearsal, model smoke through the gateway) are
Manual checks for the operator — attacks stay latched until they pass.
Installed-capture acceptance stays open (pilot command truth is events/casts).
CI images/capture jobs at `fe940fc` remain failing (pre-existing; the stale
serial bug fixed here is the likely images-gate cause — CI re-greening on
push stays open, not a pilot gate). The web-db verify's intermittent
missing-`MYSQL-COUNT` was root-caused to two real gate bugs (above) and
fixed; contradictory single-boot outcomes must be reproduced before being
believed. Browser/packet gates remain CI-required for acceptance; local
chromium passing does not replace them.

## Plan 13 implementation evidence (2026-10-14, plan 13-live-deploy-hardening)

Cross-cutting authorized exception plan (see `docs/ROADMAP.md`). It accepts
NO milestone; phase checkboxes in the plan track implementation only.
Branch `plan-13-implementation`, base revision `44a712a`. Environment:
fresh uv `.venv`, Python **3.13.5**; Docker daemon 29.8.2 / Compose 5.6.0;
QEMU 10.0.13; Node 22.23.3. No Proxmox, live range, host firewall, NAS or
unrelated-VM access; every fixture run-owned and synthetic.

### Phase 1 — contract, fresh baseline, deployment manifest

Fresh baseline reproduced at `44a712a` before any change (also recorded in
`AGENTS.md`):

| Exact command | Fresh result |
|---|---|
| `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -ra -p no:cacheprovider` | Exit 0: **176 passed, 0 failed, 0 skipped, 206 deselected**, 4 warnings, 19.43s — fast layer only |
| `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 .venv/bin/python infra/dev/acceptance.py authority` | Exit 1: **16 failed, 8 passed, 358 deselected**, 3 warnings. Classification: every failure is `tests/test_authority_boundary.py` fixture name `web01-deadbeef` rejected by the current `sr-` name policy (`infra/broker/policy.py check_name`); production naming (`sr-<scenario>-<host>-<32hex>`) already satisfies the policy. Fixture repair is phase-2 work; the policy stays. |
| `SR_MATCH_SCHEDULER_ENABLED=1 SR_MATCH_DEFAULT_DURATION_MINUTES=60` probe of `Settings(_env_file=None)` | `match_scheduler_enabled=False`, `match_default_duration_minutes=30` — documented `SR_*` names ignored (phase-4 repair target) |

Delivered (fast tests `tests/test_release_manifest.py`, 22 passed):

- User amendments recorded authoritatively: `docs/ARCHITECTURE.md`
  "Plan 13 release amendments", `docs/ROADMAP.md` 2026-10-14 exception.
- Versioned release manifest: `infra/release_manifest.py` (schema v1,
  fail-closed validation: secret-material rejection, placeholder refusal,
  VMID/address overlap refusal, mandatory template checksums, bounded clone
  window, measured-capacity headroom, three distinct HTTPS/internal/ingest
  listeners, absolute state paths, explicit backup status) +
  `deploy/manifest.example.json` (candidate values clearly marked as
  verify-first, per the plan).
- Installer inventory classification: `classify_resource` (absent/matching/
  conflicting/**unreadable — an error is never absence**),
  `assess_capacity` (measured free capacity vs payload+headroom; unreadable
  is unsafe; a storage label is never proof), `inventory_report` (refuses
  before side effects on any conflict/unreadable/version/capacity problem).
- Source-of-truth map (`SOURCE_OF_TRUTH_MAP` + `render_broker_policy` +
  `render_env(role)`): manifest → broker policy (re-validated by the real
  `BrokerPolicy.from_dict`), per-role env fragments (worker minimal, no PVE
  credentials anywhere, absolute state paths), service/template consumers.

No live installation was inferred or performed. DB/packet/browser/live gates
were not rerun in phase 1; old totals are not claimed.

### Phase 2 — Proxmox/broker boundary and recovery contracts

Fresh results at this revision (same environment; every gate run with
`env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD`):

| Exact command | Fresh result |
|---|---|
| `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -ra -p no:cacheprovider` | Exit 0: **223 passed, 0 failed, 0 skipped, 208 deselected**, 4 warnings, 40.27s (adds 22 pve-contract + 3 lease + 1 capacity tests to the 198) |
| `.venv/bin/python infra/dev/acceptance.py authority` | **PASS**: 25 passed, 0 failed, 0 skipped (was 16 failed/8 passed at `44a712a`) — fixtures repaired to the `sr-` policy; the policy itself unchanged |
| `.venv/bin/python infra/dev/acceptance.py pve-contract` (new gate) | **PASS**: 22 passed, 0 skipped — REAL pinned proxmoxer 2.3.0 over loopback HTTPS |
| `.venv/bin/python infra/dev/acceptance.py selection` | **PASS** |
| `.venv/bin/python infra/dev/acceptance.py python` | **PASS** (fresh locked install, Python 3.13.5) |

Delivered:

- **Authority fixtures repaired, policy untouched**: `web01-deadbeef` →
  `sr-web01-deadbeef` (foreign-resource fixtures deliberately keep non-`sr-`
  names); all latch/race/intent/uncertain-cleanup assertions preserved.
- **`pve-contract` gate** (`tests/test_pve_real_client_contract.py`,
  `adapter` marker — runs in the fast default AND required mode): real
  `ProxmoxAPI`/requests stack against a synthetic PVE dialect server —
  `/api2/json` prefix survival, `PVEAPIToken` header, query/form encoding,
  nextid assertion→scan, clone/start/stop/delete UPID polling, task
  exitstatus ERROR, malformed replies uncertain, 404 vs the exact
  config-absent 500 dialect (confirmed absence) vs the router
  `no such file` 500 (NEVER absence), 401/403/timeout/refused uncertain,
  TLS trust enforced (no-CA/foreign-CA fail closed), agent file-read query
  encoding + comment stripping + allowlist refusal before any HTTP.
  `_Recorder` is never substituted for this boundary.
- **Deadlines checked together**: `HttpTransport.OP_TIMEOUTS` per op exceed
  the documented server bounds (static contract test); a task longer than
  the old flat 30 s completes; a lost mutation response stays
  `BrokerUnavailable` and is **never** transport-retried; lost reads get
  exactly one safe retry; `proxmox_http_timeout_s` is an explicit setting.
- **Reservation accounting fixed**: `clone_and_wait` no longer double-charges
  the target VMID's own `reserved` claim against `max_vms`
  (`test_reserved_claim_is_not_double_counted` — old code refused the third
  guest of a three-VM range).
- **Bounded DB/control-failure lease policy**: `control_is_active()` is
  tri-state (active/provably-idle/**unverified**); renewals continue only
  within `max_unverified_s` (default 60 s = 2× broker TTL), then go silent
  so the broker watchdog latches and stops the range; unverified is never
  provable idle; recovery resets the window (4 heartbeat tests).
- **`deploy/pve_broker_acl.sh`**: dry-run default, `--apply` (idempotent,
  only "already exists" tolerated), `--verify` probes EFFECTIVE token
  permissions (allowed ops + denials on unrelated VM, ACL read/write,
  foreign file-read/stop) — role names alone are never proof; no
  broad-privilege fallback; token secret never on argv, never printed.
- **Audit A6 repaired**: resume re-pins when `state == created` but
  `host_key_ref` is missing; regression
  `tests/test_deploy_resume_repins_missing_host_key.py` is **db-layer —
  pending the db gate** (no disposable PostgreSQL in this environment; not
  claimed as run). A12/A13 comment fixes landed; every audit finding now has
  a code/test anchor in `docs/audits/pve92-alignment.md` "Fix anchors";
  remaining live probes stay explicit operator work.

### Phases 3–8 — guests, configuration, lifecycle, match contract, tooling

#### Review rounds 3–4 evidence (2026-10-15, final — HEAD `496ec7d` + round 10)
- Images rebuild (mgmt→root key policy + USER markers + native-password
  seed): 19 passed, 0 skipped — recorded 36-user sets identical across
  roles, conformance test green against built fixtures.
- Capture: 11 passed, 0 skipped (incl. live docker-MySQL protocol test
  with fixture-scoped volume tracking, no leaks).
- Fast 334/0; db layer 168/0; matrix, frontend, compose, browser,
  containment, authority, pve-contract all PASS; install sandbox proofs
  PASS (VM job pending by design). (2026-10-15, branch `plan-13-implementation`)
- Fast suite 330/0; db layer 167/0 (incl. claim-takeover supersede,
  cross-session interrupt stickiness, atomic expiry, race-decide,
  competition matrix, breach proof + no-worker-on-refusal, pin-error
  readiness + republication, assumed-breach snapshot/disclosure tests).
- Matrix (selection/python/authority/pve-contract) PASS; frontend,
  compose, browser PASS; install sandbox proofs PASS (render, preserve,
  rotate, partial recovery, CA-less refusal, 44GiB ceiling).
- Images rebuild running (role_keys mgmt→root + USER markers change all
  cache keys); recorded 36-user sets already confirmed identical across
  roles and match the expanded baselines exactly. Capture queued behind.
- Declined with documented reasons: PVE range-grants without per-VMID
  enumeration (implemented instead per audit A7); loopback-only MySQL
  observation (triangulated instead); replay/scenario-objective filtering
  (first-party / published-threat-model).

Fresh results at the phase-8 revisions (same environment; every command run
with `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD`):

| Exact command | Fresh result |
|---|---|
| `…python -m pytest -q -p no:cacheprovider` (fast default) | Exit 0: **330 passed, 0 failed, 0 skipped, 230 deselected**, 4 warnings, 50.1s |
| `bash -e …selection python authority pve-contract…` | **PASS** on the final revision — 87.5s / 4.1s / 16.2s / 26.4s, all four gates exit 0 |
| `…acceptance.py db` | **PASS** after 183.9s — disposable fixture, fresh + forward migrations (incl. 0014/0015), **151 passed, 0 failed** incl. the 202 executor, deadline, network-plane and inject tests |
| `…acceptance.py images` | **PASS** after 284.1s on the final revision (cache-warm; overlay inputs unchanged) — **18 passed, 0 skipped**, no leaks |
| `…acceptance.py capture` | **PASS** after 206.8s on the final revision — **10 passed, 0 skipped**, no leaks |
| `…acceptance.py frontend` | **PASS** — npm ci, production build, audit zero high/critical (re-run PASS on the final UI revision) |
| `…acceptance.py compose` | **PASS** — full stack + seed-bastion-keys success gate, cleaned |
| `…acceptance.py browser` | **PASS** — isolated real-browser workflow + replay incl. control builder, inject inbox, safety page (re-PASS after the session-tick fix) |
| `…acceptance.py db` | **PASS** after 155.7s — disposable fixture, fresh + forward migrations (incl. 0014/0015), **150 passed, 0 failed** (phase-3/6 regressions repaired; deploy-operation, network-plane and inject tests included) |
| `…acceptance.py containment` | **PASS** after 11.6s — real namespace/cgroup fixtures created, positive-control process migration, 21 required-mode regressions 0 skipped, no leaked run cgroups |
| `…acceptance.py packet` | **FAIL (prerequisite)** — needs root + nft (missing here); runs only in the approved disposable-netns CI packet job; never accepted from this host |
| `…acceptance.py images` | **PASS** after 1784.8s — all three role overlays rebuilt from the fixed recipe (web-local `f1b5777d`, web-db `7ae761c9`, attacker `7552a591`), **18 passed, 0 skipped**: real Ubuntu builds, boot tests, services/seeds/flaws/fixes, readiness + clone-mode + host-key contracts, attacker records its 5 resolved packages (the PKG-before-SETUP-OK fix), no QEMU or DB leaks |
| `…acceptance.py capture` | **PASS** after 202.4s — 10 passed, 0 skipped: installed auditd+shipper on the real DB overlay guest, EXECVE capture proven locally with NO delivery on the negative boot, end-to-end delivery to the synthetic API, cursor durability; two pre-existing test-expectation bugs fixed (the harness emits bare `BOOT` liveness, never `BOOT-PASS`; the DB payload check now asserts tier separation) |
| `…acceptance.py install` | Sandbox contract **PASS** (dry-run, idempotent rerun, key preservation, invalid manifest refused before effects); **FAILS** on the managed-service VM half until the disposable-VM job sets `SR_INSTALL_VM_EVIDENCE` — deliberately not accepted from a sandbox |

Delivered:

- **Phase 3 (guest/template contract)**: `infra/images/role_keys.py` role
  key policy (runner→attacker only, bastion→defender guests only, mgmt and
  separate explicit emergency; private/placeholder/unknown refused; dedup);
  attacker template now carries auditd + shipper (canonical inputs), the
  reboot-persistent cgroup delegation unit and the scoped AppArmor profile
  (`infra/runner/`), with verify checks; web/DB tiers separated (DB payload
  ships no web app; role-conditional units, firewall and verify checks;
  per-role overlay cache keys); base image pinned to the DATED retained
  directory `noble/20260926` (byte-identical to the `current` alias as
  re-verified 2026-10-14; checksum+size enforced); resolved packages
  recorded from every build including the attacker; deploy-time DB wiring
  (`srplatform/scenario_engine/guest_config.py` + orchestrator pass):
  fresh per-deployment reader credential, grants/listener/firewall narrowed
  to owned web sources + loopback probe, atomic web config to the owned DB
  IP with read-back, resume-idempotent, visible skip (event) without a
  channel; verifier reads the credential inside the guest; template build
  takes per-principal public keys and defaults to all three roles.
  17 fast contract tests (`tests/test_guest_contract.py`).
- **Phase 4 (configuration/trust/readiness)**: settings now honor the
  documented `SR_*` env names (the plan-13 baseline probe
  `SR_MATCH_SCHEDULER_ENABLED=1`/`SR_MATCH_DEFAULT_DURATION_MINUTES=60`
  resolves True/60; bare names unchanged); 55 compatibility tests prove
  EVERY key of EVERY shipped example reaches the model with non-default
  values; shipper HTTPS uses an explicit verified SSL context
  (`SR_TLS_CA_FILE`), enrollment provisions the public CA into guests,
  production refuses http/localhost/missing-anchor APIs; readiness refuses
  created clones without pinned host keys; confirmed teardown unpublishes
  pins; boot-race 255 retry now distinguishes definitive auth/pin failures;
  private keys parse-checked at startup with ssh-keygen-format fingerprints
  recorded in `TEMPLATE-INFO.json` for rotation drift detection; typed
  broker policy REFUSES `gw=` — range guests are on-link only, no default
  route by construction. The guest-facing range listener answers with
  nothing but the authenticated enrollment/ingest routes
  (`SR_API_INGEST_ONLY`; 404 elsewhere, bounded bodies); `GET /stages`
  distinguishes install-ready / lab-ready / attack-authorized with the
  explicit `SR_ATTACK_AUTHORIZED` operator gate, and the three-plane
  separation is documented in `deploy/README` §2a.
- **Phase 5 (durable lifecycle operations)**: `deploy_operations` table
  (migration 0014) + orchestrator helpers; launch/reset commit identity,
  fence, phase and deadline BEFORE effects; redacted
  `GET /sessions/{id}/operation` polling; startup reconcile marks dead
  executors `interrupted` before clearing claims (live fences survive;
  stale requests cannot finalize replacements); 4 db-layer tests pass in the
  db gate. **202 refinement (2026-10-15):** launch/reset/deploy return 202
  after synchronous durable acceptance; the supervised executor completes
  the attempt in the background and the redacted result (connections,
  readiness, deployment summary — never plaintext enrollments) is polled
  from the operation row. The deviation is closed.
- **Phase 6 (match contract)**: snapshot v2 freezes bounded
  choices (mode practice|competition, start condition manual|auto-on-ready,
  intensity pace ∈ {0,15,30,60}, injects toggle) plus scenario/rubric/seed/
  image versions, the scenario digest and effective settings with 422 before
  storage; `uptime.coverage` computes the EXPECTED schedule from the match
  clock — gaps are visible `missed`, unknown ≠ downtime, zero valid
  unscored; the prober additionally runs an authenticated read-only MySQL
  BUSINESS TRANSACTION every cycle for provisioned DB tiers (three truths
  separate: wrong seeded count = down, unestablished session = unknown,
  broken probe credential = probe-infrastructure interrupt). Versioned
  injects (`srplatform/injects.py`, migration 0015): trusted server
  schedule from the frozen duration at Begin, four versioned injects
  (restricted-account, web-restoration, DB-data-recovery technical;
  incident-report written/advisory-only), identity-bound submissions where
  the FIRST answer decides (pending|correct|incorrect|late|duplicate|
  advisory), deterministic verification through the shared verifier
  registry, disabled set releases nothing, and a SEPARATE inject score —
  no combined grade. **Open requirement:** the full control-matrix live
  tests and browser inject inbox (phase 7 UI) remain; the release gate
  exists but refuses to run without a deployed lab.
- **Phase 7 (browser/visibility/reports, partial)**: the live session page
  now carries the inject inbox (release windows, submissions, separate
  score); Begin, uptime panel, detections, AAR/replay links, per-user
  history and server-served SSH instructions already exist; competition
  visibility is enforced at the API (own sessions only for members;
  inject/readiness data per-session). Frontend gate PASS (npm ci,
  production build, zero high/critical). **Open requirement:** the
  operator safety-panel refinements and the attacker control builder
  remain unbuilt UI scope.
- **Phase 8 (installer/gates)**: `deploy/install.sh` (idempotent,
  key-preserving, verify-before-enable, explicit migrations, optional
  backups) + `install`/`release` acceptance gates with honest
  prerequisite refusal.

## Recording new acceptance evidence

For every gate record: date, evidence Git revision and dirty status, exact command
and non-secret environment, runtime/fixture versions, exit code and all
pass/fail/skip/deselect totals, boundary actually exercised, prerequisite blockers,
and observable live outcomes where applicable. Never record plaintext credentials,
real admin terminal casts or mutable generated files as proof in Git.

Only close a blocker after independently executing its agreed milestone criteria.
No implementation milestone is closed by this documentation pass.

## First production install (2026-10-15, operator-executed, agent-guided)

Host `pve` (PVE 9.2.21), bridge `srrange` (vid 66 only), storage `data`,
service VMs 201/202/203 (Ubuntu 24.04, `onboot: 1`), templates
9005/9011/9012 (16/12/16 GiB, never booted), range `10.66.0.0/24`,
mgmt `10.10.10.0/24`. Release revision `795faf4` on all three service
VMs. No secrets are recorded here; passwords/capabilities were generated
locally and transferred staged, never pasted.

| Exact command/probe | Result / meaning |
|---|---|
| `python infra/images/pve_template_build.py --out /tmp/sr-templates --cache-dir /data/sr-guest-cache --runner-key ... --bastion-key ... --mgmt-key ... --emergency-key ... --roles attacker,mojang-web-local,mojang-web-db` (KVM, `SR_QEMU_KVM=1`) + `sha256sum -c SHA256SUMS` | Build clean, checksums verify; SHAs `31f3842e…` (9005), `81c15306…` (9011), `141ac244…` (9012) written into `/etc/sparring-range/manifest.json` (no placeholders left) |
| `deploy/pve_broker_acl.sh` dry-run → `--apply` → `--verify` (node `pve`, bridge `srrange`, templates `9005,9011,9012`, window `9100-9199`, storage `data`, foreign probe `107`) | Applied clean; `pveum user token permissions` shows exactly 106 grants (node audit, bridge SDN, 3× template Clone+Audit, 100× window Base, storage); effective probes pass after the PUT/metadata probe fix (`795faf4`): template/foreign-VM denials `403`, escalation `PUT /access/acl` `403` |
| Narrow PVE firewall rule (pos 0: in/ACCEPT/vmbr0, `10.10.10.200/32` → TCP 8006) + OPNsense inter-VLAN allowance for the same tuple | `curl -sk https://192.168.86.83:8006/api2/json/version` from 202 answers `401` (transport proven; auth needs the token). Management IPSet untouched (still LAN-only) |
| `deploy/install.sh --manifest ... --no-backup` on 201 (`HTTPS_IP=10.10.10.150`) | `install[done]`; TLS identities issued; broker policy rendered (templates + window + `10.66.0.0/24` vlan 66); defect found+fixed: installer shadowed generation keys under `tls/` (now removed; bootstrap owns `ssh/`) and the `ssh/` dir blocked traversal (now `0750`) |
| PostgreSQL 16 install, `sr_owner`/`sr_app` roles, `sparring_range` DB, `alembic upgrade head` | `0001 → 0015` clean; defect found+fixed: app role had CONNECT only (fixtures never exercise the split) — standing DML + default privileges in migration `0016` |
| `GET /readyz` on 201 | `{"ready":true,"migration_version":"0015","issues":[]}` (runner host-key + recordings pending first deploy, as designed) |
| `rangectl bootstrap` on 201 | Operator account created; bastion capability minted once into the operator secret store |
| `sr-brokerd` on 202 (policy + mTLS + token via staged transfer) | `active`, `listening ('0.0.0.0', 8443)`, reconciliation empty, unlatched |
| `GET /stages` (operator auth) on 201 | `install_ready:true, lab_ready:true` (broker `ok`, latch unlatched), `attack_authorized:false` (gate holds until Manual checks) |
| `sr-bastion` on 203 (`:2222`, host key pinned by fingerprint `SHA256:uamaB/…`) | `active`, `LISTEN 0.0.0.0:2222`, clean publickey refusal; defect found+fixed: unit missed the derived env (now loads it like `sr-api`) |

Open (operator Manual checks, plan §Manual checks): teammate LAN paths
(`:8443`/`:2222` allowances), isolation denials with positive controls,
emergency-stop drill + read-back + release, rehearsal launch→end→cleanup
→second launch with a second member, then `SR_ATTACK_AUTHORIZED=1`.
Backup destination/restore remain explicitly unverified (not release-blocking).
The inference endpoint `http://10.10.10.197:8096/v1` answers
`qwen3.8-flash-next` `loaded`.

## Live deployment hardening — the pin-serving failure (2026-10-16, `a6fd49c`)

Live find (operator session on the first production install above): every
bastion guest dial failed `HostKeyNotVerifiable` after auth and token resolve
succeeded, on a deployment that reported `ready`. Deterministic, not a race.
Independent repro (standalone script, not committed): a known_hosts line
built from the truncated `host_key_ref` display form yields ZERO trusted
keys — asyncssh silently drops unparseable lines — while the full key
verifies and connects. The token endpoint served that ref as
`target_host_key` (introduced by `e6f380f`, "api-served pins"), so no
deployment pin was ever dialable. The boot-completion/stability gates
(`5fc6bb7`, `29d1471`) were sound and unrelated.

Repairs (commits `6cef3cc`, `0d33723`, `a6fd49c`):

- `_pin_host_key` stores the FULL public key as `host_key_pin` next to the
  display-only ref; resume repins when ref, full pin, or publication is
  missing — legacy ref-only rows backfill without a re-clone.
- `GET /tokens/{token}` serves only the full pin (`dial_pin_for`); a
  ref-only row serves `None` so the bastion fails closed.
- The bastion validates the pin before any dial (`PinRefused`, no pin
  material in member output or the recording).
- Readiness requires the full pin; a ref-only row stays red until resume
  repairs it.
- `read_host_key` client bound 150 → 300 → 360 s (server worst case:
  (120 s boot-marker window + one in-flight request of ≤30 s) + (120 s
  SHARED stability window + one in-flight request of ≤30 s) = 300 s; once
  a window is exhausted NO further probe is issued, so the bound is real);
  the duplicated unreachable except was removed and the stage's own
  retained obligation is no longer re-recorded.

| Exact command/probe | Result / meaning |
|---|---|
| `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest -q -ra -p no:cacheprovider` (clean tree at `a6fd49c`) | Exit 0: **361 passed, 0 failed, 0 skipped, 250 deselected**, 4 warnings, 50.29s. Fast layer; seven new tests over the previous 354. |
| `pytest -q tests/test_bastion_dial_path.py` (real asyncssh server: real host-key verification + public-key auth end-to-end through `_handle_session`) | 10 passed; the full pin reaches the guest (`echo hi`, exit 0); the display-ref shape is refused before any dial (`PinRefused`, no material echoed). |
| `pytest -q tests/test_dial_pin_serving.py` (new fast contract) | Serves `host_key_pin` only; ref-only rows serve `None`; `asyncssh.import_public_key(ref)` raises `KeyImportError` (documents the mechanism). |
| `env -u SR_PG_ADMIN_URL -u SR_PG_ADMIN_CMD .venv/bin/python infra/dev/acceptance.py authority` | Exit 0: **25 passed, 586 deselected, 0 skipped** (broker boundary/durability/cessation, required mode). |
| `.venv/bin/python infra/dev/acceptance.py db` (gate-owned disposable `postgres:16` fixture; the manual `SR_PG_ADMIN_URL` export was overridden by the gate) | Exit 0: **170 passed, 441 deselected, 0 skipped**, 464.8s; includes the new resume-backfill db tests; owned `srtest_*` resources and the fixture container/volume removed. |

Review round (2026-10-16, `e00ed70`): an independent review confirmed the
pin work and raised one blocker — the stability re-reads each received a
FRESH 120 s window, so a slow-but-working sequence (reviewer's virtual
clock: 118 s marker + 110 s read + 2 s pause + 110 s confirmation)
succeeded at ~340 s server-side while the 300 s client bound had already
failed the deployment. Fixed in `e00ed70`: the re-read phase shares ONE
window (each read gets only the time left; an exhausted window allows a
single non-blocking attempt, so `agent_ready_timeout_s=0` fixtures still
pin instantly-answered keys). Evidence: virtual-clock regression tests in
`tests/test_broker_grant_recovery.py` — the 340 s sequence now fails
bounded with `host-key-read-uncertain` retained, and a 118 s marker + 10 s
read still pins; the negative test fails `DID NOT RAISE` when run against
the previous code (regression proven genuine). Fast suite **363 passed**,
authority gate **25 passed** at `e00ed70`.

Review round 2 (2026-10-16, after `e819d95`): the shared window fixed the
polling-sleep case, but `timeout_s=0` bounds retry SLEEPS, not the HTTP
request — each post-exhaustion probe still cost up to the 30 s HTTP
timeout and a success response bypassed the deadline check, so extra
probes could stabilize at **327 s** on the reviewer's virtual clock while
the 300 s client bound had already failed. Fixed: once the shared window
is exhausted the read loop issues NO further probe, the documented server
worst case counts one in-flight request per window (120+30+120+30 = 300 s),
and the client bound is 360 s (20 % margin). Evidence in
`tests/test_broker_grant_recovery.py`: with 29 s requests the pre-fix code
RETURNS a key at t=327 s after 7 key requests; the fixed code raises
`never stabilized` at t=240 s after 4 (`host-key-unstable` retained), and a
slow-but-legitimate 29 s sequence still pins inside the window. The
zero-window fixture `test_pin_waits_for_boot_completion` moved to the
virtual clock because exhausted/zero windows may no longer probe.
Evidence at `00571e9`: fast suite exit 0, **365 passed, 0 failed,
0 skipped, 250 deselected**, 4 warnings, 53.10s; authority gate exit 0,
**25 passed, 0 skipped**; `tests/test_pve_real_client_contract.py`
**22 passed** (static `read_host_key > 300` bound).

Open (operator Manual check): deploy `00571e9` to the service VMs (201
API / 202 broker / 203 bastion), relaunch/resume the existing deployment once
so `host_key_pin` backfills, then re-test the recorded SSH login.
