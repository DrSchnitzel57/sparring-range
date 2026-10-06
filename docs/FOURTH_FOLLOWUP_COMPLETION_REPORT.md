# Fourth-follow-up handoff — completion report

Contract: `docs/FOURTH_FOLLOWUP_REVIEW.md` (baseline `213246e`, review
committed as `3b681be`) — the two acceptance blockers and the 7-item
"Focused next-agent prompt". Environment: this authoring host (Debian-ish
Linux, Python 3.13.5 in `.venv`, PostgreSQL 17 on localhost, kernel 7.0 with
cgroup v2 and a delegated user slice, **no docker, no PVE, no R740, no GPU,
no range VMs, no root**).

Legend: **☑ implemented + automatically verified** = production code changed
AND a production-boundary regression (real supervisor script + real cgroups,
real worker loop, real routes, real DB, real shipper subprocess + real
uvicorn) asserts the outcome in this environment. **☑+E hardware gate** =
additionally needs hardware unreachable from here; the automated part is
green and the hardware claim is NOT made.

## Blocker 1 (P0) — completion could hide surviving remote work — ☑

**Supervisor (`infra/runner/runner_supervise.sh`, rewritten):**
containment is now CGROUP v2 (prompt item 3): each operation runs in its own
child cgroup under `RUNNER_CGROUP_ROOT` (delegated directory; the user slice
is auto-detected when writable). Liveness is "the cgroup still has members"
— a descendant that clears its environment cannot escape it (the
`SR_OP_ID` environ scan survives only as a secondary signal). With no usable
cgroup root `start` REFUSES with exit 4 — the unsupported execution mode is
explicitly refused, never silently degraded (the review's "or" branch). The
pidfile records `<pid>:<starttime>` and no process-group signal is sent
unless that identity still matches (recycled-PID guard). Start and cancel
serialize on a per-operation flock — start holds it from the tombstone check
through spawn+pidfile registration, cancel from tombstone creation through
kill+verify — so a cancellation acknowledgement can never precede a delayed
spawn; tombstones still refuse late starts (exit 3). Every verb answers with
exactly one stdout token and unreadable `/proc` entries are skipped without
leaking shell errors into the merged channel. A documented test seam
(`RUNNER_SUPERVISOR_TEST_HOOK`, inert unless set) runs while the start lock
is held so the race is pinned deterministically.

**Runner (`srplatform/red_agent/runner.py`, item 2):** ordinary completion
(zero AND nonzero exits) now queries `containment_status()` before reporting
finished: `running` → contain via the control channel and only report done
with a persisted note when CONFIRMED; unreachable or unconfirmed →
`cancel_state='unknown'` (treated as unknown, never folded into gone). The
bounded reader stops waiting on pipe EOF once the start connection exits —
a survivor holding the pipe open can no longer fold completion into a
timeout. `_verdict()` takes the last non-empty line so channel noise cannot
forge a verdict.

**API (`srplatform/api/runs.py`, `srplatform/api/app.py`, item 4):**
terminal transitions (`stop_run`, `complete_run`) are single guarded UPDATEs
that additionally require `NOT EXISTS (unresolved operations)` —
registration cannot slip between the containment pass and the transition.
`complete_run` gates EVERY outcome (even `worker_failure`) through
`cancel_remote_operations` first; guard loss leaves the run
`cancel-unknown` with the credential consumed. The registration route takes
`SELECT … FOR UPDATE` on the run row and refuses anything outside
`queued/running` with 409 — stopping/cancel-unknown runs are owned by the
termination path. Migration `0009` adds `run_operations.detail` (the
containment verdict is persisted with the operation row).

**Regressions (`tests/test_fourth_followup_containment.py`, 14 tests, items
1/3/4):** cleared-environment descendant visible to status and killed by
cancel (with the marker scan proven blind — the test asserts the premise);
start refused (exit 4) without containment and the command NOT executed;
tombstone refuses start after acknowledged cancel; BARRIER-PINNED
start/cancel overlap via the lock-held hook — after cancel acknowledges
"gone", nothing survives; pgid signal requires start identity (live victim
with wrong startticks is never signalled); zero-exit and nonzero-exit
survivors both contained with the note persisted; unreachable supervisor at
completion ⇒ `unknown`; noise cannot forge a verdict. Full path WITHOUT any
hand-built operation rows (item 1): the real `RedAgentLoop` + real
`SshRunner` + real supervisor run a harmless command whose leader exits 0
with a background child; the ordinary operation-done path records
`completed` + containment note and the child is already gone; then the real
`/runs/{id}/stop` + `/sessions/{id}/end` succeed. The unconfirmed variant
drives the whole refusal chain: loop halts, `complete_run` refuses
finalization (`cancel-unknown`, never `completed`), stop is partial, `/end`
is 409 `worker_stop_failed`, the lease is retained — and after containment
is repaired the retry finalizes and the child is confirmed dead.
Registration-vs-stop races run 5× with barrier-synchronized independent
sessions through the production routes; the invariant "no unresolved
operation on a terminal run" holds every time.

## Blocker 2 (P1) — "enrollment confirmed" proved nothing — ☑ (real auditd/systemd capture: ☑+E)

**Phase machine (`srplatform/scenario_engine/orchestrator.py`, item 5):**
`_enroll_telemetry` now issues a FRESH ENROLLMENT NONCE with every
capability (stored on the `ServiceTokens` row with the deployment id —
migration `0009`), and `_provision_command` writes `SR_ENROLL_NONCE` into
the clone's env file. `_enroll_host_telemetry` advances ONLY on distinct,
committed evidence: `pending_token → provisioned` (channel rc) →
`service_running` (`systemctl is-active` — startup status, explicitly NOT
confirmation) → `delivery_confirmed` (the HOST calls `POST /enroll/confirm`,
authenticated by its capability and bound to the nonce) → `confirmed`
(the capture probe `/bin/true SR-CAPTURE-<nonce>` executed on the host is
OBSERVED as an audit event through the installed service). Failures are
visible with their stage (`provision_failed`, `confirm_failed@
service_running|delivery_confirmed|capture_verified`); timeouts
(`ENROLL_CONFIRM_TIMEOUT_S`, `ENROLL_CAPTURE_TIMEOUT_S`) are failures,
never assumed passes. Readiness wording updated accordingly.

**API (`srplatform/api/app.py`):** `/enroll/confirm` validates the nonce
with `secrets.compare_digest` against the capability's session+host-bound
nonce (never the body), records `enroll_confirmed_at` once + a
`telemetry_enroll_confirmed` event; `/ingest/auditd` matches the capture
marker in delivered events and records `enroll_capture_at` +
`telemetry_capture_verified`.

**Shipper (`telemetry/shipper.py`, item 5):** the INSTALLED service sends
its own authenticated callback (`EnrollmentConfirmer`, visible backoff,
visible abandonment) — the production acceptance path is host-originated,
not a controller-side claim. `install.sh` env template documents
`SR_ENROLL_NONCE`.

**Incidental product bug found by the end-to-end test:** the shipper
hex-decoded every hex-looking unquoted field, so SYSCALL's
`arch=c000003e` decoded to bytes containing NUL — which PostgreSQL JSONB
REJECTS, meaning every real auditd event would have failed ingest (500 →
permanent spool retry). The decoder now only decodes when the result is
printable text; the literal is kept otherwise.

**Regressions (`tests/test_fourth_followup_enrollment.py`, 7 tests, item
6):** callback bound to capability+nonce (wrong nonce 403, unauthenticated
401/403, foreign capability confirms nothing, idempotent repeat); capture
evidence only from the marker event through ingest; ACTIVE service with no
callback ⇒ `confirm_failed@delivery_confirmed` + readiness 409 (startup
status and delivery confirmation DISTINCT — the exact review case);
delivery OK but capture broken ⇒ `confirm_failed@capture_verified` with
delivery evidence retained; the REAL shipper subprocess against the API
served by REAL uvicorn produces BOTH evidences by itself (delivery callback
+ harmless command fed through its stdin arriving as an audit event — the
disposable-Linux-fixture acceptance; the systemd+auditd golden-image capture
remains the VM gate); active shipper with unreachable API or never-issued
token produces NO evidence; confirmer retries visibly then abandons visibly.
The two pre-existing T05 tests were updated to the new contract (their
scripted channel now simulates the host's callback + capture) — `systemctl
is-active` alone no longer reaches `confirmed` anywhere.

## Suite outcomes (exact commands, this host)

| Command | Outcome |
|---|---|
| `pytest -m "not db and not adapter" -q` | **92 passed, 4 skipped** (skips: root+nft+iproute2 ×3, nft-absent ×1) |
| `pytest -m "db or adapter" -q` | **114 passed, 1 skipped** (skip: playwright-cli absent) |
| `pytest -m browser -q` | 1 skipped (no `web/node_modules`/playwright here; CI runs it) |
| `pytest tests/test_fourth_followup_containment.py -q` | 14 passed |
| `pytest tests/test_fourth_followup_enrollment.py -q` | 7 passed |
| `pytest tests/test_third_followup_*.py -q` (T01–T06 regressions) | all pass |

The previously failing `test_t01_ssh_transport_loss_invokes_remote_cancellation`
passes (stderr noise no longer pollutes the verdict);
`test_t03_start_gate_requires_live_topology_match` was latently broken (its
double's mechanism skipped the very check under test and it lacked the `db`
marker) — fixed to actually exercise the live-topology re-check.
CI gained a cgroup-v2 delegation step so the containment tests run on
GitHub runners instead of skipping.

## Not claimed — remaining real-environment gates (☑+E)

- **R740 runner host**: real SSH transport with the supervisor installed,
  cgroup delegation (`RUNNER_CGROUP_ROOT`) provisioned per the runbook, and
  transport-loss behavior on the real link.
- **PVE/R740/GPU**: deployment, datapath, killswitch, bastion — unchanged
  gates from prior reports.
- **Golden-image auditd capture**: the capture probe observed through the
  REAL `auditd` + systemd unit on a range VM (the automated end-to-end here
  used the real shipper + real API with the audit record fed on stdin, not
  real auditd); **Sysmon/WEC** path likewise.
- **Compose/R740 boot** steps of the runbook §0.

Final acceptance is NOT declared: the software side of both blockers is
implemented and automatically verified; the hardware gates above must pass
before that.
