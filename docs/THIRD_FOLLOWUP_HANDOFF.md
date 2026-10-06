# Follow-up prompt for the local coding agent

Review baseline: `0b0d726`. Read `docs/THIRD_FOLLOWUP_REVIEW.md` and preserve its historical findings/output. Finish the original `plan.markdown` workflow. Do not expand product scope or mark software gaps as human-only hardware gates.

Implement the following in small, independently reviewable stages. Begin each with a failing production-boundary test. Keep completed fixes from earlier passes. Update the checklist using separate labels for implemented, automatically verified and hardware-unverified.

## 1. Authoritative cancellation and lifecycle coordination — T01/T02/T07

This is the next commit-sized workstream; finish it before provisioning/UI changes.

- Persist command operation identity before dispatch, associated with run and deployment generation. The API must recover and cancel it after worker death without a test-created pidfile or information supplied manually by the test.
- Connect remote cancellation acknowledgement to `/stop`, `/end`, `/teardown`, killswitch and startup recovery. `cancel_active()` returning false cannot be discarded by a signal handler. A worker exiting does not prove remote cessation. Keep unknown work visible, block new commands, and retain its range reservation.
- Handle ordinary SSH connection loss, command timeout and worker SIGKILL. Do not discard unknown remote operations from the inventory or reduce their results to exit-code/output-only evidence.
- Replace leader-PID-only containment with a mechanism that tracks descendants until all are gone and protects against PID reuse. Preserve cancellation tombstones so delayed start requests cannot execute after cancellation was acknowledged. Use harmless commands in tests.
- Make `/run` participate in the same lifecycle coordination as end/reset/teardown. Validate and claim atomically; reject stale session/deployment observations after acquiring the claim.
- Treat queued/running/stopping/cancel-unknown consistently across uniqueness, active lookup, restart recovery and lifecycle checks. A stopping response is not confirmed success. Ensure queued-stop/spawn races eventually persist a correct terminal state and retained process/operation identity on failure.
- Use conditional terminal transitions or locks for callback/stop. A failed kill must never set cancelled. Use claim owner IDs/fencing or equivalent so stale takeover and release cannot erase another request's ownership.
- Replace blocking buffered `read(4096)` with bounded byte-oriented reads and an independent deadline. Preserve a bounded partial output buffer on timeout.

Tests must use the actual lifecycle/recovery functions and, for remote containment, a disposable local SSH/runner fixture:

1. Remote child survives leader exit; API stop must still remove it before reporting success.
2. Worker SIGKILL and API restart recover the persisted operation, then confirm cessation.
3. Failed control connection/ack keeps stop partial, lease retained and subsequent execution blocked.
4. Cancel arrives before remote start registration; late start must not execute.
5. Barrier-controlled `/run` racing teardown/end cannot dispatch against released machines.
6. Queued stop races process registration; no permanent stopping row, unknown worker or false completion.
7. Callback racing stop cannot overwrite a terminal cancellation.
8. One-byte output followed by a long silent interval respects timeout; multibyte output respects byte bounds.

Do not manually kill the descendant in the assertion path and call it production recovery. Cleanup may kill leftovers only after the test has recorded the failure.

## 2. Effective network-policy checks — T03

- Reject unexpected permissive rules anywhere relevant to the expected policy, including conditional early accepts such as `meta nfproto ipv4 accept`. Verify exact expected set membership, not containment of one required element.
- Restrict established allowances to intended flows/directions/ports. Test an already-established connection from range to an otherwise forbidden management/API-host port.
- Discover bridge inventory through the same host/namespace execution mechanism as nft, even when a same-named bridge exists locally. Verify current topology before authorizing a run; config-string equality is not live coverage.
- Distinguish absent nft tables from permission/transport/inspection errors. Unknown inspection cannot substantiate successful removal.
- Add the probe's extra-rule and expanded-set regressions using real nft JSON. Run disposable packet tests that demonstrate the forbidden flows actually fail and intended flows still work.
- Wire both nft roundtrip and namespace packet tests into an explicit privileged isolated CI step. Keep real R740 verification separate.

## 3. Complete actual deployment readiness and enrollment — T04/T05/T06

- Use one immutable session snapshot in `orchestrator.deploy()` and reset. Remove mutable loader reads from session-bound deployment.
- Add a regression which changes host/template/IP/service values in YAML after session creation, invokes launch/reset and checks the real adapter requests against the original snapshot. Testing only the snapshot endpoint is insufficient.
- Implement a durable per-host enrollment phase: issue/retrieve or safely rotate the capability, write API URL/host/session token to the clone via a chosen trusted provisioning channel, start the installed service and confirm delivery before calling enrollment complete.
- Handle interrupted provisioning and lost HTTP responses. A ready deployment's idempotent retry must not make an uninstalled credential irretrievable. Do not store tokens in templates or print them in normal logs.
- Fail production readiness on missing key/pins, nonexistent files, unavailable target or failed service check. Permit the explicit dev relaxation only in dev mode.
- Route reset/relaunch through the same readiness/credential/session-state transitions as launch.
- Test a disposable actual host/service identity producing a harmless command which reaches the actual API with the correct session, then reset/revoke and reject old credentials. Browser tests may retain synthetic events but must label them as synthetic; they do not replace this test.

## 4. Crash-safe telemetry persistence — T08

- Make identity allocation crash-safe. Never reset to a sequence value that can collide with pending or in-flight records. Atomic durable state or stable non-reused IDs are acceptable; keep the solution small.
- Repair/quarantine incomplete trailing records before appending. Preserve subsequent valid events and count lost records once, rather than on every pending read.
- Add serial crash-injection tests in addition to the existing concurrent locking tests: interruption of counter persistence, malformed EOF without newline, append after recovery, restart, and acknowledgement of an older in-flight batch.
- Prove the original append/ack race stays fixed while adding these cases.

## Completion evidence

Run the locked unit, disposable database, production-route concurrency, runner/SSH, installed telemetry, nft namespace and browser tests. Add CI coverage for browser and packet tests currently omitted by its selectors. Record commands, environment, commit and actual outcomes; report unavailable tests rather than counting them as passed.

Correct `docs/SECOND_FOLLOWUP_COMPLETION_REPORT.md` with a dated addendum: snapshot deployment, host provisioning and authoritative stop/recovery were not fully implemented at `0b0d726`. Preserve the historical report rather than rewriting past evidence.

Deliver a short result per T01–T08 with code location, production-path regression and outcome. State any residual implementation work separately from genuine hardware gates. Do not claim “nothing remains unimplemented” on the basis of helper-level or simulated cleanup tests.
