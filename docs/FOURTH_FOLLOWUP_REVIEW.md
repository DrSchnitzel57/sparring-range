# Acceptance check at 213246e

Reviewed October 6, 2026 against the previous T01–T08 findings. The checkout was clean before this review.

**Not ready for final acceptance yet.** Most previous repairs are now present: snapshot deployment, explicit production readiness, provisioned telemetry credentials, durable operation records, shared lifecycle claims, stricter firewall policy checks, byte-oriented reads, spool repair and CI coverage. Keep these changes. The next pass should be narrowly focused on the two remaining acceptance blockers below, followed by the actual infrastructure acceptance run.

## 1. Command completion can still hide surviving remote work

Priority: P0 for the advertised killswitch/cessation guarantee. Source-confirmed call path, with a safe adapter probe.

`SshRunner.run()` checks remote cessation on timeout/SSH exit 255, but its ordinary return path does not query the supervisor. A successful shell can leave a background child with redirected output, allowing the SSH session to end normally while that child continues. The runner removes the operation from its local inventory and returns `cancel_state=None`.

`RedAgentLoop` then maps every result except `cancel_state == 'unknown'` to a completed operation. The API accepts that completion. `cancel_remote_operations()` only visits active/cancel-unknown rows, so later stop/end/recovery skips the surviving child's completed row. The new direct-supervisor descendant test does not exercise this full worker → operation-done → API-stop path.

The safe probe `audit/fourth_review_probe.py` executes the actual extracted adapter method with a successful SSH-process substitute and a supervisor which would answer running. Result: **zero supervisor control calls**, `cancel_state=null`, local inventory empty, and the loop's mapping is completed. This is a call-path reproduction; no real SSH/descendant test ran on this Windows host.

The supervisor itself also needs a stronger cessation boundary:

- `runner_supervise.sh` scans `SR_OP_ID` in `/proc/*/environ`. A process that clears its environment or whose environment is unreadable is invisible. The script acknowledges the cleared-environment escape in its comment, yet reports gone when it sees no tagged processes. Arbitrary model-selected shell commands cannot guarantee that descendants preserve this marker.
- The recorded PGID is signalled without a process start-identity check. An environment marker scan does not protect that separate `kill -<pgid>` path from reuse.
- Start checks the cancellation tombstone and then spawns without mutual exclusion. Cancel can create the tombstone, observe no process and finish between those two steps. The delayed start can still launch. The new test covers sequential cancel-before-start, not that interleaving.
- Operation registration accepts `runs_svc.ACTIVE`, which includes stopping/cancel-unknown. Registration and the run's terminal transition are not serialized around an invariant that all operations must be resolved. This needs to be included in the same lifecycle fix, rather than relying only on the top-level request claim.

**Required acceptance:** the production worker cannot mark an operation complete while remote work survives; stop/end/teardown never release the range until all work is confirmed gone. Use containment independent of a child-controlled environment, or explicitly refuse the unsupported execution mode. Test normal command exit with a background child, cleared environment, inaccessible process state, actual start/cancel overlap, and operation registration racing stop.

## 2. “Enrollment confirmed” still does not prove any telemetry can arrive

Priority: P1 for the complete practice/capture workflow. Source-confirmed.

The new provisioning path is real progress: it writes the token/URL/hostname to the clone and starts the service. But `_enroll_host_telemetry()` sets `phase='confirmed'` based solely on `systemctl is-active --quiet sparring-shipper`.

A shipper can remain active while its API address is wrong, the token is rejected, delivery is blocked, or the audit-log input is unreadable. The shell pipeline/service being active does not establish authenticated delivery or command capture. Those failures can still lead to a ready session with no evidence stream.

The regression uses a scripted management channel and manually submits an event to the API. It demonstrates credential attribution, but not a message sent by the enrolled clone. The completion report's description of delivery being confirmed by systemctl overstates what that check proves.

**Required acceptance:** issue an enrollment nonce/generation and require an authenticated callback from the provisioned host, bound to its session and enrollment. Keep startup status and delivery confirmation distinct. For capture acceptance, execute a harmless command and observe its audit event through the installed service, with timeout/failure visible. Tests must block readiness when the process is active but its API/token/delivery path is broken. Retain a final real auditd/Sysmon test on the user's VMs.

## Focused next-agent prompt

Finish the two acceptance blockers in `docs/FOURTH_FOLLOWUP_REVIEW.md` at baseline `213246e`. Preserve the preceding fixes; do not add product features or reopen unrelated components.

1. First add a failing end-to-end regression: real worker/runner executes a harmless command whose leader exits zero while a redirected background child remains. Let the ordinary operation-done path run, then call the actual API stop/end path. Assert the child cannot survive a successful cessation response. Do not manually construct an active operation row as a substitute for the worker's normal completion path.
2. Make successful operation completion depend on authoritative containment status, not the SSH leader's exit code. Persist unresolved descendants and refuse run finalization while they remain. Treat unknown as unknown. Cover failed normal exits as well as zero exits.
3. Replace environment-marker-only containment with a mechanism which tracks the whole operation independently of child environment changes. Guard process identity for every signal. Atomically coordinate start, cancel and tombstones so cancellation acknowledgement cannot precede a delayed spawn. Add barrier-driven race tests, not just sequential cancellation tests.
4. Serialize operation registration with stop/finalization. Reject new registration for stopping/cancel-unknown runs, and verify there are no unresolved operations before claiming a terminal run or releasing a reservation. Test both sides of the race using independent DB sessions and the production routes.
5. Add host-originated enrollment confirmation bound to a session, deployment generation and fresh nonce. The deployed shipper must send it; a controller-side or test-side synthetic POST is not the production acceptance path. Distinguish provisioned, service-running, delivery-confirmed and capture-verified evidence.
6. Test active service with unreachable API, invalid token and unreadable input. These must not masquerade as a healthy evidence stream. Verify a harmless command through the installed service under its actual identity in a disposable Linux fixture.
7. Run the existing T regressions, new full-path tests, CI unit/DB/browser/packet suites, and update the completion report with exact outcomes. Clearly distinguish automatically verified software from the remaining R740/PVE/GPU/auditd/Sysmon/Compose acceptance steps. Do not declare final completion before those real-environment gates pass.

## Verification limits

I inspected the changed safety, lifecycle, deployment, enrollment and persistence paths and the completion/test claims. All 20 Python files changed since `0b0d726` parse successfully. The safe normal-completion adapter probe ran; its output is `audit/fourth-review-results.json`.

The author's reported Linux suite results were not independently rerun here. This Windows checkout still lacks the previously required Linux/DB/packet/systemd test environment. This review changed only documentation and probe artifacts, not application code or infrastructure. It is a focused acceptance check, not a claim that every possible defect has been enumerated.
