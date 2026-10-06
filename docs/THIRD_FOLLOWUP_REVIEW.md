# Review of 0b0d726

Reviewed October 6, 2026, after the user pulled the changes. Compared `fa9b881..0b0d726` with `docs/SECOND_FOLLOWUP_HANDOFF.md` and `plan.markdown`. The checkout was clean before review.

**Verdict: materially closer, but still not ready for live model-driven acceptance.** This pass implements considerably more of the previous handoff. The completion report's statement that nothing remains unimplemented is not supported by the production paths. Eight remaining findings below explain the concrete gaps; they do not require additional product scope.

## Improvements worth keeping

- Proxmox lookup distinguishes unavailable from absent, ownership is checked on resume, tags use the full session identity, and teardown preserves uncertain resources.
- Committed operation claims and the partial active-run unique index improve concurrency protection. Legacy deploy checks scenario/status, and ordinary teardown now attempts worker stop.
- Worker settings are role-specific, exclude controller dotenv loading, and receive resolved allowed configuration. Model calls now return through the API's shared scheduler.
- A runner-side cancellation protocol exists, output capture is incremental, and missing bridge coverage no longer claims successful emergency application.
- nft verification inspects structured rules; apply/remove handle individual emergency table presence and check baseline before release.
- Safety evidence merges stores, includes configured ports/API destination, and requires a killswitch-test record.
- The telemetry spool uses locking and acknowledgement IDs; audit grouping handles interleaving, and the installed script now has a shebang and a dedicated service identity.
- The worker consumes the saved scenario snapshot. Verifiers have pinned SSH settings and no longer fall back to arbitrary DNS names when inventory is absent.
- Browser E2E, bootstrap, and shared-scheduler tests are now checked in. Coach labels are more restrained about attribution and claims.

These are meaningful changes. The remaining problem is that several new mechanisms pass isolated tests while their callers still ignore or bypass their guarantees.

## Findings

### T01 — P0: remote cancellation is not connected to authoritative API stop/recovery

**Source-confirmed.** `red_agent/runner.py:113` can return an unsuccessful cancellation summary, but `install_cancellation_handlers():175` discards it and exits the worker anyway. `api/runs.py:203` only checks termination of the worker's local process group and then marks the run cancelled. The API can therefore report successful stop while the remote command is unconfirmed. Its five-second worker grace period can also expire before the remote cancellation control path finishes.

The remote operation UUID and command-group identity remain in the worker's in-memory `_ACTIVE` dictionary. They are not persisted into the API's Run record or another operation inventory. After SIGKILL, `_watch()`/`reconcile_on_startup()` know only the **worker** PGID, not the separate command group or remote operation. `test_worker_crash_does_not_abandon_command_group` manually reads the test's pidfile and kills the command group itself; it does not exercise production recovery and supplies information that recovery does not have.

Transport failure is another hole: a non-timeout SSH exit does not invoke remote cancellation. A timeout returns `cancel_state='unknown'`, but `RedAgentLoop` reduces the result to exit/output and does not halt on that state or retain the remote operation UUID in its action evidence.

Finally, `infra/runner/runner_supervise.sh` tracks the session leader's PID, checks only that it is currently a group leader, and removes its pidfile when the leader exits. A surviving background descendant can outlive that leader; status/cancel then report gone or not-found. There is no recorded start identity protecting against PID reuse, and cancel-before-start leaves no tombstone preventing a later start of the same operation.

**Acceptance:** stop/end/teardown must wait for durable operation cessation; unknown must retain the reservation and block further commands. Crash/restart must recover operation IDs through production code. Test real harmless remote descendants, leader exit, transport loss, SIGKILL, cancellation before remote registration, and PID reuse. Do not use a test-only manual kill as the proof.

### T02 — P1: run requests still bypass lifecycle serialization; stopping is treated as finished

**Source-confirmed interleavings, not executed against PostgreSQL here.** `/run` (`api/app.py:638`) checks the lease and ready deployment but does not acquire/check the operation claim used by teardown/reset/end. A run can pass those checks, pause, then spawn after teardown's “no active worker” check and while the VMs/lease are being released. The active-run unique index prevents duplicate runs; it does not serialize run with teardown/end.

`runs.py:34` excludes `stopping` from `ACTIVE`, although the database index includes it. The queued-stop branch commits `stopping` and, after a wait, returns `ok=True` without confirmed cessation. The spawner's failed queued-to-running update does not persist the new PGID or a terminal cancelled state when termination succeeds. Subsequent lifecycle calls can skip the stopping row; a new run can also remain blocked by that row's unique-index membership. Startup recovery skips stopping rows too.

The post-spawn latch branch marks cancelled regardless of `terminate_group()['ok']`, retaining a false-success path. `complete_run` remains a read/check/update operation without an atomic terminal-state transition, so a concurrent stop/callback can overwrite each other's results.

Operation claims additionally have a time-only stale takeover without a claim token, owner fencing or heartbeat; an operation lasting over 30 minutes can be replaced and its original request can later delete the replacement's claim. Retain this in the same state-machine repair rather than adding another locking layer ad hoc.

**Acceptance:** one consistent operation state machine, atomic/fenced ownership, and production-route barrier tests for run/teardown, run/end, queued stop/spawn, stopping/restart, and callback/stop. Unknown termination is not success.

### T03 — P0: structural firewall verification accepts policies that permit egress

**Reproduced with the real validator/normalizer and explicit nft JSON/inventory substitutes.** `NftDatapath.baseline_status()` only requires the expected rules as a subsequence and rejects extras only when the entire normalized rule is exactly `accept` or `return`. Insert `meta nfproto ipv4 accept` before the expected sequence and verification still returns `ok=True`. This allows all IPv4 packets before they reach the deny rules.

The range set check only requires the configured CIDR to be one member. Adding `0.0.0.0/1` also passes. That expanded destination set turns the intended intra-range accept into an allowance to many external addresses. The probe includes a valid baseline control which passes, then mutates just the extra rule or set membership and observes both false positives.

The current established accepts are also destination-wide for the management CIDR/API host, rather than tied to the permitted connection direction/ports. Existing range-originated connections to other ports at those destinations survive the baseline. This is a source-confirmed policy gap, not a packet test performed here.

`discover_bridge_ports()` prefers local `/sys` before applying the configured command prefix, so a same-named local bridge can be mistaken for the actual target namespace/host. `start_gate()` checks recorded identities, whose topology component is the configured port list; it does not rediscover current ports. A newly attached port can leave old proofs valid until an emergency operation discovers the mismatch and refuses to apply.

**Acceptance:** exact effective-policy equivalence or a genuinely conservative semantic validator, exact range set membership, correct allowed connection tuples, and discovery in the same namespace as nft. Validate current coverage before starting. Add negative-policy tests and packet tests for these cases.

### T04 — P1: deployment still ignores the saved scenario snapshot

**Source-confirmed.** `scenario_engine/orchestrator.py:235` still calls `load_scenario(scenario_id)`. The worker and verifier use the session snapshot, but deployment uses current YAML. Editing the topology after session creation still changes deployed machines independently of the specification being executed and graded.

The new snapshot test changes objective names and checks the snapshot endpoint; it never launches after changing topology or inspects clone/config calls. Thus it does not prove the claimed deployment behavior.

**Acceptance:** deploy/reset must resolve the immutable session specification. Create a session, change the source YAML's template/IP/host/services, then call the real launch/reset routes and verify that every external operation still uses the original snapshot.

### T05 — P1: telemetry enrollment creates credentials but never installs them into hosts

**Source-confirmed.** `_enroll_telemetry()` inserts a ServiceToken and returns plaintext in the deployment response. No deployment code writes the clone's `shipper.env`, installs that credential through cloud-init/guest agent/management SSH, or starts/confirms the enrolled service. The installer still leaves `PROVISION-PER-DEPLOYMENT` and `SET-PER-CLONE` placeholders. Its printed instruction delegates the missing software step to the operator.

The committed token also becomes difficult to recover through the intended interface after a deployment response is lost: a ready deployment's idempotent return omits enrollments; a created resource with `telemetry_token_ref` is skipped. A retry cannot complete automatic enrollment because that mechanism is absent.

The browser test queries the database for the token and manually POSTs a synthetic command event. This is useful API/UI integration evidence, but it does not exercise installation, actual command capture, or delivery from a clone.

**Acceptance:** persist an enrollment phase, securely provision each clone, verify service delivery, and resume safely after a lost response or interrupted provisioning. Test the actual installer/service identity and a harmless command through the real ingest endpoint. Do not count token issuance as host enrollment.

### T06 — P1: production launch can skip readiness checks

**Reproduced with extracted `readiness_checks()` and explicit production settings.** `verification_service.py:134–142` returns `enforced=False, ok=True` when the management key/pins are unavailable, without checking `sr_env`. `/launch` rejects only enforced failures, so this branch allows ready status in production while the returned message claims production refuses it.

Controller validation requires a nonempty known-hosts setting, but not a verifier private key or an existing known-hosts file. A production configuration can pass that validation and still hit this branch. Reset also does not run the launch readiness workflow or establish a clear new session state after recreating resources.

**Acceptance:** dev relaxation must explicitly require dev mode. Production missing key/pins/unavailable checks must block readiness; reset/relaunch must use the same readiness and credential workflow. Assert actual route status and database state, not only the helper's output.

### T07 — P1: streaming command reads can block beyond their deadline

**Reproduced with the actual buffered subprocess pipe and extracted `_bounded_reader()`.** `runner.py:219` calls `stream.read(4096)` on the Popen text stream after select says some data is available. A small write followed by a silent long-running child can leave that buffered read waiting for more characters or EOF. No deadline check runs while blocked.

A harmless Python child wrote one character and held the pipe for half a second: a 0.05-second reader deadline returned/raised only after about 0.53 seconds. Windows does not support select on pipe handles, so the probe substitutes readiness reporting only; the actual blocking text read and subprocess are unchanged. A Linux regression must use real pipe readiness and a long silent interval.

The bound counts text characters rather than encoded bytes as well. The current high-volume `yes | head` test proves truncation under continuous output, not timeout correctness.

**Acceptance:** bounded nonblocking byte reads or a separate drain mechanism with an independent deadline and cancellation; test sparse output, no output, multibyte output and held-open descendant pipes.

### T08 — P1: spool crash recovery can reuse IDs and lose later valid events

**Reproduced using the actual Spooler methods with only Linux flock replaced for serial temporary-file tests.** `_next_seq()` truncates and rewrites its counter in place; a crash after truncation leaves an empty/invalid counter, which the next append resets to zero. Two events can then receive ID 1. Acknowledging the old in-flight ID removes the newer unsent event too, with no drop recorded.

`_read_lines()` skips a malformed trailing line in memory but does not repair the file. With an interrupted `{"interrupted":` tail, a subsequent valid append is joined onto that same malformed physical line and is also excluded from pending delivery. The probe observes the new event in the file but an empty pending queue. Repeated reads count the same bad line repeatedly.

**Acceptance:** durable identity allocation that cannot reuse an outstanding ID after interruption, and actual tail repair/quarantine before any append. Inject crashes between counter truncate/write, record writes and acknowledgements; prove new unsent events survive and gaps count physical loss once.

## Test evidence and plan adherence

The original M0 safety and M3 supervision acceptance remain blocked by T01–T03/T07. M1/M4 still require T04/T06, and M2 still requires T05/T08. Shared model scheduling and coach labels are substantially improved; the browser test is a useful addition to M7, with synthetic capture clearly distinguished from actual host enrollment/recording.

The author's reported 62 unit, 85 DB/adapter and browser/packet results were not independently rerun here. The existing CI workflow does not run the browser suite, and its privileged `-k real_nft` invocation excludes the separate `test_r06_disposable_netns_packet_semantics` test. Add explicit jobs so these new acceptance tests remain enforced.

Local validation:

- `audit/second_review_probes.py` cannot run unchanged on Windows because the new shipper imports Linux-only `fcntl`. This is a platform limitation, not evidence that the Linux shipper import is broken.
- `audit/third_review_probes.py` runs successfully and saves `audit/third-review-results.json`. It contains the firewall, production-readiness, deadline and spool reproductions above, plus a passing exact execution of `test_unit_and_installer_agree_on_service_identity`.
- No project `.venv`/frontend dependencies, Docker, PostgreSQL tools or nft are available here; WSL reports not installed. Full pytest/packet/systemd/browser verification remains unavailable on this host.
- Reviewed the changed production paths, regression boundaries, CI and completion claims. No application code, actual range, firewall, VM or credentials were changed. Probe files use temporary local storage and one short harmless subprocess.

Next assignment: `docs/THIRD_FOLLOWUP_HANDOFF.md`. Concentrate first on authoritative cancellation and lifecycle coordination; do not add features or rerun another broad cosmetic pass.
