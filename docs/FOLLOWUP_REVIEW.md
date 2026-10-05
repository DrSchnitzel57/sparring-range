# Follow-up review of the remediation

Reviewed October 4, 2026 at `bd93f0d`, against original audit baseline `a5b19ab`.

**Verdict: substantial architectural progress, but not ready for live model-driven practice or acceptance sign-off.** Several findings marked complete in `FINDINGS_CHECKLIST.md` remain broken in production paths. The immediate priority is a real launch → worker → API → runner → verifier integration test, plus network/process shutdown tests. Another broad feature pass would not help as much.

The working tree was clean before review. This review adds this document and safe reproduction artifacts only. No application changes or live infrastructure operations were performed.

## Improvements that are real

- Authentication dependencies, password hashing, member ownership checks and restricted event kinds replace the open API.
- Scoring moved into the backend with score snapshots; deterministic reports no longer invent the old red-completion penalty.
- The default runner is explicit SSH instead of local API-shell execution; the API spawns a separate worker process.
- Deployment ownership tables, a range reservation, task polling and forward migrations now exist.
- Typed scenario/verifier schemas, unknown verifier results, event cursor pagination, summary carry-forward and recording IDs improve the core design.
- Disposable database fixtures, locked requirements, CI and operator documentation are useful additions.

These changes deserve to be retained. The remaining problem is that the pieces are not yet connected and validated consistently.

## Acceptance blockers

### R01 — P1: real worker credentials fail normal API authentication

**Source-confirmed; authentication function reproduced with explicit DB stubs.** `srplatform/api/runs.py:67` stores a SHA-256 credential only in `Run.worker_token`. `worker.py` supplies its plaintext as the bearer token to `HttpTransport`. `api/auth.py:104` looks up only `WebToken` and `ServiceToken`; it never resolves a Run credential. Thus worker reads/writes/verifier requests fail authentication. The dedicated completion callback is a separate auth path and does not fix normal requests.

The tests conceal this mismatch: `tests/helpers.py::make_runner_token` inserts a ServiceToken which `start_run()` never creates. The supervision test replaces the actual worker with `sleep`.

**Fix/test:** unify issuance and validation of a run-scoped credential; enforce active run/session and revocation. Commit the credential/run before spawning so the worker cannot race the transaction. Launch the actual worker against the actual HTTP API with fake model/runner external boundaries, and assert it reads state, appends intent/result and obtains trusted verification. Do not inject a different test-only credential format.

### R02 — P1: launch-issued SSH login cannot authorize the member key

**Source-confirmed.** `srplatform/bastion/proxy.py::_BastionServer.validate_public_key` resolves the token then requires `target['username']` to authorize the owner's key. `api_resolve_token()` explicitly sets `data['username'] = None`; `/tokens/{token}` returns `user_id` but no username. The documented keys file is keyed by member username, not the generated `tok-*` login. Normal token logins therefore fail.

**Fix/test:** return/resolve an authenticated member identity and bind it to the allowed public key. Exercise the production resolver, keys file and API together, not an override callback that approves any key. Verify a different member's key fails for the same token.

### R03 — P0: stopping the worker does not stop its actual command processes

**Source-confirmed.** `api/runs.py` creates a worker process group. Both `SshRunner.run` and `LocalDevRunner.run` create another process group with `start_new_session=True` (`red_agent/runner.py:77` and the corresponding local path). `stop_run` kills only the worker group. The SSH/local command group can survive. Killing a local SSH client would not, by itself, guarantee termination of a detached remote process either; there is no runner-side operation/cancellation protocol despite the docstring claiming remote group cancellation.

After API restart, `/safety/killswitch` queries durable run groups but merely includes them in its response as `recovered_groups`; it never passes them to `kill_workers`. Startup reconciliation does not re-register surviving unlatched groups. A later engagement can therefore miss those workers too. Stored numeric PGIDs are not tied to process start identity, so reuse is another unresolved concern.

**Fix/test:** supervise command handles on the runner, cancel and acknowledge the remote operation, clean up local transport processes, and recover real handles after restart. Test a harmless long-running child/descendant, API restart then engagement, and transport loss. The API must remain alive; no command may survive the advertised successful stop. Ensure an exception in worker termination cannot prevent the datapath half from executing.

### R04 — P0: the safety latch and release evidence can fail open

**Source-confirmed; release behavior reproduced.** `safety/__init__.py:50` returns `latched=False` for missing/corrupt/unreadable state files. The DB mirror is written but never consulted by `latch_status`. State persistence errors are swallowed. A previously engaged latch can be forgotten even when its DB mirror exists.

`release()` says evidence is invalidated but only appends a `release` record. `_record_fresh()` checks neither release time nor engagement time. With fresh pre-existing baseline/proof records, `start_gate()` returns `(True, [])` immediately after release; reproduced locally. No required killswitch-success proof is checked. The baseline endpoint allows `ok=True` to override a failed backend check, and the datapath-proof endpoint records success for any dict containing `ping` and `dns`, without requiring the observations to represent failed egress.

**Fix/test:** reconcile durable stores conservatively, expose persistence failures, invalidate proofs across engage/release/configuration changes, and require fresh checks plus an explicit successful shutdown proof. Operator attestation can remain a trust boundary, but its schema must distinguish successful isolation from observed reachable egress. Add tests starting with valid old proofs, then release; also corrupt/remove the local latch while DB state remains engaged.

### R05 — P0: the nftables controller still cannot substantiate its datapath guarantees

**Source-confirmed; host packet behavior not executed here.** `safety/firewall.py` uses `iifname/oifname "vmbr1"` inside the bridge-family forward hook. That hook sees bridge ports; matching the bridge master requires the appropriate bridge metadata or explicit port topology. Adding a bridge-family table alone does not prove same-bridge drops. The baseline has `ip protocol ip ip saddr @range_hosts accept`, which is not a destination-constrained intra-range allowance; the intended intra-range rule needs correction and packet tests. VLAN is printed in comments but not matched, the ingest port is hardcoded, and existing connections are accepted ahead of restrictions.

`NftDatapath.remove_emergency()` removes only `inet sr_emergency`, leaving `bridge sr_emergency_l2` installed. It can report successful release with the L2 emergency still active. Apply deletes old rules in separate commands before loading replacements, creating a gap and removing old protection if the replacement fails. Baseline verification checks table existence, not required rules. The command prefix still needs a validated deployment path to the actual Proxmox host/network namespace.

**Fix/test:** render and inspect topology-correct rules, atomically replace both families, remove/verify both on release, and check effective baseline contents. Run disposable bridge-port packet tests covering same-bridge traffic, routed egress, established flows, IPv6, isolation scope and management preservation. CI presently does not install nft or provide a privileged packet-test environment; its substring/optional-parser test cannot close this finding. Netfilter distinguishes bridge and interface metadata in its [official metadata documentation](https://wiki.nftables.org/wiki-nftables/index.php/Matching_packet_metainformation) and shows port matching in [bridge filtering examples](https://wiki.iptables.org/wiki-nftables/index.php/Bridge_filtering).

### R06 — P1: Proxmox clone parameter was changed to an invalid name

**Source-confirmed against official documentation.** `infra/proxmox_client.py:120` now posts `newvmid`; QEMU clone expects `newid`. The new fake expects `newvmid` too (`:238`), so adapter tests agree with the same mistake. The old literal-node error was fixed, but real cloning still fails. See the [official Proxmoxer example](https://proxmoxer.github.io/docs/dev/examples/cloud-init/), which calls clone with `newid`.

**Fix/test:** use the documented request schema and make the fake reject unknown parameters rather than mirror invented ones. Confirm the full request against the intended PVE version, including config tags and NIC schema, before closing F05.

### R07 — P1: ending a session releases the shared IP space while VMs remain running

**Source-confirmed.** `api/app.py:296` stops the red worker, scores and releases the range lease. It does not stop, isolate or destroy target VMs. The runbook explicitly retains VMs. Next launch creates additional machines with the same static addresses on the same VLAN. Completed-session status also permits lease takeover in `orchestrator.acquire_lease` without checking residual resources. This defeats the single-active-range design and can make grading/SSH reach the wrong VM.

End also ignores a failed result from `stop_run`, then marks complete anyway. Teardown releases the lease even if individual destroys failed. Reset does not acquire/verify the global lease, and a completed session can reset while another owns it.

**Fix/test:** retain the reservation until all conflicting machines are destroyed or positively isolated; do not finalize as safely stopped after cancellation failure. Validate the lease for every operation that creates/restarts resources. Test end→launch of the same and different scenario with existing targets still up, failed teardown and reset of a historical session.

### R08 — P1: deployment failures can still orphan VMs; retries are not idempotent

**Source-confirmed.** `orchestrator.py:117` clones, sets config, checks NIC and starts the VM before appending its ID to `dep.resources` at line 130. Failure after clone but before append leaves an actual VM outside the cleanup inventory. The intent event is only flushed before the side effect, not durably committed; process crash can lose it. The exception handler records only previously completed resources.

Every launch creates another Deployment and new VMs; repeated requests are not idempotent. Teardown only considers the latest deployment, marks it torn_down even when destroys failed, retains stale resource IDs, and does not perform the promised ownership-tag readback before deletion. Repeated teardown after VMID reuse could delete an unrelated resource. Concurrent start/launch requests also lack sufficient run/deployment uniqueness and transactional serialization.

**Fix/test:** persist owned/pending VM identity and operation state before external work; reconcile uncertain outcomes. Make launch resumable/idempotent, retain partial failures accurately, and verify full ownership before deletion. Cover failures at clone-return/config/start, a process crash between side effects, simultaneous requests, repeated teardown and VMID reuse.

### R09 — P1: backend scoring silently drops the requested polarity

**Reproduced.** `verification_service.py::build_scorecard` excludes `expect` from the arguments passed to `Verifier.evaluate`. A YAML check with `expect: absent` therefore evaluates as the default `true`, potentially rewarding the vulnerability and penalizing its removal. The verifier's own polarity unit test passes, but the backend wiring does not use it. The probe captured `{'host': 'h'}` reaching the verifier and `expected='true'` in the output for an absent check.

**Fix/test:** forward the normalized expected condition and cover both clean/compromised states through POST score and end/finalize, including the resulting report/progress values.

### R10 — P1: one model timeout can permanently stop the queue

**Reproduced.** `model_gateway.py:57` cancels a Future on timeout. `_run()` never calls `set_running_or_notify_cancel`, so the Future can be cancelled while its function is already executing. When it finishes, `set_result` raises InvalidStateError; the exception handler then calls `set_exception` on the same cancelled Future and raises again, terminating the sole worker thread. The next queued request never completes. The probe reproduced both the dead worker and stuck subsequent request.

Also, red runs now execute in separate OS processes, each constructing its own singleton gateway. API coach calls use another queue. Priority across red/coach is therefore still not enforced for a shared GPU endpoint. The architecture note acknowledges this deferral while F18 is marked complete.

**Fix/test:** implement correct Future state transitions/cancellation, survive task exceptions, and route actual shared-server traffic through one scheduler or require truly separate model capacity. Test timeout during execution followed by another request, and contention between the actual worker and API processes.

### R11 — P1: auditd parsing separates fields from the command and drops final groups

**Reproduced with SYSCALL→EXECVE→PROCTITLE fixture.** `telemetry/shipper.py::group_event_records` treats SYSCALL as the closing record. With a syscall-first event, it emits the syscall separately and then emits a command without uid/comm/exe/key. A trailing group is not flushed on EOF. This undermines attribution and correlation. The supplied tests do not establish robust handling of record orders and interleaving.

Delivery retry runs only during startup or when a new input event arrives; the main loop blocks on stdin while idle. A spooled record can remain indefinitely after connectivity returns if no more commands run. The actual false-return outage path does not increment/sleep exponential backoff. Spool bounds remove only one old line and disregard incoming record size, and rewrites are not crash-atomic. Host-only tokens from the runbook create events with null session_id; there is no automatic deployment enrollment.

**Fix/test:** assemble by boot/event identity until EOE/timeout, preserve all fields, flush on shutdown, run delivery independently of incoming activity, enforce byte limits atomically and bind host enrollment to the deployment. Use real audit stream fixtures, idle outage recovery and crash/rotation tests.

### R12 — P1: documented Compose and golden-image wiring is still incomplete

**Source-confirmed.** Compose API still loads the entire `.env` via `env_file`, which contains the owner URL in the supplied example, contradicting its credential split claim. Worker spawning copies all API environment values, contradicting its credential-minimality claim. This is controller credential overexposure; it is not evidence that SSH automatically forwards those values to the remote attacker.

Bastion Compose configuration lacks its service token/authorized-keys/target-known-hosts setup, and API does not mount the recordings volume used by bastion. Thus the documented shared path is not established by this stack. `provision-linux-golden.sh` still only copies a shipper file and enables auditd; it never calls the new `telemetry/install.sh` or creates its unit. The runbook claims it installs vulnerable services too, but that code is absent.

**Fix/test:** restrict environment variables explicitly; connect bastion credentials and shared storage; call the actual installer/provisioner. Run a fresh-volume stack and template install test. Do not close these items based on file presence or comments.

## Further scope/completeness gaps

- `RedAgentLoop` and deployment still load the current scenario YAML, whereas backend verification uses the session snapshot. Mid-session YAML edits can make objectives/topology disagree with grading. All components should resolve one immutable session spec.
- Coach correlation accepts any same-host telemetry command, including unrelated/red-generated host activity, as a response; member-supplied `remediation` events count as wins. `detection` remains absent from the timeline's rendering branches. These labels still exceed the available attribution/evidence.
- Worker completion accepts a result dict and session end trusts its `complete` field for `red_verified_complete` rather than independently reconstructing all trusted objective results. Credentials/callbacks are not actually one-shot, and terminal run states can be overwritten by a late callback.
- Verifier SSH still uses `StrictHostKeyChecking=no`; inventory/IP freshness is not server identity verification.
- No checked-in browser E2E workflow was found; build/smoke claims do not prove real launch/login/capture/finalization. CI's nft test can skip and its release test is conditional, allowing it to pass when the claimed invalidation does not happen.

These should remain open in the tracker. Do not expand product scope to address them; finish the existing shared workflow and operational guarantees.

## Validation performed and limits

Ran `audit/followup_probes.py` with the bundled Python. It uses the real stdlib-only telemetry and gateway modules and AST-extracted checked-in functions with explicit stubs for database/configuration boundaries. It reproduces worker credential rejection, lost scoring polarity, split audit fields/missing EOF output, queue death after timeout, and acceptance of pre-release proofs. Results are in `audit/followup-results.json`.

These are focused reproductions, not a full integration run. This checkout has no `.venv` or frontend node_modules; Docker/psql/nft were not found on PATH. Full pytest, migrations, frontend build, packet tests and live infrastructure remain unverified in this review. No network attacks, model actions, signals, firewall changes or VM operations were run.

## Recommended next agent instruction

Repair R01–R12 above in focused changes. First add failing production-boundary regressions: actual worker-issued bearer auth, production bastion token-to-member lookup, documented Proxmox clone parameter, backend absent-polarity scoring, timeout recovery, and release with previously valid evidence. Then fix the process/datapath stop boundary and session/resource invariants. Finish with one actual HTTP/API/worker/bastion/telemetry/final-score practice loop using safe external substitutes and a disposable PostgreSQL database. Keep real network isolation and human practice as explicit live gates. Reopen checklist entries until that evidence exists; do not use a fake that implements a different protocol than production.
