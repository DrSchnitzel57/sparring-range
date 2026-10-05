# Second follow-up review

Reviewed October 5, 2026 at `18377c6`, comparing the remediation with `23688f2`, `docs/FOLLOWUP_REVIEW.md`, and the original **`plan.markdown`** (the actual plan filename).

**Verdict: meaningful improvement, but another focused handoff is necessary. This is not ready for acceptance of M0–M3 or a live model-driven practice session.** The earlier small reproductions now pass. The remaining failures are in resource ownership, concurrency, production configuration, safety evidence, and telemetry delivery. They are not reasons to redesign the product or add features.

The working tree was clean at the start. This review adds documentation and safe probe artifacts only. It does not change application code or operate the range.

## What this pass genuinely fixes

- Run-issued bearer credentials now resolve through ordinary API authentication, are session-bound, and are rejected once the run becomes inactive. The credential is committed before spawn. Normal completion consumes it.
- Bastion token resolution returns the owner's username, and the key check uses it. The new test exercises the real resolver and key file, although it is not a full SSH session test.
- Blue score checks forward `expect`, fixing inverted checks such as `expect: absent`.
- The model queue now marks running Futures correctly and survives the reproduced timeout and task-error paths.
- Contiguous SYSCALL-first audit events retain their fields; trailing groups flush at EOF. Previously recorded evidence is invalidated by an ordinary successful release.
- Proxmox clone now uses `newid`. Pending deployment intent is committed before clone, and sequential retry/idempotency behavior is substantially better.
- Normal end retains the lease while recorded VMs remain; ordinary destroy failures retain resources. Completion derives objective success from verifier events rather than the worker's `complete` flag.
- Worker recovery, local command cleanup, credential allowlists, shared recording storage, and CI's nft installation are worthwhile improvements.

The new tests are better than the prior suite. However, passing those tests does not establish the stronger claims in `docs/FOLLOWUP_REMEDIATION.md`. Its “all twelve acceptance blockers were repaired” statement should be withdrawn until the cases below pass.

## Remaining findings

### N01 — P1: Proxmox read failures authorize deletion or falsely complete teardown

**Reproduced with the actual adapter and extracted ownership function.**

`orchestrator.py:246` catches **every** config-read exception and returns `(True, "gone")`. `_destroy_owned()` still calls destroy after that result. If the ownership read times out but the subsequent status/delete requests work, deletion proceeds without positively identifying the VM. A stale/reused VMID can therefore refer to someone else's resource.

Separately, `infra/proxmox_client.py:132` turns every status-read exception into `unknown`; `destroy_and_wait():161` treats `unknown` as absent and returns successfully. On an outage, teardown can mark a live VM removed, report complete, and release the lease. The new R07 tests inject failing tasks, not read failures, so they miss this path.

Resume has another ownership hole: `orchestrator.py:187` skips cloning whenever the recorded VMID exists, then overwrites its network configuration and ownership tag without checking its identity. A pending VMID is an intention, not proof that the current VM belongs to this deployment.

**Required:** typed absent/unavailable/present outcomes; positively identify resources before *any* mutation, including resume; use exact, collision-resistant ownership markers; retain uncertain resources and reservations. Test config/status timeout, 403/500, actual absent response, foreign VMID on resume, and transient config failure followed by successful status. Do not merely change the exception text.

### N02 — P1: the launch row lock does not serialize deployment; run starts also race

**Source-confirmed transaction boundary defect; concurrent database execution not run here.**

`api/app.py:272` locks the session row, then calls `acquire_lease()`, whose `db.commit()` at `orchestrator.py:92` releases that lock **before deployment**. Two launches for the same session can both pass the lease check. They can create separate deployments, or concurrently resume the same pending deployment. The later per-resource commits release transaction locks too.

`start_run()` does a select-then-insert duplicate check without a lock or database uniqueness constraint. There is no partial unique active-run index in the checked-in migrations. Concurrent `/run` requests can spawn multiple workers. Checking the latch before spawn also leaves a start/engage race: engagement can complete between the gate check and process registration.

**Required:** a durable operation claim or correctly scoped locking that survives the necessary intent commits, plus database-enforced active-run uniqueness and coordinated start/stop/engage transitions. Use barrier-based tests with independent DB sessions; sequential repeated requests do not test concurrency. Include concurrent launch/launch, run/run, launch/teardown, run/end, and start/engage.

### N03 — P1: lifecycle endpoints can release or change the range underneath an active worker

**Source-confirmed.** `api/app.py:413–430` tears down VMs and releases the lease without stopping or rejecting an active run. It leaves the session's ready/running state unchanged. A subsequent session can acquire the static address space while the old worker still operates; `/run` checks session status but not current lease ownership or a ready owned deployment.

The legacy `/deploy/{scenario_id}` endpoint at `app.py:456` also does not check the URL scenario against the session scenario or reject a terminal session. It can deploy an additional topology under an existing session's lease, while teardown filters by the original scenario. This bypasses the tighter `/launch` workflow.

**Required:** one shared state machine for all entrypoints. Teardown must stop and confirm the worker first, or return a conflict. A torn-down session cannot start a run without a valid new launch. Legacy routes must enforce the same scenario, status, reservation, and ownership invariants. Cover retained old tokens and reset behavior as part of that lifecycle.

### N04 — P1: the production worker configuration conflicts with the new environment allowlist

**Validator failure reproduced; end-to-end production subprocess not run here.** `_worker_env()` excludes Proxmox credentials, CA configuration, and bastion target-known-hosts settings. But the worker's runner and LLM use global `get_settings()`, which calls `validate_production()` and requires those controller-only settings. A correctly isolated `SR_ENV=production` worker with only its allowed inputs fails before doing useful work.

There is a second, opposite path: `Settings` always reads `.env` (`settings.py:15`) and the subprocess inherits the controller's working directory. When that file exists, the worker can load the controller credentials back in despite the environment filter. Merely filtering `os.environ` does not enforce the claimed configuration separation. Also, allowlisted settings loaded only from the parent's dotenv are not serialized from the resolved settings object; behavior depends on how the operator supplied configuration.

**Required:** component-specific settings and validation; explicitly pass resolved worker configuration; disable implicit controller-dotenv loading for the worker. Test production spawn without controller credentials and with a sentinel controller `.env`, proving both successful worker startup and absence of those sentinel settings. The new HTTP worker integration test explicitly uses dev/local-dev and cannot close this issue.

### N05 — P0: remote cancellation is still missing implementation, not just missing live evidence

**Source-confirmed and acknowledged in the new runner docstring.** `SshRunner` still kills the local SSH client, without a remote operation ID, remote process inventory, cancellation request, or acknowledgement. `exec bash -lc ...` is not an implementation of remote descendant supervision. Local SIGTERM cleanup is useful but does not establish the remote stop guarantee in the plan.

Local cleanup also depends on the worker signal handler running. A crash or SIGKILL bypasses it while command groups have their own sessions. `_spawn_monitored()` has a gap between spawning and registering the child. The safety layer can still report successful worker termination without knowing whether the command process survived. Startup reconciliation unconditionally marks a latched surviving run cancelled even if `terminate_group()` returned `ok=False` (`api/runs.py`, final branch).

**Required:** supervised remote operations with durable identities and cancel/status acknowledgement, or an equally authoritative runner containment mechanism. Unknown cancellation must remain partial/failed. Test harmless long-running descendants, worker crash, transport loss, API restart, and failure to terminate. These tests can be implemented with disposable local SSH/container fixtures; only final host acceptance needs the user's Proxmox installation.

### N06 — P0: nft success checks still do not establish effective isolation

**Several controller behaviors reproduced with explicit nft boundary doubles; packet behavior assessed from source, not executed here.**

1. With no `RANGE_BRIDGE_PORTS`, `apply_emergency()` still returns `ok=True`, merely embedding a warning that same-bridge coverage is absent. `Supervisor.engage()` can label that a fully engaged killswitch. A nonempty but stale/incomplete port list is not checked against the actual topology either; new clone ports are not incorporated by deployment.
2. `baseline_status()` searches four substrings. An unhooked ordinary chain containing those strings passes, despite filtering no traffic. It does not verify hook, interface scope, ordering, earlier accepts/returns, or the current configuration. The probe demonstrates the unhooked-chain false positive.
3. The baseline still contains `ip protocol ip` (`firewall.py:94`). `ip protocol` tests the **upper-layer protocol**, not “is IPv4”; it is not the intended generic intra-range IPv4 allowance. The new substring test ignores this prefix. The [official nft manual](https://netfilter.org/projects/nftables/manpage.html) documents this field as the upper-layer protocol.
4. For a routed management SSH connection, replies originate from a range address and arrive on the range bridge. The new established rule tests a **management/control source**. Those range-to-management replies miss that rule, the intra-range destination rule and API-port allowance, then hit the IPv4 drop. This needs explicit reply-direction packet tests.
5. Apply tests whether *either* emergency table exists, then unconditionally deletes *both* inside the transaction. If just one exists, the missing-table delete can abort replacement. Removal has the same unconditional two-table problem. Release removes emergency protection before checking baseline health, so a failed release can leave the datapath open even while the latch remains set.

**Required:** topology-aware coverage, truthful partial results, semantic inspection of effective rules, correct reply handling, and atomic operations for every table-presence combination. Preserve emergency protection if baseline verification fails. Add isolated Linux network-namespace/bridge packet tests for permitted SSH/API flows and forbidden WAN/IPv6/same-bridge emergency traffic. The privileged test currently installs and directly removes emergency tables; it does not call `remove_emergency()` through a valid baseline, or send packets.

### N07 — P0: latch/proof reconciliation still has fail-open cases

**Missing-file case and configuration-identity gap reproduced. Other paths source-confirmed.**

- A missing latch file is reported as a successful empty read. With an unreadable DB, `latch_status()` returns `latched=False`, because only two explicit errors trigger fail-closed. Losing the file during a DB outage can forget engagement. A corrupt file plus a reachable DB with no row likewise lacks affirmative release evidence.
- `_latest_records()` returns DB records whenever any exist and never merges newer file records. An engage/release recorded only to the file while DB writes fail can be ignored once the stale DB becomes reachable. Record write failures are still swallowed.
- `config_identity()` omits `range_bridge_ports` and API address/port even though they change rendered rules. The probe changes both and obtains the same identity.
- `start_gate()` still requires only baseline and datapath-proof records; it never requires a successful killswitch test. The proof endpoint asks only for ping and DNS observations. Neither proves worker cancellation or emergency same-bridge isolation, which the plan explicitly requires before model-driven runs.

**Required:** distinguish first bootstrap from lost state, reconcile the newest durable records conservatively, surface persistence failure, bind evidence to the effective topology/configuration, and require explicit successful stop/isolation acceptance evidence. Keep authenticated operator attestation as the documented trust boundary; do not replace it with increasingly permissive string matching.

### N08 — P1: background telemetry delivery introduces a silent data-loss race

**Reproduced with the real stdlib shipper.** `Spooler.remove()` reads pending lines, then replaces the file. The main thread can append between that read and replace; the new, unsent event disappears without a gap count. The probe schedules exactly that interleaving and leaves an empty spool with `dropped=0`.

Delivery identifies acknowledgements by line positions. Trimming during a request can change what those positions refer to, causing unsent records to be removed after another batch was acknowledged. Atomic rename does not make these multi-threaded operations transactional.

Two additional cases still fail: an oversized *first* event creates a file larger than `max_bytes` because the size-rejection branch requires an existing file (513 bytes accepted under a 100-byte limit); and interleaved SYSCALL/EXECVE groups lose uid/comm/exe because a changed event ID closes the prior SYSCALL group. Both are reproduced. Group assembly also has no idle timeout; delivery retries cannot flush an event which the parser has not yet yielded from a long-lived input stream.

**Required:** one synchronized durable queue with stable event IDs and acknowledgement semantics; enforce bounds for every append; assemble by complete event identity with timeout/EOE handling. Test append/ack/trim interleavings, interruption during writes, oversized-first input, mixed event IDs, repeated record types, and idle final-group flushing.

### N09 — P1: the installed telemetry unit still cannot provide the promised command capture

**Source-confirmed; systemd execution not available on this Windows host.** `telemetry/install.sh:27` installs `shipper.py` directly as `/usr/local/bin/sparring-shipper`. The Python file starts with a docstring and has no shebang. The unit invokes that file through `/bin/sh` rather than `python3`; it cannot run as the Python program intended.

The unit uses `DynamicUser=yes`, but the installer creates a root-owned spool directory without `StateDirectory=` or equivalent ownership setup. `ReadWritePaths=` relaxes mount protection; it does not grant Unix write permission. Audit-log read permission for the dynamic identity is not provisioned either.

The per-clone API URL/token/host values remain placeholders; deployment does not replace them. The new golden-image test asserts text presence, not executable installation, permissions, enrollment, or an ingested event.

**Required:** explicit Python invocation or an executable wrapper, correctly owned state storage, narrowly granted audit-log access, and deployment-bound enrollment/revocation. Test the installed systemd service under its actual identity in a disposable Linux VM/container with systemd, then prove a harmless command reaches the correct session.

### N10 — P1: trusted verifiers can read another session's reused addresses

**Source-confirmed; retained from the prior review and sharpened by the new resource states.** `verification_service.host_map_for():58` uses the latest deployment's resources without filtering removed/foreign/failed state or checking lease ownership. Teardown retains those recorded IPs. Scoring an old session after another session acquires the range can SSH to the new session's machines at the same addresses and append results under the old session.

`_resolve():72` falls back to the input hostname when inventory is missing, and `_ssh_exec():38` still sets `StrictHostKeyChecking=no`. Those paths do not uphold the module's “session's OWNED inventory” guarantee.

**Required:** positively resolve an active owned deployment and reservation, use pinned host identity, and return unknown/unavailable without any SSH call on stale or missing inventory. Historical views should serve their recorded final score; do not silently run historical verifiers against current occupants. Add end/teardown → new session → old-session-score tests.

### N11 — P1: the scenario factory still lacks one immutable, actually provisioned specification

**Source-confirmed remaining plan gap.** Deployment and `RedAgentLoop` still load current YAML while backend verification uses the saved session snapshot. Editing YAML between session creation and launch/run changes machines or objectives without changing grading's specification.

The golden script now says vulnerable services belong to per-host scenario cloud-init, but deployment only sets IP, NIC and tags. It does not consume topology `services`, provision the described per-host scenario services, or attach such cloud-init. Moving responsibility into a comment is not implementation. The existing generic cloud-init file is copied to a path; that alone does not execute it.

**Required:** all components consume the same validated session snapshot. Define and implement the minimal provisioning contract for the supported scenarios, or explicitly require versioned prebuilt templates containing their documented services and verify that contract before reporting ready. This is completion of M1/M4, not a request for a general-purpose provisioning framework.

## Plan coverage and scope

| Plan area | Current assessment |
|---|---|
| M0 safety | Blocked by N05–N07. Rule rendering and a successful parser invocation are insufficient for the explicit tested-killswitch prerequisite. |
| M1 deployment | Much improved sequential behavior; blocked by N01–N03 and the provisioning portion of N11. Real template builds remain human acceptance work. |
| M2 capture | Bastion identity wiring improved; complete SSH/recording flow remains unverified. N08–N09 block reliable session command capture. |
| M3 red harness | Worker auth and queue recovery fixed in the tested dev path; production settings, cancellation and concurrency remain blocked. Output is still buffered by `communicate()` before truncation, so the claimed memory/output bound also needs a streaming implementation. |
| M4 verifiers/scenarios | Polarity fixed. N10–N11 still undermine which machines/specification are being graded. |
| M5 coach | Existing per-process queues do not provide shared-server priority between the API and worker. Same-host telemetry still counts as defender response, member remediation claims still count as wins, and the timeline lacks an explicit detection branch. These remain implementation gaps. |
| M6 practice | No independently verified full human practice session. The new worker HTTP test accepts completed **or failed** and merely requires a verifier event and callback; it does not establish a passing verifier, blue capture, score correctness or a usable report. |
| M7 browser | Frontend build is not the planned browser workflow acceptance. No new checked-in browser E2E flow was supplied in this change. |

Do not add product scope now. Keep the approved single-active-range design. Implement shared-server scheduling or explicitly require and validate separate capacity; implement host enrollment and remote cancellation. They cannot be closed merely by listing them as “live gates.” The genuinely environment-dependent gates are actual PVE/template behavior, R740 packet isolation, GPU capacity/latency, Windows image setup, and a full human practice session.

## Validation and confidence

- Re-ran `audit/followup_probes.py`: its earlier auth, polarity, contiguous grouping/EOF, queue and ordinary release reproductions now pass.
- Ran `audit/second_review_probes.py`. Results are saved in `audit/second-review-results.json`: ownership authorized on read timeout; destruction silently returns on status timeout; interleaved command attribution lost; oversize-first spool accepted; concurrent append silently lost; missing-file/DB-outage latch false; configuration identity unchanged after topology/API changes; unhooked baseline accepted; missing-port emergency apply marked successful; isolated production worker settings rejected by the controller validator.
- Reviewed changed production paths, new tests, migrations, Compose, service installation, documentation, and relevant unchanged plan requirements.
- Full pytest was **not** run here: bundled Python lacks pytest/FastAPI/SQLAlchemy/pydantic-settings; no project virtualenv, frontend dependencies, Docker, psql, or nft were found. The remediation's “78 passed” is its author's recorded claim, not independently verified by this review. No real infrastructure, firewall rules, signals, attacks, SSH sessions or credentials were used by the probes.
- Concurrency interleavings and packet semantics marked source-confirmed above still need the explicit database/network tests in the handoff. AST probes isolate real functions with named substitutes; they are focused reproductions, not end-to-end acceptance tests.

Use `docs/SECOND_FOLLOWUP_HANDOFF.md` for the next coding-agent assignment. Preserve the fixes already made; repair and prove the remaining boundaries in small stages.
