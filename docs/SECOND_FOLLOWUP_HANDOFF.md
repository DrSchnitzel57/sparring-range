# Coding-agent handoff: finish the production boundaries

Copy the prompt below into the coding agent working on this repository. Baseline reviewed: `18377c6`.

---

Review and repair the remaining implementation defects in `docs/SECOND_FOLLOWUP_REVIEW.md`. The contract is the original `plan.markdown`, interpreted with the accepted single-active-range architecture. Preserve the genuine fixes in the latest remediation. Do not redesign the product, expand to multi-tenancy, or add unrelated features.

Work in the stages below, with small cohesive commits if your normal workflow permits commits. Finish each stage's negative-path regressions before calling that stage complete. Do not announce that all previous findings are repaired while assigning missing implementation to the human as a “live gate.” Real hardware acceptance and missing software are different things.

First read the review, relevant source, `docs/ARCHITECTURE_NOTES.md`, and the existing tests. Run the current baseline suite in a disposable database. Reproduce `audit/second_review_probes.py` before fixing it. Those probes deliberately use narrow substitutes; convert their cases into production-path regression tests as appropriate. Preserve the review and original reproduction output as historical evidence. Save new validation output separately with its commit and environment.

## Stage 1 — Make resource ownership and lifecycle operations safe (N01–N03)

This is the first implementation priority. An unavailable management API must never mean “VM absent,” and a pending VMID must never mean “VM owned.”

1. Introduce explicit resource lookup outcomes at the Proxmox adapter boundary. Classify actual absence according to the target PVE API response contract; propagate authentication, permission, transport, timeout and server failures. Do not broadly catch everything as missing. Strengthen the HTTP fake to produce these distinct responses.
2. Make destroy return a meaningful confirmed outcome. On an uncertain read/task result, retain the resource and lease and report incomplete teardown. On confirmed absence, do not issue another delete. A transient failure to read identity must never authorize a later successful delete.
3. Validate ownership before resume reconfiguration/start as well as deletion. Use exact parsed, PVE-valid, collision-resistant ownership identity. Handle the clone-before-tag crash window with a documented creation identity rather than adopting any VM at the intended numeric ID. A foreign VM must receive no set-config, start, stop, or delete calls. Validate tags and other request schemas against the supported PVE version.
4. Replace ineffective request-row locking with a correct operation claim/serialization design. Intent commits are necessary; they must not surrender ownership of the operation. Use DB-backed claims or properly scoped locks, with crash recovery. Do not hold a normal row lock and assume it survives `commit()`.
5. Add database-enforced active-run uniqueness and atomic state transitions. Resolve simultaneous starts without spawning duplicate workers. Coordinate start registration with engagement and end/stop; a start racing an engaged latch must not escape supervision. Cover a worker reporting completion before the spawner's post-spawn state update, and a callback racing stop.
6. Apply one lifecycle policy to launch, legacy deploy, reset, teardown, run and end. Validate session/scenario equality everywhere. Reject terminal-session deployment except through an explicitly documented reset/relaunch transition. Stop and confirm the worker before teardown releases its machines/lease, or reject teardown until stopped. Require current reservation and a ready owned deployment before starting a run. Revoke/refresh capabilities on reset/teardown as needed.
7. Preserve partially failed reset/teardown bookkeeping across request rollback. A failed reset must not lose the evidence of what was already removed or what remains uncertain.

Required tests, using actual API routes and independent DB sessions where relevant:

- Config-read timeout followed by a working status endpoint: no deletion without ownership.
- Status timeout/403/500 during teardown: resource retained, `complete=false`, next launch conflicts.
- Confirmed missing VM: idempotent removal, no unnecessary delete.
- Pending VMID now belongs to foreign VM: zero mutation of that VM.
- Failure at clone acceptance/completion, tag/config and start; retry reconciles exactly once.
- Barrier-synchronized launch/launch, run/run, launch/teardown, run/end and start/engage. Assert external call counts and final database state, not only response codes.
- Running session → teardown attempt → second session launch: no old worker can act on reused addresses.
- Mismatched legacy deploy and terminal-session deploy are refused before side effects.
- Failed teardown followed by retry, reset failure followed by retry, and API restart during a claimed operation.

Acceptance: only confirmed owned resources are mutated, uncertain resources keep their reservation, concurrent requests cannot create duplicate live operations, and every public route preserves those invariants.

## Stage 2 — Close the safety implementation gaps (N05–N07)

Keep network and process shutdown independent. Report each layer's observed outcome. A warning about missing isolation must not accompany an overall `ok=true` claim.

1. Implement authoritative runner operation supervision and cancellation. Give commands stable operation identities and a status/cancel/acknowledgement path, with restart reconciliation. An SSH disconnect alone is insufficient. A runner-side service or equivalent supervised containment is acceptable; choose the smallest maintainable design. Scope it to the configured isolated runner.
2. Ensure worker crash/SIGKILL and API restart do not abandon command groups. Close spawn/register races. Mark cancellation unknown or failed until confirmed; never unconditionally convert a failed termination into cancelled at startup. Do not signal unrelated reused process identities. Add bounded streaming output capture rather than buffering arbitrary output before truncating it.
3. Make emergency bridge coverage follow the actual selected topology, including ports created after evidence was recorded. Either use the correct bridge metadata with the chosen VLAN design or maintain and validate the complete port inventory. Missing/incomplete coverage must prevent a full-success response and subsequent start authorization.
4. Repair baseline packet logic. Remove the mistaken generic use of `ip protocol ip`; allow only intended intra-range traffic and the permitted control paths with their replies. Test management-to-range SSH replies explicitly. Maintain default deny for range WAN/IPv6, including pre-existing forbidden connections. Keep unrelated management traffic intact.
5. Verify effective nft policy structurally, preferably with JSON output and normalized expected configuration. Require the correct family/table/base-chain hook/priority, interface/topology scope, rule ordering, sets and allow/drop behavior. Reject unhooked chains or earlier unconditional accepts/returns. Substring presence is not sufficient.
6. Make apply/release atomic and idempotent for neither table present, inet only, bridge only and both. Distinguish missing tables from inspection failures. A failed replacement must retain prior protection. Verify baseline before dropping emergency protection and preserve/reinstate protection if release cannot safely finish.
7. Fix durable state reconciliation: missing/corrupt state is not affirmative release. Define explicit first-install initialization. Reconcile stores without preferring stale DB data over newer file events. Make persistence failure observable and deny new starts if state/evidence cannot be established.
8. Bind evidence to all effective network settings and topology, including API destination/port and bridge ports or discovered equivalent. Add a distinct successful killswitch-test requirement covering command cessation and datapath isolation, with defined validity across configuration and deployment changes. Do not let release immediately reuse old baseline/datapath proofs. Use typed operator observations and retain their provenance; operators remain the stated trust boundary.

Required automated evidence:

- Harmless remote long-running child/descendant is gone after stop, timeout, transport loss, worker crash and API restart; failed acknowledgement yields partial/failed status and blocks reuse.
- No command spawned concurrently with engagement escapes supervision.
- Disposable Linux namespaces/bridges test permitted management SSH and API flows, intra-range IPv4, forbidden routed WAN, IPv6, existing forbidden connections, same-bridge emergency isolation and unaffected management paths.
- Empty/stale port inventory, an unhooked baseline, wrong scope, early accept, and modified sets all fail validation.
- Both emergency table presence combinations and failed atomic loads/releases retain correct protection.
- Missing file + unavailable DB, corrupt file + no mirror, stale DB + newer file engage/release, and dual write failures cannot authorize a start.
- A topology/API setting change invalidates proof; no successful killswitch acceptance record means no production run.

Run privileged tests only in disposable test namespaces/VMs. Never install audit test tables in the developer's real range namespace. Keep final R740 packet validation as an explicit human gate after these automated tests pass.

## Stage 3 — Make the production worker and installed telemetry actually work (N04, N08–N09)

1. Split controller and worker configuration validation. The worker must start in production using only the API capability, model endpoint configuration and runner channel it requires. Serialize resolved allowed settings explicitly; do not depend on whether the operator used environment variables versus dotenv.
2. Disable automatic loading of the controller `.env` in the worker. Add a test with dummy sentinel controller secrets in the parent working directory; prove the worker neither needs nor loads them. Do not fix this by handing Proxmox/owner DB/bastion secrets to the worker.
3. Replace positional, unsynchronized spool acknowledgements with a durable queue design using stable record identities. Synchronize append/trim/acknowledge; account for records created while an HTTP batch is in flight. Enforce byte limits including the first oversized record. Persist visible gap/drop counters; recover safely from interrupted writes.
4. Fix audit assembly for interleaving and live idle streams. Group by appropriate boot/source/event identity, preserve all required record fields, and close by EOE or a bounded completion timeout. Do not close just because a different event ID appeared or because SYSCALL arrived. Support or visibly reject repeated/chunked EXECVE data without silent replacement. Preserve source encoding semantics for quoted versus hex fields.
5. Fix the installed unit: use `python3` or an actual shebang wrapper, provision writable state for its service identity, and grant only the log access it needs. Exercise the installed artifact, not just source imports or substring checks.
6. Implement per-deployment telemetry enrollment: provision API URL, host identity and session-bound token in each clone; revoke on end/reset/teardown according to the lifecycle policy. Keep live tokens out of templates and repository files. Validate ingest under the correct session. State what can and cannot be trusted from a compromised host.

Required tests:

- Actual production-mode worker startup under least-privilege configuration, including settings originally supplied through dotenv.
- Deterministic concurrent append/acknowledge and trim/in-flight-delivery tests; no unsent event disappears without an explicit gap.
- Empty-spool oversized first append, interrupted rewrite/append, malformed trailing data recovery, outage followed by idle delivery, graceful shutdown.
- Interleaved SYSCALL/EXECVE/PROCTITLE/EOE fixtures with uid/comm/exe/argv preserved; final no-EOE event becomes deliverable while input remains open.
- Fresh Linux install under systemd: unit starts with its configured identity, reads a harmless command event, writes its spool, and delivers it to the actual API with the enrolled session. Revoke/redeploy and verify old credentials cannot contribute to the new session.

Acceptance: the claimed production worker and capture path run from the documented deployment mechanism, with no controller configuration leakage and no reproduced silent spool loss.

## Stage 4 — Make specification, targets and grading agree (N10–N11)

1. Resolve deployment, worker objectives, verification and reporting from one immutable validated session snapshot. Expose the needed snapshot to the worker through its session-scoped API capability. Do not reread mutable current YAML mid-session.
2. Restrict verifier host resolution to active positively owned resources for the correct reservation/deployment generation. Filter removed/foreign/uncertain resources. Missing or stale inventory must produce unknown/unavailable with no DNS fallback or SSH attempt.
3. Pin verifier SSH host keys and handle changed/missing keys visibly. Record the target/deployment identity in verification evidence. Historical report retrieval uses recorded score snapshots; any explicit live rescore must validate that it is still addressing the same owned deployment.
4. Complete the minimum scenario provisioning contract. Either implement the supported per-host configuration or declare versioned prebuilt template requirements with real readiness checks for the services a scenario needs. Do not list service names in YAML and silently ignore them. Do not claim cloud-init applied because a YAML file was copied to disk.
5. Strengthen the real worker HTTP integration test so a passing objective requires a controlled true host state, a false state fails, and unavailable verification remains unknown. It must assert the intended outcome, not accept both completed and failed as equivalent success.

Required tests:

- Create session → change source YAML → deploy/run/score still use the original snapshot.
- End/teardown A → launch B at reused static IPs → score/check A makes no SSH call to B.
- Missing inventory, foreign/removed resource, stale deployment generation, and wrong host key do not yield a pass.
- Fresh supported scenario reaches ready only after documented service/configuration readiness, with correct inventory, enrollment and host identity.
- Successful controlled objective and final blue score reach the API event log and report with correct values.

## Stage 5 — Close remaining original-plan acceptance gaps without expanding scope

After the safety/resource/capture work passes:

- Route API hint/coach and real worker calls through one shared scheduler when they share model capacity, or explicitly configure and validate separate endpoints/capacity. Demonstrate interactive priority across actual processes. An in-process singleton does not satisfy this.
- Fix coach evidence labels: same-host activity without defender attribution is unattributed activity, not verified response; a member's remediation statement is a claim until verified. Render detection events explicitly. Add small tests that attacker-originated activity cannot earn defender credit.
- Supply a reproducible fresh-stack/bootstrap path for bastion key material and service capability, recordings and required configuration. Confirm `docker compose config` and a fresh-volume boot. Clearly document any dev-only external substitutions; never label an inert configuration key as working integration.
- Add a browser E2E workflow against the actual API: authenticated member → create/launch → connection instructions → captured command/recording → run/end → score/report/progress, with controlled external services. Frontend build remains a separate check.
- Run a full safe practice loop asserting capture, deterministic verification, score, report and cleanup. Retain actual PVE/R740/GPU/Windows image and human-practice acceptance as explicit unexecuted gates where infrastructure is unavailable.

## Completion report and evidence rules

Run the locked unit suite, disposable PostgreSQL/migration/API tests, new concurrency regressions, isolated nft packet tests, runner cancellation tests, installation/enrollment tests and browser workflow appropriate to the changes. For each command record its outcome and environment. If a prerequisite is unavailable, report the exact blocked test; do not count it as passed or silently skip it in an acceptance summary.

Update `docs/FINDINGS_CHECKLIST.md` with N01–N11 and the remaining M5/M7 requirements. Distinguish **implemented**, **automatically verified**, **requires live hardware verification**, and **still missing implementation**. Correct the overclaims in `docs/FOLLOWUP_REMEDIATION.md`, service docstrings and runbook. Do not rewrite historical review findings to imply they never existed.

Deliver a concise final report containing:

- What changed per stage, with the production entrypoints affected.
- New regression tests and exact results, including failure/unknown cases.
- Any unresolved implementation with concrete next steps.
- Human-only acceptance procedures and expected observations.
- Whether a new model-driven practice run is actually authorized by the completed safety gates.

The finish line is the original usable, isolated, honestly graded practice workflow. More passing tests are useful only when they prove that workflow and its failure handling.
