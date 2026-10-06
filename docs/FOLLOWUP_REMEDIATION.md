# Follow-up review remediation (R01–R12)

> **Correction (second follow-up review, `docs/SECOND_FOLLOWUP_REVIEW.md` at
> `18377c6`):** the "all twelve acceptance blockers were repaired" verdict
> above was OVERCLAIMED. The review demonstrated that several fixes had
> fail-open paths (R04/R05/R07/R08 equivalents → N01–N03, N07), that some
> "live gates" were actually missing implementation (remote cancellation →
> N05, the installed telemetry unit → N09, provisioning readiness → N11), and
> that in-process proofs stood in for cross-process contracts (→ N08, F18).
> The R-table below stands as historical record of what was attempted; the
> authoritative current status is the N-table in `docs/FINDINGS_CHECKLIST.md`.
> The "live gates that remain" items 4 (cross-process scheduling), 5
> (enrollment binding) and 7 (browser E2E) were subsequently IMPLEMENTED with
> automated evidence (Stages 3–5) — they are no longer mere deferrals.

Executed October 5, 2026, against `docs/FOLLOWUP_REVIEW.md` (reviewed at
`bd93f0d`), with production-boundary regression tests, per the review's
recommended instruction: failing boundary regressions first, then the
process/datapath stop boundary and session/resource invariants, then one real
worker→API→runner→verifier practice loop with safe external substitutes.

**Suite status: 78 passed** (47 pre-existing + 31 new) against a real
disposable PostgreSQL 17; nftables rulesets validated with the real `nft`
parser plus a privileged apply/remove round-trip. The review's own probes
(`audit/followup_probes.py`, updated for the fixed code) now report every
original reproduction as resolved; results in `audit/followup-results.json`.

## What changed, per finding

| R | Fix (production code) | Regression evidence |
|---|----------------------|---------------------|
| **R01** | `api/auth.py` resolves the run-scoped credential (sha256 on `Run`) as a session-bound `runner` capability; revoked the moment the run is inactive. `start_run` **commits the run + credential before spawning** (no credential race). Completion callback is **one-shot** (credential consumed) and **terminal state is final** (`RunStateError` → 409). `tests/helpers.make_runner_token` now issues the REAL credential format (Run row), not a ServiceToken stand-in. | `test_r01_run_credential_authenticates_and_dies_with_the_run`, `test_r01_completion_callback_is_one_shot_and_terminal_final`, and `test_r01_real_worker_end_to_end_over_http`: the REAL worker subprocess against the REAL uvicorn API with only the model server (fake OpenAI HTTP) and Proxmox (fake PVE HTTP) faked — asserts red-attributed intent/result events, trusted backend verifier events, and a landed completion. |
| **R02** | `GET /tokens/{token}` resolves the owner's **username** server-side; `api_resolve_token` stops discarding it; the bastion binds the token login to that member's provisioned key. Also fixed the bastion's key rendering for the pinned asyncssh (2.24) API. | `test_r02_bastion_token_login_binds_owner_key` — production resolver + production authorized_keys file + live API; owner key accepted, **another member's key rejected for the same token**. |
| **R03** | Runner supervises command handles; the worker installs a SIGTERM handler that kills the CURRENT command group (`runner.install_cancellation_handlers`). Killswitch now **passes recovered durable groups into the kill** (was report-only); startup reconciliation **re-registers surviving groups** into the registry. PGID-reuse guard: `runs.pgid_pstart` (migration 0006) records the group-leader start time; termination refuses mismatched identity. Worker-termination exceptions can no longer block the datapath half of `engage`. SSH docstring made honest (remote cancel-ack is a live gate; remote command runs as session leader for SIGHUP-on-transport-loss). | `test_r03_worker_sigterm_kills_the_command_group` (real subprocess + real command group), `test_r03_killswitch_kills_recovered_groups_and_reconcile_reregisters` (real process killed via durable row), `test_r03_terminate_group_refuses_reused_pgid_identity`. |
| **R04** | `latch_status` reconciles file **OR** DB mirror conservatively; both unreadable → **fail closed**; persistence errors exposed (`persistence_error`), DB mirror row auto-created. `_record_fresh` invalidates any evidence predating the latest engage/release. Datapath-proof endpoint **structurally rejects reachable-egress observations** (regex markers; `100% packet loss` vs `0% packet loss` handled). Baseline endpoint cannot override a failed live check to `ok=True` (409). | `test_r04_release_invalidates_previously_valid_evidence`, `test_r04_corrupt_local_latch_cannot_forget_engaged_db_mirror`, `test_r04_probe_schema_distinguishes_isolation_from_reachability`, `test_r04_attestation_endpoints_fail_closed`; the m0 release test's conditional assertion was made unconditional. |
| **R05** | Bridge-family rules match **bridge ports** (`RANGE_BRIDGE_PORTS` set; honest warning when unconfigured). Baseline: destination-constrained intra-range allow, source-scoped established accept (no blanket pre-allow), ingest port from settings. Apply = **one atomic `nft -f` transaction** (delete-if-present + replacement; a failed load keeps the old protection). Release removes **both families** in one transaction and **verifies both are gone**. Baseline verification checks REQUIRED RULES, not table existence. | `test_r05_*` (render topology, atomicity, both-family removal, rule-level baseline check) + real `nft -c` parse of every render + privileged apply/remove round-trip (`test_r05_real_nft_apply_remove_roundtrip`), now running in CI (nftables installed; privileged step). |
| **R06** | Clone posts the documented `newid`; `FakePVEHttp` **rejects unknown clone parameters** and 404s config reads of missing VMs like real PVE. | `test_r06_clone_posts_documented_newid_and_fake_rejects_unknowns`. |
| **R07** | `end` keeps the reservation while owned machines exist (`lease_released: false`); a failed `stop_run` → 409 and the session is NOT finalized; lease takeover blocked by residual resources; teardown completes (and frees the lease) only when every destroy succeeded; `reset` acquires/verifies the lease; `red_verified_complete` is **reconstructed from trusted verifier events**, never from the worker's self-report. | `test_r07_teardown_failure_retains_lease_until_destroy_succeeds`, `test_r07_reset_requires_the_lease`, rewritten `test_m1_end_releases_lease_revokes_tokens_and_scores` (end→conflict→teardown→launch). |
| **R08** | Durable **PENDING** resource intent committed BEFORE the clone; resume reconciles an existing VM instead of re-cloning; launch is **idempotent** (same deployment, no extra VMs); every delete is preceded by an ownership read-back (tag OR recorded name); foreign VMIDs are disowned, never deleted; launch takes a row lock to serialize concurrent requests. | `test_r08_crash_after_clone_leaves_vm_owned_and_resumable`, `test_r08_launch_is_idempotent`, `test_r08_teardown_never_deletes_foreign_vmid`. |
| **R09** | `build_scorecard` forwards `expect` to the verifier. | `test_r09_absent_polarity_flips_with_host_state` (clean host earns the absent-check; compromised host scores 0). |
| **R10** | Correct Future lifecycle in the gateway loop (`set_running_or_notify_cancel`), lost `set_result`/`set_exception` tolerated, loop survives any task failure — a timeout during execution can no longer kill the sole worker thread. | `test_r10_timeout_during_execution_keeps_worker_and_queue_alive`, `test_r10_task_exception_does_not_kill_worker`. |
| **R11** | Event assembly keyed by event id, tolerant of SYSCALL-first order, EOE, interleaving, and **EOF flush of trailing groups**. Delivery moved to a background `DeliveryLoop` — retries while idle, exponential backoff on the real (false-return) outage path, final flush at shutdown. Spool trim is byte-aware (fits the incoming record) and crash-atomic (temp+fsync+rename). | `test_r11_syscall_first_event_keeps_attribution_fields`, `test_r11_trailing_group_flushed_on_eof_and_eoe`, `test_r11_delivery_backoff_on_false_and_idle_flush`, `test_r11_spool_byte_bounds_and_atomic_trim`. |
| **R12** | Compose API: `env_file` removed, explicit auditable env (owner URL impossible), recordings volume mounted on BOTH api and bastion, bastion service token/authorized-keys/target-known-hosts wired. Spawned workers get an **environment allowlist** (`runs._worker_env`) instead of the full API env. `provision-linux-golden.sh` calls `telemetry/install.sh` (unit + ENRICHED + spool) and enables the unit; the runbook's "vulnerable services" claim corrected. | `test_r12_compose_splits_credentials_and_wires_bastion`, `test_r12_golden_image_calls_the_real_installer`. |

## Also fixed along the way

- `tests/conftest.py`: the `SR_PG_ADMIN_URL` admin path wrapped `CREATE DATABASE`
  in a transaction (harness bug — DB tests could never run on that path);
  `wipe_data` now clears `safety_state` (the latch mirror leaked across tests).
- Bastion key comparison worked only with an old asyncssh API; now version-tolerant.

## Validation performed

- Full suite: **78 passed** repeatedly against real PostgreSQL 17 (disposable
  per-session DBs via the real Alembic path, including new migration 0006).
- Real `nft` parser validates every rendered ruleset; privileged apply/remove
  round-trip against the real kernel netfilter (CI now installs nftables and
  runs that step).
- The review's own probe suite re-run against the fixed code: worker bearer
  auth accepted + revocation enforced, `expect: absent` reaches the verifier,
  SYSCALL-first attribution preserved + EOF flush, gateway worker alive after
  timeout, gate refuses pre-release evidence.
- Real worker subprocess → real HTTP API → real local runner → trusted
  verifier loop, green.

## Explicit live gates that remain (cannot be closed in-repo)

1. Packet-level bridge tests on the real Proxmox host (same-bridge drop,
   routed egress, IPv6, management preservation) — the rendered rules are now
   topology-correct and kernel-validated, but packet truth is Drew's gate.
2. Real PVE version confirmation of the full clone/config request (F05).
3. Remote-runner cancel-and-acknowledge protocol (SSH transport loss leaves a
   best-effort SIGHUP, not a guarantee).
4. Cross-process shared-GPU model scheduling (one scheduler per shared server,
   or separate capacity) — documented deferral stands.
5. Telemetry host enrollment bound to the deployment (per-clone token
   provisioning) and real auditd/Sysmon streams.
6. `docker compose config`/fresh-volume stack boot; golden-image build.
7. Browser E2E against the deployed stack.

The "further scope/completeness gaps" section of the review (single immutable
session spec across loop/deployment, coach attribution labels, verifier SSH
host-key pinning, checked-in browser E2E workflow) was deliberately NOT
expanded into, per the review's own instruction to keep them open in the
tracker and finish the shared workflow first.
