# Findings checklist F01–F23 (remediation tracker)

Baseline audit: `IMPLEMENTATION_AUDIT.md` @ `a5b19ab`. Handoff: `LOCAL_AGENT_HANDOFF.md`.
Legend: ☑ = code + automated evidence in-repo; ☑+E = live evidence on Drew's
hardware (operator gate — cannot be closed by the harness, see
docs/OPERATOR_RUNBOOK.md §LIVE GATEs). No finding below is marked done by
claiming live acceptance.

> **Follow-up review round (docs/FOLLOWUP_REVIEW.md, R01–R12):** the review at
> `bd93f0d` reopened several rows below as broken in production paths. All
> twelve R-findings have since been remediated with production-boundary
> regression tests (`tests/test_followup_regressions.py`); see the R-table at
> the bottom of this file for the mapping and evidence. Rows whose R-fix needs
> live hardware stay behind the live gates.

| ID | Priority | Fix (code) | Automated evidence | Status |
|----|----------|-----------|--------------------|--------|
| F01 | P0 | `red_agent/runner.py` ssh-only runner (pinned known_hosts, no local fallback in prod), `red_agent/worker.py`, `api/runs.py` process-group supervision + watchdog + startup reconciliation | m3 `test_m3_run_endpoint_supervises_worker_lifecycle` (dup-guard, killpg, durable state); `start_gate` refuses unconfigured runner | ☑ |
| F02 | P0 | `safety/` package: persisted latch (file+DB), records with config-identity+freshness, run registry, independent datapath layer; arbitrary-PID endpoint removed | m0 killswitch/partial-engage/release-evidence-invalidation tests; m3 `test_m3_run_endpoint_guards` (423 + reasons) | ☑ |
| F03 | P0 | `safety/firewall.py` rendered rulesets (v4+v6+bridge L2, range-scoped, idempotent); `infra/firewall/killswitch.sh` standalone | m0 `nft -c` parse + default-deny structure assertions (also run in CI; `nft -c` green on this host) | ☑ (packet-drop live gate remains) |
| F04 | P0 | `api/auth.py` real credentials (scrypt, documented deviation), per-principal token issuance/revocation, producer-scoped ingest, server-assigned actors, service capabilities (bastion/telemetry/runner) | m7 login lifecycle (expiry semantics via revocation), m2 bastion/telemetry capability tests, m3 `FORBIDDEN_KINDS` path used throughout | ☑ |
| F05 | P1 | `infra/proxmox_client.py` correct verbs/URLs, UPID task polling, TLS policy; `FakePVEHttp` simulates the HTTP boundary (async tasks, failures) | m1 tests drive the REAL client over the fake incl. task-failure injection (`fail_task_fragments`) | ☑ |
| F06 | P1 | single-active `range_lease`, deployment ownership rows, NIC read-back validation, teardown of owned resources only | m1 launch/lease-conflict/reset/teardown/prefix-orphan + failed-deploy ownership tests | ☑ |
| F07 | P1 | compose without red-agent/coach services, migrate job, credential split, `.dockerignore`, locked deps | `docker compose config` cannot run here (no docker) — files reviewed & CI lint only | ◐ (needs operator `docker compose config` + build) |
| F08 | P1 | `/sessions/{id}/launch` shared CLI/browser workflow issuing per-host connection capabilities; revocation at end | m1 launch + `test_m1_end_releases_lease_revokes_tokens_and_scores`; m2 bastion consumes launch token; browser flow smoke | ☑ |
| F09 | P1 | `telemetry/shipper.py` raw audit-line parse (multi-record events), bounded spool + backoff + gap note, capability identity; install script + systemd unit; Sysmon config + fixture | m2 `test_m2_shipper_groups_raw_auditd_lines`, dedup + host-identity tests | ☑ (live VM gate remains) |
| F10 | P1 | verifier typed args (pydantic), polarity (`expect`), three-valued status, baseline-aware cron, flag provenance, shlex quoting | m4 polarity/unknown/provenance/quoting tests | ☑ |
| F11 | P1 | backend `POST /sessions/{id}/score` + trusted finalize on end; CLI/web score over HTTP only | m4 score endpoint (scored/partial), m1 end-score, m6 CLI score prints backend card | ☑ |
| F12 | P1 | coach timeline correlation (same-host, windowed), explicit wins, telemetry gaps, UNSCORED ≠ F, citation validation, failure-weighted study | m5 correlation/gap/miss/win tests, `test_aar_unscored_never_becomes_an_f`, narrative citation test | ☑ |
| F13 | P1 | lifecycle states preparing→ready→running→stopping→complete/failed, `/run` validation + duplicate guard, lease lifecycle | m1/m3 endpoint tests incl. 409-before-launch, 409 busy, watchdog-failed worker | ☑ |
| F14 | P1 | event-id cursor pagination server-side (no head window), prior-summary carry-forward, intent-before-exec, no blind replay | m7 `test_m7_cursor_pagination_deterministic`, m3 restart/compression tests | ☑ |
| F15 | P1 | DONE requires ALL objectives verifier-confirmed (3-strike stop), strict schema + single retry, scenario phases | m3 `test_m3_done_claim_without_verifier_truth_is_refused`, partial-progress test | ☑ |
| F16 | P1 | opaque recording ids, UUID cast names (exclusive create), path containment at registration AND read, exec-channel recording | m2 recording-name opacity + registration; m7 containment + symlink rejection | ☑ |
| F17 | P2 | asciinema-player (vendored via npm) fed by blob URL, header-epoch alignment, multi-recording selector, seek from timeline | m7 replay shape/epoch test; browser check (see final report) | ☑ |
| F18 | P2 | `model_gateway.py` single bounded priority queue shared by hints/red/AAR; outage = visible outcome | m5 `test_hint_jumps_the_queue_ahead_of_batch_work`, AAR persistence/version tests | ☑ |
| F19 | P2 | typed pydantic scenario schema, strict loader (ids/paths/points/polarity/verifier args), session YAML snapshot | m4 loader rejection matrix + snapshot semantics (session YAML embedded in session_start) | ☑ |
| F20 | P2 | per-domain progress from `v_score_items` trusted snapshots, dedup per session, trend, partial visibility | m7 `test_m7_progress_is_per_domain_from_snapshots_over_multiple_sessions` (incl. view fix payload path) | ☑ |
| F21 | P2 | golden provisioning installs auditd rules + shipper + systemd unit + env contract; packer fixed (hashicorp plugin, file provisioner); Windows checklist + Sysmon config/fixture | `telemetry/install.sh` reviewed; packer file valid HCL (no packer binary here to `validate` — operator run) | ◐ (live image build gate) |
| F22 | P2 | test layering: markers (db/adapter/browser/live), disposable unique DB + roles, explicit admin (`SR_PG_ADMIN_URL`/`_CMD`), `sys.executable`, singleton reset, per-test truncate | conftest + whole suite green on clean run; no implicit cluster mutation paths remain | ☑ |
| F23 | P2 | `SR_ENV=production` validation rejects placeholders/TOFU/local runner; docs honest about every deviation | settings validator unit-covered? partially (validator exists); docs/ARCHITECTURE_NOTES + OPERATOR_RUNBOOK rewritten | ☑ (validator test small) |

## Remaining operator (live-evidence) gates — cannot be auto-closed
1. nft packet-level egress proof from a booted range VM (ping/DNS/IPv6).
2. Real Proxmox: linked clone/reset/teardown on R740 + concurrent-launch lease conflict.
3. Real Kali runner over SSH (pinned host keys) + full red run vs live hosts.
4. Real model endpoint through the gateway under load (hints vs AAR).
5. Telemetry from real Linux VM (auditd) AND Windows VM (Sysmon→WEC→ingest).
6. `docker compose config`/build + full-stack boot; golden-image builds (packer/manual); Windows template + Sysmon checklist items.
7. Browser E2E against the deployed stack (local build smoke done).

## Follow-up review remediation (R01–R12, docs/FOLLOWUP_REVIEW.md)

Evidence: `tests/test_followup_regressions.py` unless noted. Full suite green
against a real disposable PostgreSQL 16; nft rulesets validated with the real
`nft` parser and a privileged apply/remove round-trip.

| R | Reopened because… | Fix | Evidence | Status |
|---|-------------------|-----|----------|--------|
| R01 | worker bearer token never resolved by API auth (only the completion callback worked) | `auth.py` resolves the run credential (sha256) as session-bound `runner` capability; revoked when the run is inactive; `start_run` commits the credential BEFORE spawn; callback one-shot; terminal state final; tests use the real credential format | `test_r01_run_credential_authenticates_and_dies_with_the_run`, `test_r01_completion_callback_is_one_shot_and_terminal_final`, `test_r01_real_worker_end_to_end_over_http` (REAL worker subprocess → REAL uvicorn API → local runner → trusted verifier) | ☑ |
| R02 | `/tokens/{token}` returned no username → token logins could never authorize the owner's key | API resolves the owner's username server-side; bastion binds the login to that member's provisioned key (production keys file, no override); asyncssh key-rendering fixed for the pinned version | `test_r02_bastion_token_login_binds_owner_key` (production resolver + keys file + live API; foreign member's key rejected) | ☑ |
| R03 | stopping the worker left command groups alive; killswitch only REPORTED recovered groups; PGID reuse unguarded | runner supervises command handles; worker SIGTERM kills the command group; killswitch PASSES recovered groups to the kill; startup RE-REGISTERS surviving groups; leader start-time identity guard (`runs.pgid_pstart`, migration 0006); worker-termination exceptions cannot block the datapath half | `test_r03_worker_sigterm_kills_the_command_group`, `test_r03_killswitch_kills_recovered_groups_and_reconcile_reregisters`, `test_r03_terminate_group_refuses_reused_pgid_identity` | ☑ (remote-runner cancel-ack protocol remains a live gate) |
| R04 | latch read missing/corrupt state as not-latched; release did not invalidate evidence; proofs accepted reachable-egress observations | conservative latch reconciliation (file OR DB mirror; both unreadable → fail closed; persistence errors exposed); engage/release invalidate prior evidence; datapath-proof schema rejects REACHABLE observations; baseline endpoint cannot override a failed live check | `test_r04_release_invalidates_previously_valid_evidence`, `test_r04_corrupt_local_latch_cannot_forget_engaged_db_mirror`, `test_r04_probe_schema_distinguishes_isolation_from_reachability`, `test_r04_attestation_endpoints_fail_closed`; m0 release test made unconditional | ☑ |
| R05 | bridge-family rules matched the master not ports; release left the L2 table; apply was delete-then-load; baseline verified table existence only | port-set topology render (`RANGE_BRIDGE_PORTS`); destination-constrained intra-range rule; source-scoped established accept; ingest port from settings; ONE atomic `nft -f` transaction for apply and for removal of BOTH families; baseline checks REQUIRED rules | `test_r05_*` (render/atomicity/verification) + real `nft -c` parse + privileged apply/remove round-trip in CI | ☑ (packet-level bridge tests remain a live gate) |
| R06 | clone posted invented `newvmid`; the fake agreed with the mistake | documented `newid`; fake rejects unknown parameters and 404s config of missing VMs | `test_r06_clone_posts_documented_newid_and_fake_rejects_unknowns` | ☑ (real PVE version confirmation remains a live gate) |
| R07 | end released the lease while VMs ran; stop failures ignored; teardown freed the lease after failed destroys; reset skipped the lease | end keeps the reservation while owned machines exist; stop failure → 409, session NOT finalized; lease takeover blocked by residual resources; teardown completes only when all destroys succeeded; reset acquires/verifies the lease; red_verified_complete reconstructed from trusted verifier events | `test_r07_teardown_failure_retains_lease_until_destroy_succeeds`, `test_r07_reset_requires_the_lease`, updated m1 end/lease test | ☑ |
| R08 | VMs cloned before being recorded could orphan; launches not idempotent; teardown trusted stale rows | durable PENDING intent committed before the clone; resume reconciles existing VMs instead of re-cloning; launch idempotent (same deployment, no extra VMs); ownership read-back (tag OR recorded name) before every delete; foreign VMIDs disowned, never deleted | `test_r08_crash_after_clone_leaves_vm_owned_and_resumable`, `test_r08_launch_is_idempotent`, `test_r08_teardown_never_deletes_foreign_vmid` | ☑ |
| R09 | `build_scorecard` dropped `expect` → absent-checks scored with default polarity | polarity forwarded to the verifier | `test_r09_absent_polarity_flips_with_host_state` (clean earns, compromised scores 0) | ☑ |
| R10 | a timeout during execution killed the sole gateway thread, permanently stalling the queue | correct Future state machine (`set_running_or_notify_cancel`), lost-result tolerated, loop survives any task failure | `test_r10_timeout_during_execution_keeps_worker_and_queue_alive`, `test_r10_task_exception_does_not_kill_worker` | ☑ (cross-process shared-GPU scheduling remains a documented live gate) |
| R11 | SYSCALL-first events lost attribution; trailing groups dropped at EOF; delivery only ran when new input arrived; backoff dead on the real outage path; spool trim not byte-aware/atomic | event-id assembly tolerant of record order + EOE + EOF flush; background `DeliveryLoop` (idle recovery, backoff on the false path, final flush at shutdown); byte-bounded atomic spool trim | `test_r11_syscall_first_event_keeps_attribution_fields`, `test_r11_trailing_group_flushed_on_eof_and_eoe`, `test_r11_delivery_backoff_on_false_and_idle_flush`, `test_r11_spool_byte_bounds_and_atomic_trim` | ☑ (host enrollment binding remains a live gate) |
| R12 | compose API loaded the whole `.env` (owner URL); worker inherited all API env; bastion wiring absent; golden script never called the installer | explicit API env allowlist (also for spawned workers via `runs._worker_env`); compose: no env_file, shared recordings volume on BOTH services, bastion token/keys/known-hosts wired; golden script calls `telemetry/install.sh`; runbook claim corrected | `test_r12_compose_splits_credentials_and_wires_bastion`, `test_r12_golden_image_calls_the_real_installer` | ☑ (`docker compose config`/fresh-volume boot remains a live gate) |
