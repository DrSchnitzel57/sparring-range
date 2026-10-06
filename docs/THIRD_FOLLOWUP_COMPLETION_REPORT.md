# Third-follow-up handoff — completion report

Contract: `docs/THIRD_FOLLOWUP_HANDOFF.md` against review
`docs/THIRD_FOLLOWUP_REVIEW.md` (baseline `0b0d726`). Environment: this
authoring host (Debian-ish Linux, Python 3.13.5 in `.venv`, PostgreSQL 17 on
localhost via `SR_PG_ADMIN_CMD="su postgres -c"`, real `nft` + root in
disposable netns, node 22 + `@playwright/cli`; **no docker, no PVE, no R740,
no GPU, no range VMs**).

Stages (each began with failing production-boundary tests; every stage kept
the earlier passes green):

| Stage | Findings | Commit |
|-------|----------|--------|
| 1 | T01, T02, T07 | `77c7971` |
| 2 | T03 | `5c4caf6` |
| 3 | T04, T05, T06 | `f5c5ffd` |
| 4 | T08 | `370d23c` |

## Result per finding (T01–T08)

Legend: **☑ implemented + automatically verified** = production code changed
AND a production-boundary regression (real route / real subprocess / real
nft / real packets) asserts the outcome in this environment. **☑+E hardware
gate** = additionally needs hardware unreachable from here; the automated
part is green and the hardware claim is NOT made.

### T01 — remote child survived leader exit; API stop reported success without remote confirmation — ☑ (real-SSH transport loss on the R740 runner: ☑+E)
Code: `infra/runner/runner_supervise.sh` (rewritten: descendant tracking by
`SR_OP_ID` environment identity — immune to PID reuse — tombstones that refuse
delayed starts after a cancel, `setsid -w`, leader-written pidfile);
`srplatform/red_agent/runner.py` (operation identity persisted before dispatch,
SSH client exit 255 → `cancel_remote`, handler exit 144 on unconfirmed
cessation); `srplatform/api/runs.py` (`cancel_remote_operations` retries
`active` AND `cancel-unknown` operations; a failed remote kill can NEVER yield
`cancelled`).
Regression: `tests/test_third_followup_lifecycle.py`
(`test_t01_descendant_survives_leader_exit_status_still_sees_it`,
`test_t01_cancel_before_start_tombstone_blocks_late_start`,
`test_t01_ssh_transport_loss_invokes_remote_cancellation`,
`test_t01_api_stop_confirms_remote_cessation_via_production_recovery`,
`test_t01_worker_sigkill_and_restart_recovers_persisted_operation`,
`test_t01_failed_control_connection_keeps_stop_partial`,
`test_t01_worker_signal_handler_reports_unconfirmed_cancellation`) — real
supervisor script + real shell descendants, real recovery functions, no
test-authored pidfiles.
Outcome: stop returns success only with confirmed local AND remote cessation;
unconfirmed stays tracked and retried; late starts are refused.

### T02 — lifecycle races (run vs teardown, queued-stop vs registration, callback vs cancellation) — ☑
Code: `srplatform/api/runs.py` (state machine `queued/running → stopping →
completed/failed/cancelled` + `cancel-unknown`; conditional row transitions;
`complete_run` refuses to overwrite terminal cancellation; `stopping` is never
success), `srplatform/api/app.py` (claim-owner fencing at every call site;
`/run` claims its operation and revalidates session state),
`srplatform/scenario_engine/orchestrator.py` (`claim_operation` returns an
owner token; `release_operation` is fenced), `srplatform/db/models.py` +
migration `0008` (`RunOperation` inventory, `OperationClaim.owner`, unique
index extended to `cancel-unknown`).
Regression: `test_t02_run_participates_in_lifecycle_claim`,
`test_t02_barrier_run_versus_teardown_never_dispatches_after_release`
(barrier-synchronized), `test_t02_queued_stop_spawn_race_persists_terminal_state`,
`test_t02_callback_cannot_overwrite_terminal_cancellation`,
`test_t02_failed_kill_never_sets_cancelled`, `test_t02_claim_owner_fencing`.
Outcome: no permanent `stopping` rows, no dispatch after release, no
false-cancellation; DB state asserted after each race.

### T03 — baseline verification accepted policy-weakening edits — ☑ (packet truth on the R740 bridge: ☑+E)
Code: `srplatform/safety/datapath.py` (`baseline_status()` requires EXACT
ordered effective-rule equivalence incl. set references and EXACT
`range_hosts` membership from `nft -j`; tri-state `inspect_table()`
present/absent/unknown — unknown is neither absent nor verified;
apply/remove refuse on unknown), `srplatform/safety/firewall.py`
(established allowances PORT-SCOPED — mgmt SSH `sport 22`, API ingest
`dport` — instead of destination-wide; discovery runs THROUGH
`nft_command_prefix`, never local `/sys`), `srplatform/safety/__init__.py`
(start gate re-checks LIVE bridge coverage for the nft controller).
Regression: `tests/test_third_followup_firewall.py` — the probe's own nft
JSON fixtures (inserted `meta nfproto ipv4 accept`, widened `0.0.0.0/1`,
reordered rules, destination-wide established accepts all REJECTED; exact
policy accepted), prefix-namespace discovery, unknown-inspection refusal,
plus `test_t03_netns_established_flows_are_port_scoped`: REAL packets in
disposable netns — a pre-established range→management:8080 flow DIES when the
rendered baseline is applied, while mgmt→range:22 replies and range→API
ingest still work.
Outcome: verification now means the EFFECTIVE policy equals the intended one.

### T04 — deployment ignored the session snapshot — ☑
Code: `srplatform/scenario_engine/orchestrator.py` (`deploy()` resolves
`verification_service.scenario_spec(db, session_id)` — the immutable session
bytes — instead of `load_scenario`).
Regression: `tests/test_third_followup_deployment.py::test_t04_launch_and_reset_use_the_session_snapshot_not_live_yaml`
— create session, edit template/IP/topology in the YAML, then the REAL
launch AND reset routes: inspected FakePVE clone calls still use the snapshot
template 9001 / IP 10.66.0.10 and never clone the added host.
Outcome: what is deployed is what is executed and graded.

### T05 — enrollment issued credentials but never installed them — ☑ (real auditd/Sysmon streams on VMs: ☑+E)
Code: `srplatform/scenario_engine/orchestrator.py` (per-resource enrollment
phase machine `pending_token → provisioned → confirmed` committed after every
step; provisioning writes the REAL `/etc/sparring-range/shipper.env`
(session-bound token, no placeholders, 0640 root:srshipper) and
`systemctl enable --now` + restart THROUGH the management channel
(`verification_service.management_exec`, injectable via
`set_enrollment_exec`); delivery CONFIRMED via `systemctl is-active`; lost
responses resume from the committed phase and RECOVER the same plaintext
capability from the `ServiceToken` row), `srplatform/verification_service.py`
(readiness refuses `ready` while any created clone is unconfirmed),
`telemetry/install.sh` (no longer delegates the software step).
Regression: `test_t05_enrollment_provisions_env_and_confirms_service`
(captured provisioning command + real `/ingest/auditd` round trip under the
issued token), `test_t05_interrupted_provisioning_resumes_with_the_same_token`
(exactly one token row after a failed attempt + retry),
`test_t05_unconfirmed_service_blocks_ready` (route 409 + DB phase),
`test_t05_dev_relaxation_is_visible`.
Outcome: enrollment = provision + confirm, durable and resumable; token
issuance alone no longer counts.

### T06 — production could skip readiness; reset skipped the launch workflow — ☑
Code: `srplatform/verification_service.py` (relaxation EXPLICITLY requires
`sr_env=dev`; production without a working channel — missing key or missing
pins FILE — is an enforced failure), `srplatform/api/app.py`
(`_finalize_ready` shared by `/launch` and `/reset`; reset failure persists
`preparing` + `readiness_failed` evidence through a separate session).
Regression: `test_t06_production_without_channel_refuses_ready` (a
validate_production-PASSING config with a non-existent pins file — the exact
review reproduction — now 409s; DB not `ready`),
`test_t06_dev_relaxation_requires_dev_mode_and_is_visible`,
`test_t06_reset_runs_the_launch_readiness_and_credential_workflow` (reset →
ready + NEW login tokens, old revoked; readiness failure → 409 + durable
`preparing`).
Outcome: route status AND database state asserted, dev relaxation visible.

### T07 — streaming reads blocked past their deadline — ☑ (Windows select-on-pipe remains documented)
Code: `srplatform/red_agent/runner.py` (`_bounded_reader`: `select` on the raw
pipe + `os.read` BYTE-oriented reads with an absolute deadline; returns
`(bytes, timed_out)`; partial buffer retained on timeout).
Regression: `test_t07_sparse_output_respects_deadline_and_keeps_partial_buffer`
(one byte then a long silence — returns within the deadline, partial output
kept), `test_t07_multibyte_output_respects_BYTE_bounds`,
`test_t07_local_runner_timeout_retains_partial_output`.
Outcome: deadlines hold against sparse, silent and multibyte output.

### T08 — spool crash recovery could reuse IDs and lose later events — ☑
Code: `telemetry/shipper.py` (`_write_seq` tmp+rename+fsync of file AND dir;
empty/invalid counter RECOVERS from the largest `_seq` in the spool — never
reissues an outstanding ID; `_repair()` QUARANTINES torn/malformed fragments
to `malformed.ndjson` and counts them ONCE before any append; `_read_lines`
stays tolerant without re-counting; append/pending/ack self-heal under the
flock).
Regression: `tests/test_third_followup_spool.py` — serial crash injection at
the counter truncate/write, the record write and the ack window using the
REAL Spooler: no ID reuse after an emptied counter, no duplicate IDs after a
crash mid-rename, new events survive a torn tail, loss counted exactly once,
ack-by-stable-ID across restart (the N08 append/ack race stays fixed).
Outcome: durable identity allocation + real tail repair.

## Commands, environment, outcomes (this host, at this commit)

| Command | Result |
|---------|--------|
| `.venv/bin/python -m pytest -m "not db and not adapter" -q` | **86 passed, 1 skipped** (skip: DB-gated start-gate test run without admin env; it passes in the DB run) |
| `SR_PG_ADMIN_CMD="su postgres -c" .venv/bin/python -m pytest -m "db or adapter" -q` | **103 passed** (disposable PostgreSQL 17, incl. production-route concurrency, real worker-subprocess adapter tests) |
| `… -m "not db and not adapter" -k "real_nft or netns"` (root) | included above and green: real `nft` apply/remove round-trip + disposable-netns PACKET tests (T03 + prior R/N suites) |
| `SR_PG_ADMIN_CMD=… .venv/bin/python -m pytest tests/test_stage5_browser_e2e.py -m browser -q` | **1 passed** (real Chromium via `@playwright/cli`, real `next start`, real uvicorn + worker; controlled PVE/model/runner/verifier/datapath) |
| installed-telemetry tests | green inside the unit run (`test_stage3_telemetry.py`: installed artifact, unit/installer identity, enrollment, no live tokens) |

New third-follow-up regressions: 43 tests
(`tests/test_third_followup_lifecycle.py` 17, `..._firewall.py` 11,
`..._deployment.py` 8, `..._spool.py` 7). CI selectors extended: the
privileged step now runs `-k "real_nft or netns"` (was `real_nft` only) and a
new `browser-e2e` job installs `@playwright/cli` + Chromium and runs the
browser suite (previously omitted entirely by CI selectors).

## Residual work — stated separately

Implementation gaps remaining: **none known at the automated boundary** —
every T-finding above has production code + a production-path regression.
This is NOT a claim that nothing remains unverified: the following are
hardware/environment gates that CANNOT be executed here and stay open
(unchanged from the second report):

1. Real PVE/R740: linked clones, concurrent-launch lease conflicts, packet
   truth from BOOTTED range VMs (netns proves the kernel semantics, not the
   R740 bridge/VLAN topology).
2. Real Kali runner: SSH transport-loss cancellation over the wire (the
   cancel protocol, tombstones and 255-handling are tested locally with real
   processes).
3. Real auditd/Sysmon streams from golden images (enrollment provisioning is
   tested against a scripted management channel; the installer contract and
   unit identity are checked, a systemd VM is not).
4. `docker compose config`/fresh-volume boot, packer image builds, deployed-
   stack browser E2E with bastion playback.
5. Windows runner path (select() on pipes): Linux is the supported production
   runner; documented, not claimed.
