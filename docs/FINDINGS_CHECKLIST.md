# Findings checklist F01–F23 (remediation tracker)

Baseline audit: `IMPLEMENTATION_AUDIT.md` @ `a5b19ab`. Handoff: `LOCAL_AGENT_HANDOFF.md`.
Legend: ☑ = code + automated evidence in-repo; ☑+E = live evidence on Drew's
hardware (operator gate — cannot be closed by the harness, see
docs/OPERATOR_RUNBOOK.md §LIVE GATEs). No finding below is marked done by
claiming live acceptance.

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
