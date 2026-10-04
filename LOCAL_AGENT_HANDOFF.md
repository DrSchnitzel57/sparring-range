# Local coding agent handoff — repair and complete sparring-range

Copy everything below into your local coding agent, or ask it to read and execute this file alongside `IMPLEMENTATION_AUDIT.md` and `plan.markdown`.

---

You are implementing the remediation of this repository, not doing another planning-only pass. Read `plan.markdown` as the original product contract and `IMPLEMENTATION_AUDIT.md` as the audit of baseline commit `a5b19ab`. Check the current checkout before applying findings, because it may have changed. The requested outcome is a safe, reproducible, evidence-based, single-active-range CCDC practice system whose CLI and browser complete the same lifecycle through FastAPI.

Implement fixes in dependency order with focused, reviewable changes. Preserve useful existing modules and tests. Do not rewrite the project around a new framework. Keep a running checklist mapping findings F01–F23 to code, tests and remaining operator evidence. At the end, provide actual validation results and exact live steps still requiring the operator; do not mark hardware gates passed from mocks or claim M0–M7 complete solely because unit tests pass.

## Operating contract

1. Inspect repository instructions, git status, current branch, environment and available runtimes first. Preserve unrelated edits. Use the repository's existing source layout (`srplatform`, not `platform`). Do not amend the original plan to erase unmet requirements; record justified changes separately.
2. Python/FastAPI/SQLAlchemy/Alembic/Typer/asyncssh/OpenAI-compatible client and Next.js remain the stack. Prefer existing dependencies and stdlib. Justify a terminal player, password hashing library or other necessary dependency before adding it to the implementation notes.
3. Production is Linux/Proxmox; a documented Linux container test environment is acceptable from a Windows checkout. Do not require arbitrary root access to a developer's PostgreSQL cluster. Use disposable databases and explicit integration-test configuration.
4. Do not run the current model execution path, host killswitch, reset/teardown or firewall scripts on real infrastructure while investigating. Implement and test in isolated disposable environments. Real host deployment and packet tests require the operator's intended target and existing authorization; no unattended destructive changes to unrelated VMs or networks.
5. The API is the business-logic front door. CLI and browser must not SSH to targets, access Postgres or submit referee results. Migration/bootstrap tooling is an explicit administrative exception. Backend orchestration code invoked by the API may use database helpers; that is not a second client front door.
6. The attacker runner must never receive database, Proxmox, referee SSH or general administrative API credentials. The local-model controller stays on the control plane and sends commands through a restricted runner channel. Trusted verification is a separate boundary from arbitrary model shell execution.
7. All grading/objective completion uses authenticated deterministic verifier evidence. Model narrative cannot award points, alter verifier results or establish that a defender investigated an event.
8. Keep the SQL event log append-only. Introduce forward Alembic migrations rather than modifying applied history. Operational session/deployment/lease/auth metadata may be mutable if justified; evidence and historical scoring decisions must remain append-only/versioned.
9. Default to one active range reservation across all scenarios. Multiple people can have accounts and historical progress, but concurrent launches must fail cleanly. Do not build per-member VLAN orchestration or enterprise RBAC to solve a problem a global lease can solve in v1.
10. Continue implementing code and offline validations while a human infrastructure gate is unavailable, with model execution disabled. Clearly label those stages unaccepted. Never silently substitute a fake for a live proof.

## Phase A — Establish an honest, reproducible baseline

Addresses F07, F21–F23; supports every later test.

- Create a findings checklist and short architecture note documenting current production entrypoints, the controller/runner/referee boundaries, the chosen safety controller placement and the single-active-range assumption.
- Separate unit tests from database, transport, browser and opt-in live acceptance tests. Replace `su postgres` and fixed database drops with a disposable PostgreSQL 16 test database/container, explicit URLs, defensive test-DB checks and unique names. Use `sys.executable`; restore environment/cache/singleton overrides after tests. Avoid dependence on test ordering or a globally installed unrelated `tests` package.
- Preserve the old test intentions, but replace assertions that only inspect strings or fake method names. Add regression cases for audited failures before repairing their behaviors.
- Fix the actual Compose service graph. Remove/replace the nonexistent coach module; choose one real red worker launch/supervision mechanism rather than a service missing required arguments. Add role bootstrap, one-shot migration job, readiness dependencies and stable healthchecks. A fresh-volume startup must work without manual SQL patching.
- Do not supply owner credentials to runtime API/runner services. Add `.dockerignore` covering `.env`, private keys, recordings, `.git`, test/build caches and irrelevant dependencies. Ignore generated bastion private keys in git. Keep `.env.example` without real secrets.
- Lock Python dependencies with a documented install command; retain/use the frontend lockfile. Add CI for unit/database/adapter tests, Python supported-version checks and frontend build. Do not upgrade everything indiscriminately; review advisories and compatibility, then record the choice.
- Complete configuration docs: Proxmox node/token identity including realm, gateway/CIDR/VLAN/bridge, VMID policy, API origins, runner transport, referee credentials, bastion bind/port/user/host-key trust, recording storage and model timeouts. Validate placeholders at startup in production mode.
- Make scenario/config packaging explicit: either test installation from a built wheel with resources included, or clearly require a checkout-based deployment and validate paths.

Acceptance: one documented command sequence creates a fresh local test stack, applies migrations using only the owner service, and runs DB-independent tests without PostgreSQL. CI contains real commands. Report build/test failures rather than copying historical README results. `audit/reproduce_findings.py` is baseline evidence, not the repaired acceptance suite; convert its relevant behaviors into assertions of corrected behavior.

## Phase B — Enforce execution isolation and fail-closed safety

Addresses F01–F03 and the safety portion of F13.

- Replace local `KaliSandbox.run()` with an explicit isolated runner adapter. Select one practical transport to the designated Kali container/VM, with fixed destination, bounded execution time, output size and cancellation. There must be no fallback to local shell if the runner is unavailable. Unit tests must exercise the real adapter boundary without issuing attack commands.
- Keep verifier execution in a separate service or backend adapter with scoped management access. Build its host resolution from the owned deployment inventory. Never mount its credentials or the API environment into the attacker runner. Authenticate the controller-runner channel with only the privileges required for that runner.
- Replace daemon threads/arbitrary client PID registration with supervised run handles, process identity and durable run state/lease. Repeated `/run` for the same active run must not start a second worker. Reject invalid sessions/scenarios before spawning work.
- Introduce a persisted safety latch and verification record bound to the current network/configuration identity. Default state is not safe. A start requires successful baseline checks and recorded killswitch proof with clear freshness/invalidation policy. A handwritten success string or arbitrary client POST is not attestation.
- Implement a privileged host-side datapath operation through one constrained authenticated mechanism. Attempt datapath isolation independently of worker termination and report each result. Failure to signal a worker must not prevent the network operation; failure of the network operation must not be reported as fully engaged. Provide an operator recovery path if the API is unavailable.
- Kill the worker's active command and descendants without terminating the API. Remove arbitrary PID inputs. Preserve the latch across API/worker restart, reject new commands while latched, and require explicit operator release. Release must remove only this application's emergency rule while preserving baseline isolation, then invalidate/recheck safety evidence as appropriate.
- Replace firewall templates with syntactically valid, rendered, range-scoped rules for the actual Proxmox bridge/VLAN topology. Default deny range egress, allow only explicit necessary endpoints/ports, cover IPv4 and IPv6, and test established connections. Ensure host management and unrelated bridges survive. The emergency switch must sever intended range traffic, including same-bridge traffic if the requirement is all range datapath traffic.
- Make apply/release idempotent with bounded errors and no global ruleset flush. Do not interpret “turn firewall off” as “deny.” Document a rollback/recovery procedure that does not depend on the blocked network.

Regression acceptance: production `/run` rejects unverified, stale, killed and unavailable-runner states; an isolated harmless marker command proves where execution occurs; control-plane canary files/credentials are absent inside the runner; network namespace tests prove scope and IPv6 behavior; active worker/descendant shutdown leaves API `/healthz` responsive; repeated engage/release works; injected signal/firewall failures give truthful partial-failure results; API restart retains the latch. Syntax-check rendered rules with `nft -c` in the intended environment. Never execute model-selected actions until the operator performs the final datapath proof.

## Phase C — Establish simple identity and trusted evidence

Addresses F04, F08 authentication, F16 file trust.

- Implement actual LAN member authentication, using operator-provisioned passwords with established password hashing or per-member provisioned secrets. Do not use username knowledge as authentication. Add token expiry, server-side revocation/logout, protected route dependencies and ownership checks. Use a simple operator/member distinction where necessary, not a general-purpose enterprise role system.
- Protect deploy/run/end/reset/teardown/safety/account administration and session reads. Derive the acting member from authenticated identity rather than accepting arbitrary usernames. Define explicit permission for the operator to inspect/manage sessions.
- Separate member, telemetry, bastion, runner and referee capabilities. Narrow event ingest schemas by producer. The server supplies trusted actor/source/session association; members and attacker commands cannot submit verifier or scorecard events or alter agent state.
- Run deterministic verifiers in the trusted backend and append their results internally. If a separate referee service is used, authenticate it and bind its check request/result to session, deployment, objective, timestamp and verifier version. Do not rely on a client-controlled `actor=system` label.
- Retain SQL SELECT/INSERT-only permissions for events and mutation trigger. Add tests for UPDATE, DELETE and app-role TRUNCATE denial. Apply minimal session UPDATE grants required by lifecycle through a new migration. Verify default privileges/role inheritance do not undermine the intended app role.
- Represent recordings as opaque IDs owned by sessions. Prevent arbitrary local path opens; enforce root containment, symlink policy, size and frame validation. Storage paths and verifier internals must not be user-controlled capabilities.

Acceptance: missing/expired/revoked/wrong-member credentials cannot read or mutate another member's session; members/telemetry/runner cannot forge scores or objective passes; invalid actor/action combinations fail; DB role tests run against migrated PostgreSQL; malformed recording paths/content are rejected safely; no secrets are returned in API errors/logs.

## Phase D — Repair deployment and implement the shared session lifecycle

Addresses F05–F08, F11 and F13.

- Repair real Proxmox request paths, concrete node handling and resource DELETE method. Use the target PVE version's documented API. Wait for clone/start/stop/delete tasks, inspect exit status, enforce timeouts and readiness, and handle missing resources idempotently. Validate TLS with a configured CA or documented explicit lab override; do not hardcode verification off.
- Add production-adapter contract tests below `ProxmoxClient` that simulate asynchronous task statuses and failures; do not replace the adapter under test with `FakeProxmox`.
- Acquire a durable global range reservation before creating resources. Create session/deployment intent before cloning, record exact VMIDs/nodes/IPs and ownership tags, and validate NIC placement on the range bridge/VLAN. Avoid allocation races; treat the PVE allocator response as subject to concurrent failure/retry.
- Make launch a backend workflow: authenticate/reserve → validate scenario/safety/templates → persist intent → clone/configure/ready → issue member-specific host connection capability → start approved worker. Return session/deployment status and concrete connection instructions. Both CLI and web use it. Preserve useful explicit deploy/run CLI commands as wrappers around the same services with well-defined staged states.
- Handle failures after each external side effect through recorded state and reconciliation. If logging fails, do not silently return a clean deployment; make recovery possible from ownership tags/intents. Cleanup must only affect positively owned resources and preserve unrelated/similarly named VMs. Never select targets for deletion solely by scenario prefix.
- Define lifecycle states such as preparing, ready, running, stopping, complete, failed and torn_down (or an equally clear smaller set). Distinguish session completion from red objective success. Record run outcomes/budget exhaustion/worker failure; avoid permanently “running” dead sessions.
- Implement stop/end/finalize as idempotent backend operations: stop actions, collect trusted final scores before teardown, append score snapshot and end evidence, revoke terminal capabilities, and release reservation only when resource safety/ownership is resolved. Reports/history remain readable. Decide and document whether end retains stopped VMs or tears down; expose a separate safe teardown if useful.
- Create an API scoring endpoint backed by trusted verifier execution. CLI scoring becomes HTTP only; browser finalization calls the same code. Return explicit unavailable/unscored status rather than a fabricated zero if scoring cannot run.

Acceptance: two simultaneous launches, including two different scenarios with shared IPs, yield one owner and one clear conflict; duplicate requests do not create extra VMs/workers/tokens; failure injected after each clone/config/start stage is recoverable; reset/teardown leaves unrelated VMs untouched; finalized sessions successfully update under app DB role; both clients can create and finish a session without direct DB/SSH access. Include a migration test from the existing schema, not just an empty database.

## Phase E — Deliver real terminal capture and host telemetry

Addresses F08, F09, F16 and F21.

- Configure a stable bastion bind address/port, member public-key authorization, target host-key verification and expiry/revocation checks. Resolve targets only through session-owned host inventory. Generate unique session-bound login capabilities; provide per-host SSH instructions in CLI and browser.
- Record interactive and exec output correctly. Use exclusive UUID recording names; tokens must not become paths. Capture actual terminal size/resize as supported, use monotonic elapsed time, flush safely, and handle EOF/cancellation without discarding buffered target output. Avoid treating raw keystrokes as authoritative command events. Handle recording/API sink failures visibly.
- Implement a recording storage/transfer contract between bastion and API LXCs, with authenticated access and safe incomplete-file handling. Include persistent storage in deployment instructions. The API must not assume another machine's local path exists.
- Finish one Linux auditd pipeline using a documented actual input format. Either parse raw audit records or supply/configure the real converter/Vector pipeline. Install dependencies, rules, configuration, service and inputs; copying an executable file alone is insufficient. Group audit records by source event identity, decode argv correctly, preserve original timestamps and report relevant persistence/account detections.
- Attribute telemetry using authenticated host deployment identity and event-time session association, not newest token by hostname. Preserve source serial/boot ID and UID/audit identity so retries deduplicate and attribution survives reconnects. Unknown attribution must remain explicitly unknown rather than silently selecting another session.
- Add bounded on-disk spool/retry/backoff and rotation/restart behavior, with visible gap/drop counters. Prevent endless unbounded buffering. Document the trust limit of telemetry from compromised range hosts.
- Add the planned Sysmon configuration and ingest/transport fixtures with source identity/timestamps, plus a Windows installation checklist. Windows OOBE/licensing/image creation remain operator work; do not claim Windows acceptance without a real check.
- Repair the golden-image setup so scripts actually install/run telemetry and configure verifier/defender access. Define baseline service/seed-data/readiness requirements for each supplied scenario. Fix and validate optional Packer using the correct plugin and file transfer, or explicitly remove the broken optional path and document the supported manual image-build path.

Acceptance: an actual command run through the bastion into a disposable Linux target yields a replayable cast and correctly attributed audit event through the production shipper, not synthetic direct POSTs; two SSH connections in one second produce distinct recordings; disconnect/reconnect preserves attribution; API downtime and shipper restart replay spooled records without duplicate commands; cross-session/expired tokens fail; shared-storage/transfer works with separate processes/filesystem locations. Include representative Windows fixture tests and a clearly pending live Windows gate where hardware is unavailable.

## Phase F — Make scenarios and deterministic scoring trustworthy

Addresses F10, F12 rubric, F19 and F20 domain scores.

- Use typed nested scenario schemas and typed verifier argument models. Validate IDs, host/objective uniqueness, legal ranges and IPs, positive points/time limits, OS compatibility, objective/check host references, phase definitions and required args. Reject unknown fields where practical. Return actionable load errors, and validate library entries rather than bypassing the validator.
- Restrict scenario identifier paths. Define template configuration precedence and resolve logical hosts to actual deployment addresses; do not depend on accidental host DNS resolution.
- Add explicit expected result/polarity and scoring-domain metadata per check so a vulnerability predicate can be reused without awarding blue for vulnerability. Document scenario/rubric semantics with valid examples.
- Implement baseline-aware cron/account/service/task/run-key checks. Require successful command execution and valid parsed results; errors/timeouts become unknown/error, never passes. Quote/validate all command parameters. Normalize versions with stated limitations. Use stable integrity artifacts and scenario-specific flag/exfil identity where the objective requires proof of access or data movement.
- Log each check's verifier/version, args or safe identifiers, expected condition, result, evidence, source time, awarded points/domain and errors. Preserve immutable scenario/rubric/template/baseline identity for the session so edits to YAML cannot alter history.
- Remove implicit AAR penalties unless explicitly declared in the deterministic rubric and supported by all required objective results. Missing scoring is unscored; unavailable checks follow a documented rubric policy and remain visible. Keep progress/report totals consistent.

Acceptance: table-driven real verifier tests cover clean baseline, actual change, benign cron files, nonzero exit with plausible stdout, missing command, timeout, version edge cases, invalid host and parameters with spaces/metacharacters; no shell injection occurs. Blue checks with inverse predicates award the intended condition. A YAML-only new objective/check using existing verifiers works. Historical score meaning remains unchanged after editing the scenario file. Empty/zero-total/error scorecards never cause a 500 or a fabricated F.

## Phase G — Repair durable loop behavior and model scheduling

Addresses F14, F15 and F18.

- Implement bounded event-ID cursor pagination server-side, returning deterministic ingestion-order pages. Separate source timestamp display from ingestion checkpointing; late telemetry must not disappear. Provide a latest-events query for CLI/live UI. Test beyond 5,000 events and with backdated records.
- Carry the previous situation report into each compression along with newly folded events. Bound context/output and persist checkpoint only after successful evidence/state updates. Verify two or more compression cycles preserve early facts.
- Fix DONE to finish successfully only when every required objective is confirmed. An unconfirmed DONE may prompt retry or end as no-progress under explicit budgets; it cannot stop merely because one new objective passed. Enforce a strict nested command schema with nonempty string, length bound, exact tool enum and valid phase field or remove unused phase proposals.
- Supply actual target topology to prompts. Map phase transitions explicitly to scenario/verifier facts rather than counting successes. Persist structured objectives independently of LLM prose.
- Append action intent before sending it to the runner and append result after execution. Use operation IDs and a runner result/status protocol. After worker crash, reconcile completed/in-flight/unknown actions; do not blindly replay an arbitrary command with uncertain outcome. Handle cancellation, logging failure, timeout and connection loss as first-class outcomes.
- Route red actions, summaries, hints and AAR requests sharing a model server through one bounded scheduling layer. Preserve interactive priority without claiming preemption of an already running model call. Define maximum request latency, queue size, overflow behavior, retries, cancellation, shutdown and endpoint recovery. Avoid keeping DB transactions open while waiting for the model.

Acceptance: actual supervised worker kill/restart resumes the session without losing history or blindly duplicating an uncertain command; partial DONE remains incomplete and work can continue; malformed tool calls never execute; sessions exceeding 5,000 events remain current; multiple compressions preserve prior facts; concurrent real client paths show hints scheduled before queued red/AAR batches within the declared bound; model outages recover without API restart and failures are visible.

## Phase H — Ground coaching and complete the browser workflow

Addresses F12, F17 and F20 plus integration of earlier work.

- Render actual detection events and source times. Build misses/wins from explicit host/objective/technique-linked evidence and remediation checks; connecting, disconnecting or running an unrelated command must not erase a miss or count as a defensive win. Distinguish observation, inference and telemetry gaps. Do not assert “never investigated” where only absence of evidence is known.
- Separate declared scenario techniques from techniques observed in evidence. Use consistent checked mappings and a deterministic failure-weighted study priority. Validate generated narrative citations against supplied IDs/timestamps; reject or omit unsupported claims. Keep deterministic report output useful when the model is unavailable.
- Persist or reproducibly address the full report snapshot, evidence cutoff and rubric version. Fetching a report page should retrieve an existing result; explicit regeneration may create a new version instead of silently generating/logging on every page load.
- Complete the browser path: login → filtered library → shared backend launch → preparation status → real per-host SSH instructions → live detections/clock/hint → end/score → AAR → replay → multi-session progress. Include stop/error/retry states and session history. Display per-domain score details and trends based on scoring items, not whole-scenario scores copied to all focus tags.
- Fix replay using a maintained asciinema/terminal rendering approach. Align each recording's header epoch with absolute event times, support multiple recordings, clamp seeking, and make scrubbing during playback update the active cursor correctly. Handle missing/corrupt/large casts without endless loading or raw stack traces.
- Configure explicit LAN API origins or same-origin reverse proxy. Do not default teammates' browsers to their own localhost. Add token expiry/logout handling and visible fetch errors. Keep visual polish secondary to a usable workflow.

Acceptance: checked-in browser E2E runs against the real API and disposable DB through production lifecycle/score endpoints with safe fake infrastructure at external boundaries. It must not seed final scorecards by posting generic events. Test two completed sessions, actual progress changes, unauthorized navigation, failed launch recovery, request-hint, usable connection information, unscored/zero-total reports, multiple recordings and delayed recording start. A recording starting 120 seconds after session creation must align to that actual offset. Coach tests prove unrelated blue events do not alter conclusions and unsupported citations cannot appear as facts.

## Phase I — Operational finish and live acceptance

- Add readiness diagnostics for DB/migration level, runner, verifier access, bastion, recordings, telemetry freshness, model and safety status; separate liveness from readiness. Document time synchronization across producers.
- Set practical limits for session duration, model calls, command output, ingest request sizes/rates, spool, DB growth and recordings. Define retention/archive/backup/restore ownership without granting the runtime role permission to mutate event evidence. Include a restore test for a disposable database plus its recording references.
- Update README milestone status to separate implemented code, automated passing evidence and human acceptance. Remove nonexistent service/Sysmon/relay claims; do not claim checked-in tests prove actions they bypass. Include the exact supported deployment/start/stop/recovery commands and a concise operator runbook.
- Execute all available checks and record commands, runtime versions, pass/fail/skip counts and environment. Run relevant fault injection and migration tests, frontend build and browser E2E. Mark infrastructure-only gaps explicitly.
- Provide the operator a short, concrete live gate sheet: (1) verify baseline network isolation from a range VM with valid positive controls, including TCP/UDP/DNS/IPv6; (2) start harmless controlled traffic/processes and prove emergency isolation plus worker termination while management remains reachable; (3) release to baseline without enabling WAN; (4) clone/readiness/reset/owned teardown against designated disposable Proxmox resources; (5) terminal and real host telemetry reach the correct session; (6) model endpoint answers from the control plane; (7) first supervised model-driven lab scenario; (8) unaided human practice, then a different teammate's browser-plus-terminal session across two scored sessions. Save actual evidence only after those checks run.

## Required regression coverage checklist

At minimum cover all of these, with failures observable at the production boundary:

| Area | Required adverse case |
|---|---|
| Safety | Unverified/stale/latched start; API restart; active child commands; datapath operation fails; unrelated management survives |
| Trust | Anonymous mutation; expired token; wrong member; forged referee/score event; arbitrary PID/target/file reference |
| Database | Existing-schema upgrade; app-role lifecycle update; event UPDATE/DELETE/TRUNCATE denied; no runtime owner credentials |
| Deploy | Wrong node/path; asynchronous clone failure; VMID collision; simultaneous launch; partial failure; prefix-similar unrelated VM |
| Lifecycle | Duplicate start/end/reset; unknown session; mismatched scenario; worker crash; final scoring unavailable |
| Telemetry | Real raw/source format; source timestamp; duplicate/late record; reconnect; rotation; API outage; stale token; wrong host identity |
| Verification | Baseline cron; nonzero result with plausible stdout; timeout/unknown; reversed polarity; invalid/unsafe args; changed YAML after completion |
| Agent | One-of-two DONE; invalid JSON/schema; repeated compression; over-5,000 history; crash between execution and logging |
| Coach | Unscored session; unrelated disconnect; telemetry gap; unsupported citation; red/model queue contention; endpoint recovery |
| Browser/replay | LAN URL config; failed fetch; full finalize/score flow; zero-total progress; delayed recording epoch; multiple casts; seek while playing |

## Definition of done and final response

The code remediation is complete when F01–F23 have either a demonstrated fix or a narrowly justified documented deferral accepted by the user, the shared lifecycle works in a reproducible test stack, and the acceptance matrix has actual evidence. Hard constraints and core lifecycle cannot be deferred to optional enhancements. Live readiness remains pending until real host and human gates are performed; say so plainly.

Your final response must identify changed behavior, link the findings checklist and runbook, summarize tests actually run, list any residual risks/blocked live checks, and give the next concrete operator command. Do not finish with a vague offer to implement later. Do not expand into PvP, C2, enterprise auth, concurrent ranges or a UI redesign.
