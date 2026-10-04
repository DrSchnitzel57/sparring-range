# Implementation audit — sparring-range

Audit date: October 4, 2026. Baseline: commit `a5b19ab` (clean working tree at start). Contract reviewed: `plan.markdown`, not `plan.md`.

**Verdict: a readable prototype with broad component coverage, but not a completed or safe-to-run implementation of M0–M7.** The largest problems are at integration boundaries: command isolation, emergency shutdown, trusted evidence, real infrastructure APIs, session ownership, telemetry delivery, and end-to-end scoring. Fix these before running model-selected commands against the range or investing in more scenarios/UI polish.

This audit adds documentation and safe reproduction probes only; it does not change application behavior.

## Evidence and limits

Reviewed the plan, README, Python source, migrations, infrastructure scripts, both scenarios, all acceptance tests, frontend pages, dependency manifests and commit history. No repository `AGENTS.md` was found. Reviewed production call paths alongside their test doubles.

Executed `audit/reproduce_findings.py` with the available bundled Python 3.12. It parses 61 repository Python files successfully, identifies 25 test functions, and reproduces pure-function/adapter defects without network access, database access, shell execution or process signals. Output is retained in `audit/reproduction-results.json`. Dependency stubs used by that script are explicit; these are focused reproductions, not infrastructure validation.

**Not executed:** the full pytest suite, PostgreSQL migrations, Next.js build/browser flow, Docker Compose, nftables/Packer validation, or live Proxmox/GPU/bastion/range tests. This Windows checkout has no installed project Python environment or frontend node_modules; the bundled Python lacks pytest, FastAPI, SQLAlchemy, asyncssh and other project dependencies. Docker, psql, nft and Packer were not found on PATH. The existing DB tests additionally assume Linux `su postgres`, pre-existing roles and `.venv/bin/python`, and drop/recreate a fixed test database. I did not run that destructive fixture against an unknown database or provision infrastructure for this audit. Historical README/commit claims are not fresh test evidence.

Confidence labels below: **source-confirmed** means directly established by the checked-in call path; **reproduced** means additionally exercised locally; **live-unverified** means the host behavior still needs an integration gate.

## What is worth keeping

- The chosen stack is mostly respected: FastAPI, SQLAlchemy/Alembic, Typer, asyncssh, OpenAI-compatible client, YAML scenarios and a simple red loop.
- `srplatform/` avoids shadowing Python's standard `platform` module; this is a good, documented deviation.
- Append-only event storage has actual SQL grants and an UPDATE/DELETE trigger, not just a comment. The tests attempt both app-role and owner-role UPDATEs.
- Verifiers have a small reusable interface. The loop usually checks host state rather than accepting model prose as completion.
- CLI/deploy/report and the web UI mostly use one API. Event-derived progress is implemented as a SQL view.
- Tests exercise real HTTP, SQL and asyncssh boundaries in selected places. They are useful foundations despite inadequate production-path coverage.
- The code is small and approachable. A focused repair is more appropriate than a framework rewrite.

## Plan compliance

| Contract area | Actual implementation | Audit status |
|---|---|---|
| M0 safety and backbone | Schema/migrations exist; safety verification prints instructions; default supervisor cannot drop datapath; no start gate | **Blocked: hard constraints not enforced** |
| M1 deployment | API/CLI and linked-clone intent exist; production adapter paths and asynchronous sequencing are broken; no session resource ownership | **Partial; real deployment unproven** |
| M2 evidence and recording | asyncssh tee and ingest endpoint exist; no working installed telemetry pipeline; token/session attribution and recording distribution incomplete | **Partial** |
| M3 red harness | Simple loop, schema, state and verifier calls exist; execution runs locally in API environment; restart/memory/completion defects | **Partial; unsafe default execution** |
| M4 YAML and verifiers | Two YAML scenarios, validator and verifier library exist; false positives, incomplete schemas, CLI-only scoring | **Partial** |
| M5 coach | Citable deterministic report and hint queue exist; missing scores become F, unsupported behavioral conclusions, red traffic bypasses queue | **Partial; feedback not trustworthy** |
| M6 real practice | CLI-over-HTTP test uses fake infra and bypasses actual `/run`; no human practice evidence checked in | **Not demonstrated** |
| M7 browser gym | Pages/API present; login not enforced; launch creates no usable token; no browser score/end flow; replay/progress incomplete | **Not demonstrated end-to-end** |

The README distinguishes some human gates, which is helpful, but “all built” and checkmarks overstate operational completion. Commit-per-milestone organization does not demonstrate that live acceptance gates passed before subsequent milestones.

Hard constraints: no-egress and tested killswitch are not enforced; verifier-only truth can be bypassed through event ingest; SQL append-only defenses are present but do not establish authenticity of inserted evidence; `.env` is ignored but Docker build context and generated key handling remain incomplete; LAN scope is respected conceptually but does not justify unprotected administrative/evidence endpoints.

## Findings, ordered by priority

P0 = stop before model execution; P1 = fix before first reliable practice session; P2 = quality/maintainability or incomplete later milestone. Related defects are grouped into 23 actionable findings.

### F01 — P0: the command “sandbox” executes in the control-plane API environment

**Source-confirmed.** `srplatform/api/app.py:235` starts `RedAgentLoop` in a daemon thread in the API process, with `KaliSandbox()`. `srplatform/red_agent/sandbox.py:34` directly launches `/bin/bash -lc` using `subprocess.run`. No container/remote runner is selected; `KALI_CONTAINER` is unused. Model commands inherit the API's filesystem, credentials and network access. Compose supplies the API both application and owner database URLs; `.env` may also contain Proxmox/model credentials.

This violates the explicit M3 requirement to execute inside Kali on the range VLAN. Documentation telling the operator to place the process “inside/next-to” Kali does not fix the shipped API path. Verifier management SSH is also on the same object as untrusted command execution. Separate model orchestration, isolated execution, and trusted verification; never expose referee credentials to attacker commands. Prove the boundary through the production run entrypoint.

### F02 — P0: killswitch can terminate its own API and reports success without isolation

**Source-confirmed and partially reproduced.** `srplatform/red_agent/loop.py:104` registers `os.getpid()`. With the API thread runner, that is the API PID. `srplatform/safety.py:37` sends SIGTERM before applying the datapath half; a real invocation can terminate the API before it reaches isolation or returns a response. PID registration is unauthenticated and accepts arbitrary integers, including values with process-group semantics on POSIX. No unregister in `finally`, process identity validation, child-process cancellation, or durable engaged latch exists.

`get_supervisor()` constructs `Supervisor()` without Proxmox. The default `killswitch()` still returns `engaged` with “datapath drop NOT applied” (reproduced). The real branch runs a host script locally with `check=False`; it neither reaches the Proxmox host nor verifies success. The fake-specific branch posts `state="0"` and is treated as evidence of isolation by tests. `release()` is only a response string; it does not remove the kill table. `verify()` checks no actual configuration or packets. `/run` consults none of these states.

Replace arbitrary PID signaling with supervised execution handles and an independent, authenticated datapath controller. Engage each safety layer even if another fails; report partial failure accurately. Reject starts with missing/stale safety evidence and while latched. Test API survival and termination of active command descendants.

### F03 — P0: firewall artifacts are neither deployable as supplied nor range-scoped

**Source-confirmed; actual packet behavior live-unverified.** `infra/firewall/range-egress-deny.nft.conf.tmpl` declares a table and a separate top-level chain rather than a valid table-contained ruleset. Its global forwarding default drop is not limited to the range, its control-plane exception admits all ports to an entire CIDR, and there is no explicit management-to-range NEW connection allowance. `RANGE_VLAN` is unused. Established connections are accepted before range restrictions. `killswitch.sh` ignores `RANGE_BRIDGE` except in its message and drops all traffic hitting the inet forward hook; it does not demonstrate coverage of bridged L2 traffic. Repeated table creation under `set -e` is not idempotent.

Render and syntax-check a real configuration, scope it to the actual VLAN/bridge path, and explicitly enumerate allowed management/ingest endpoints. Validate both IPv4 and IPv6, established flows, range-to-range isolation under the killswitch, and preservation of unrelated host management. These are properties of the host network topology, not substring tests. The [nftables manual](https://netfilter.org/projects/nftables/manpage.html) documents table/chain syntax and separate inet/bridge families; the topology-specific final rules still require live proof.

### F04 — P0: anyone reaching the API can forge the evidence used for grades

**Source-confirmed.** `/events` (`srplatform/api/app.py:101`) accepts caller-supplied actor, action type, session and arbitrary payload without authentication. A client can submit `actor=system`, `action_type=verifier`, `passed=true` or an arbitrary `scorecard`. The loop rehydrates achieved objectives from those events; AAR and progress trust them. Append-only SQL only prevents rewriting those forged rows afterward.

`/run`, deploy/reset/teardown, safety, PID registration, token creation and agent-state writes are also unprotected. `web_routes.py:61` defines `user_from_token` but never uses it as an endpoint dependency; the frontend's `X-Token` is ignored. Login requires only a username and tokens have no expiry/revocation flow. Simple LAN authentication is enough, but identity and evidence provenance must actually be enforced. Restrict evidence creation to a trusted verifier service/API code path and scope worker/telemetry credentials to permitted event kinds and sessions.

### F05 — P1: production Proxmox adapter is bypassed by its tests and has wrong requests

**Source-confirmed and request paths reproduced.** `infra/proxmox_client.py:61` sends `/nodes/{node}/qemu/.../clone` with literal braces. `destroy()` posts to `/qemu/{vmid}/destroy` instead of the QEMU resource DELETE operation. The orchestrator configures/starts immediately after clone and deletes immediately after stop, without waiting on task completion or checking task exit status. A fake VM is instantly present/running, so current tests cannot catch those races or endpoint mistakes.

Use concrete nodes, correct verbs/paths, bounded UPID polling, task-error propagation, and guest readiness checks. Production call ordering must be tested using a simulated HTTP/API boundary below `ProxmoxClient`, not a replacement adapter. The official [Proxmoxer cloud-init example](https://proxmoxer.github.io/docs/dev/examples/cloud-init/) explicitly waits for the clone task before configuring/starting the guest.

### F06 — P1: deployment has no session ownership, collision protection or recovery

**Source-confirmed.** `orchestrator.py:32` names VMs by scenario and host, reuses static IPs, allocates VMIDs with a read-then-use scan, and does not verify NIC bridge/VLAN placement. Reset/teardown (`:52`, `:70`) delete every resource matching the scenario name prefix, using the configured node rather than the resource's actual node. Two launches can collide or destroy each other's machines. Both shipped scenarios share `web01` and `10.66.0.10`, so merely locking by scenario is insufficient.

Launch deploys before session creation; deployments therefore have no ownership link in the normal browser/CLI flow. Partial clones are not rolled back/reconciled, and `_log()` swallows every database error after external side effects. Persist exact session-to-resource ownership and operation intent/result. For v1, a durable **single-active-range reservation** is enough; per-session networks can remain deferred. Teardown must use owned resource IDs, never a name prefix alone.

### F07 — P1: shipped Compose stack cannot start the claimed services

**Source-confirmed.** `docker-compose.yml:42` runs the red loop without its required `--scenario` and `--session` flags. Line 48 imports nonexistent `srplatform.coach.service`. No migration service initializes tables on a fresh volume. API depends on bootstrap start rather than successful completion. There is no bastion/Kali runner or recording-storage wiring. API owner credentials are injected into runtime even though only migrations need them.

`infra/dev/Dockerfile` does `COPY . .` and no `.dockerignore` exists; a user's `.env`, generated keys or recordings can enter image layers. Git ignore rules do not control Docker build contexts. The default bastion private-key filename is not gitignored either. Fix the actual service model, initialize roles/migrations in order, separate credentials, bind dev ports appropriately, and exclude secrets/build outputs.

### F08 — P1: launch does not produce a usable terminal session

**Source-confirmed.** `web/pages/library.js:17` deploys, creates a session and starts red, but creates no bastion token. The live page prints the same hardcoded `ssh drew@bastion -l tok_web01` for every scenario (`web/pages/session/[id].js:83`). No lifecycle creates/revokes that token. `bastion/proxy.py:185` calls `start()` with its defaults, listening only on loopback on a random port. Production accepts any public key, disables target host-key checking, and has no configured per-member key binding.

Return actual member/session/host connection instructions from the API, configure a stable listener, verify client and target keys, and invalidate capabilities when a session ends/resets. Bind target selection to owned range inventory so the bastion cannot dial arbitrary management destinations through user-created tokens.

### F09 — P1: telemetry capture is an unconnected skeleton, and attribution loses truth

**Source-confirmed.** The golden-image script says it installs a systemd service but installs only the Python file; no unit, audit JSON converter, transport configuration or Python/httpx installation is supplied. The copied executable has no shebang. `shipper.py` discards normal non-JSON audit lines and expects an unspecified upstream converter. The cloud-init config file is not consumed by the shipper. Failed POSTs are logged as drops; no retry/spool/cursor/deduplication exists.

`app.py:335` ignores the supplied event timestamp and selects the newest unrevoked token for the supplied host. It does not check session status, host identity or source event identity; hostnames versus token IP addresses may not match. Tokens are not revoked on end. Multi-record audit events are not assembled into one command, and persistence/account watch events are filtered out. There is no Sysmon configuration/shipper/ingest implementation despite README claims.

Ship and exercise one real Linux audit pipeline first, with authenticated host/deployment attribution, source time, serial/boot identity, bounded durable retry and explicit gaps. Add documented Windows/Sysmon support before claiming Windows coverage; manual Windows image creation can remain the human's task.

### F10 — P1: verifier results can be false positives or reward the wrong condition

**Reproduced and source-confirmed.** `CronPersistencePresent` counts any output from `ls /etc/cron.d`, including normal baseline files, as unexpected persistence. Firewall, AV and version checks ignore the exit code in their final passed expression; probes with nonzero exit code and plausible output still pass. Version tuple parsing is simplistic; service-name matching is substring-based. Verifier parameters are interpolated into remote shell commands without quoting/validation.

The same predicate cannot safely reward blue and red without expressing expected polarity. For example, a persistence-present or unpatched-service predicate used directly in blue scoring awards points for a bad state. Flag/exfil checks accept any nonempty file and do not establish scenario-specific content/provenance. The supplied DB integrity check hashes a live database file against a hardcoded value, with no documented baseline-generation procedure; normal DB writes can change it.

Define typed arguments, baseline-aware exact checks, expected pass condition per use, and an explicit error/unknown result distinct from confirmed false. Keep verifier credentials unavailable to the model. Use a seeded stable lab artifact for data-integrity scoring unless a proper database consistency protocol is documented.

### F11 — P1: scoring is implemented in the CLI, so browser sessions never get scored

**Source-confirmed.** `rangectl/commands/scoring.py:8` constructs `KaliSandbox`, performs verifier SSH on the CLI machine and posts its own scorecard to generic event ingest. No server scoring endpoint exists. This breaks the API-only business-logic rule and assumes the member laptop has privileged verifier access. Neither browser launch/report nor CLI `report` invokes scoring. The M6 test goes straight to report without scoring; M7 directly seeds scorecard events.

Move trusted verification/scoring into the backend. Add an idempotent end/finalize workflow used by both clients, with explicit score snapshot/version and unknown/unscored handling. Progress must arise from real scoring, not a separate manual CLI step.

### F12 — P1: AAR feedback asserts conclusions its evidence does not support

**Reproduced.** `coach/timeline.py:18` treats *any* later `blue:*` event, even a bastion disconnect, as investigation of every earlier passed verifier. The authoritative auditd commands are `actor=telemetry` and do not qualify as follow-up. Every blue event is also called a win. The compressor does not render actual `detection` events in its timeline branches.

`coach/aar.py:38` gives an unscored session an F with a synthetic denominator of 1. Any passed verifier is treated as “red completed objectives” and subtracts 15 percentage points; one of two completed objectives changes a perfect score to B. There is no configured rubric for that penalty. Scenario-declared techniques are labeled “seen,” study items are alphabetically sorted rather than prioritized by failures, and per-domain score details are missing. LLM narrative is inserted without validating citations or claims.

Require trusted, specific evidence for claims. Say “no correlated response observed” when evidence is incomplete; never infer intent or investigation from connection lifecycle. Derive grades only from a declared deterministic rubric, show unscored/unknown clearly, and retain evidence references and rubric version with reports. A genuine human usefulness gate is still required after correctness tests.

### F13 — P1: session lifecycle is incomplete and ending a session lacks DB permission

**Source-confirmed.** `/run` does not validate session existence, scenario association, ownership, deployed readiness, prior run status or duplicate calls before starting its thread. Exceptions remain in a background thread; there is no persisted failed/completed outcome, worker lease or cancellation state. The loop does not end the session. End marks complete regardless of objective state and does not stop red, score, revoke tokens or release resources.

Migration `0001_initial.py:107` grants SELECT/INSERT on `sessions` but no UPDATE; later migrations do not fix it. `/sessions/{id}/end` updates that table and therefore cannot commit with the intended app role. No test exercises that production-role transition.

Add a small durable lifecycle with explicit operation/run outcomes, narrowly scoped grants, and idempotent transitions. Distinguish “defender ended practice” from “red achieved all objectives.” Keep the API alive and observable after worker failure.

### F14 — P1: long-session event reads and rolling memory discard history

**Source-confirmed.** `red_agent/transport.py:30` always requests the first 5,000 events sorted by source timestamp, then applies `after_event_id` on the client. Events beyond that window disappear permanently from the loop. CLI `status` tails the earliest default 500 rows instead of the latest events. Source-time ordering combined with an event-ID checkpoint also mishandles late-arriving records.

`loop.py:97` summarizes only the newest window and replaces the existing summary without including it in the summarizer prompt; a second compression loses prior discoveries. Commands execute before their result is logged, so a crash between execution and event insert leaves an ambiguous action that may be repeated after restart. Persist execution intent and outcomes, define recovery for unknown outcomes, paginate by ingestion/event-ID cursor, and merge previous summary with newly folded evidence.

### F15 — P1: DONE exits early and phase progression is disconnected from the scenario

**Reproduced.** `loop.py:174` breaks when `_check_objectives()` reports *any newly achieved objective*, even if others remain. The returned `complete` stays false, but the worker stops after one model call in the two-objective probe. `parse_tool_call()` accepts empty args and converts numeric command values to strings. `propose_phase` is unconstrained and unused. Phase advances one step per batch with any success, not according to an objective/phase relationship; two objectives may finish while phase still says `priv-esc`.

Require all objectives for successful completion, separate done/no-progress/budget outcomes, validate nested tool args strictly, and explicitly model or document the scenario phase rules. Provide the model the session's actual target inventory; currently its prompt names objectives but omits topology/IP inventory.

### F16 — P1: replay file references are untrusted paths, and recordings can overwrite

**Source-confirmed.** `api/web_routes.py:88` opens arbitrary `payload.cast` values from events. Combined with open event ingest, callers can request reads of server-local paths; valid JSON/JSONL contents can be returned, and malformed content raises uncaught errors. This is not a universal plaintext file download, but it is an inappropriate arbitrary file-open boundary. Reads are unbounded. The API expects the bastion's local pathname to exist on a different LXC without a storage/transfer contract.

`bastion/proxy.py:104` builds filenames from user-controlled token text plus second-resolution timestamps; `CastWriter` opens with `w`. Concurrent/repeated connections within one second can overwrite evidence, and path separators are not constrained. Exec-channel output is not written to the cast. Persist opaque recording IDs, constrain storage paths, use unique exclusive creation, validate frames/size, and implement authenticated transfer or a deliberate shared-storage contract.

### F17 — P2: replay UI is not synchronized terminal playback

**Source-confirmed.** `web/pages/session/[id]/replay.js:49` uses the first event timestamp as the recording epoch instead of `cast.header.timestamp`, so recordings started later highlight the wrong events. It renders accumulated escape sequences as plain `<pre>` text, includes input alongside echoed output, selects only the first cast and does not update playback's captured cursor correctly when scrubbing while playing. Use a real terminal/asciinema renderer, an explicit recording selector, absolute-time synchronization and tested play/seek state.

### F18 — P2: coach priority queue does not govern the red model traffic

**Source-confirmed.** `coach/queue.py` receives hints/AARs only. Red actions and summaries call `LLM.complete` directly. The comment promises an optional relay endpoint which does not exist. Hint initialization probes the model before entering the queue; long active AAR calls are not preemptible, and `_coach_llm=False` suppresses recovery indefinitely. Futures time out without removing queued work; DB transactions remain open during expensive model calls.

Route all calls sharing one GPU through one bounded scheduler, or explicitly configure independent capacity. Bound requests/retries and define the hint latency bound, acknowledging an already-running request. Add cancellation, shutdown, periodic recovery and saturation tests using real call paths, not only heap ordering.

### F19 — P2: scenario validation omits values needed for safe, executable scenarios

**Source-confirmed.** `scenario_engine/loader.py:43` checks selected types but not nested shapes, unique objective/host IDs, valid IPs/CIDRs, positive limits, required verifier args, red objective host references or OS applicability. Malformed nested values can raise AttributeError rather than ScenarioError. The library bypasses validation. Filesystem lookup does not constrain scenario IDs to a safe identifier/root. `Context.hosts` stays empty; verifier SSH uses hostnames without resolving deployed addresses. YAML and template environment settings have no clear precedence.

Use the existing Pydantic dependency for strict nested schemas and per-verifier argument validation. Validate all scenarios at startup/launch; snapshot the selected scenario and template/baseline version into session evidence so later file edits cannot rewrite the meaning of historical scores. Keep new scenario features data-driven.

### F20 — P2: M7 progress and library provide less than the promised experience

**Source-confirmed.** Progress assigns the whole scenario percentage to every `focus` tag instead of computing actual CCDC-domain check scores. Zero-total scores produce None which is passed to `sum(v)`, causing a server error. Session rows are ordered by UUID, not chronology; latest scores lack an event-ID tie-break. There are averages but no trends. The library displays metadata without filters. Error handlers on live/replay/scenario pages can leave endless loading states. Login state in the shared header is only read on mount.

Define domains per scoring item and calculate trends from stable evidence; handle empty/zero/unknown scores, show chronological history, and add working filters and recoverable error states. Fix after end-to-end scoring works.

### F21 — P2: image/template setup is not repeatable from the shipped artifacts

**Source-confirmed; Packer validation not run.** The Packer file references `github.com/bpg/proxmox` (the Terraform-provider identity), while the actual Packer plugin uses `github.com/hashicorp/proxmox`. Several configuration names/blocks also need validation against that builder. The shell provisioner assumes repository files already exist inside the VM, but no file provisioner transfers them. Merely copying cloud-init YAML into `/etc/sparring-range` does not apply it. No working vulnerable web/database service, scenario seed data, verifier management key provisioning or host readiness contract is defined in these scripts.

Provide one reproducible Linux golden-template path and a separate Windows/Sysmon checklist; either repair the optional Packer path or mark it unsupported and remove misleading executable examples. Verify against the official [Packer Proxmox plugin](https://github.com/hashicorp/packer-plugin-proxmox) and [clone builder](https://github.com/hashicorp/packer-plugin-proxmox/blob/main/docs/builders/clone.mdx).

### F22 — P2: the test suite does not substantiate its acceptance labels

**Source-confirmed.** M0 checks a string and a helper defined only in the test. The killswitch test accepts any fake POST containing “firewall.” M1 replaces the adapter containing the wrong production URLs. M2 posts synthetic auditd records rather than running the shipper pipeline. M3 injects KeyboardInterrupt inside a fake model rather than killing/restarting a production worker. M6 uses `--no-start`, manually runs a loop, and never scores or closes the session. M7 launch does not call `/run`; progress is seeded by posting fabricated scorecards; no checked-in browser E2E test exists. M5 tests text presence and queue ordering, not claim validity or contention with red traffic.

DB fixtures are environment-specific, globally destructive to a fixed test DB, and recreated separately for M6 while pooled connections/singletons may survive. README says 23 tests; source contains 25 test functions. Introduce separate unit, disposable PostgreSQL integration, adapter-contract, browser and opt-in live acceptance layers. Each hard constraint needs a production-path negative test and a separately documented human datapath gate.

### F23 — P2: reproducibility, operational limits and diagnostics need finishing

**Source-confirmed.** Python dependencies are lower bounds despite the plan asking for pins; frontend has a lockfile. There is no checked-in CI configuration. Package discovery does not package top-level scenarios/configs as wheel data even though runtime code resolves them relative to installation paths. Environment docs omit settings such as node, gateway, VMID base and bastion user, plus a LAN web API origin. CORS allows only localhost/127.0.0.1, and frontend defaults to the visiting browser's localhost, which does not work for teammates on another machine.

HTTP response checks are inconsistent; health reports true without dependency readiness; broad exception swallowing hides loss/failure; there are no bounded log/recording quotas or retention/backup/restore instructions. Add a reproducible Linux deployment/test path, locked Python resolution, startup diagnostics, explicit LAN origins and documented operational bounds. Review dependency advisories during remediation; no current CVE scan was performed in this audit. Do not imply that a specific dependency version is vulnerable without checking advisories.

## Scope recommendation

The highest-value addition is a **truthful, bounded single-session product**, not more attack capability. Add a durable lifecycle, trusted evidence provenance, health/readiness checks, resource ownership, a real telemetry delivery path, reproducible scenario baselines and an evidence-based scoring rubric. These fill gaps in the original plan that became visible when its pieces were connected.

Keep one active range at a time for v1, multiple member accounts and historical sessions, manual Windows template creation, and one backend. Do not add Kubernetes, workflow frameworks, enterprise IAM, PvP, C2 integration, concurrent shared scenarios, adaptation or spaced repetition until the first complete practice loop and AAR usefulness gates pass. A small schema extension for operational state is justified if documented; preserving the event log as evidence does not require storing locks, worker leases or credentials as ad hoc event payloads.

Suggested order: reproducible baseline → fail-closed execution/safety → identity/evidence → real deploy/session ownership → capture/bastion → trustworthy verification/scoring → durable loop/coach → complete browser experience → live acceptance. The detailed execution contract is in `LOCAL_AGENT_HANDOFF.md`.
