# Architecture notes — production entrypoints, trust boundaries, safety placement

Status: written during the F01–F23 remediation (see `docs/FINDINGS_CHECKLIST.md`).
This supplements `plan.markdown` (the contract) — it does not replace it.

## Production entrypoints (front-door rule)

| Entrypoint | Role | Talks to |
|---|---|---|
| FastAPI app (`srplatform.api.app:app`) | THE business-logic front door | Postgres (app role), Proxmox, runner channel, verifier exec channel |
| `rangectl` CLI | Thin HTTP client of the API (+ `db` admin subcommands) | HTTP only (except explicit admin ops) |
| Next.js web app (`web/`) | Browser client of the API | HTTP only |
| Recording bastion (`srplatform.bastion.proxy`) | SSH proxy + cast recorder | API over HTTP; member keys; range hosts |
| Telemetry shipper (`telemetry/shipper.py`) | auditd → API forwarder on each range host | API over HTTP; local spool dir |
| Red worker (`srplatform.red_agent.worker`) | Supervised child process spawned by the API per run | API over HTTP with a run-scoped token; runner channel |

Migration/bootstrap tooling (`rangectl db migrate`, compose `migrate` job) is the
explicit administrative exception allowed to hold owner DB credentials. Backend
orchestration invoked by the API may use DB helpers — that is inside the front
door, not a second one.

## Trust boundaries

1. **Model orchestration (control plane)** — the loop builds prompts, parses
   tool calls, decides what to run. Never executes attack commands itself.
2. **Execution (runner channel)** — `red_agent/runner.py` ships commands to a
   designated isolated runner (Kali container/VM) over a restricted transport
   (SSH with pinned host key + dedicated low-privilege user). No local-shell
   fallback exists in production mode; runner unavailable ⇒ `/run` rejects.
   The runner receives ONLY the runner SSH credential. It never sees the
   database, Proxmox, referee/verifier credentials, or the API admin surface.
3. **Trusted verification (separate adapter)** — `verifiers` run inside backend
   code paths only, through a management exec channel built from the *owned
   deployment inventory* (`deployments.resources`), never from user input.
   Verifier results are appended to the event log by backend code with actor
   `system`; no client can post verifier/scorecard events.
4. **Evidence** — `events` is append-only (trigger + role grants). Actor and
   session association are assigned by the server from authenticated
   identity, never from request bodies.
5. **Identity** — operator/member. Password-hashed member accounts
   (scrypt, stdlib), server-side token expiry/revocation. Service capabilities
   (bastion, telemetry, runner) are separate token scopes; the API is
   fail-closed (anonymous mutation refused; anonymous reads limited).
6. **Telemetry trust limit (audit N09)** — each deployed clone is enrolled at
   deploy time with a telemetry capability bound to BOTH the session and the
   host name; ingest attributes session/host from the capability, never the
   payload. What CAN be trusted from a range host: that a holder of that
   host's capability CLAIMED these audit records at ingest time, under a
   capability valid for exactly one session — revocation on end/reset/teardown
   means an old clone can never contribute events to a new session. What
   CANNOT be trusted: the truthfulness of the records themselves — a
   compromised host controls what its auditd reports (it can omit, reorder or
   fabricate), so telemetry is attacker-observable evidence of what the host
   claimed, not ground truth. Verifier-side checks remain the scoring source
   of record for that reason.

## Safety controller placement

The safety supervisor lives **inside the API process boundary** (so engage is
reachable when members need it) but the **datapath operation itself is a
privileged host-side mechanism** invoked through exactly one constrained
adapter (`safety/datapath.py`), running pre-rendered, range-scoped nftables
rules for the configured bridge/VLAN. The emergency rule set is managed by
handle (add/replace/delete only its own set — never a global flush). The
latched state is durable (DB + local state file fallback) so an API restart
cannot forget an engagement. If the API is unreachable, operators run
`infra/firewall/killswitch.sh` directly on the Proxmox host — the recovery
path never depends on the blocked network.

## Single-active-range assumption

v1 has exactly one active range reservation across all scenarios and members
(`range_lease` single-row table, acquired before any resource creation).
Concurrent launches fail cleanly with the current holder visible. Multiple
members with accounts/history are supported; concurrent ranges, per-member
VLANs, and enterprise RBAC are explicitly out of scope (plan scope traps).

## Lifecycle states

`sessions.status`: `preparing → ready → running → stopping → complete | failed`,
plus `torn_down` recorded on the deployment (not the session). Session
completion is distinct from red objective success: a finalized session whose
verifiers show unconfirmed objectives ends `complete` with outcome
`incomplete`; worker death ends `failed`. End/finalize is idempotent: stop
worker → trusted score (verifiers) → append score snapshot + end evidence →
revoke session capabilities → release the lease only when resources are
accounted for. Reports/history stay readable afterwards.

## Justified deviations / additions

- **scrypt password hashing via stdlib `hashlib`** instead of a new dependency
  (memory-hard KDF, no supply-chain addition; LAN-scale work factor).
- **Worker as subprocess of the API** (process-group supervised) instead of a
  compose service — gives kill isolation without a scheduler framework.
- **Single-row operational-state tables** (`range_lease`, `safety_state`,
  `runs`, `deployments`, `recordings`) — locks/leases/metadata do not belong
  in the append-only evidence log (audit scope recommendation).
- Model scheduling is a per-process bounded priority gateway
  (`srplatform/model_gateway.py`). Cross-process GPU serialization (a relay)
  stays deferred: red and coach models are separately configurable today; a
  single-GPU deployment should point both at one server and accept the
  documented bound or run one process.
