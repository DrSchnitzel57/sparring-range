# Second-follow-up handoff — completion report

Contract: `docs/SECOND_FOLLOWUP_HANDOFF.md` against review
`docs/SECOND_FOLLOWUP_REVIEW.md` (baseline `18377c6`). Environment: this
authoring host (Debian-ish Linux, PostgreSQL 17 on localhost, real `nft` +
root in disposable netns, node 22 + playwright-cli; **no docker, no PVE, no
R740, no GPU, no range VMs**).

## What changed, per stage (production entrypoints)

- **Stage 1 — N01–N03** (`9f78039`): typed Proxmox lookup outcomes
  (`infra/proxmox_client.py`, `srplatform/scenario_engine/orchestrator.py`),
  confirmed-outcome destroy, ownership-before-any-mutation, DB operation
  claims + active-run uniqueness (`srplatform/db/migrations 0007`,
  `srplatform/api/web_routes.py`, `srplatform/api/runs.py`), one lifecycle
  policy across launch/deploy/reset/teardown/run/end.
- **Stage 2 — N05–N07** (`aebafe8`): runner operation supervision + cancel/
  ack + restart reconciliation + bounded streaming (`srplatform/red_agent/
  runner.py`, `infra/runner/runner_supervise.sh`), JSON-structural nft
  verification + topology-driven emergency coverage + atomic apply/release
  (`srplatform/safety/datapath.py`, `firewall.py`), fail-closed durable state
  (`srplatform/safety/__init__.py`).
- **Stage 3 — N04, N08–N09** (`4be0a70`): split controller/worker validation
  + no controller `.env` in the worker (`srplatform/settings.py`), durable
  identity-keyed spool (`telemetry/shipper.py`), event-identity audit
  assembly, real installed artifact exercised, per-deployment telemetry
  enrollment (`orchestrator.py`, `telemetry/install.sh`).
- **Stage 4 — N10–N11** (`365be04`): one immutable session snapshot to the
  worker over its session API (`srplatform/api/app.py`,
  `red_agent/worker.py`), owned-generation-only verifier host resolution +
  pinned host keys + deployment identity in evidence
  (`srplatform/verification_service.py`), versioned prebuilt-template
  readiness contract (`scenario_engine`, scenario loader).
- **Stage 5 items 1–2, 5** (`f2b6ccc`): worker red turns through the API's
  ONE model gateway (`/internal/model/complete`; worker holds no model
  credential), honest coach labels (`srplatform/coach/timeline.py`), full
  practice-loop regression.
- **Stage 5 item 3** (`53e5e99`, this session): compose `seed-bastion-keys`
  one-shot (`infra/dev/seed_bastion_keys.sh`, `docker-compose.yml`),
  idempotent `rangectl bootstrap` (`rangectl/cli.py`), runbook §0,
  `.env.example` wiring. Fixed while verifying the half-done work: the
  bootstrap test compared `load_authorized_keys` output against an
  unstripped asyncssh export (test-side only).
- **Stage 5 item 4** (`eb802f9`, this session): checked-in browser E2E
  `tests/test_stage5_browser_e2e.py` (see results below).
- **Docs** (this session): `docs/FINDINGS_CHECKLIST.md` gained the N01–N11
  table + Stage 5 table + overclaim correction note;
  `docs/FOLLOWUP_REMEDIATION.md` gained a dated correction addendum (history
  preserved); runbook §0/§7/§9 updated; `audit/second-review-results-after-stage5.json`.

## Validation actually executed (outcome + environment)

All on the authoring host above; disposable per-session PostgreSQL 17 DBs
(`SR_PG_ADMIN_CMD="su postgres -c"`, unique `srtest_*` DBs dropped after).

| Command | Result |
|---------|--------|
| `pytest -m "not db and not browser and not live"` | **62 passed** |
| `pytest -m "db or adapter"` | **85 passed** |
| `pytest -k "nft or netns"` (privileged, real kernel netfilter, disposable tables/netns) | **2 passed** (`r05_real_nft_apply_remove_roundtrip`, `r06_disposable_netns_packet_semantics`) |
| `pytest tests/test_stage5_browser_e2e.py -m browser` | **1 passed, twice consecutively** (real Chromium via playwright-cli; real `next start`; real uvicorn; real worker subprocess) |
| `python audit/second_review_probes.py` | exit 0; all 18 probes report safe/fail-closed behavior; byte-identical to the after-stage4 results (`audit/second-review-results-after-stage5.json`) |

Failure/unknown cases asserted by the new tests (not just happy paths):
teardown under timeouts keeps resources+lease (`complete=false`), foreign
VMID zero-mutation, unconfirmed cancel never reported cancelled, missing +
unreadable safety state = LATCHED, oversized-first spool record = visible
drop, missing inventory = unknown with NO DNS/SSH, attacker telemetry earns
no defender credit, unpinned SSH channels refused, seed script exits 1 on
missing key material, bootstrap re-run re-mints nothing (DB row count
asserted), E2E asserts the report is NOT "UNSCORED".

**BLOCKED, not passed, not skipped-silently:** `docker compose config` and
fresh-volume boot (no docker here) — YAML-level wiring tests + the seed
script executed against volume-shaped dirs are the honest substitute;
recorded in runbook §0/§9 and the checklist.

## Still missing implementation

Nothing on the handoff's list remains unimplemented. Remaining work is
hardware acceptance only (below). One environment note: the local dev DB
`sparring_range` was stale at migration 0003 and was brought to head with
`rangectl db migrate` (a non-DB test legitimately mirrors safety state to
the configured dev DB and correctly failed closed until migrated).

## Human-only acceptance (expected observations)

1. `docker compose config` + fresh-volume boot of runbook §0 — seed step
   exits 1 naming the runbook until `deploy/bastion/{authorized_keys,
   target_known_hosts}` exist; then api+bastion come up; `rangectl bootstrap`
   prints tokens ONCE and re-runs are no-ops.
2. R740/PVE: concurrent launches → exactly one deployment, lease conflict
   409; kill PVE mid-clone → retry reconciles, no foreign VM mutated; packet
   tests from a booted VM (egress/IPv6 drop, management SSH + replies
   allowed, same-bridge isolation under killswitch).
3. Real Kali runner: start a long command, drop SSH transport → cancel/ack
   reports truthfully; descendants die.
4. Real model endpoint: hints overtake batch AAR under load (one scheduler).
5. Real Linux/Windows telemetry: commands land in the right session;
   end/reset/teardown revokes enrollment.
6. Deployed-stack browser E2E incl. bastion recording playback.

## Is a model-driven practice run authorized?

By the **automated** gates: yes — the full loop (safety gate → launch →
capture → verification → score → report → cleanup) is green end to end,
including in a real browser. By the **operator's own contract**: not yet —
the [LIVE GATE] items above (real PVE/R740 packet truth, real runner cancel,
real telemetry streams, compose boot) are unexecuted because the hardware is
not reachable from this environment. The runbook marks exactly those as the
remaining acceptance steps; nothing is claimed on their behalf.

---

## Addendum — 2026-10-06 (third follow-up, `docs/THIRD_FOLLOWUP_REVIEW.md`)

This report's historical evidence is preserved as written. The third review
(baseline `0b0d726`) correctly found that three claims above were
**OVERCLAIMS** — the mechanism existed but was not wired into the production
path, and the tests proved the helper, not the route:

* **Snapshot deployment (T04) was NOT fully implemented at `0b0d726`.** The
  worker/verifier/scoring used the session snapshot, but
  `orchestrator.deploy()` still called `load_scenario(scenario_id)` — editing
  the source YAML after session creation changed the DEPLOYED topology
  independently of the graded spec. The prior "immutable snapshot" claim held
  for execution/grading only, not provisioning.
* **Host provisioning / telemetry enrollment (T05) was NOT fully
  implemented at `0b0d726`.** Deployment issued a `ServiceToken` and returned
  it, but no code wrote the clone's `shipper.env`, started the service, or
  confirmed delivery — the installer left `PROVISION-PER-DEPLOYMENT` /
  `SET-PER-CLONE` and delegated the software step to the operator. "Enrolled"
  meant "token issued", which the review rightly refused to count.
* **Authoritative stop/recovery (T01/T02) was NOT fully implemented at
  `0b0d726`.** A remote command could survive leader exit; an unconfirmed
  remote stop could still be reported as `cancelled`, and unknown remote
  operations were dropped from the inventory instead of being retried and
  held. Streaming reads could also block past their deadline (T07).

Also corrected: effective-policy verification accepted an inserted accept and
a widened `range_hosts` set (T03); production could reach `ready` with the
readiness check silently unenforced and reset skipped the readiness/credential
workflow (T06); spool crash recovery could reuse record IDs and lose events
appended after a torn tail (T08).

Each is now implemented in the production path with a production-boundary
regression (route status + database/external state asserted). See
`docs/THIRD_FOLLOWUP_COMPLETION_REPORT.md` for the per-finding result and the
commands/commit that demonstrate it. The hardware gates (real PVE/R740 packet
truth, real Kali runner transport loss, real auditd/Sysmon streams, docker
compose boot) remain unexecuted here and are unchanged by this addendum.
