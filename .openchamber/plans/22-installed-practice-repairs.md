# 22 — Installed practice repair batch

## Steps
- [ ] Fixture installed findings and retained review defects.
- [ ] Repair upgrade, diagnostics and SSH onboarding.
- [ ] Deliver evidence-based safety admission/recovery UX.
- [ ] Repair coach, citations and replay/output defects.
- [ ] Prove integrated practice/upgrade, package and independently review.
- [ ] Update findings, tick roadmap 22 on its gates and update architecture if changed.

## Goal and context
Authorized 2026-10-29: autonomous Qwen Flash Next high / independent review on
practice-upgrades-18-21; no push, merge, branch switch or deployed operations.
Bindings: AGENTS, ARCHITECTURE, ROADMAP, FINDINGS LIVE-01–10 and plan-20 F5–F9.
Baseline 1083f22, exact AGENTS fast command: 678 passed, 480 deselected,
0 failed/skipped, 6 warnings, 95.97s. Preserve accumulated findings.

## Scope
All accumulated software repairs; LIVE-08 was an unrelated resolved outage.
Preserve commissioning evidence, users, keys, pins, history, reports, recordings,
role isolation and deterministic scoring. No new scenarios, live calls, automatic
attacks, host firewall execution, outer-PVE access or invented qualification.
Applied migrations stay immutable.

## Implementation
1. Reproduce old-config/UID faults through the actual CLI. Provision API-only
   legacy-key traversal/read without key rotation or broad permissions. Pass
   manifest public URL into web build; prove upgraded browser login. Version
   verified receipts only after successful upgrade; real drift still fails.
   Separate historical errors from current success. Doctor/status use authorized
   read-only access or explain peer denial; never allowlist root. Preserve -B,
   backups, ownership/unknown-work fences and readiness/schema checks.
2. Deliver operator account/public-key enrollment/status via API/CLI/UI: no private
   keys, API host-root or arbitrary file writes; preserve other accounts/keys.
   Explain missing enrollment; advertise only authorized defender SSH, not attacker
   access. Document one-time IdentityFile setup, encrypted persistent keys/agent
   choices and idle expiry; no forced hourly export.
3. Separate commissioned isolation/stop qualification from admission health.
   Qualification remains usable for unchanged, versioned relevant config/contract;
   age alone is advisory. Run bounded non-disruptive authoritative checks before
   Begin automatically, not manual ping/stop rituals. Preserve legacy records,
   timestamps, provenance and compatibility checks; never mint passed retests from
   old attestations. Failed/missing/unknown checks, relevant changes, latch
   transitions, unknown cessation/ownership or incompatible evidence fail closed
   with reasons/recovery. No destructive per-Begin tests, fake renewal, blanket
   disable or worker privileges. Probes use fixed typed existing boundaries, never
   model-selected host shell/destinations. UI/readiness/stages/Begin agree.
4. Coach gets phase/run and authenticated provenance: member commands, registered
   red operations versus untrusted/background telemetry. No attacker attribution
   from host labels; acknowledge corrections without verifying user assertions.
   Audience-isolate history/jobs/SSE; citations use canonical prompt-visible IDs,
   not payload regexes; no verified points. Finish F5–F9: filter-independent replay
   origin, hide future pre-cast frames, full metadata idempotency and plausible
   worker-claimed timing/provenance. Preserve honest historical gaps.
5. Add required-mode `practice` gate: real local HTTP, disposable DB, UID/ACL and
   browser fixtures. Check disk/inodes/RAM/PIDs before heavy work; serialize,
   reuse images, clean only owned resources. Version a new bundle, never overwrite
   the sealed test release. Inspect staged changes for secrets before each commit.

## Manual checks
Operator checks installed provider/isolation/stop/SSH/Begin/coach/replay.
Agents run no live tests.

## Acceptance criteria
1. Exact AGENTS fast pytest command passes with zero failures/skips.
2. `acceptance.py practice` passes all LIVE regressions and unchanged/aged versus changed/failed/unknown admission cases, with no required skips.
3. `acceptance.py db` and `agent` pass, including provenance/audience/citation and immutable evidence cases.
4. `acceptance.py authority` and `containment` pass without privilege weakening.
5. `acceptance.py install` and `upgrade` pass real old-schema/config/UID sequences; upgraded browser login and verify need no manual fixes.
6. `acceptance.py frontend` then `browser` pass online audit, onboarding, safety eligibility, coach correction and replay regressions.
7. `acceptance.py bundle` verifies new runtime/reused images, rejects tampering; record receipts/cleanup.
