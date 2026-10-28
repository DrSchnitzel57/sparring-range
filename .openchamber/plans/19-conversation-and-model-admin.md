# 19 — Conversational agent and model administration

> Workflow normalized 2026-10-28: the [native-workflow decision](../../docs/ARCHITECTURE.md#workflow-decision--native-openchamber-2026-10-28) supersedes old procedural rules in this record, not product requirements or acceptance gates. Retained status is not fresh verification.

## Steps
- [ ] Define versioned model profiles, secrets, checkpoints and scoped API protocol.
- [ ] Implement one-slot jobs, streaming/cancellation and admin model GUI.
- [ ] Integrate pinned Pydantic AI slim with durable conversation history.
- [ ] Prove compatibility, isolation, recovery and behavioral regressions.
- [ ] Record evidence, tick 19 on its gates and update architecture if changed.

## Goal and context
Replace conversation, not execution authority. Depends on 18 software; retain
completed commissioning. Binding docs: ARCHITECTURE J/K, ROADMAP, FINDINGS_CHECKLIST.
Approved 2026-10-24. Use current task execution choices.
Historical baseline: 571 fast passed/267 deselected/
4 warnings; focused memory 37 passed/1 deselected.

## Scope
In: Pydantic AI slim, protocol, history/compaction, admin GUI/cancellation.
Out: general shell/plugins/MCP/subagents, restart resume, new scenarios, 20's UI.
Preserve separate worker UID, API-only secrets, fixed pinned attacker runner,
operation UUID/intent before dispatch, pacing/deadline and deterministic scoring.

## Implementation
1. Add forward-only DB migrations/API stores for versioned shared named profiles,
   attacker/coach-report/summarizer overrides and append-only conversation/checkpoint
   revisions. Profile version pins whole session; generation records exact config.
   API secrets are masked/write-only, never in prompts/workers/browser/logs/exports.
   Rotation/revocation invalidates old references and cancels affected jobs visibly;
   never substitute model/key. Bootstrap existing env config without exposing keys.
2. Extend settings, model_gateway, internal API, red_agent llm/transport/worker
   with bounded structured messages/tools/results/usage/finish reasons. Add durable
   async job/status/stream APIs; all probes/retries/compaction/coach/report calls
   share one slot, including removal of coach's out-of-queue ping. Hints outrank
   queued attacks then reports; no in-flight preemption, visible queue states,
   bounded retries/admission/timeouts, no DB transactions across waits. Cancel
   queued/running/retry work; verify endpoint cessation where supported and retain
   unknown slot obligations rather than overlapping requests. Isolate failures.
3. New operator-only model routes/page: endpoint, discovered/manual model, key,
   thinking levels none/low/medium/high and extra named mappings, role overrides,
   tests/capabilities and Advanced limits. Validated presets plus allowlisted
   generation kwargs only: no messages/tools/auth/destination overrides or secret
   redirects. Explicit admin tests, never shared Strata global settings changes.
   Defaults: context 262144, completion 32768 including thinking, timeout 900s
   capped by match deadline; compact near 80% with completion reserve. Token counts
   authoritative where available, conservative/labeled estimates otherwise.
4. Pin Pydantic AI slim/OpenAI in pyproject/lockfile; adapter keeps keys API-side.
   Replace prompt
   reconstruction/JSON-action parsing in red_agent/loop.py with structured history
   and one range tool. No SDK retries/external tracing.
   Persist action/result/facts/hypotheses/plan and evidence IDs; telemetry cannot
   flood memory. Compact for token pressure, retain recent tool pairs and failed
   windows, bounded backoff, no data-loss cursor advance. Preserve execution
   transaction, unknown-cessation fence and match supervision. Exhausted model
   failure interrupts honestly; checkpoints never authorize blind redispatch.
5. Add required-mode `agent` gate: local protocol server/disposable DB, native and
   forged/parallel tools, streaming/truncation/empty output, 262k accounting,
   telemetry flood/recon, checkpoint/stop races, isolation/rotation/slot release.

## Manual checks
Operator tests installed Strata kwargs/tokenization/tools/cancellation/latency
before production switch. Upstream is not installed proof. No live model calls.

## Acceptance criteria
1. AGENTS.md fast pytest command passes, zero failed/skipped.
2. `.venv/bin/python infra/dev/acceptance.py agent` passes without required-layer skips; fixtures are not model-competence claims.
3. `.venv/bin/python infra/dev/acceptance.py db` passes additive migrations, immutable checkpoints and secret/profile/job invariants.
4. `.venv/bin/python infra/dev/acceptance.py authority` and `containment` pass existing execution/cessation boundaries.
5. `.venv/bin/python infra/dev/acceptance.py frontend` and `browser` pass admin authorization, profile/test/rotation flows and queued-job reload recovery.
6. Sessions stay pinned, revocation fails visibly; no call bypasses admission or exposes provider keys to workers.
