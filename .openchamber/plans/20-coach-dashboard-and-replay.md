# 20 — Conversational coach, dashboard and replay

> Workflow normalized 2026-10-28: the [native-workflow decision](../../docs/ARCHITECTURE.md#workflow-decision--native-openchamber-2026-10-28) supersedes old procedural rules in this record, not product requirements or acceptance gates. Retained status is not fresh verification.

## Steps
- [ ] Build authenticated evidence projections and conversational coaching.
- [ ] Capture bounded timed attacker output with honest legacy fallback.
- [ ] Modernize home/history, session navigation and report presentation.
- [ ] Integrate synchronized review and test authorization/failure cases.
- [ ] Record evidence, tick 20 on its gates and update architecture if changed.

## Goal and context
Requires 18–19 software, ARCHITECTURE J/K, ROADMAP and FINDINGS_CHECKLIST backlog.
Agreed: hints then direct help, modern dark dashboard, timed new-run playback.
Approved 2026-10-24. Use current task execution choices.
Retain completed live gates; never invent evidence.

## Scope
In: coach chat/AAR, session/history UI and filtered synchronized replay.
Out: coach execution, fake recordings, new scenarios, host tools, AI scores/spoilers.

## Implementation
1. In srplatform coach/{aar,timeline}, API coach_routes/visibility, capture and
   verifier/runner paths, identify management/verifier/attacker/member provenance
   at authenticated boundaries; host audit alone cannot assign identity. Legacy
   unknown stays unknown. Version projections without modifying raw audit; fix
   probe attribution and correlational overclaims. Claims cite relevant evidence,
   qualify uncertainty and cannot contradict trusted score/UNSCORED. Regeneration
   appends cutoff/profile/rubric versions, never edits old reports.
2. Persistent per-session coach conversation via 19's checkpoint/jobs/gateway,
   bound to owning session and authorized evidence. Guiding hints first; explicit
   request can obtain explanations/example commands in practice. Never execute
   commands or create verified credit. Competition cannot reveal sealed red
   evidence via chat, memory, citations, job status, reports or replay endpoints.
   Post-match chat reviews permitted history. Deterministic report survives model
   loss; queued/unavailable answers are visible.
3. Extend red_agent runner/transport, API storage and operation evidence with
   sequence-numbered timestamped bounded output chunks for new operations. Keep
   final results/exit/timeout/truncation/containment even on capture failure;
   never block stop on replay persistence. Separate output capture/storage quotas
   from model context; bounded memory/draining and explicit gaps/truncation. Safe
   terminal rendering, no control-sequence HTML/script execution or secret logs.
   Historical first-4000-character results stay incomplete, never reconstructed
   into fake timed casts. New output is non-interactive execution, not defender PTY.
4. In web pages/_app/index/library/session/[id], report/replay and shared styles/
   components, deliver modern dark responsive dashboard: proportional navigation/
   chat/report text, monospace terminals. Authenticated home shows active and
   paginated history including interrupted/unscored/cleanup-pending;
   members see own sessions, admin authorized all-session view. Clear session
   Overview/Activity/Replay/Report/Coach links, back navigation, reload/deep links,
   empty/error/loading states and keyboard access. Safe Markdown/citations link
   to authorized evidence, not a preformatted report dump.
5. Replay on a session clock with separate attacker/defender tracks, play/pause/
   seek/speed and previous/next command controls. Work without a defender cast;
   choose host/actor/type, meaningful default events and collapsed infrastructure
   noise; expandable full raw audit. Distinguish pre-recording/outside-coverage,
   missing/corrupt casts, gaps and command-only historical fallback. Paginate APIs,
   avoid downloading whole audit/casts to render a list. No scoring from playback.

## Manual checks
Operator judges desktop/mobile usability, useful model follow-ups, report grounding
and sync. Never record real admin operations. Retain visibly limited old evidence.

## Acceptance criteria
1. AGENTS.md fast pytest command passes with zero failed/skipped.
2. `.venv/bin/python infra/dev/acceptance.py db` passes provenance, chat/cutoff, append-only artifacts and competition isolation tests.
3. `.venv/bin/python infra/dev/acceptance.py containment` passes output-limit/drain/cancellation regressions.
4. `.venv/bin/python infra/dev/acceptance.py frontend` passes production build/audit with zero high/critical findings.
5. `.venv/bin/python infra/dev/acceptance.py browser` proves two-user/admin access, coach, report links/history, player seek and command navigation without defender casts.
6. Verifier/MOTD noise is not attacker attribution; UNSCORED cannot become AI fail; legacy gaps/timing stay honest.
7. Raw audit remains authorized-accessible; no endpoint/chat leaks sealed competition data.
