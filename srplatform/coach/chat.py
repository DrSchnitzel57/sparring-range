"""Conversational practice coach (plan 20) — hints first, honest always.

Conversation rules the prompts and persistence enforce together:
* guidance FIRST (Socratic hints); an EXPLICIT request may obtain
  explanations and EXAMPLE commands in practice — but the coach never
  executes anything and never creates verified credit;
* the model reasons ONLY over the caller-authorized, visibility-filtered
  evidence window it is given at enqueue time, up to a recorded CUTOFF
  event — a queued answer can never be expanded with later events when
  it finally runs, and citations to events outside the window (or that
  never existed) are dropped, never rewritten;
* a missing/failing model yields an honest recorded fallback, never an
  invented answer; the deterministic report path is untouched by chat.
"""
from __future__ import annotations

import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from srplatform.db.models import CoachMessage

CITE_RE = re.compile(r"#(\d+)")
EVENT_WINDOW = 60
HISTORY_WINDOW = 12

CHAT_SYSTEM = (
    "You are a practice coach for a defensive cyber range, chatting with "
    "the team that owns this session. Default mode: guide with questions "
    "and small next-step hints (5 sentences max). If — and only if — the "
    "member explicitly asks for an explanation or an example command, you "
    "may give the explanation and example commands for them to run "
    "themselves. You NEVER run commands yourself, never claim actions were "
    "taken, and never award or invent scores or grades. Base every claim "
    "ONLY on the evidence you were given; cite it as #<event_id> and never "
    "cite an id you were not given. If the trusted scorecard says "
    "UNSCORED, do not contradict it. If evidence is missing, say so. "
    "ATTRIBUTION: trust the per-line actor classes and the session "
    "context line; activity recorded before the first RED entry is setup "
    "or defender work, not attacker reconnaissance, and host telemetry "
    "alone never proves who acted or why — when attribution is unclear, "
    "say it is unknown instead of guessing. CORRECTIONS: when the person "
    "you are chatting with corrects you, acknowledge the correction and "
    "restate with explicit uncertainty; their correction is context, not "
    "independently verified evidence, and not a reason to double down.")

CHAT_FALLBACK = (
    "The coach model could not answer, so nothing was invented here. "
    "Deterministic evidence stays available in Activity and the Report; "
    "try again once the model is reachable.")

CHAT_UNAVAILABLE = (
    "The coach is not reachable right now (no bound model profile or the "
    "queue is saturated), so nothing was invented. Your message is kept — "
    "ask again once an operator has the model available.")


# Independent review finding 1: ONE conversation cannot be shared across
# audiences. An operator answer generated over sealed red evidence must
# never be replayed into a member's history OR a member's next provider
# prompt, so every persisted message carries an immutable audience and
# history reconstruction filters on it at the API boundary (never by
# model redaction, never by role guessing from prose).
AUDIENCES = ("member", "operator")

AUDIENCE_NOTES = {
    "member": "",
    "operator": (
        " The person you are chatting with is the RANGE OPERATOR for this "
        "session; the evidence may include sealed attacker activity that "
        "members cannot see. That context stays in this conversation."),
}

USER_LABELS = {"member": "Member question", "operator": "Operator question"}


def recent_messages(db: Session, session_id, *, audience: str = "member",
                    limit: int = HISTORY_WINDOW,
                    before_id: int | None = None) -> list[CoachMessage]:
    """The bounded conversation window FOR ONE AUDIENCE (migration 0026
    backfilled pre-existing rows as member history)."""
    stmt = select(CoachMessage).where(
        CoachMessage.session_id == session_id,
        CoachMessage.audience == audience)
    if before_id is not None:
        stmt = stmt.where(CoachMessage.message_id < before_id)
    rows = db.execute(stmt.order_by(CoachMessage.message_id.desc())
                      .limit(limit)).scalars().all()
    return list(reversed(rows))


def window_events(events: list[dict]) -> list[dict]:
    """The bounded evidence window the chat model may reason over: the
    most recent EVENT_WINDOW entries (the caller already applied the
    requesting principal's competition visibility BEFORE this point —
    sealed red payloads never reach the model, so chat cannot launder
    them back)."""
    return events[-EVENT_WINDOW:]


def build_chat_prompt(events: list[dict], history: list[CoachMessage],
                      question: str,
                      audience: str = "member",
                      context: dict | None = None
                      ) -> tuple[str, str, int | None, list[int]]:
    """(system, user, cutoff_event_id, allowed_citation_ids).

    The cutoff and the allowed citation ids are captured AT ENQUEUE:
    a durable answer produced later cannot drift its evidence base, and
    anything it cites outside this window is dropped on persistence.

    Independent review finding 8: the prompt is COMPRESSED (max_lines),
    so window membership is not evidence visibility — allowed ids are the
    event ids the RENDERED timeline actually shows (the compressor's own
    canonical accounting). A citation to an event the model was never
    actually shown is rejected exactly like one outside the window — and
    so is an id a command payload merely mentions (plan 20 F5: an attacker
    command ``echo reference #99999999`` must not forge a citation).
    ``context`` (plan 22 LIVE-10) carries phase/run state so the model
    knows whether ANY red activity is even possible yet. The audience
    selects the conversation context (finding 1); history must already be
    audience-filtered."""
    from srplatform.coach.timeline import compress_timeline, session_context_note
    window = window_events(events)
    timeline, index = compress_timeline(window, max_lines=40)
    visible_ids = sorted(index["shown_ids"])
    lines = []
    for m in history:
        who = "member" if m.role == "user" else "coach"
        lines.append(f"{who}: {m.body[:600]}")
    note = session_context_note(context)
    header = ((note + "\n") if note else "") + \
        ("Evidence window (events up to cutoff; cite as #<id>):\n"
         f"{timeline or '(no recorded evidence yet)'}\n")
    if lines:
        header += "\nRecent conversation:\n" + "\n".join(lines) + "\n"
    cutoff = max((e["event_id"] for e in window), default=None)
    label = USER_LABELS.get(audience, "Member question")
    system = CHAT_SYSTEM + AUDIENCE_NOTES.get(audience, "")
    user = f"{header}\n{label}: {question[:4000]}"
    return system, user, cutoff, visible_ids


def validated_citations(body: str, allowed_ids: list[int] | None) -> list[int]:
    """Citations the answer may keep: #ids that were in its own evidence
    window. Unknown/out-of-window citations are dropped — the coach's
    prose stays verbatim (like the AAR narrative), but it may not point
    at evidence it was not given."""
    if not allowed_ids:
        return []
    allowed = set(allowed_ids)
    return sorted({int(m) for m in CITE_RE.findall(body or "")} & allowed)
