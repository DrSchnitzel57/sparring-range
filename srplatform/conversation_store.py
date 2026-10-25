"""Durable conversation thread (plan 19).

The session's attacker conversation lives in ``conversation_revisions``
(append-only): every persisted model turn is a ``messages`` revision, and
a compaction summary is a ``checkpoint`` revision that COVERS a revision
range — it never replaces or deletes history, so replay can still show
exactly what the model saw. Reconstruction rule: start from the newest
checkpoint (its summary opens the thread), then re-apply every messages
revision after the covered point.
"""
from __future__ import annotations

import uuid

from sqlalchemy import select

from srplatform.db.models import ConversationRevision


def latest_checkpoint(db, session_id) -> ConversationRevision | None:
    return db.execute(
        select(ConversationRevision)
        .where(ConversationRevision.session_id == session_id,
               ConversationRevision.kind == "checkpoint")
        .order_by(ConversationRevision.revision_id.desc())
    ).scalars().first()


def messages_after(db, session_id, after_revision_id: int) -> list:
    return list(db.execute(
        select(ConversationRevision)
        .where(ConversationRevision.session_id == session_id,
               ConversationRevision.kind == "messages",
               ConversationRevision.revision_id > after_revision_id)
        .order_by(ConversationRevision.revision_id.asc())
    ).scalars().all())


def load_thread(db, session_id) -> tuple[list, dict | None, int]:
    """(reconstructed messages, checkpoint row or None, covered_through).

    The checkpoint payload is ``{"summary": str,
    "covers_through": int}``. The reconstructed head is NOT the original
    system prompt — after compaction the model continues from the summary,
    which is exactly what compaction means; the CURRENT turn's system
    framing rides on the fresh request the caller appends.
    """
    from pydantic_ai.messages import (ModelMessagesTypeAdapter,
                                      ModelRequest, SystemPromptPart,
                                      UserPromptPart)
    cp = latest_checkpoint(db, session_id)
    covered = int((cp.payload or {}).get("covers_through") or 0) if cp \
        else 0
    msgs: list = []
    if cp is not None:
        msgs.append(ModelRequest(parts=[
            SystemPromptPart(content=(
                "COMPACTED CONVERSATION (this replaces earlier turns; the "
                "full history remains durably recorded): "
                + str((cp.payload or {}).get("summary") or ""))),
            UserPromptPart(content="Continue the engagement from here.")])
                         )
    for rev in messages_after(db, session_id, covered):
        msgs.extend(ModelMessagesTypeAdapter.validate_python([rev.payload]))
    return msgs, cp, covered


def last_usage(db, session_id) -> dict | None:
    """Authoritative usage of the most recent provider answer (for token
    pressure accounting)."""
    rev = db.execute(
        select(ConversationRevision)
        .where(ConversationRevision.session_id == session_id,
               ConversationRevision.kind == "messages",
               ConversationRevision.usage.is_not(None))
        .order_by(ConversationRevision.revision_id.desc())
    ).scalars().first()
    return (rev.usage if rev else None) or None


def thread_max_revision(db, session_id) -> int:
    from sqlalchemy import func
    n = db.execute(
        select(func.max(ConversationRevision.revision_id))
        .where(ConversationRevision.session_id == session_id)
    ).scalar_one()
    return int(n or 0)


def append_checkpoint(db, session_id, *, summary: str, covers_through: int,
                      profile_id: uuid.UUID | None = None) -> int:
    rev = ConversationRevision(
        session_id=session_id, kind="checkpoint",
        payload={"summary": summary, "covers_through": covers_through},
        profile_id=profile_id)
    db.add(rev)
    db.flush()
    return rev.revision_id


def render_thread_for_summary(db, session_id) -> str:
    """Flatten the live thread into bounded text for the summarizer. The
    model's tool calls/results are rendered explicitly — the summarizer
    sees what was attempted and returned, not raw JSON envelopes."""
    from pydantic_ai.messages import (ModelRequest, ModelResponse,
                                      SystemPromptPart, TextPart,
                                      ToolCallPart, ToolReturnPart,
                                      UserPromptPart)
    msgs, cp, _ = load_thread(db, session_id)
    lines: list[str] = []
    if cp is not None:
        lines.append(f"[earlier compacted] "
                     f"{str((cp.payload or {}).get('summary') or '')[:1500]}")
    for m in msgs:
        for p in getattr(m, "parts", []):
            if isinstance(p, SystemPromptPart):
                lines.append(f"[system] {p.content}"[:2000])
            elif isinstance(p, UserPromptPart):
                lines.append(f"[observation] {p.content}"[:2000])
            elif isinstance(p, TextPart):
                lines.append(f"[assistant] {p.content}"[:2000])
            elif isinstance(p, ToolCallPart):
                lines.append(f"[call {p.tool_name}] {p.args}"[:1200])
            elif isinstance(p, ToolReturnPart):
                lines.append(f"[result] {p.content}"[:1200])
    # keep the TAIL when the rendering is huge (most recent matters most)
    blob = "\n".join(lines)
    return blob[-60_000:]
