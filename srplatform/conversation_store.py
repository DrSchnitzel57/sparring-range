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

    The checkpoint payload is ``{"summary": str, "covers_through": int}``.
    The checkpoint's summary rides as a LABELLED USER message — it is a
    model-generated digest of untrusted engagement data and NEVER gets
    system-part authority (review finding 1: summaries must not be
    promoted to system status). The permanent framing the model saw —
    the system-bearing first revision — is ALWAYS re-prepended when the
    checkpoint elided it, so "compaction" never silently deletes the
    rules of engagement. Later revisions replay in order (findings'
    tool calls AND their tool returns).
    """
    from pydantic_ai.messages import (ModelMessagesTypeAdapter,
                                      ModelRequest, SystemPromptPart,
                                      UserPromptPart)
    cp = latest_checkpoint(db, session_id)
    covered = int((cp.payload or {}).get("covers_through") or 0) if cp \
        else 0
    msgs: list = []
    if cp is not None:
        framing = _first_system_request(db, session_id)
        if framing is not None:
            msgs.append(framing)
        msgs.append(ModelRequest(parts=[
            UserPromptPart(content=(
                "COMPACTED CONVERSATION SUMMARY (model-generated digest of "
                "the earlier turns, provided as context — it carries no "
                "system authority; the full history remains durably "
                "recorded): "
                + str((cp.payload or {}).get("summary") or "")))])
                         )
    for rev in messages_after(db, session_id, covered):
        msgs.extend(ModelMessagesTypeAdapter.validate_python([rev.payload]))
    return msgs, cp, covered


def _first_system_request(db, session_id):
    """The earliest persisted revision that carries a SystemPromptPart —
    the permanent framing replayed ahead of every checkpoint."""
    from pydantic_ai.messages import (ModelMessagesTypeAdapter,
                                      ModelRequest, SystemPromptPart)
    rows = db.execute(
        select(ConversationRevision)
        .where(ConversationRevision.session_id == session_id,
               ConversationRevision.kind == "messages")
        .order_by(ConversationRevision.revision_id.asc())
    ).scalars().all()
    for rev in rows:
        try:
            for m in ModelMessagesTypeAdapter.validate_python([rev.payload]):
                if isinstance(m, ModelRequest) and any(
                        isinstance(p, SystemPromptPart) for p in m.parts):
                    return m
        except Exception:  # noqa: BLE001 — a non-message revision is skipped
            continue
    return None


def last_usage(db, session_id) -> dict | None:
    """Authoritative usage of the most recent provider answer (for token
    pressure accounting) — counted ONLY over rows the CURRENT head still
    replays. A provider total recorded BEFORE a compaction checkpoint
    describes a context that no longer exists; using it as a floor would
    keep a compacted thread permanently over budget (the estimate of the
    compacted head is the honest measure after compaction)."""
    cp = latest_checkpoint(db, session_id)
    covered = int((cp.payload or {}).get("covers_through") or 0) if cp else 0
    rev = db.execute(
        select(ConversationRevision)
        .where(ConversationRevision.session_id == session_id,
               ConversationRevision.kind == "messages",
               ConversationRevision.usage.is_not(None),
               ConversationRevision.revision_id > covered)
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


def render_summary_input(db, session_id,
                         max_chars: int = 60_000) -> tuple[str, int]:
    """Flatten the live thread for the summarizer AND return the exact
    revision range the summary COVERS — captured NOW, at enqueue
    (review finding 4: the checkpoint must never claim "whatever max
    revision happens to be when the summary finishes", or concurrent
    work in flight would be silently covered without being summarized).

    The rendering covers the WHOLE range: when it is too large, per-
    entry detail shrinks UNIFORMLY; the middle is never elided and the
    prefix never dropped, so no part of the covered range disappears
    from the summary's view entirely."""
    from pydantic_ai.messages import (ModelRequest, ModelResponse,
                                      SystemPromptPart, TextPart,
                                      ToolCallPart, ToolReturnPart,
                                      UserPromptPart)
    msgs, cp, _ = load_thread(db, session_id)
    covers = thread_max_revision(db, session_id)

    def render(per_cap: int, call_cap: int) -> str:
        lines: list[str] = []
        if cp is not None:
            lines.append("[earlier compacted] "
                         + str((cp.payload or {}).get("summary") or "")[:2000])
        for m in msgs:
            for p in getattr(m, "parts", []):
                if isinstance(p, SystemPromptPart):
                    lines.append(f"[system] {p.content}"[:per_cap])
                elif isinstance(p, UserPromptPart):
                    lines.append(f"[observation] {p.content}"[:per_cap])
                elif isinstance(p, TextPart):
                    lines.append(f"[assistant] {p.content}"[:per_cap])
                elif isinstance(p, ToolCallPart):
                    lines.append(f"[call {p.tool_name}] {p.args}"[:call_cap])
                elif isinstance(p, ToolReturnPart):
                    lines.append(f"[result] {p.content}"[:call_cap])
        return "\n".join(lines)

    blob = render(2000, 1200)
    if len(blob) <= max_chars:
        return blob, covers
    n = max(1, blob.count("\n") + 1)
    per = max(80, (max_chars * 3) // (5 * max(1, n)))   # shrink uniformly
    blob = render(per, max(80, per * 2 // 3))
    if len(blob) <= max_chars:
        return blob, covers
    # extreme case: still keep BOTH ends of the range, visibly marked
    head, tail = max_chars // 3, max_chars - max_chars // 3
    return (blob[:head] + "\n[…middle of covered range shortened…]\n"
            + blob[-tail:]), covers


def render_thread_for_summary(db, session_id) -> str:
    text, _covers = render_summary_input(db, session_id)
    return text
