"""SQLAlchemy 2.x models — Part 4 of the plan (the backbone).

The event log is append-only (enforced by DB trigger + role grants);
everything downstream (AAR, timeline, scorecard, /hint, replay) is a query
over `events`. Do not add columns that let the app rewrite history.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    BigInteger,
    DateTime,
    ForeignKey,
    Index,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    display_name: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Session(Base):
    __tablename__ = "sessions"

    session_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scenario_id: Mapped[str] = mapped_column(Text, nullable=False)
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.user_id"))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # 'running' | 'stopped' | 'complete'
    status: Mapped[str] = mapped_column(Text, nullable=False, default="running")
    players: Mapped[dict | None] = mapped_column(JSONB)  # reserved for future team mode


class Event(Base):
    """THE event log. Append-only: no UPDATE/DELETE via the application role,
    and a DB trigger raises for anyone who tries (hard constraint #4)."""

    __tablename__ = "events"

    event_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    session_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("sessions.session_id"))
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)  # when it actually happened
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    actor: Mapped[str] = mapped_column(Text, nullable=False)  # 'red' | 'blue:<user>' | 'system' | 'telemetry'
    host: Mapped[str | None] = mapped_column(Text)  # target host, or 'bastion'
    action_type: Mapped[str] = mapped_column(Text, nullable=False)  # tool_call|command|detection|verifier|hint|aar
    phase: Mapped[str | None] = mapped_column(Text)  # red kill-chain phase, nullable
    mitre_technique: Mapped[str | None] = mapped_column(Text)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    raw_ref: Mapped[str | None] = mapped_column(Text)  # pointer to .cast offset / raw blob
    raw_output_hash: Mapped[str | None] = mapped_column(Text)  # integrity of raw output

    __table_args__ = (
        Index("events_session_ts_idx", "session_id", "ts"),
        Index("events_action_type_idx", "action_type"),
    )


class AgentState(Base):
    """Rolling agent memory — context lives in the DB, never in a chat window."""

    __tablename__ = "agent_state"

    session_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("sessions.session_id"), primary_key=True)
    summary: Mapped[str | None] = mapped_column(Text)  # LLM-compressed "situation report"
    summary_upto: Mapped[int | None] = mapped_column(BigInteger)  # last event_id folded into summary
    current_phase: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class LoginToken(Base):
    """Bastion token logins: ssh drew@bastion -l tok_web01 -> target host mapping.
    Also backs the M7 simple LAN session tokens."""

    __tablename__ = "login_tokens"

    token: Mapped[str] = mapped_column(Text, primary_key=True)  # e.g. 'tok_web01'
    session_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("sessions.session_id"))
    target_host: Mapped[str] = mapped_column(Text, nullable=False)  # host/ip to dial on the range side
    target_port: Mapped[int] = mapped_column(BigInteger, nullable=False, default=22)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (UniqueConstraint("token", name="uq_login_token"),)
