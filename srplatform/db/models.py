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
    SmallInteger,
    Text,
    UniqueConstraint,
    func,
    text,
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
    # scrypt hash (stdlib hashlib) — operator provisions passwords (F04)
    password_hash: Mapped[str | None] = mapped_column(Text)
    role: Mapped[str] = mapped_column(Text, nullable=False, default="member")  # operator|member
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Session(Base):
    __tablename__ = "sessions"

    session_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scenario_id: Mapped[str] = mapped_column(Text, nullable=False)
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.user_id"))
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # lifecycle (F13): preparing | ready | running | stopping | complete | failed
    status: Mapped[str] = mapped_column(Text, nullable=False, default="preparing")
    # session completion is DISTINCT from red objective success:
    # complete | incomplete | no_progress | budget | worker_failure | canceled | None
    outcome: Mapped[str | None] = mapped_column(Text)
    finalized_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
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
    Session-bound member capabilities (F08): issued by the launch workflow,
    expired/revoked with the session, bound to the owning member."""

    __tablename__ = "login_tokens"

    token: Mapped[str] = mapped_column(Text, primary_key=True)  # e.g. 'tok_web01'
    session_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("sessions.session_id"))
    user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("users.user_id"))
    target_host: Mapped[str] = mapped_column(Text, nullable=False)  # host/ip to dial on the range side
    target_port: Mapped[int] = mapped_column(BigInteger, nullable=False, default=22)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (UniqueConstraint("token", name="uq_login_token"),)


class WebToken(Base):
    """Simple LAN session tokens for the M7 web app (no SSO — scope traps out).
    Server-side expiry + revocation (F04); no password-less login."""

    __tablename__ = "web_tokens"

    token: Mapped[str] = mapped_column(Text, primary_key=True)
    user_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("users.user_id"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class ServiceToken(Base):
    """Scoped capability tokens for non-member producers (F04/F09): the
    bastion resolves targets with a `bastion` token; range hosts ship telemetry
    with a host-bound `telemetry` token; workers act with run-scoped `runner`
    tokens. Server assigns actor/session from the token — never from the body."""

    __tablename__ = "service_tokens"

    token: Mapped[str] = mapped_column(Text, primary_key=True)
    scope: Mapped[str] = mapped_column(Text, nullable=False)  # bastion|telemetry|runner|score
    session_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("sessions.session_id"))
    host: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class RangeLease(Base):
    """The single-active-range reservation (F06): one row (id=1). Acquired
    before any external resource is created; concurrent launches conflict."""

    __tablename__ = "range_lease"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    session_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("sessions.session_id"))
    acquired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class OperationClaim(Base):
    """Durable per-session operation claim (audit N02): survives the intent
    commits that release normal row locks. One row per session — the session's
    lifecycle operations (launch/deploy/reset/teardown/end/run) serialize on
    it. Cleared at API startup; stale claims are taken over with loud
    evidence.

    OWNER FENCING (audit T02): every acquire mints an owner token. Release
    only deletes the row it still owns — a stale request whose claim was
    taken over can never erase the REPLACEMENT request's ownership."""

    __tablename__ = "operation_claims"

    session_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True),
                                                  ForeignKey("sessions.session_id"),
                                                  primary_key=True)
    operation: Mapped[str] = mapped_column(Text, nullable=False)
    claimed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 server_default=func.now(), nullable=False)
    owner: Mapped[str | None] = mapped_column(Text)  # fencing token (audit T02)


class Deployment(Base):
    """Exact owned resources for a session deployment (F06). Teardown/reset
    only ever act on vmids recorded here — never on a scenario-name prefix."""

    __tablename__ = "deployments"

    deployment_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("sessions.session_id"))
    scenario_id: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="preparing")
    # [{vmid, node, name, host, ip, template_vmid}] — recorded as each side effect completes
    resources: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class Run(Base):
    """Durable supervised run state (F02/F13): one active run per session,
    worker identity (pid/pgid of its own process group), outcome, and the
    sha256 of the run-scoped worker capability."""

    __tablename__ = "runs"

    run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("sessions.session_id"), nullable=False)
    scenario_id: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="queued")
    outcome: Mapped[str | None] = mapped_column(Text)
    pid: Mapped[int | None] = mapped_column(BigInteger)
    pgid: Mapped[int | None] = mapped_column(BigInteger)
    pgid_pstart: Mapped[int | None] = mapped_column(BigInteger)  # leader start-time (R03 reuse guard)
    worker_token: Mapped[str | None] = mapped_column(Text)
    result: Mapped[dict | None] = mapped_column(JSONB)
    error: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        # DATABASE-ENFORCED single active run per session (audit N02): a
        # select-then-insert duplicate check races; a partial unique index
        # cannot. Concurrent /run requests resolve to exactly one active
        # worker. 'cancel-unknown' is ACTIVE for this purpose (audit T02):
        # unconfirmed cessation blocks new runs until recovery confirms it.
        Index("uq_runs_one_active_per_session", "session_id", unique=True,
              postgresql_where=text("status IN ('queued', 'running', 'stopping', 'cancel-unknown')")),
    )


class RunOperation(Base):
    """Durable COMMAND-operation inventory (audit T01): the identity of every
    dispatched red-agent command is persisted BEFORE dispatch, associated with
    its run and the deployment generation it was dispatched against. After a
    worker death the API recovers the operation rows and cancels the remote
    work through the runner control channel — no pidfiles, no information
    supplied by a test. A row stays 'active' until cessation is CONFIRMED;
    an unconfirmed cancellation is retained as 'cancel-unknown', never
    dropped from the inventory."""

    __tablename__ = "run_operations"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("runs.run_id"),
                                              nullable=False)
    session_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True),
                                                  ForeignKey("sessions.session_id"),
                                                  nullable=False)
    deployment_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    op_id: Mapped[str] = mapped_column(Text, nullable=False)   # runner operation identity
    kind: Mapped[str] = mapped_column(Text, nullable=False)    # local | remote
    # active -> dispatched, cessation unconfirmed; completed -> worker reported
    # the result; cancel-unknown -> cancellation attempted but NOT confirmed
    state: Mapped[str] = mapped_column(Text, nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 server_default=func.now(), nullable=False)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("uq_run_operations_op", "run_id", "op_id", unique=True),
        Index("run_operations_active_idx", "run_id", "state"),
    )


class SafetyState(Base):
    """Durable killswitch latch (F02): default is NOT safe; engagement survives
    API restart; release is explicit and operator-only."""

    __tablename__ = "safety_state"

    id: Mapped[int] = mapped_column(SmallInteger, primary_key=True)
    latched: Mapped[bool] = mapped_column(nullable=False, default=False)
    latched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    reason: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class SafetyRecord(Base):
    """Append-only-ish trail of safety checks/proofs/engagements (F02). Rows
    are never rewritten; current validity is derived from the newest records
    plus config identity + freshness window."""

    __tablename__ = "safety_records"

    record_id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    ok: Mapped[bool] = mapped_column(nullable=False)
    config_identity: Mapped[str | None] = mapped_column(Text)
    detail: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class Recording(Base):
    """Opaque recording identities (F16): clients reference recording_ids,
    never filesystem paths. Paths live server-side only."""

    __tablename__ = "recordings"

    recording_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("sessions.session_id"), nullable=False)
    cast_path: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="recording")
    bytes: Mapped[int | None] = mapped_column(BigInteger)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
