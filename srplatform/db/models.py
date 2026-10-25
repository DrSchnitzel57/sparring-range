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
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
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
    # TELEMETRY ENROLLMENT (audit T-05): a fresh nonce issued with the token,
    # the deployment generation it belongs to, and the two DISTINCT evidence
    # timestamps — the authenticated callback FROM THE PROVISIONED HOST
    # (delivery_confirmed) and the first audit event observed THROUGH THE
    # INSTALLED SERVICE (capture_verified). A running service proves neither.
    enroll_nonce: Mapped[str | None] = mapped_column(Text)
    enrollment_deployment_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    enroll_confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    enroll_capture_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
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
    # Supervisor heartbeat (milestone 15): a separate-UID supervisor renews
    # this while the child runs. A stale value is visible evidence for
    # reconciliation; it never authorizes an API-side kill across UIDs.
    worker_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    # The SUPERVISOR's own claim credential (hash). Distinct from
    # ``worker_token`` (the worker's one-shot run capability): every
    # supervisor callback is fenced by this, so an obsolete claimant whose
    # claim was already reclaimed and rotated cannot assign, heartbeat or
    # overwrite a terminal state.
    worker_claim_token: Mapped[str | None] = mapped_column(Text)
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
    # truthful completion/containment detail (audit T-04): surviving-descendant
    # containment verdicts and unconfirmed-stop reasons are RETAINED here.
    detail: Mapped[str | None] = mapped_column(Text)
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


class MatchModel(Base):
    """Minimal durable match lifecycle (pilot step 4). One row per session,
    created AT SESSION CREATION: the effective preset, match duration and
    attack pace are SNAPSHOT then (never re-read live mid-match).

    Server clock is the only authority: Begin binds started_at/deadline_at;
    the scheduler ends the match at the deadline, expires ready-but-unstarted
    labs after READY_IDLE_EXPIRY, and an API restart INTERRUPTS (never
    resumes). Mutable by design — this is operational lifecycle state (like
    the range lease), not history; every transition also appends an event.

    States: provisioning -> ready -> running -> finalizing -> completed,
    with `interrupted` for idle expiry / API restart / blocked cleanup.
    'finalizing' is the DURABLE INTENT marker: a crash mid-cleanup leaves it,
    and the scheduler (or startup reconcile) retries — unknown cleanup is
    never treated as success."""

    __tablename__ = "matches"

    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sessions.session_id"), primary_key=True)
    preset: Mapped[str] = mapped_column(Text, nullable=False)
    duration_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    pace_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    state: Mapped[str] = mapped_column(Text, nullable=False, default="provisioning")
    snapshot: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)
    ready_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    deadline_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    expiry_reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False)


class UptimeSample(Base):
    """Web-uptime probe sample (pilot step 5): IDENTITY-BOUND (session +
    deployment generation + host) and APPEND-ONLY (the app role holds only
    SELECT+INSERT — history cannot be rewritten). 'unknown' is a first-class
    state: unknown/missed checks never award anything and never count as
    downtime."""

    __tablename__ = "uptime_samples"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    session_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True),
                                                  ForeignKey("sessions.session_id"),
                                                  nullable=False)
    deployment_id: Mapped[str] = mapped_column(Text, nullable=False)
    host: Mapped[str] = mapped_column(Text, nullable=False)
    ts: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                         server_default=func.now(), nullable=False)
    state: Mapped[str] = mapped_column(Text, nullable=False)  # up|down|unknown
    latency_ms: Mapped[int | None] = mapped_column(Integer)
    detail: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        Index("ix_uptime_session_ts", "session_id", "ts"),
    )


class DeployOperation(Base):
    """Durable lifecycle-operation record (plan 13 phase 5): identity,
    owner/fence, phase, deadline, progress and outcome are committed
    BEFORE the first side effect, so a browser disconnect, a lost
    response or an API restart can never duplicate a deployment or erase
    the evidence of the first attempt. Mutable operational state (like
    range_lease / operation_claims): transitions are also appended as
    events; rows are never deleted.

    States: accepted -> running -> succeeded | failed; accepted/running
    rows found at startup are reconciled to interrupted (the executor died
    with the process — the range stays owned, the next launch resumes)."""

    __tablename__ = "deploy_operations"

    operation_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sessions.session_id"), nullable=False)
    operation: Mapped[str] = mapped_column(Text, nullable=False)  # launch|reset
    state: Mapped[str] = mapped_column(Text, nullable=False, default="accepted")
    phase: Mapped[str] = mapped_column(Text, nullable=False, default="queued")
    fence: Mapped[str] = mapped_column(Text, nullable=False)  # owner token (T02)
    deadline_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    progress: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    error: Mapped[str | None] = mapped_column(Text)  # redacted, bounded
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class InjectRelease(Base):
    """Versioned inject release (plan 13 phase 6): trusted server-side
    schedule derived from the snapshotted duration; identity-bound,
    idempotent submissions decide ONCE (pending|correct|incorrect|late),
    written work is advisory. Mutable lifecycle state (like
    deploy_operations); every transition is also appended as an event."""

    __tablename__ = "inject_releases"

    release_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sessions.session_id"), nullable=False)
    inject_id: Mapped[str] = mapped_column(Text, nullable=False)  # versioned
    kind: Mapped[str] = mapped_column(Text, nullable=False)       # technical|written
    status: Mapped[str] = mapped_column(Text, nullable=False, default="pending")
    scheduled_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    deadline_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    submissions: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    evidence: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb"))

    __table_args__ = (
        UniqueConstraint("session_id", "inject_id",
                         name="uq_inject_releases_session_inject"),
        Index("ix_inject_releases_session_status", "session_id", "status"),
    )


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


class ModelProfile(Base):
    """Versioned named model profile (plan 19). An edit creates a NEW
    version and demotes the old one (partial unique index: one ACTIVE
    per name); sessions pin a specific version and keep it for their
    whole life. ``api_key`` is the provider credential and lives ONLY
    here — no API response, event payload, log line or export ever
    carries it; every read path must use ``masked()``. Lifecycle only
    mutates (active → retired/revoked): rotation/revocation is a
    visible transition, never an in-place model or key swap."""

    __tablename__ = "model_profiles"

    profile_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(Text, nullable=False, default="active")
    base_url: Mapped[str] = mapped_column(Text, nullable=False)
    model_name: Mapped[str] = mapped_column(Text, nullable=False)
    api_key: Mapped[str] = mapped_column(Text, nullable=False, default="")
    thinking_level: Mapped[str] = mapped_column(Text, nullable=False, default="none")
    thinking_map: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    generation_kwargs: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    context_window: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="262144")
    max_completion_tokens: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="32768")
    timeout_s: Mapped[int] = mapped_column(
        Integer, nullable=False, server_default="900")
    capabilities: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    note: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False)
    retired_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        UniqueConstraint("name", "version", name="uq_model_profiles_name_version"),
        Index("uq_model_profiles_one_active", "name", unique=True,
              postgresql_where=text("status = 'active'")),
    )

    def masked(self) -> dict:
        """The ONLY serialization shape: presence, never value."""
        return {
            "profile_id": str(self.profile_id), "name": self.name,
            "version": self.version, "status": self.status,
            "base_url": self.base_url, "model_name": self.model_name,
            "api_key_set": bool(self.api_key),
            "thinking_level": self.thinking_level,
            "thinking_map": self.thinking_map,
            "generation_kwargs": self.generation_kwargs,
            "context_window": self.context_window,
            "max_completion_tokens": self.max_completion_tokens,
            "timeout_s": self.timeout_s, "capabilities": self.capabilities,
            "note": self.note,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "retired_at": self.retired_at.isoformat() if self.retired_at else None,
        }

    def public_config(self) -> dict:
        """The exact non-secret configuration a session pin freezes."""
        return {
            "name": self.name, "version": self.version,
            "base_url": self.base_url, "model_name": self.model_name,
            "thinking_level": self.thinking_level,
            "thinking_map": self.thinking_map,
            "generation_kwargs": self.generation_kwargs,
            "context_window": self.context_window,
            "max_completion_tokens": self.max_completion_tokens,
            "timeout_s": self.timeout_s,
        }


class ModelRoleOverride(Base):
    """Role → profile-name selection (plan 19). Roles are exactly
    attacker/coach/summarizer; a missing row means the bootstrap
    profile. Selecting a profile never changes global environment
    configuration — overrides live only here."""

    __tablename__ = "model_role_overrides"

    role: Mapped[str] = mapped_column(Text, primary_key=True)
    profile_name: Mapped[str] = mapped_column(Text, nullable=False)
    updated_by: Mapped[str | None] = mapped_column(Text)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False)


class SessionModelPin(Base):
    """The version a session RUNS ON (plan 19): created when the session
    first uses a role, honored for the session's whole life. ``config``
    freezes the exact masked configuration so a generation can state
    what it ran on without re-reading mutable profile state. Replacing
    a pin is an explicit operator rebind (the old version was revoked),
    never an automatic substitution."""

    __tablename__ = "session_model_pins"

    pin_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sessions.session_id"), nullable=False)
    role: Mapped[str] = mapped_column(Text, nullable=False)
    profile_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("model_profiles.profile_id"),
        nullable=False)
    config: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    bound_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        UniqueConstraint("session_id", "role",
                         name="uq_session_model_pins_session_role"),
    )


class ModelJob(Base):
    """Durable record of every model admission (plan 19): primary turns,
    hints, AAR narratives, compaction, probes, tests and visible retry
    attempts are ALL rows, so the ONE slot, the queue state, and the
    obligations of a cancelled-but-possibly-live call survive reloads
    and restarts. The partial unique index on state='running' is the
    database-enforced single admission slot."""

    __tablename__ = "model_jobs"

    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sessions.session_id"))
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, nullable=False)
    # queued | running | succeeded | failed | cancelled | cessation_unknown
    state: Mapped[str] = mapped_column(Text, nullable=False, default="queued")
    profile_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    profile_name: Mapped[str | None] = mapped_column(Text)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    parent_job: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    payload: Mapped[dict] = mapped_column(
        JSONB, nullable=False, server_default=text("'{}'::jsonb"))
    result: Mapped[dict | None] = mapped_column(JSONB)
    error: Mapped[str | None] = mapped_column(Text)
    cancel_requested: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false"))
    actor: Mapped[str | None] = mapped_column(Text)
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        Index("uq_model_jobs_single_running", "state", unique=True,
              postgresql_where=text("state = 'running'")),
        Index("ix_model_jobs_queue", "state", "priority", "requested_at"),
        Index("ix_model_jobs_session", "session_id"),
    )


class ConversationRevision(Base):
    """Append-only structured conversation history (plan 19). ``kind``
    is ``messages`` (a serialized pydantic-AI ModelMessage list — the
    structured turn, tool calls, returns, usage, finish reasons) or
    ``checkpoint`` (a compaction summary that COVERS a revision range —
    it never replaces or deletes history). The DB trigger and grants
    make mutation impossible; a checkpoint therefore cannot hide what
    it compacted, and replay can reconstruct what the model saw."""

    __tablename__ = "conversation_revisions"

    revision_id: Mapped[int] = mapped_column(BigInteger, primary_key=True,
                                             autoincrement=True)
    session_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sessions.session_id"), nullable=False)
    kind: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict] = mapped_column(JSONB, nullable=False)
    profile_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    usage: Mapped[dict | None] = mapped_column(JSONB)
    finish_reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False)

    __table_args__ = (
        Index("ix_conversation_revisions_session", "session_id", "revision_id"),
    )
