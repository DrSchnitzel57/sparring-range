"""plan 19: versioned model profiles, pins, jobs and conversation history.

Model administration replaces "one env-configured endpoint" with named,
VERSIONED profiles (endpoint/model/key/thinking/generation kwargs), a
per-role override map, and a per-session PIN recorded when the session
first uses a role: the profile version that begins a session is the
version that serves it — rotation or revocation can only invalidate
(honorarily, visibly), never silently swap what a running session uses.

* ``model_profiles`` — immutable versioned rows; edits create a new
  version (``(name, version)`` unique) and demote the old one. The API
  key lives ONLY here (the API is the sole identity allowed to hold it);
  every read path masks it. Mutable only in its lifecycle column
  (active → retired/revoked), which is why grants omit DELETE.
* ``model_role_overrides`` / ``session_model_pins`` — role → profile
  name selection and the immutable exact-config snapshot a generation
  records. Pins are created once per (session, role); replacement is an
  explicit operator rebind, never an automatic substitution.
* ``model_jobs`` — the durable record behind the ONE admission slot:
  every primary/aux/probe/generation/retry call is a row, so queue
  state, cancellation and unknown-cessation obligations survive reloads
  and process restarts. A partial UNIQUE index enforces at the DATABASE
  level what the gateway enforces in-process: at most one job RUNNING.
* ``conversation_revisions`` — append-only structured history and
  checkpoints (the same trigger pattern as ``events``): a checkpoint
  never replaces history, it covers a range of it.

Grants honour 0017's narrowed defaults: append-only stays
SELECT+INSERT (plus the no-mutation trigger), mutable operational
tables get UPDATE explicitly, nothing gets DELETE.

Revision ID: 0020
Revises: 0019
"""
from alembic import op
import os
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0020"
down_revision = "0019"
branch_labels = None
depends_on = None

APP_ROLE = os.environ.get("DB_APP_ROLE", "sr_app")


def upgrade() -> None:
    op.create_table(
        "model_profiles",
        sa.Column("profile_id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("version", sa.Integer, nullable=False),
        sa.Column("status", sa.Text, nullable=False, server_default="active"),
        sa.Column("base_url", sa.Text, nullable=False),
        sa.Column("model_name", sa.Text, nullable=False),
        # The provider credential. NEVER serialized by any API surface,
        # log line or export — the API resolves it only at call time.
        sa.Column("api_key", sa.Text, nullable=False, server_default=""),
        sa.Column("thinking_level", sa.Text, nullable=False,
                  server_default="none"),
        sa.Column("thinking_map", JSONB, nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("generation_kwargs", JSONB, nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("context_window", sa.Integer, nullable=False,
                  server_default="262144"),
        sa.Column("max_completion_tokens", sa.Integer, nullable=False,
                  server_default="32768"),
        sa.Column("timeout_s", sa.Integer, nullable=False,
                  server_default="900"),
        sa.Column("capabilities", JSONB, nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("note", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("name", "version",
                            name="uq_model_profiles_name_version"),
    )
    # Exactly one ACTIVE version per profile name — creating a version
    # and demoting its predecessor is one visible transition.
    op.execute(
        "CREATE UNIQUE INDEX uq_model_profiles_one_active "
        "ON model_profiles (name) WHERE status = 'active';")
    op.create_index("ix_model_profiles_name", "model_profiles", ["name"])
    op.execute(f'GRANT SELECT, INSERT, UPDATE ON model_profiles '
               f'TO "{APP_ROLE}";')

    op.create_table(
        "model_role_overrides",
        sa.Column("role", sa.Text, primary_key=True),
        sa.Column("profile_name", sa.Text, nullable=False),
        sa.Column("updated_by", sa.Text, nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    op.execute(f'GRANT SELECT, INSERT, UPDATE ON model_role_overrides '
               f'TO "{APP_ROLE}";')

    op.create_table(
        "session_model_pins",
        sa.Column("pin_id", UUID(as_uuid=True), primary_key=True),
        sa.Column("session_id", UUID(as_uuid=True),
                  sa.ForeignKey("sessions.session_id"), nullable=False),
        sa.Column("role", sa.Text, nullable=False),
        sa.Column("profile_id", UUID(as_uuid=True),
                  sa.ForeignKey("model_profiles.profile_id"),
                  nullable=False),
        # The EXACT configuration the pin freezes (masked — no key), so
        # every generation can state what it ran on without re-reading
        # mutable profile state.
        sa.Column("config", JSONB, nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("bound_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.UniqueConstraint("session_id", "role",
                            name="uq_session_model_pins_session_role"),
    )
    op.execute(f'GRANT SELECT, INSERT, UPDATE ON session_model_pins '
               f'TO "{APP_ROLE}";')

    op.create_table(
        "model_jobs",
        sa.Column("job_id", UUID(as_uuid=True), primary_key=True),
        sa.Column("session_id", UUID(as_uuid=True),
                  sa.ForeignKey("sessions.session_id"), nullable=True),
        sa.Column("kind", sa.Text, nullable=False),
        sa.Column("priority", sa.Integer, nullable=False),
        sa.Column("state", sa.Text, nullable=False, server_default="queued"),
        sa.Column("profile_id", UUID(as_uuid=True), nullable=True),
        sa.Column("profile_name", sa.Text, nullable=True),
        sa.Column("attempt", sa.Integer, nullable=False,
                  server_default="1"),
        sa.Column("parent_job", UUID(as_uuid=True), nullable=True),
        sa.Column("payload", JSONB, nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("result", JSONB, nullable=True),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("cancel_requested", sa.Boolean, nullable=False,
                  server_default=sa.text("false")),
        sa.Column("actor", sa.Text, nullable=True),
        sa.Column("requested_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
    )
    # The single model slot, enforced by the DATABASE: a second RUNNING
    # row cannot commit, in any process. A cancellation whose provider
    # call may still be live stays 'cessation_unknown' — the obligation
    # outlives the row's active life and is never silently deleted.
    op.execute(
        "CREATE UNIQUE INDEX uq_model_jobs_single_running "
        "ON model_jobs (state) WHERE state = 'running';")
    op.create_index("ix_model_jobs_queue", "model_jobs",
                    ["state", "priority", "requested_at"])
    op.create_index("ix_model_jobs_session", "model_jobs", ["session_id"])
    op.execute(f'GRANT SELECT, INSERT, UPDATE ON model_jobs '
               f'TO "{APP_ROLE}";')

    op.create_table(
        "conversation_revisions",
        sa.Column("revision_id", sa.BigInteger, primary_key=True,
                  autoincrement=True),
        sa.Column("session_id", UUID(as_uuid=True),
                  sa.ForeignKey("sessions.session_id"), nullable=False),
        sa.Column("kind", sa.Text, nullable=False),
        sa.Column("payload", JSONB, nullable=False),
        sa.Column("profile_id", UUID(as_uuid=True), nullable=True),
        sa.Column("usage", JSONB, nullable=True),
        sa.Column("finish_reason", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION conversation_revisions_no_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'conversation_revisions is append-only: % not allowed', TG_OP;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER conversation_revisions_append_only
        BEFORE UPDATE OR DELETE ON conversation_revisions
        FOR EACH ROW EXECUTE FUNCTION conversation_revisions_no_mutation();
        """
    )
    op.create_index("ix_conversation_revisions_session",
                    "conversation_revisions", ["session_id", "revision_id"])
    # 0017's default (SELECT, INSERT) is exactly right; the sequence is
    # all that must be granted explicitly.
    op.execute('GRANT USAGE, SELECT ON SEQUENCE '
               'conversation_revisions_revision_id_seq TO "' + APP_ROLE + '";')


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS conversation_revisions_append_only "
               "ON conversation_revisions;")
    op.execute("DROP FUNCTION IF EXISTS conversation_revisions_no_mutation();")
    op.drop_table("conversation_revisions")
    op.drop_table("model_jobs")
    op.drop_table("session_model_pins")
    op.drop_table("model_role_overrides")
    op.drop_table("model_profiles")
