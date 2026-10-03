"""initial schema — users, sessions, events (append-only), agent_state, login_tokens

Revision ID: 0001
Revises:
Create Date: 2026-10-03

Append-only enforcement (hard constraint #4 / Part 4.2):
  * RAISE trigger on UPDATE/DELETE of events (belt),
  * role-level revocation of UPDATE/DELETE for the application role (braces).
"""
from alembic import op
import os
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

APP_ROLE = os.environ.get("DB_APP_ROLE", "sr_app")


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("user_id", UUID(as_uuid=True), primary_key=True),
        sa.Column("username", sa.Text, unique=True, nullable=False),
        sa.Column("display_name", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    op.create_table(
        "sessions",
        sa.Column("session_id", UUID(as_uuid=True), primary_key=True),
        sa.Column("scenario_id", sa.Text, nullable=False),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.user_id")),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True)),
        sa.Column("status", sa.Text, nullable=False, server_default="running"),
        sa.Column("players", JSONB),
    )

    op.create_table(
        "events",
        sa.Column("event_id", sa.BigInteger, primary_key=True),
        sa.Column("session_id", UUID(as_uuid=True), sa.ForeignKey("sessions.session_id")),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ingested_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("actor", sa.Text, nullable=False),
        sa.Column("host", sa.Text),
        sa.Column("action_type", sa.Text, nullable=False),
        sa.Column("phase", sa.Text),
        sa.Column("mitre_technique", sa.Text),
        sa.Column("payload", JSONB, nullable=False),
        sa.Column("raw_ref", sa.Text),
        sa.Column("raw_output_hash", sa.Text),
    )
    op.create_index("events_session_ts_idx", "events", ["session_id", "ts"])
    op.create_index("events_action_type_idx", "events", ["action_type"])

    op.create_table(
        "agent_state",
        sa.Column("session_id", UUID(as_uuid=True), sa.ForeignKey("sessions.session_id"), primary_key=True),
        sa.Column("summary", sa.Text),
        sa.Column("summary_upto", sa.BigInteger),
        sa.Column("current_phase", sa.Text),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )

    op.create_table(
        "login_tokens",
        sa.Column("token", sa.Text, primary_key=True),
        sa.Column("session_id", UUID(as_uuid=True), sa.ForeignKey("sessions.session_id")),
        sa.Column("target_host", sa.Text, nullable=False),
        sa.Column("target_port", sa.BigInteger, nullable=False, server_default="22"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
    )

    # --- Append-only enforcement (Part 4.2) --------------------------------
    op.execute(
        """
        CREATE OR REPLACE FUNCTION events_no_mutation() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'events is append-only: % not allowed (hard constraint #4)', TG_OP;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER events_append_only
        BEFORE UPDATE OR DELETE ON events
        FOR EACH ROW EXECUTE FUNCTION events_no_mutation();
        """
    )

    # Role-level defense: the app role can read and insert, nothing else on events.
    op.execute(f'GRANT USAGE ON SCHEMA public TO "{APP_ROLE}";')
    op.execute(f'GRANT SELECT, INSERT ON events TO "{APP_ROLE}";')
    op.execute(f'GRANT SELECT ON users, sessions, agent_state TO "{APP_ROLE}";')
    # The app role writes agent_state through the API; give it insert/update there
    # (agent_state is mutable working memory, NOT the immutable log).
    op.execute(f'GRANT UPDATE ON agent_state TO "{APP_ROLE}";')
    op.execute(f'GRANT SELECT, INSERT, UPDATE ON login_tokens TO "{APP_ROLE}";')
    op.execute(f'GRANT SELECT, INSERT ON users, sessions TO "{APP_ROLE}";')
    # Explicitly ensure no UPDATE/DELETE on the log for the app role.
    op.execute(f'REVOKE UPDATE, DELETE ON events FROM "{APP_ROLE}";')
    op.execute('GRANT USAGE, SELECT ON SEQUENCE events_event_id_seq TO "' + APP_ROLE + '";')


def downgrade() -> None:
    op.drop_table("login_tokens")
    op.drop_table("agent_state")
    op.execute("DROP TRIGGER IF EXISTS events_append_only ON events;")
    op.execute("DROP FUNCTION IF EXISTS events_no_mutation();")
    op.drop_index("events_action_type_idx", table_name="events")
    op.drop_index("events_session_ts_idx", table_name="events")
    op.drop_table("events")
    op.drop_table("sessions")
    op.drop_table("users")
