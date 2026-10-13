"""pilot step 4: minimal durable match lifecycle (preset/30min/pace snapshot)

One `matches` row per session, created at session creation: the effective
preset, match duration and attack pace are SNAPSHOT there (never re-read
live). Server-clock lifecycle: Begin binds started_at/deadline_at; ready-but-
unstarted labs expire after 15 minutes; end/expiry finalize + destroy owned
VMs + release the lease; an API restart interrupts, never resumes.

Operational lifecycle state (like range_lease / operation_claims): mutable
by design, every transition also appends an append-only event. The app role
needs SELECT/INSERT/UPDATE — rows are never deleted (history of every match
remains).

Revision ID: 0012
Revises: 0011
"""
from alembic import op
import os
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None

APP_ROLE = os.environ.get("DB_APP_ROLE", "sr_app")


def upgrade() -> None:
    op.create_table(
        "matches",
        sa.Column("session_id", UUID(as_uuid=True),
                  sa.ForeignKey("sessions.session_id"), primary_key=True),
        sa.Column("preset", sa.Text, nullable=False),
        sa.Column("duration_minutes", sa.Integer, nullable=False,
                  server_default="30"),
        sa.Column("pace_seconds", sa.Integer, nullable=False,
                  server_default="30"),
        sa.Column("state", sa.Text, nullable=False, server_default="provisioning"),
        sa.Column("snapshot", JSONB, nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("ready_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expiry_reason", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
    )
    # scheduler scans by state (idle-ready expiry, deadline expiry, retry)
    op.create_index("ix_matches_state_deadline", "matches",
                    ["state", "deadline_at"])
    op.execute(f'GRANT SELECT, INSERT, UPDATE ON matches TO "{APP_ROLE}";')


def downgrade() -> None:
    op.drop_table("matches")
