"""plan 13 phase 6: versioned inject releases.

Trusted server-side schedule (release/deadline derived from the
snapshotted duration), identity-bound idempotent submissions, and
deterministic technical verification state. Mutable operational
lifecycle state; transitions are additionally appended as events.

Revision ID: 0015
Revises: 0014
"""
from alembic import op
import os
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None

APP_ROLE = os.environ.get("DB_APP_ROLE", "sr_app")


def upgrade() -> None:
    op.create_table(
        "inject_releases",
        sa.Column("release_id", UUID(as_uuid=True), primary_key=True),
        sa.Column("session_id", UUID(as_uuid=True),
                  sa.ForeignKey("sessions.session_id"), nullable=False),
        sa.Column("inject_id", sa.Text, nullable=False),
        sa.Column("kind", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False, server_default="pending"),
        sa.Column("scheduled_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("submitted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("submissions", sa.Integer, nullable=False, server_default="0"),
        sa.Column("evidence", JSONB, nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.UniqueConstraint("session_id", "inject_id",
                            name="uq_inject_releases_session_inject"),
    )
    op.create_index("ix_inject_releases_session_status", "inject_releases",
                    ["session_id", "status"])
    op.execute(f'GRANT SELECT, INSERT, UPDATE ON inject_releases '
               f'TO "{APP_ROLE}";')


def downgrade() -> None:
    op.drop_table("inject_releases")
