"""pilot step 5: web-uptime samples (append-only, identity-bound)

The app role gets SELECT + INSERT ONLY — samples are history, never
mutable state. Aggregation (score = % up among VALID checks) is computed
at read time; unknown/missed checks award nothing.

Revision ID: 0013
Revises: 0012
"""
from alembic import op
import os
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None

APP_ROLE = os.environ.get("DB_APP_ROLE", "sr_app")


def upgrade() -> None:
    op.create_table(
        "uptime_samples",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("session_id", UUID(as_uuid=True),
                  sa.ForeignKey("sessions.session_id"), nullable=False),
        sa.Column("deployment_id", sa.Text, nullable=False),
        sa.Column("host", sa.Text, nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("state", sa.Text, nullable=False),
        sa.Column("latency_ms", sa.Integer, nullable=True),
        sa.Column("detail", sa.Text, nullable=True),
    )
    op.create_index("ix_uptime_session_ts", "uptime_samples",
                    ["session_id", "ts"])
    op.execute(f'GRANT SELECT, INSERT ON uptime_samples TO "{APP_ROLE}";')
    op.execute('GRANT USAGE, SELECT ON SEQUENCE uptime_samples_id_seq TO "'
               + APP_ROLE + '";')


def downgrade() -> None:
    op.drop_table("uptime_samples")
