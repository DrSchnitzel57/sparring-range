"""plan 13 phase 5: durable lifecycle-operation records.

One row per launch/reset attempt: identity, owner fence, phase, deadline,
progress and outcome committed BEFORE the first side effect. Startup
reconciles accepted/running rows to `interrupted` — the executor died with
the process; the range stays owned and the next launch resumes. Rows are
never deleted (history of every attempt). Operational mutable state, like
range_lease / operation_claims.

Revision ID: 0014
Revises: 0013
"""
from alembic import op
import os
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None

APP_ROLE = os.environ.get("DB_APP_ROLE", "sr_app")


def upgrade() -> None:
    op.create_table(
        "deploy_operations",
        sa.Column("operation_id", UUID(as_uuid=True), primary_key=True),
        sa.Column("session_id", UUID(as_uuid=True),
                  sa.ForeignKey("sessions.session_id"), nullable=False),
        sa.Column("operation", sa.Text, nullable=False),
        sa.Column("state", sa.Text, nullable=False, server_default="accepted"),
        sa.Column("phase", sa.Text, nullable=False, server_default="queued"),
        sa.Column("fence", sa.Text, nullable=False),
        sa.Column("deadline_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("progress", JSONB, nullable=False,
                  server_default=sa.text("'{}'::jsonb")),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True),
                  server_default=sa.text("now()"), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    # polling: latest operation for a session; startup reconcile scans state
    op.create_index("ix_deploy_operations_session_created",
                    "deploy_operations", ["session_id", "created_at"])
    op.create_index("ix_deploy_operations_state", "deploy_operations",
                    ["state"])
    op.execute(f'GRANT SELECT, INSERT, UPDATE ON deploy_operations '
               f'TO "{APP_ROLE}";')


def downgrade() -> None:
    op.drop_table("deploy_operations")
