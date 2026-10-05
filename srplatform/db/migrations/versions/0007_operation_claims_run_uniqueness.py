"""durable operation claims + database-enforced active-run uniqueness (audit N02)

* ``operation_claims``: one row per session; lifecycle operations (launch /
  deploy / reset / teardown / end) serialize on this COMMITTED row, because
  the intent commits deployment correctness requires release ordinary row
  locks. Startup reconciliation clears claims (single-API architecture).
* ``uq_runs_one_active_per_session``: partial unique index — a select-then-
  insert duplicate check races, the database does not. Concurrent /run
  requests resolve to exactly one active run.

Revision ID: 0007
Revises: 0006
"""
from alembic import op
import os
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None

APP_ROLE = os.environ.get("DB_APP_ROLE", "sr_app")


def upgrade() -> None:
    op.create_table(
        "operation_claims",
        sa.Column("session_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("sessions.session_id"), primary_key=True),
        sa.Column("operation", sa.Text(), nullable=False),
        sa.Column("claimed_at", sa.DateTime(timezone=True), server_default=sa.func.now(),
                  nullable=False),
    )
    op.create_index(
        "uq_runs_one_active_per_session", "runs", ["session_id"], unique=True,
        postgresql_where=sa.text("status IN ('queued', 'running', 'stopping')"),
    )
    # lifecycle claim acquire/release needs DML (same minimal-grant pattern as
    # 0004; the append-only revocations on events stay untouched)
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON operation_claims TO "{APP_ROLE}";')


def downgrade() -> None:
    op.drop_index("uq_runs_one_active_per_session", table_name="runs")
    op.drop_table("operation_claims")
