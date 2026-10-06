"""durable command-operation inventory + claim fencing (audit T01/T02)

* ``run_operations``: every dispatched command's operation identity is
  persisted BEFORE dispatch, associated with its run and deployment
  generation, so the API recovers and cancels remote work after worker
  death through production code (no pidfiles, no test-supplied identity).
* ``operation_claims.owner``: acquire mints an owner token; release is
  fenced so a stale takeover can never erase the replacement's ownership.
* ``uq_runs_one_active_per_session`` now ALSO covers ``cancel-unknown``:
  unconfirmed cessation blocks new runs until recovery confirms quiescence.

Revision ID: 0008
Revises: 0007
"""
from alembic import op
import os
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None

APP_ROLE = os.environ.get("DB_APP_ROLE", "sr_app")


def upgrade() -> None:
    op.create_table(
        "run_operations",
        sa.Column("id", sa.BigInteger(), primary_key=True, autoincrement=True),
        sa.Column("run_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("runs.run_id"), nullable=False),
        sa.Column("session_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("sessions.session_id"), nullable=False),
        sa.Column("deployment_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("op_id", sa.Text(), nullable=False),
        sa.Column("kind", sa.Text(), nullable=False),
        sa.Column("state", sa.Text(), nullable=False, server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(),
                  nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("uq_run_operations_op", "run_operations", ["run_id", "op_id"],
                    unique=True)
    op.create_index("run_operations_active_idx", "run_operations", ["run_id", "state"])
    op.add_column("operation_claims", sa.Column("owner", sa.Text(), nullable=True))
    # 'cancel-unknown' joins the active-run uniqueness predicate
    op.drop_index("uq_runs_one_active_per_session", table_name="runs")
    op.create_index(
        "uq_runs_one_active_per_session", "runs", ["session_id"], unique=True,
        postgresql_where=sa.text(
            "status IN ('queued', 'running', 'stopping', 'cancel-unknown')"),
    )
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON run_operations TO "{APP_ROLE}";')
    # BIGINT identity sequence needs USAGE for the app role (same pattern the
    # other big tables use via 0001/0004)
    op.execute('GRANT USAGE, SELECT ON SEQUENCE run_operations_id_seq TO "' + APP_ROLE + '";')


def downgrade() -> None:
    op.drop_index("uq_runs_one_active_per_session", table_name="runs")
    op.create_index(
        "uq_runs_one_active_per_session", "runs", ["session_id"], unique=True,
        postgresql_where=sa.text("status IN ('queued', 'running', 'stopping')"),
    )
    op.drop_column("operation_claims", "owner")
    op.drop_index("run_operations_active_idx", table_name="run_operations")
    op.drop_index("uq_run_operations_op", table_name="run_operations")
    op.drop_table("run_operations")
