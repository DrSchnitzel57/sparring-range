"""worker supervisor heartbeat (milestone 15)

The API no longer spawns production workers: a separate-UID supervisor
claims a durable queued run and owns the child process group. The API
records supervisor heartbeats so a dead supervisor is visible to
reconciliation without giving the API authority to signal a foreign UID.

Revision ID: 0018
Revises: 0017
"""
from alembic import op
import sqlalchemy as sa

revision = "0018"
down_revision = "0017"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("runs", sa.Column("worker_heartbeat_at",
                                    sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("runs", "worker_heartbeat_at")
