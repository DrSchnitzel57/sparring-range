"""run process-group identity (audit R03)

Adds ``runs.pgid_pstart`` — the recorded start time (proc clock ticks) of the
worker process-group leader. A stored numeric PGID says nothing about WHICH
process occupies it after a restart; termination refuses to signal a group
whose leader identity does not match, closing the PID/PGID-reuse hole.

Revision ID: 0006
Revises: 0005
"""
from alembic import op
import sqlalchemy as sa

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("runs", sa.Column("pgid_pstart", sa.BigInteger(), nullable=True))


def downgrade() -> None:
    op.drop_column("runs", "pgid_pstart")
