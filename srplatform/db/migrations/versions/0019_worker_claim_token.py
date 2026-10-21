"""separate claim credential for the worker supervisor (milestone 15)

The supervisor's callbacks (assign, heartbeat, failure, stop) must be fenced
by the credential it was given when it CLAIMED the run.  Without a second
credential the worker's own one-shot run token was used for both, and an
obsolete claimant — whose claim was already reclaimed and its token rotated —
could still assign, heartbeat and overwrite a terminal state.

This revision adds ``worker_claim_token``: the hash of the supervisor's
claim credential, distinct from the worker's own run capability.

Revision ID: 0019
Revises: 0018
"""
from alembic import op
import sqlalchemy as sa

revision = "0019"
down_revision = "0018"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("runs", sa.Column("worker_claim_token", sa.Text(),
                                    nullable=True))


def downgrade() -> None:
    op.drop_column("runs", "worker_claim_token")
