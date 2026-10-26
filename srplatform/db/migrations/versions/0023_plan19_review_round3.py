"""plan 19 review ROUND 3 — durable cancellation fence on the logical request.

The third independent review reproduced two HIGH races against the
"one slot" contract:

* cancellation read a QUEUED snapshot without a lock while the scheduler
  claimed and dispatched the same row; the stale write then stamped the
  LIVE row ``cancelled`` — the provider request stayed live while the
  database told everyone the slot had been released (finding 1);
* root cancellation snapshotted the chain while an attempt was live; the
  live call failed definitively and the retry child was CREATED after
  the cancellation committed, so a "cancelled" logical request
  re-spawned a fresh queued attempt (finding 2).

Both are the same missing primitive: a DURABLE cancellation INTENT that
child creation and admission must consult ATOMICALLY, under the row
lock, at every point where the chain could grow or dispatch. This
migration adds two columns — ``model_jobs.cancel_intent`` stamped on
EVERY row of a logical request when it is cancelled, and
``model_jobs.chain_root`` naming the attempt-1 row so the whole logical
request is one index lookup (SQL-side dependency gates and admission
guards need the chain, not one row). Intent is NOT an operational
mutable-state abuse: like ``cancel_requested`` it is a lifecycle
intent, and like the round-2 ``outcome_persisted`` claim it is written
under a conditional/locked protocol so no stale writer can invent or
erase it. ``chain_root`` stays nullable: a NULL dependency is treated
as UNKNOWN and conservatively blocks the gated job (unknown ownership
is never success).

Applied migrations 0020, 0021 and 0022 remain byte-unchanged; this is
purely forward.
"""
from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0023"
down_revision = "0022"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "model_jobs",
        sa.Column("cancel_intent", sa.Boolean(), nullable=False,
                  server_default=sa.false()),
    )
    op.add_column(
        "model_jobs",
        sa.Column("chain_root", sa.UUID(), nullable=True),
    )
    # Backfill existing chains: roots first, then one hop at a time
    # until nothing dangles (retry chains are bounded by MODEL_ATTEMPTS,
    # so the loop is short; the final sweep is a fail-safe, never silent).
    op.execute("UPDATE model_jobs SET chain_root = job_id "
               "WHERE parent_job IS NULL")
    while True:
        result = op.get_bind().execute(sa.text(
            "UPDATE model_jobs j SET chain_root = p.chain_root "
            "  FROM model_jobs p "
            " WHERE j.parent_job = p.job_id AND j.chain_root IS NULL "
            "   AND p.chain_root IS NOT NULL"))
        if result.rowcount == 0:
            break
    op.execute("UPDATE model_jobs SET chain_root = job_id "
               "WHERE chain_root IS NULL")
    op.create_index("ix_model_jobs_chain_root", "model_jobs",
                    ["chain_root"])


def downgrade() -> None:
    op.drop_index("ix_model_jobs_chain_root", table_name="model_jobs")
    op.drop_column("model_jobs", "chain_root")
    op.drop_column("model_jobs", "cancel_intent")
