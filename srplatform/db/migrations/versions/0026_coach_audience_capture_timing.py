"""coach audiences + capture read timestamps + truncation-marker uniqueness

Independent review of 28b1f8b (MILESTONE20, VERDICT: FIX):

* finding 1 (HIGH): one coach conversation was shared across audiences,
  so an operator answer carrying sealed red evidence was returned to a
  member AND entered the member's next provider prompt. Every persisted
  coach message now carries an immutable audience ('member' |
  'operator'); the default preserves existing rows as member history.
* finding 3 (HIGH): the server charged quota only for non-empty output
  text, so gap/marker rows were unbounded, and two concurrent
  truncations could both persist a marker. A unique partial index makes
  "one truncation marker per operation" a database fact.
* finding 10 (MEDIUM): merged pipe reads inherited one persist time;
  each row now records the observed read timestamp when the runner
  measured one.

Revision ID: 0026
Revises: 0025
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0026"
down_revision = "0025"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "coach_messages",
        sa.Column("audience", sa.Text(), nullable=False,
                  server_default="member"),
    )
    op.create_index(
        "ix_coach_messages_session_audience", "coach_messages",
        ["session_id", "audience"],
    )

    op.add_column(
        "operation_outputs",
        sa.Column("read_ts", sa.Float(), nullable=True,
                  comment="wall-clock seconds (time.time) when the bytes "
                          "were READ from the child pipe; independent of "
                          "persist time; NULL = not observed (finding 10)"),
    )

    op.create_index(
        "uq_operation_outputs_truncated_once", "operation_outputs",
        ["run_id", "op_id"],
        unique=True,
        postgresql_where=sa.text("kind = 'truncated'"),
    )


def downgrade() -> None:
    op.drop_index("uq_operation_outputs_truncated_once",
                  table_name="operation_outputs")
    op.drop_column("operation_outputs", "read_ts")
    op.drop_index("ix_coach_messages_session_audience",
                  table_name="coach_messages")
    op.drop_column("coach_messages", "audience")
