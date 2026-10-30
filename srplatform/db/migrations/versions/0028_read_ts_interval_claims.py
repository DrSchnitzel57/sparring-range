"""per-operation read_ts intervals + honest timing claims (plan 22 review)

Item 8 (MEDIUM): ingest previously accepted ANY worker timing claim
inside a 400-day wall window around server time — a fresh operation could
store a "read" instant from six months ago and replay would happily place
it. The server now adjudicates every claim against the operation's own
lifetime (registration to end, ± a documented 300 s clock-skew allowance):
accepted claims populate ``read_ts``; rejected ones are KEPT VERBATIM in
``read_ts_claim`` with a status, so idempotence compares what the worker
actually sent and the surface can state honestly why a chunk is placed at
persist time instead.

Rows written under the old weak window are not re-adjudicated (the
operation's interval at CLAIM time cannot be reconstructed retroactively
from here) — they are labelled ``legacy-window-accepted`` /
``legacy-unknown``, which is honest about what is known. Append-only is
respected: the single relabel is bracketed explicitly on the append-only
trigger, exactly like migration 0027's coach relabel.

Revision ID: 0028
Revises: 0027
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0028"
down_revision = "0027"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    bind.execute(sa.text(
        "ALTER TABLE operation_outputs ADD COLUMN IF NOT EXISTS "
        "read_ts_claim double precision"))
    bind.execute(sa.text(
        "ALTER TABLE operation_outputs ADD COLUMN IF NOT EXISTS "
        "read_ts_status text"))

    # The one relabel the append-only table ever receives, bracketed
    # EXPLICITLY (disable, work, re-enable inside this transaction —
    # never a silent bypass).
    bind.execute(sa.text(
        "ALTER TABLE operation_outputs "
        "DISABLE TRIGGER operation_outputs_append_only"))
    try:
        bind.execute(sa.text(
            "UPDATE operation_outputs SET "
            "  read_ts_claim = CASE WHEN read_ts IS NOT NULL "
            "                        THEN read_ts ELSE read_ts_claim END, "
            "  read_ts_status = CASE WHEN read_ts IS NOT NULL "
            "      THEN 'legacy-window-accepted' "
            "      ELSE 'legacy-unknown' END "
            "WHERE read_ts_status IS NULL"))
    finally:
        bind.execute(sa.text(
            "ALTER TABLE operation_outputs "
            "ENABLE TRIGGER operation_outputs_append_only"))


def downgrade() -> None:
    # Dropping the columns also drops the honest labels they carry; the
    # adjudicated ``read_ts`` values themselves are untouched.
    bind = op.get_bind()
    bind.execute(sa.text(
        "ALTER TABLE operation_outputs DROP COLUMN IF EXISTS read_ts_status"))
    bind.execute(sa.text(
        "ALTER TABLE operation_outputs DROP COLUMN IF EXISTS read_ts_claim"))
