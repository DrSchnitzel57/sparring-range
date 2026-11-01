"""fail-closed legacy coach history + legacy-safe truncation-marker guard

Second independent review of ``adc10d4`` (milestone-21 pulled blockers):

* F1 (HIGH): 0026 backfilled EVERY pre-existing coach message to
  ``audience='member'`` via ``server_default``, silently publishing old
  OPERATOR history (which may carry sealed red evidence) to members.
  This migration re-labels all rows existing at migration time to the
  fail-closed ``'legacy'`` audience: never member-visible, never part of
  a provider prompt, renderable only in the privileged (operator) thread
  explicitly marked as legacy. No row is deleted or rewritten otherwise.
* F3 (HIGH): 0025 permitted (pre-fix race) two ``truncated`` marker rows
  for one operation, and 0026's unique partial index cannot be created
  over such data. Applied 0026 is immutable and must stay byte-identical.
  This migration is the FORWARD half of the supported compatibility
  path (the upgrade engine performs the explicit prerequisite — see
  ARCHITECTURE "Plan-21 upgrade-compatibility decisions"): it re-applies
  0026's column/index effects IDEMPOTENTLY (so a database whose upgrade
  skipped only 0026's data-dependent index statement ends with the same
  columns), and it installs the forward uniqueness guard — one
  truncation marker per operation for every marker written AT OR AFTER
  this migration, enforced by the database, while legacy duplicate rows
  remain untouched and readable.

Revision ID: 0027
Revises: 0026
"""
from __future__ import annotations

import datetime

import sqlalchemy as sa
from alembic import op

revision = "0027"
down_revision = "0026"
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()

    # ---- F3 forward half: idempotent catch-up of 0026's effects. -------- #
    # The supported upgrade path skips ONLY 0026's data-dependent unique
    # index when the legacy data provably violates it (the engine proves
    # the condition and records it); everything 0026 would have created
    # that the data can hold is ensured here, so both paths converge on
    # the same columns. IF NOT EXISTS makes this a no-op on every
    # database where 0026 ran normally.
    bind.execute(sa.text(
        "ALTER TABLE coach_messages ADD COLUMN IF NOT EXISTS audience "
        "text NOT NULL DEFAULT 'member'"))
    bind.execute(sa.text(
        "CREATE INDEX IF NOT EXISTS ix_coach_messages_session_audience "
        "ON coach_messages (session_id, audience)"))
    bind.execute(sa.text(
        "ALTER TABLE operation_outputs ADD COLUMN IF NOT EXISTS "
        "read_ts double precision"))

    # ---- F1: unknown audience fails closed, never silently member. ----- #
    # Every row that exists at migration time predates per-message
    # audience truth; its real audience is unknowable, so it is neither
    # member-visible nor deleted. Fresh installs have no rows here.
    #
    # The 0025 append-only trigger protects RUNTIME mutation of coach
    # history; this one relabel is schema maintenance performed by the
    # migration itself, so it is bracketed EXPLICITLY (never a silent
    # bypass): disable the trigger, fail the whole step closed, relabel,
    # re-enable. The trigger is back in force before this transaction
    # commits; no UPDATE other than this relabel ever touched the table.
    bind.execute(sa.text(
        "ALTER TABLE coach_messages "
        "DISABLE TRIGGER coach_messages_append_only"))
    try:
        bind.execute(sa.text(
            "UPDATE coach_messages SET audience = 'legacy' "
            "WHERE audience = 'member'"))
    finally:
        bind.execute(sa.text(
            "ALTER TABLE coach_messages "
            "ENABLE TRIGGER coach_messages_append_only"))

    # ---- F3: the future-proof guard that legacy rows still satisfy. ---- #
    # One truncation marker per (run, op) for every marker persisted at
    # or after this instant; legacy duplicates are excluded by time, not
    # touched. Post-upgrade writers can never create a new duplicate —
    # and the server-side quota admission (finding F2) rejects a second
    # marker long before the database has to.
    cutoff = datetime.datetime.now(datetime.timezone.utc)
    bind.execute(sa.text(
        "CREATE UNIQUE INDEX IF NOT EXISTS "
        "uq_op_outputs_truncated_once_forward "
        "ON operation_outputs (run_id, op_id) "
        "WHERE kind = 'truncated' AND ts >= "
        f"'{cutoff.isoformat(sep=' ')}'::timestamptz"))


def downgrade() -> None:
    # Reverse of the FORWARD delta only. The audience relabel is
    # deliberately NOT reversed: 'legacy' means "audience unknown", and
    # rewriting it back to 'member' would RECREATE the F1 leak.
    bind = op.get_bind()
    bind.execute(sa.text(
        "DROP INDEX IF EXISTS uq_op_outputs_truncated_once_forward"))
