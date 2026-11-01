"""plan 20: coach conversation and timed operation output, both append-only.

Two durable evidence surfaces — the same trigger/grants discipline as
``events`` and ``conversation_revisions`` (append-only: SELECT+INSERT +
no-mutation trigger; the app role never gets UPDATE/DELETE):

* ``coach_messages`` — the persistent per-session coach conversation
  (milestone 20). Roles are only ``user`` (the authenticated member
  themselves) and ``coach`` (a model answer that rode a durable job).
  A coach row records the job that produced it, the evidence CUTOFF it
  was generated under, and the event citations it may reference. It is
  conversation, not audit: it never carries verified points, and it is
  never rewritten — corrections append as new messages.

* ``operation_outputs`` — sequence-numbered, timestamped bounded output
  chunks for NEW red-agent command operations, so a later review can
  replay timed attacker output on the session clock. Chunks are
  additive evidence: the final exit/timeout/containment facts stay on
  ``run_operations`` and the ``action_result`` event even when capture
  fails. ``kind`` distinguishes real ``output`` from honestly-marked
  ``gap`` (capture failure / dropped bytes) and ``truncated`` (quota
  reached) markers; unique ``(run_id, op_id, seq)`` makes re-delivery
  idempotent. Historical operations simply have no rows — they are
  rendered as command-only fallback, never reconstructed.

Revision ID: 0025
Revises: 0024
"""
from alembic import op
import os
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0025"
down_revision = "0024"
branch_labels = None
depends_on = None

APP_ROLE = os.environ.get("DB_APP_ROLE", "sr_app")

_APPEND_ONLY_FN = """
CREATE OR REPLACE FUNCTION {name}() RETURNS trigger AS $$
BEGIN
    RAISE EXCEPTION '{table} is append-only: % not allowed', TG_OP;
END;
$$ LANGUAGE plpgsql;
"""

_APPEND_ONLY_TRG = """
CREATE TRIGGER {table}_append_only
BEFORE UPDATE OR DELETE ON {table}
FOR EACH ROW EXECUTE FUNCTION {fn}();
"""


def upgrade() -> None:
    op.create_table(
        "coach_messages",
        sa.Column("message_id", sa.BigInteger, primary_key=True,
                  autoincrement=True),
        sa.Column("session_id", UUID(as_uuid=True),
                  sa.ForeignKey("sessions.session_id"), nullable=False),
        sa.Column("role", sa.Text, nullable=False),
        sa.Column("body", sa.Text, nullable=False),
        sa.Column("citations", JSONB, nullable=True),
        sa.Column("model_job", UUID(as_uuid=True), nullable=True),
        sa.Column("model_ok", sa.Boolean, nullable=True),
        sa.Column("context_cutoff_event_id", sa.BigInteger, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.CheckConstraint("role IN ('user','coach')",
                           name="coach_messages_role_chk"),
    )
    op.create_index("ix_coach_messages_session", "coach_messages",
                    ["session_id", "message_id"])
    op.execute(_APPEND_ONLY_FN.format(name="coach_messages_no_mutation",
                                      table="coach_messages"))
    op.execute(_APPEND_ONLY_TRG.format(table="coach_messages",
                                       fn="coach_messages_no_mutation"))
    op.execute('GRANT SELECT, INSERT ON coach_messages TO "' + APP_ROLE + '";')
    op.execute('GRANT USAGE, SELECT ON SEQUENCE coach_messages_message_id_seq '
               'TO "' + APP_ROLE + '";')

    op.create_table(
        "operation_outputs",
        sa.Column("id", sa.BigInteger, primary_key=True, autoincrement=True),
        sa.Column("run_id", UUID(as_uuid=True),
                  sa.ForeignKey("runs.run_id"), nullable=False),
        sa.Column("session_id", UUID(as_uuid=True),
                  sa.ForeignKey("sessions.session_id"), nullable=False),
        sa.Column("op_id", sa.Text, nullable=False),
        sa.Column("seq", sa.BigInteger, nullable=False),
        sa.Column("ts", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
        sa.Column("kind", sa.Text, nullable=False, server_default="output"),
        sa.Column("text", sa.Text, nullable=True),
        sa.Column("dropped_bytes", sa.BigInteger, nullable=True),
        sa.CheckConstraint("kind IN ('output','gap','truncated')",
                           name="operation_outputs_kind_chk"),
    )
    op.create_index("uq_operation_outputs_op_seq", "operation_outputs",
                    ["run_id", "op_id", "seq"], unique=True)
    op.create_index("ix_operation_outputs_session", "operation_outputs",
                    ["session_id", "op_id", "seq"])
    op.execute(_APPEND_ONLY_FN.format(name="operation_outputs_no_mutation",
                                      table="operation_outputs"))
    op.execute(_APPEND_ONLY_TRG.format(table="operation_outputs",
                                       fn="operation_outputs_no_mutation"))
    op.execute('GRANT SELECT, INSERT ON operation_outputs TO "'
               + APP_ROLE + '";')
    op.execute('GRANT USAGE, SELECT ON SEQUENCE operation_outputs_id_seq '
               'TO "' + APP_ROLE + '";')


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS operation_outputs_append_only "
               "ON operation_outputs;")
    op.execute("DROP FUNCTION IF EXISTS operation_outputs_no_mutation();")
    op.drop_table("operation_outputs")
    op.execute("DROP TRIGGER IF EXISTS coach_messages_append_only "
               "ON coach_messages;")
    op.execute("DROP FUNCTION IF EXISTS coach_messages_no_mutation();")
    op.drop_table("coach_messages")
