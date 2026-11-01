"""durable lab aggregate + membership + reset plans (Underpressure plan)

Forward-only. Adds the durable environment aggregate (`labs`), per-guest
owned generations (`lab_guests`), timestamped team membership
(`lab_members`), and versioned destructive-reset records
(`lab_reset_plans`); `sessions.lab_id` (nullable) lets exercise sessions
bind to a lab without reinterpreting any existing row. No existing table
is modified beyond that additive nullable column.

Revision ID: 0029
Revises: 0028
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0029"
down_revision = "0028"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "labs",
        sa.Column("lab_id", UUID(as_uuid=True), primary_key=True),
        sa.Column("environment_id", sa.Text, nullable=False),
        sa.Column("pins", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("owner_id", UUID(as_uuid=True),
                  sa.ForeignKey("users.user_id"), nullable=True),
        sa.Column("state", sa.Text, nullable=False, server_default="provisioning"),
        sa.Column("power", sa.Text, nullable=False, server_default="on"),
        sa.Column("reservation", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_labs_state", "labs", ["state"])
    op.create_index("ix_labs_environment", "labs", ["environment_id"])

    op.create_table(
        "lab_guests",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("lab_id", UUID(as_uuid=True), sa.ForeignKey("labs.lab_id"),
                  nullable=False),
        sa.Column("guest", sa.Text, nullable=False),
        sa.Column("generation", sa.Integer, nullable=False, server_default="1"),
        sa.Column("state", sa.Text, nullable=False, server_default="pending"),
        sa.Column("resource", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.UniqueConstraint("lab_id", "guest", name="uq_lab_guests_lab_guest"),
    )

    op.create_table(
        "lab_members",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("lab_id", UUID(as_uuid=True), sa.ForeignKey("labs.lab_id"),
                  nullable=False),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.user_id"),
                  nullable=False),
        sa.Column("role", sa.Text, nullable=False, server_default="member"),
        sa.Column("added_by", UUID(as_uuid=True), sa.ForeignKey("users.user_id"),
                  nullable=True),
        sa.Column("added_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("removed_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint("lab_id", "user_id", name="uq_lab_members_lab_user"),
    )

    op.create_table(
        "lab_reset_plans",
        sa.Column("plan_id", UUID(as_uuid=True), primary_key=True),
        sa.Column("lab_id", UUID(as_uuid=True), sa.ForeignKey("labs.lab_id"),
                  nullable=False),
        sa.Column("requested_by", UUID(as_uuid=True), sa.ForeignKey("users.user_id"),
                  nullable=True),
        sa.Column("request", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("plan", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("status", sa.Text, nullable=False, server_default="proposed"),
        sa.Column("approved_by", UUID(as_uuid=True), sa.ForeignKey("users.user_id"),
                  nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.func.now()),
    )

    # additive, nullable: existing sessions stay NULL and unchanged
    with op.batch_alter_table("sessions") as batch:
        batch.add_column(sa.Column("lab_id", UUID(as_uuid=True),
                                   sa.ForeignKey("labs.lab_id"), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("sessions") as batch:
        batch.drop_column("lab_id")
    op.drop_table("lab_reset_plans")
    op.drop_table("lab_members")
    op.drop_table("lab_guests")
    op.drop_index("ix_labs_environment", table_name="labs")
    op.drop_index("ix_labs_state", table_name="labs")
    op.drop_table("labs")
