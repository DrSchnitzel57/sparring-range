"""fourth-follow-up acceptance blockers (audit T-04 / T-05)

* ``run_operations.detail``: the truthful containment verdict of an operation
  (surviving-descendant containment, unconfirmed-stop reason) is RETAINED in
  the durable inventory, not only in the event log.
* ``service_tokens`` enrollment evidence: a fresh ``enroll_nonce`` issued
  with the capability, the deployment generation it belongs to, and two
  DISTINCT confirmation timestamps — the authenticated callback FROM THE
  PROVISIONED HOST (delivery) and the first audit event observed THROUGH THE
  INSTALLED SERVICE (capture). ``systemctl is-active`` proves neither.

Revision ID: 0009
Revises: 0008
"""
from alembic import op
import os
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None

APP_ROLE = os.environ.get("DB_APP_ROLE", "sr_app")


def upgrade() -> None:
    op.add_column("run_operations", sa.Column("detail", sa.Text(), nullable=True))
    op.add_column("service_tokens", sa.Column("enroll_nonce", sa.Text(), nullable=True))
    op.add_column("service_tokens", sa.Column("enrollment_deployment_id",
                                              postgresql.UUID(as_uuid=True), nullable=True))
    op.add_column("service_tokens", sa.Column("enroll_confirmed_at",
                                              sa.DateTime(timezone=True), nullable=True))
    op.add_column("service_tokens", sa.Column("enroll_capture_at",
                                              sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column("service_tokens", "enroll_capture_at")
    op.drop_column("service_tokens", "enroll_confirmed_at")
    op.drop_column("service_tokens", "enrollment_deployment_id")
    op.drop_column("service_tokens", "enroll_nonce")
    op.drop_column("run_operations", "detail")
