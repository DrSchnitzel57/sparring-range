"""web_tokens + v_session_scores (M7).

The progress dashboard is a VIEW (a query over the append-only log), per plan
Part 4.3 — "add a feature means write a new query", not a new table. web_tokens
backs simple LAN login (not SSO — scope traps stay out).

Revision ID: 0003
Revises: 0002
"""
from alembic import op
import os
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None

APP_ROLE = os.environ.get("DB_APP_ROLE", "sr_app")


def upgrade() -> None:
    op.create_table(
        "web_tokens",
        sa.Column("token", sa.Text, primary_key=True),
        sa.Column("user_id", UUID(as_uuid=True), sa.ForeignKey("users.user_id"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.execute(f'GRANT SELECT, INSERT, DELETE ON web_tokens TO "{APP_ROLE}";')

    # Blue scorecards across time — per member, per session. A VIEW, not a table.
    op.execute(
        """
        CREATE OR REPLACE VIEW v_session_scores AS
        SELECT e.session_id, s.scenario_id, s.user_id, u.username,
               (e.payload->'scorecard'->>'earned')::int AS earned,
               (e.payload->'scorecard'->>'total')::int  AS total,
               e.ts AS scored_at
        FROM events e
        JOIN sessions s ON s.session_id = e.session_id
        LEFT JOIN users u ON u.user_id = s.user_id
        WHERE e.action_type = 'verifier' AND e.payload ? 'scorecard'
        """
    )
    op.execute(f'GRANT SELECT ON v_session_scores TO "{APP_ROLE}";')


def downgrade() -> None:
    op.execute("DROP VIEW IF EXISTS v_session_scores;")
    op.drop_table("web_tokens")
