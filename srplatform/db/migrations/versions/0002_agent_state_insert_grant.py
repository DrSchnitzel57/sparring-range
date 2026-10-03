"""grant INSERT on agent_state to the app role (M3 loop saves working memory via API)

Revision ID: 0002
Revises: 0001
"""
from alembic import op
import os

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

APP_ROLE = os.environ.get("DB_APP_ROLE", "sr_app")


def upgrade() -> None:
    op.execute(f'GRANT INSERT ON agent_state TO "{APP_ROLE}";')


def downgrade() -> None:
    op.execute(f'REVOKE INSERT ON agent_state FROM "{APP_ROLE}";')
