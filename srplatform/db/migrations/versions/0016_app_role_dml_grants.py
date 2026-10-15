"""plan 13 phase 8: standing DML grants for the app role.

Production migrates as sr_owner while the API serves as sr_app (DML-only).
Per-table grants rot on every schema change (live find 2026-10-15: fresh
0015 schema answered `permission denied` to the app role), so this revision
grants DML on all present tables/sequences AND installs ALTER DEFAULT
PRIVILEGES for the migrating role — future migrations inherit without
installer surgery. DDL (CREATE/ALTER/DROP) is never granted. Default
privileges deliberately omit FOR ROLE: they attach to whoever runs the
migration (sr_owner live, disposable roles in test) — a hardcoded owner
broke every non-default environment (review find 2026-10-15). The one
production application ran as sr_owner, so live state is unaffected.

Revision ID: 0016
Revises: 0015
"""
from alembic import op
import os

revision = "0016"
down_revision = "0015"
branch_labels = None
depends_on = None

APP_ROLE = os.environ.get("DB_APP_ROLE", "sr_app")


def upgrade() -> None:
    op.execute(f'GRANT USAGE ON SCHEMA public TO "{APP_ROLE}";')
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES '
               f'IN SCHEMA public TO "{APP_ROLE}";')
    op.execute(f'GRANT USAGE, SELECT ON ALL SEQUENCES '
               f'IN SCHEMA public TO "{APP_ROLE}";')
    op.execute('ALTER DEFAULT PRIVILEGES IN SCHEMA '
               f'public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES '
               f'TO "{APP_ROLE}";')
    op.execute('ALTER DEFAULT PRIVILEGES IN SCHEMA '
               f'public GRANT USAGE, SELECT ON SEQUENCES TO "{APP_ROLE}";')


def downgrade() -> None:
    op.execute('ALTER DEFAULT PRIVILEGES IN SCHEMA '
               f'public REVOKE ALL ON SEQUENCES FROM "{APP_ROLE}";')
    op.execute('ALTER DEFAULT PRIVILEGES IN SCHEMA '
               f'public REVOKE ALL ON TABLES FROM "{APP_ROLE}";')
    op.execute(f'REVOKE ALL ON ALL SEQUENCES IN SCHEMA public '
               f'FROM "{APP_ROLE}";')
    op.execute(f'REVOKE ALL ON ALL TABLES IN SCHEMA public FROM "{APP_ROLE}";')
