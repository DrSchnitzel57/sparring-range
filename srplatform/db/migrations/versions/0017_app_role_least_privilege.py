"""plan 13 phase 8: least-privilege correction for the app role.

0016 granted blanket UPDATE/DELETE over present tables, including tables
the application only ever appends to or reads (review find 2026-10-15:
after 0016, sr_app could rewrite/delete uptime_samples and touch
migration metadata). Code audit: no UPDATE or DELETE targets events,
uptime_samples, recordings, or safety_records anywhere outside tests;
alembic_version is read-only for the app (readiness check). Everything
else keeps 0016's DML — sessions, runs, matches, tokens (revocation),
claims, leases, agent working memory, inject releases, and web state are
all mutated by live code paths.

Default privileges narrow to read+insert for future tables/sequences, so
a future mutable table fails LOUD at runtime until its migration grants
explicitly (the 0002 precedent) instead of inheriting silent mutation
rights over the next audit trail.

Owner-agnostic throughout (no FOR ROLE): privileges attach to the
migrating role.

Revision ID: 0017
Revises: 0016
"""
from alembic import op
import os

revision = "0017"
down_revision = "0016"
branch_labels = None
depends_on = None

APP_ROLE = os.environ.get("DB_APP_ROLE", "sr_app")

APPEND_ONLY_TABLES = ("events", "uptime_samples", "recordings",
                      "safety_records")


def upgrade() -> None:
    for table in APPEND_ONLY_TABLES:
        op.execute(f'REVOKE UPDATE, DELETE ON "{table}" FROM "{APP_ROLE}";')
    op.execute(f'REVOKE ALL ON alembic_version FROM "{APP_ROLE}";')
    op.execute(f'GRANT SELECT ON alembic_version TO "{APP_ROLE}";')
    # Narrow the 0016 defaults for FUTURE objects: read+insert only.
    # Present mutable tables keep their grants; new mutable tables need
    # explicit per-migration grants (fail closed, like 0002).
    op.execute('ALTER DEFAULT PRIVILEGES IN SCHEMA public '
               f'REVOKE ALL ON TABLES FROM "{APP_ROLE}";')
    op.execute('ALTER DEFAULT PRIVILEGES IN SCHEMA public '
               f'GRANT SELECT, INSERT ON TABLES TO "{APP_ROLE}";')
    op.execute('ALTER DEFAULT PRIVILEGES IN SCHEMA public '
               f'REVOKE ALL ON SEQUENCES FROM "{APP_ROLE}";')
    op.execute('ALTER DEFAULT PRIVILEGES IN SCHEMA public '
               f'GRANT USAGE, SELECT ON SEQUENCES TO "{APP_ROLE}";')


def downgrade() -> None:
    for table in APPEND_ONLY_TABLES:
        op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON "{table}" '
                   f'TO "{APP_ROLE}";')
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON alembic_version '
               f'TO "{APP_ROLE}";')
    op.execute('ALTER DEFAULT PRIVILEGES IN SCHEMA public '
               f'REVOKE ALL ON TABLES FROM "{APP_ROLE}";')
    op.execute('ALTER DEFAULT PRIVILEGES IN SCHEMA public '
               f'GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES '
               f'TO "{APP_ROLE}";')
