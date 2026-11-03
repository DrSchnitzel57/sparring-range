"""runtime grants for the lab aggregate (Underpressure step 3 fix)

Migration 0029 created `labs`, `lab_guests`, `lab_members` and
`lab_reset_plans` but never granted them to the API's app role, so every
runtime read/write failed with "permission denied for table labs" the
first time the lab API was exercised against a real database (found by
tests/test_lab_api.py, 2026-11-03).

Forward-only and idempotent: GRANT is safe to re-run and does not touch
any existing row. Rows are operational state, so the app role gets
SELECT/INSERT/UPDATE and NOT DELETE — a lab or membership is never
hard-deleted; explicit delete is a timestamped soft delete.

Revision ID: 0030
Revises: 0029
"""
from __future__ import annotations

from alembic import op

revision = "0030"
down_revision = "0029"
branch_labels = None
depends_on = None

APP_ROLE_ENV = "DB_APP_ROLE"


def _app_role() -> str:
    import os

    role = os.environ.get(APP_ROLE_ENV)
    if not role:
        raise RuntimeError(
            f"{APP_ROLE_ENV} must name the API's database role for grants")
    return role


def upgrade() -> None:
    role = _app_role()
    for table in ("labs", "lab_guests", "lab_members", "lab_reset_plans"):
        op.execute(f'GRANT SELECT, INSERT, UPDATE ON {table} TO "{role}";')


def downgrade() -> None:
    role = _app_role()
    for table in ("labs", "lab_guests", "lab_members", "lab_reset_plans"):
        op.execute(f'REVOKE SELECT, INSERT, UPDATE ON {table} FROM "{role}";')
