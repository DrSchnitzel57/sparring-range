"""Plan 19 review round 2: credential lineage, once-per-request outcomes,
and an HONEST single-occupancy slot index.

Three schema facts the round-2 review proved missing:

1. Credential rotation only revoked the ACTIVE version. Sessions pinned
   to a SUPERSEDED version that carried the same credential kept working
   after a "compromise" rotation. ``model_profiles.credential_digest``
   is a one-way identity of the credential VALUE, so "replace this key"
   can invalidate every version carrying it. Legacy rows stay NULL and
   never match (no false revocations).

2. Result handlers (coach hint / AAR persistence) ran per ATTEMPT, so a
   failed-then-retried request persisted its member-visible outcome
   twice. ``model_jobs.outcome_persisted`` makes the outcome claim
   atomic across processes: exactly one writer per logical request.

3. Index ``uq_model_jobs_slot`` was UNIQUE on ``state`` restricted to
   ``('running','cessation_unknown')`` — two DIFFERENT values are not
   unique against EACH OTHER, so it allowed one running PLUS one
   unknown: two "occupied" rows. The replacement indexes a CONSTANT
   occupied-key (``0``) for every occupying state and NULL otherwise
   (NULLs never conflict), which is the invariant actually advertised:
   at most ONE occupying row. Before swapping, the upgrade REFUSES to
   proceed if an existing database currently holds running and
   cessation_unknown together — the operator resolves the obligation
   first (that is what the state means); silently dropping one row's
   protection would be exactly the fail-open this index prevents.

0020 and 0021 stay byte-unchanged; this is the forward path.
"""
from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0022"
down_revision = "0021"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()

    conn.exec_driver_sql(
        "ALTER TABLE model_profiles ADD COLUMN IF NOT EXISTS "
        "credential_digest TEXT")
    conn.exec_driver_sql(
        "ALTER TABLE model_jobs ADD COLUMN IF NOT EXISTS "
        "outcome_persisted BOOLEAN NOT NULL DEFAULT FALSE")

    # --- refuse to swap the slot index over a live violation ----------
    occupying = conn.execute(sa.text(
        "SELECT count(*) FROM model_jobs WHERE state IN "
        "('running', 'cessation_unknown')")).scalar_one()
    if occupying > 1:
        raise RuntimeError(
            "refusing to upgrade: model_jobs currently holds "
            f"{occupying} occupying rows (running/cessation_unknown). "
            "The old slot index allowed one of EACH state at once — "
            "resolve the outstanding cessation obligation (operator "
            "resolution of the possibly-live call) until at most one "
            "occupying row remains, then rerun the migration. Never "
            "auto-resolve: the provider may still be generating.")

    conn.execute(sa.text(
        "DROP INDEX IF EXISTS uq_model_jobs_slot"))
    conn.execute(sa.text(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_model_jobs_occupied "
        "ON model_jobs ((CASE WHEN state IN "
        "('running', 'cessation_unknown') THEN 0 END))"))


def downgrade() -> None:
    conn = op.get_bind()
    conn.execute(sa.text(
        "DROP INDEX IF EXISTS uq_model_jobs_occupied"))
    conn.execute(sa.text(
        "CREATE UNIQUE INDEX IF NOT EXISTS uq_model_jobs_slot "
        "ON model_jobs (state) WHERE state IN "
        "('running', 'cessation_unknown')"))
    # the new columns stay: they record history, and dropping data in a
    # downgrade is its own kind of incident
