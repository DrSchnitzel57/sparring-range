"""plan 19 review round: cessation obligations, secret isolation, limits.

Forward-only repairs on top of 0020 (which is applied and is NOT edited):

* ``model_jobs`` gains ``depends_on`` (a turn gated behind compaction),
  ``deadline_at`` (match-remaining caps admission and generation), and
  ``resolved_by`` / ``resolution`` / ``resolved_at`` (the bounded
  operator resolution of an unknown-cessation obligation).
* The admission slot index is REWIDEN: ``running`` AND
  ``cessation_unknown`` share one UNIQUE partial index. A call whose
  provider-side cessation cannot be confirmed now genuinely HOLDS the
  slot — the defect this fixes was that only ``running`` did, so a
  client timeout admitted a second request while the provider was
  still generating.
* ``model_profiles`` gains ``compaction_ratio`` (operator-editable
  pressure point instead of the hardcoded 0.8).
* ``model_profile_secrets`` — the provider credentials LEAVE
  ``model_profiles``. 0020 granted the APPLICATION role SELECT over the
  plaintext ``api_key`` column, but the ingest plane shares that role:
  the key was not actually isolated. The new table is created WITHOUT
  any grant to the app role and granted only to the dedicated secret
  identity (``DB_SECRET_ROLE``), which holds no other table. Existing
  keys are copied forward here, then the plaintext column is DROPPED —
  0020's table-level grant cannot be narrowed by a column REVOKE, so
  removal is the only repair that bites. No key material is printed or
  logged by this migration.

Revision ID: 0021
Revises: 0020
"""
from alembic import op
import os
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = "0021"
down_revision = "0020"
branch_labels = None
depends_on = None

APP_ROLE = os.environ.get("DB_APP_ROLE", "sr_app")
SECRET_ROLE = os.environ.get("DB_SECRET_ROLE", "sr_secret")


def upgrade() -> None:
    # ---- job obligation + gating columns ------------------------------
    op.add_column("model_jobs", sa.Column(
        "depends_on", UUID(as_uuid=True), nullable=True))
    op.add_column("model_jobs", sa.Column(
        "deadline_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("model_jobs", sa.Column(
        "resolved_by", sa.Text, nullable=True))
    op.add_column("model_jobs", sa.Column(
        "resolution", sa.Text, nullable=True))
    op.add_column("model_jobs", sa.Column(
        "resolved_at", sa.DateTime(timezone=True), nullable=True))
    op.create_index("ix_model_jobs_parent", "model_jobs", ["parent_job"])

    # ---- the slot must protect uncertain cessation too ------------------
    op.execute("DROP INDEX uq_model_jobs_single_running;")
    op.execute(
        "CREATE UNIQUE INDEX uq_model_jobs_slot ON model_jobs (state) "
        "WHERE state IN ('running', 'cessation_unknown');")

    # ---- profile-editable compaction point ------------------------------
    op.add_column("model_profiles", sa.Column(
        "compaction_ratio", sa.Float, nullable=False, server_default="0.8"))

    # ---- credential isolation -------------------------------------------
    op.create_table(
        "model_profile_secrets",
        sa.Column("profile_id", UUID(as_uuid=True), primary_key=True),
        sa.Column("api_key", sa.Text, nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False,
                  server_default=sa.text("now()")),
    )
    # Copy existing credentials forward, then make the plaintext column
    # impossible to read by removing it. Only the secret identity ever
    # holds SELECT here. NOTE: 0016/0017 established owner DEFAULT
    # PRIVILEGES that auto-grant SELECT, INSERT on new tables to the app
    # role — CREATE TABLE alone would have handed the app role the keys,
    # so the default grant is explicitly REVOKED per-table here (this
    # is exactly the rot the grant-guard test documents, weaponized).
    op.execute(
        "INSERT INTO model_profile_secrets (profile_id, api_key) "
        "SELECT profile_id, api_key FROM model_profiles "
        "WHERE api_key IS NOT NULL AND api_key <> ''")
    op.execute('REVOKE ALL ON model_profile_secrets FROM PUBLIC;')
    op.execute(f'REVOKE ALL ON model_profile_secrets FROM "{APP_ROLE}";')
    op.execute(f'GRANT USAGE ON SCHEMA public TO "{SECRET_ROLE}";')
    op.execute(f'GRANT SELECT, INSERT, UPDATE, DELETE ON '
               f'model_profile_secrets TO "{SECRET_ROLE}";')
    op.execute("ALTER TABLE model_profiles DROP COLUMN api_key;")


def downgrade() -> None:
    # NOT a supported path in a release (a dropped credential column can
    # only be restored from the secret table, and only for rows that
    # still have one). Present for migration-tool completeness.
    op.execute("ALTER TABLE model_profiles ADD COLUMN api_key text "
               "NOT NULL DEFAULT ''")
    op.execute(
        "UPDATE model_profiles p SET api_key = s.api_key "
        "FROM model_profile_secrets s WHERE s.profile_id = p.profile_id")
    op.execute(f'REVOKE ALL ON model_profile_secrets FROM "{SECRET_ROLE}";')
    op.drop_table("model_profile_secrets")
    op.drop_column("model_profiles", "compaction_ratio")
    op.execute("DROP INDEX uq_model_jobs_slot;")
    op.execute(
        "CREATE UNIQUE INDEX uq_model_jobs_single_running ON model_jobs "
        "(state) WHERE state = 'running';")
    op.drop_index("ix_model_jobs_parent", table_name="model_jobs")
    op.drop_column("model_jobs", "resolved_at")
    op.drop_column("model_jobs", "resolution")
    op.drop_column("model_jobs", "resolved_by")
    op.drop_column("model_jobs", "deadline_at")
    op.drop_column("model_jobs", "depends_on")
