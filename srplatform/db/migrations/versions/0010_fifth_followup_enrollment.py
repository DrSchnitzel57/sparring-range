"""fifth-follow-up: enrollment evidence binding (audit F3/F4)

Migration 0009 added the enrollment evidence columns but did NOT invalidate
pre-upgrade ``telemetry_enroll.phase=confirmed`` markers: a resource whose
capability carries no delivery/capture evidence (the pre-0009 shape — all
evidence fields NULL) must NOT keep a deployment 'ready' after the upgrade.

This data step:

1. binds un-bound enrollment capabilities of READY deployments to the
   deployment generation whose resource inventory references their host
   (evidence must be attributable to a generation — audit F4); and
2. downgrades every ``phase=confirmed`` resource whose capability lacks
   complete evidence for that generation to ``stale_evidence`` — the resume
   path then safely RE-ENROLLS the same capability (no re-clone, no second
   token) and readiness requires the fresh evidence.

Evidence-backed confirmations are left untouched. The step is idempotent.

Revision ID: 0010
Revises: 0009
"""
from alembic import op
import sqlalchemy as sa

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


_BIND_SQL = sa.text("""
UPDATE service_tokens st SET enrollment_deployment_id = d.deployment_id
FROM deployments d
CROSS JOIN LATERAL jsonb_array_elements(d.resources) AS r
WHERE jsonb_typeof(d.resources) = 'array'
  AND d.status = 'ready'
  AND st.scope = 'telemetry'
  AND st.session_id = d.session_id
  AND st.host = r->>'host'
  AND st.revoked_at IS NULL
  AND st.enrollment_deployment_id IS NULL
  AND r->'telemetry_enroll'->>'phase' = 'confirmed'
""")

_DOWNGRADE_SQL = sa.text("""
UPDATE deployments d
SET resources = (
  SELECT jsonb_agg(
           CASE
             WHEN elem -> 'telemetry_enroll' ->> 'phase' = 'confirmed'
              AND NOT EXISTS (
                SELECT 1 FROM service_tokens st
                WHERE st.session_id = d.session_id
                  AND st.host = elem ->> 'host'
                  AND st.scope = 'telemetry'
                  AND st.revoked_at IS NULL
                  AND st.enroll_confirmed_at IS NOT NULL
                  AND st.enroll_capture_at IS NOT NULL
                  AND (st.enrollment_deployment_id IS NULL
                       OR st.enrollment_deployment_id = d.deployment_id)
              )
             THEN jsonb_set(
                    jsonb_set(elem,
                              '{telemetry_enroll,phase}', '"stale_evidence"'::jsonb),
                    '{telemetry_enroll,stale_at_upgrade}', 'true'::jsonb)
             ELSE elem
           END
           ORDER BY ord)::jsonb
  FROM jsonb_array_elements(d.resources) WITH ORDINALITY AS t(elem, ord)
)
WHERE jsonb_typeof(d.resources) = 'array'
  AND EXISTS (
    SELECT 1 FROM jsonb_array_elements(d.resources) r
    WHERE r -> 'telemetry_enroll' ->> 'phase' = 'confirmed')
""")


def downgrade_stale_confirmed(bind) -> None:
    """Invalidate phase-only confirmations and bind un-bound enrollment
    capabilities to their deployment generation. Exposed for the upgrade and
    for the acceptance test that exercises it directly."""
    bind.execute(_BIND_SQL)
    bind.execute(_DOWNGRADE_SQL)


def upgrade() -> None:
    downgrade_stale_confirmed(op.get_bind())


def downgrade() -> None:
    # data-only migration: the pre-0010 shape (phase-only 'confirmed'
    # trusted) is exactly the defect being closed — there is no safe
    # automatic re-promotion, so downgrade is a documented no-op.
    pass
