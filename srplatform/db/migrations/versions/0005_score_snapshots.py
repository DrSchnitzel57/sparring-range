"""score snapshots + per-domain score items (F11/F20)

Trusted scoring (backend verifier execution) appends ``score_snapshot`` events;
this view exposes them chronologically with an event-ID tie-break (F20: UUID
ordering was meaningless), and a lateral expansion of the rubric items so
progress can be computed per CCDC domain instead of copying one whole-scenario
percentage onto every focus tag.

Revision ID: 0005
Revises: 0004
"""
from alembic import op
import os
import sqlalchemy as sa

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None

APP_ROLE = os.environ.get("DB_APP_ROLE", "sr_app")

VIEW = """
CREATE OR REPLACE VIEW v_score_items AS
SELECT e.session_id,
       s.scenario_id,
       s.user_id,
       u.username,
       e.event_id,
       e.ts AS scored_at,
       i->>'domain'               AS domain,
       i->>'verifier'             AS verifier,
       i->>'host'                 AS host,
       (i->>'awarded')::int       AS awarded,
       (i->>'points')::int        AS points,
       i->>'status'               AS status,
       (e.payload->>'scorecard_status') AS scorecard_status
FROM events e
JOIN sessions s ON s.session_id = e.session_id
LEFT JOIN users u ON u.user_id = s.user_id
CROSS JOIN LATERAL jsonb_array_elements(e.payload->'scorecard'->'items') AS i
WHERE e.action_type = 'score_snapshot'
"""


def upgrade() -> None:
    op.execute(VIEW)
    op.execute(f'GRANT SELECT ON v_score_items TO "{APP_ROLE}";')


def downgrade() -> None:
    op.execute("DROP VIEW IF EXISTS v_score_items;")
