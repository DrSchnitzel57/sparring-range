"""milestone 02: forward upgrades start LATCHED when legacy deployments exist

Deployments created before the broker authority have resources the broker
ledger has never seen. Until an operator runs ``brokerctl reconcile-legacy``
(verified adoption against PVE identity) and releases explicitly, the range
must not start new work and cessation must be assumed engaged.

The Supervisor treats the DB mirror conservatively (latched if EITHER store
says so), so latching this row is effective even where the state file was
written by an older release. The step is idempotent and NEVER unlatches:
release is an explicit operator action after reconciliation.

Revision ID: 0011
Revises: 0010
"""
from alembic import op
import sqlalchemy as sa

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    conn = op.get_bind()
    legacy = conn.execute(sa.text(
        "SELECT EXISTS (SELECT 1 FROM deployments WHERE status <> 'torn_down')"
    )).scalar()
    if not legacy:
        return
    conn.execute(sa.text("""
INSERT INTO safety_state (id, latched, latched_at, reason)
VALUES (1, true, now(),
        'milestone-02 upgrade: deployments predate the broker authority — run '
        'brokerctl reconcile-legacy, resolve every obligation, then release')
ON CONFLICT (id) DO UPDATE
SET latched = true,
    latched_at = now(),
    reason = CASE WHEN safety_state.latched THEN safety_state.reason
                  ELSE EXCLUDED.reason END
"""))
    conn.execute(sa.text("""
INSERT INTO safety_records (kind, ok, config_identity, detail, recorded_at)
VALUES ('engage', true, 'migration-0011',
        jsonb_build_object('reason',
          'upgrade latch: legacy deployments pending offline broker reconciliation'),
        now())
"""))


def downgrade() -> None:
    # Deliberately does NOT unlatch: releasing cessation is an operator
    # action, never a side effect of a schema downgrade.
    pass
