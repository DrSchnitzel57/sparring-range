"""remediation core: identity, lifecycle, lease, safety, recordings (F04/F06/F08/F13/F16)

Forward migration (applied history is never edited). Adds the small operational
state the audit identified as missing — explicitly NOT evidence: leases,
deployments, runs, safety latch, recordings index, service tokens, and member
credentials. The event log stays append-only and untouched.

Grants (F13): the app role gains the *minimum* mutations the lifecycle needs —
sessions UPDATE (status transitions), users UPDATE (password provisioning) —
never UPDATE/DELETE on events.

Revision ID: 0004
Revises: 0003
"""
from alembic import op
import os
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None

APP_ROLE = os.environ.get("DB_APP_ROLE", "sr_app")


def upgrade() -> None:
    # --- identity (F04): real authentication, revocation, expiry ----------------
    op.add_column("users", sa.Column("password_hash", sa.Text))
    op.add_column("users", sa.Column("role", sa.Text, nullable=False, server_default="member"))
    op.add_column("web_tokens", sa.Column("expires_at", sa.DateTime(timezone=True)))
    op.add_column("web_tokens", sa.Column("revoked_at", sa.DateTime(timezone=True)))
    op.add_column("login_tokens", sa.Column("user_id", UUID(as_uuid=True),
                                            sa.ForeignKey("users.user_id")))
    op.add_column("login_tokens", sa.Column("expires_at", sa.DateTime(timezone=True)))
    # lifecycle outcome is DISTINCT from status (F13): finishing practice and
    # "red achieved everything" are different facts
    op.add_column("sessions", sa.Column("outcome", sa.Text))
    op.add_column("sessions", sa.Column("finalized_at", sa.DateTime(timezone=True)))

    # scoped service capability tokens: bastion / telemetry host / runner / run
    op.create_table(
        "service_tokens",
        sa.Column("token", sa.Text, primary_key=True),
        sa.Column("scope", sa.Text, nullable=False),   # bastion|telemetry|runner|score
        sa.Column("session_id", UUID(as_uuid=True), sa.ForeignKey("sessions.session_id")),
        sa.Column("host", sa.Text),                    # telemetry: bound host identity
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
    )

    # --- single-active-range lease (F06): one row, one owner, clean conflict ----
    op.create_table(
        "range_lease",
        sa.Column("id", sa.SmallInteger, primary_key=True),  # always 1
        sa.Column("session_id", UUID(as_uuid=True), sa.ForeignKey("sessions.session_id")),
        sa.Column("acquired_at", sa.DateTime(timezone=True)),
        sa.Column("released_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("id = 1", name="range_lease_singleton"),
    )

    # --- deployment ownership (F06): exact owned resources, never name prefixes -
    op.create_table(
        "deployments",
        sa.Column("deployment_id", UUID(as_uuid=True), primary_key=True),
        sa.Column("session_id", UUID(as_uuid=True), sa.ForeignKey("sessions.session_id")),
        sa.Column("scenario_id", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False, server_default="preparing"),
        sa.Column("resources", JSONB, nullable=False, server_default="[]"),  # [{vmid,node,name,host,ip,template_vmid}]
        sa.Column("error", sa.Text),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # --- supervised runs (F02/F13): durable run state, worker identity -----------
    op.create_table(
        "runs",
        sa.Column("run_id", UUID(as_uuid=True), primary_key=True),
        sa.Column("session_id", UUID(as_uuid=True), sa.ForeignKey("sessions.session_id"), nullable=False),
        sa.Column("scenario_id", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False, server_default="queued"),  # queued|running|stopping|completed|failed|cancelled
        sa.Column("outcome", sa.Text),           # complete|incomplete|no_progress|budget|worker_failure|canceled
        sa.Column("pid", sa.BigInteger),
        sa.Column("pgid", sa.BigInteger),
        sa.Column("worker_token", sa.Text),      # sha256 of the run-scoped capability
        sa.Column("result", JSONB),
        sa.Column("error", sa.Text),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("ended_at", sa.DateTime(timezone=True)),
    )

    # --- safety latch + evidence records (F02) ----------------------------------
    op.create_table(
        "safety_state",
        sa.Column("id", sa.SmallInteger, primary_key=True),
        sa.Column("latched", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.Column("latched_at", sa.DateTime(timezone=True)),
        sa.Column("reason", sa.Text),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint("id = 1", name="safety_state_singleton"),
    )
    op.execute("INSERT INTO safety_state (id, latched) VALUES (1, false)")
    op.create_table(
        "safety_records",
        sa.Column("record_id", sa.BigInteger, primary_key=True),
        sa.Column("kind", sa.Text, nullable=False),   # baseline_check|datapath_proof|release|engage
        sa.Column("ok", sa.Boolean, nullable=False),
        sa.Column("config_identity", sa.Text),        # hash of network/config identity
        sa.Column("detail", JSONB, nullable=False, server_default="{}"),
        sa.Column("recorded_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.execute("CREATE SEQUENCE IF NOT EXISTS safety_records_record_id_seq")

    # --- recordings as opaque IDs (F16) ------------------------------------------
    op.create_table(
        "recordings",
        sa.Column("recording_id", UUID(as_uuid=True), primary_key=True),
        sa.Column("session_id", UUID(as_uuid=True), sa.ForeignKey("sessions.session_id"), nullable=False),
        sa.Column("cast_path", sa.Text, nullable=False),
        sa.Column("status", sa.Text, nullable=False, server_default="recording"),
        sa.Column("bytes", sa.BigInteger),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )

    # --- minimal lifecycle grants (F13) ------------------------------------------
    op.execute(f'GRANT SELECT, UPDATE ON sessions TO "{APP_ROLE}";')
    op.execute(f'GRANT SELECT, INSERT, UPDATE ON users TO "{APP_ROLE}";')
    op.execute(f'GRANT UPDATE ON web_tokens TO "{APP_ROLE}";')
    op.execute(f'GRANT SELECT, INSERT, UPDATE ON service_tokens, range_lease, deployments, runs, recordings TO "{APP_ROLE}";')
    op.execute(f'GRANT SELECT, INSERT ON safety_state, safety_records TO "{APP_ROLE}";')
    op.execute(f'GRANT UPDATE ON safety_state TO "{APP_ROLE}";')
    op.execute(f'GRANT USAGE, SELECT ON SEQUENCE safety_records_record_id_seq TO "{APP_ROLE}";')
    # /readyz reports migration version using the APP role — allow that read only
    op.execute(f'GRANT SELECT ON alembic_version TO "{APP_ROLE}";')


def downgrade() -> None:
    op.drop_table("recordings")
    op.drop_table("safety_records")
    op.execute("DROP SEQUENCE IF EXISTS safety_records_record_id_seq")
    op.drop_table("safety_state")
    op.drop_table("runs")
    op.drop_table("deployments")
    op.drop_table("range_lease")
    op.drop_table("service_tokens")
    op.drop_column("sessions", "finalized_at")
    op.drop_column("sessions", "outcome")
    op.drop_column("login_tokens", "expires_at")
    op.drop_column("login_tokens", "user_id")
    op.drop_column("web_tokens", "revoked_at")
    op.drop_column("web_tokens", "expires_at")
    op.drop_column("users", "role")
    op.drop_column("users", "password_hash")
