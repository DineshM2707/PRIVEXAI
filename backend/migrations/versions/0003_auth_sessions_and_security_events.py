"""Add auth session tracking and security event logging."""

from alembic import op
import sqlalchemy as sa


revision = "0003_auth_sessions_and_security_events"
down_revision = "0002_user_profile"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("session_key", sa.String(length=64), nullable=False),
        sa.Column("refresh_token_hash", sa.String(length=255), nullable=False),
        sa.Column("access_jti", sa.String(length=64), nullable=True),
        sa.Column("refresh_jti", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=255), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("replaced_by_session_id", sa.Integer(), sa.ForeignKey("auth_sessions.id"), nullable=True),
    )
    op.create_index("ix_auth_sessions_user_id", "auth_sessions", ["user_id"])
    op.create_index("ix_auth_sessions_session_key", "auth_sessions", ["session_key"], unique=True)
    op.create_index("ix_auth_sessions_access_jti", "auth_sessions", ["access_jti"], unique=False)
    op.create_index("ix_auth_sessions_refresh_jti", "auth_sessions", ["refresh_jti"], unique=False)

    op.create_table(
        "security_events",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("event_type", sa.String(length=40), nullable=False),
        sa.Column("identifier", sa.String(length=120), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("user_agent", sa.String(length=255), nullable=True),
        sa.Column("details", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_security_events_user_id", "security_events", ["user_id"])
    op.create_index("ix_security_events_event_type", "security_events", ["event_type"])
    op.create_index("ix_security_events_identifier", "security_events", ["identifier"])


def downgrade() -> None:
    op.drop_index("ix_security_events_identifier", table_name="security_events")
    op.drop_index("ix_security_events_event_type", table_name="security_events")
    op.drop_index("ix_security_events_user_id", table_name="security_events")
    op.drop_table("security_events")

    op.drop_index("ix_auth_sessions_refresh_jti", table_name="auth_sessions")
    op.drop_index("ix_auth_sessions_access_jti", table_name="auth_sessions")
    op.drop_index("ix_auth_sessions_session_key", table_name="auth_sessions")
    op.drop_index("ix_auth_sessions_user_id", table_name="auth_sessions")
    op.drop_table("auth_sessions")
