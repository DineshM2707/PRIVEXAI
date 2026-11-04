"""Add optional user profile fields for self-service registration."""

from alembic import op
import sqlalchemy as sa


revision = "0002_user_profile"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("email", sa.String(length=254), nullable=True))
    op.add_column("users", sa.Column("full_name", sa.String(length=120), nullable=True))
    op.create_index("ix_users_email", "users", ["email"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_users_email", table_name="users")
    op.drop_column("users", "full_name")
    op.drop_column("users", "email")
