"""External exposure: each client's public addresses and domains, and what the internet sees.

Revision ID: 0009
Revises: 0008
"""

from alembic import op
import sqlalchemy as sa

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "external_target",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("client_id", sa.Integer(), sa.ForeignKey("client.id", ondelete="CASCADE"), nullable=False),
        sa.Column("kind", sa.String(8), nullable=False),
        sa.Column("value", sa.String(253), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("first_checked_at", sa.DateTime()),
        sa.Column("last_checked_at", sa.DateTime()),
        sa.Column("last_error", sa.String(500)),
        sa.Column("snapshot", sa.JSON()),
        sa.UniqueConstraint("client_id", "kind", "value"),
    )
    op.create_index("ix_external_target_client_id", "external_target", ["client_id"])
    op.create_table(
        "external_issue",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("target_id", sa.Integer(), sa.ForeignKey("external_target.id", ondelete="CASCADE"), nullable=False),
        sa.Column("check_id", sa.String(40), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("severity", sa.String(8), nullable=False),
        sa.Column("detail", sa.String(1000)),
        sa.Column("solution", sa.String(500)),
        sa.Column("status", sa.String(8), nullable=False),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.Column("fixed_at", sa.DateTime()),
        sa.UniqueConstraint("target_id", "check_id"),
    )
    op.create_index("ix_external_issue_target_id", "external_issue", ["target_id"])
    op.create_index("ix_external_issue_status", "external_issue", ["status"])


def downgrade() -> None:
    op.drop_table("external_issue")
    op.drop_table("external_target")
