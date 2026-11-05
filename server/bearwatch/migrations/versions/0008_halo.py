"""HaloPSA: each client's Halo id, and the ticket BearWatch keeps for each fix.

Revision ID: 0008
Revises: 0007
"""

from alembic import op
import sqlalchemy as sa

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("client") as b:
        b.add_column(sa.Column("halo_client_id", sa.Integer(), nullable=True))
    op.create_table(
        "halo_ticket",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("client_id", sa.Integer(), sa.ForeignKey("client.id", ondelete="CASCADE"), nullable=False),
        sa.Column("fix_key", sa.String(220), nullable=False),
        sa.Column("halo_id", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(8), nullable=False),
        sa.Column("digest", sa.String(64), nullable=False),
        sa.Column("opened_at", sa.DateTime(), nullable=False),
        sa.Column("closed_at", sa.DateTime()),
        sa.Column("updated_at", sa.DateTime()),
        sa.Column("last_error", sa.Text()),
        sa.UniqueConstraint("client_id", "fix_key"),
    )
    op.create_index("ix_halo_ticket_client_id", "halo_ticket", ["client_id"])


def downgrade() -> None:
    op.drop_table("halo_ticket")
    with op.batch_alter_table("client") as b:
        b.drop_column("halo_client_id")
