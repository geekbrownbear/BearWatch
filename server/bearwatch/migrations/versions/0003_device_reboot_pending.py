"""Device restart-pending flag.

Revision ID: 0003
Revises: 0002
"""

from alembic import op
import sqlalchemy as sa

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("device") as batch:
        batch.add_column(sa.Column("reboot_pending", sa.Boolean(), nullable=False, server_default="0"))


def downgrade() -> None:
    with op.batch_alter_table("device") as batch:
        batch.drop_column("reboot_pending")
