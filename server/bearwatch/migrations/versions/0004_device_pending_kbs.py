"""KBs installed but waiting for a restart, so only their findings say "a restart is pending".

Revision ID: 0004
Revises: 0003
"""

from alembic import op
import sqlalchemy as sa

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("device") as batch:
        batch.add_column(sa.Column("pending_kbs", sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("device") as batch:
        batch.drop_column("pending_kbs")
