"""Posture: the Windows settings values each agent read for the posture rules.

Revision ID: 0006
Revises: 0005
"""

from alembic import op
import sqlalchemy as sa

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("device") as b:
        b.add_column(sa.Column("posture", sa.JSON(), nullable=True))
        b.add_column(sa.Column("posture_at", sa.DateTime(), nullable=True))


def downgrade() -> None:
    # Posture findings are ordinary finding rows (source "posture"); they stay, closed or not.
    with op.batch_alter_table("device") as b:
        b.drop_column("posture_at")
        b.drop_column("posture")
