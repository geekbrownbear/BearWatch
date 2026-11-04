"""Triage: device importance and exposure, finding risk and deadline, exceptions.

Existing findings get opened_at = first_seen, and every device is queued so the worker fills in
risk and deadlines within a minute of startup.

Revision ID: 0005
Revises: 0004
"""

from alembic import op
import sqlalchemy as sa

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "finding_exception",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("client_id", sa.Integer(), nullable=False),
        sa.Column("device_id", sa.Integer(), nullable=True),
        sa.Column("fix_key", sa.String(length=220), nullable=True),
        sa.Column("cve_id", sa.String(length=32), nullable=True),
        sa.Column("reason", sa.String(length=24), nullable=False),
        sa.Column("note", sa.Text(), nullable=False),
        sa.Column("expires_on", sa.Date(), nullable=False),
        sa.Column("created_by", sa.String(length=200), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("revoked_by", sa.String(length=200), nullable=True),
        sa.Column("revoked_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["client_id"], ["client.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["device_id"], ["device.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_finding_exception_client_id", "finding_exception", ["client_id"])
    op.create_index("ix_finding_exception_device_id", "finding_exception", ["device_id"])

    with op.batch_alter_table("device") as batch:
        batch.add_column(sa.Column("criticality", sa.Integer(), nullable=True))
        batch.add_column(sa.Column("internet_facing", sa.Boolean(), nullable=False, server_default="0"))

    with op.batch_alter_table("finding") as batch:
        batch.add_column(sa.Column("opened_at", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("due_at", sa.DateTime(), nullable=True))
        batch.add_column(sa.Column("risk", sa.Float(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("exception_id", sa.Integer(), nullable=True))
        batch.create_foreign_key("fk_finding_exception_id", "finding_exception", ["exception_id"], ["id"], ondelete="SET NULL")
        batch.create_index("ix_finding_due_at", ["due_at"])
        batch.create_index("ix_finding_exception_id", ["exception_id"])

    op.execute("UPDATE finding SET opened_at = COALESCE(first_seen, CURRENT_TIMESTAMP)")
    with op.batch_alter_table("finding") as batch:
        batch.alter_column("opened_at", existing_type=sa.DateTime(), nullable=False)

    device = sa.table("device", sa.column("needs_match", sa.Boolean()))
    op.execute(device.update().values(needs_match=True))


def downgrade() -> None:
    with op.batch_alter_table("finding") as batch:
        batch.drop_index("ix_finding_exception_id")
        batch.drop_index("ix_finding_due_at")
        batch.drop_constraint("fk_finding_exception_id", type_="foreignkey")
        batch.drop_column("exception_id")
        batch.drop_column("risk")
        batch.drop_column("due_at")
        batch.drop_column("opened_at")
    with op.batch_alter_table("device") as batch:
        batch.drop_column("internet_facing")
        batch.drop_column("criticality")
    op.drop_index("ix_finding_exception_device_id", table_name="finding_exception")
    op.drop_index("ix_finding_exception_client_id", table_name="finding_exception")
    op.drop_table("finding_exception")
