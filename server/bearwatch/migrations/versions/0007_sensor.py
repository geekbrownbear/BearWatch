"""Sensor mode: one PC per site scans its network; hosts it finds and their issues.

Revision ID: 0007
Revises: 0006
"""

from alembic import op
import sqlalchemy as sa

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("site") as b:
        b.add_column(sa.Column("sensor_device_id", sa.Integer(), nullable=True))
        b.add_column(sa.Column("sensor_first_scan_at", sa.DateTime(), nullable=True))
        b.add_column(sa.Column("sensor_scan_at", sa.DateTime(), nullable=True))
    with op.batch_alter_table("device") as b:
        b.add_column(sa.Column("macs", sa.JSON(), nullable=True))

    op.create_table(
        "network_host",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("site_id", sa.Integer(), sa.ForeignKey("site.id", ondelete="CASCADE"), nullable=False),
        sa.Column("key", sa.String(80), nullable=False),
        sa.Column("mac", sa.String(64)),
        sa.Column("ip", sa.String(64), nullable=False),
        sa.Column("vendor", sa.String(255)),
        sa.Column("name", sa.String(255)),
        sa.Column("names", sa.JSON(), nullable=False),
        sa.Column("workgroup", sa.String(255)),
        sa.Column("ports", sa.JSON(), nullable=False),
        sa.Column("device_id", sa.Integer(), sa.ForeignKey("device.id", ondelete="SET NULL")),
        sa.Column("known", sa.Boolean(), nullable=False, server_default="0"),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("site_id", "key"),
    )
    op.create_index("ix_network_host_site_id", "network_host", ["site_id"])
    op.create_index("ix_network_host_device_id", "network_host", ["device_id"])

    op.create_table(
        "network_issue",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("host_id", sa.Integer(), sa.ForeignKey("network_host.id", ondelete="CASCADE"), nullable=False),
        sa.Column("check_id", sa.String(255), nullable=False),
        sa.Column("port", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("cvss", sa.Float()),
        sa.Column("evidence", sa.String(500)),
        sa.Column("solution", sa.String(1000)),
        sa.Column("status", sa.String(8), nullable=False),
        sa.Column("first_seen", sa.DateTime(), nullable=False),
        sa.Column("last_seen", sa.DateTime(), nullable=False),
        sa.Column("fixed_at", sa.DateTime()),
        sa.UniqueConstraint("host_id", "check_id", "port"),
    )
    op.create_index("ix_network_issue_host_id", "network_issue", ["host_id"])
    op.create_index("ix_network_issue_status", "network_issue", ["status"])


def downgrade() -> None:
    op.drop_table("network_issue")
    op.drop_table("network_host")
    with op.batch_alter_table("device") as b:
        b.drop_column("macs")
    with op.batch_alter_table("site") as b:
        b.drop_column("sensor_scan_at")
        b.drop_column("sensor_first_scan_at")
        b.drop_column("sensor_device_id")
