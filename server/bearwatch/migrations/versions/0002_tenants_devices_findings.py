"""Tenants, devices, inventory and findings (Phase 1).

Revision ID: 0002
Revises: 0001
"""

from alembic import op
import sqlalchemy as sa

revision = "0002"
down_revision = '0001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # The app matcher's fallback looks programs up by product name alone.
    op.create_index('ix_cpe_match_product', 'cpe_match', ['product'])
    op.create_table('client',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('site',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('client_id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('enroll_key_hash', sa.String(length=64), nullable=False),
    sa.Column('enroll_key_hint', sa.String(length=12), nullable=False),
    sa.Column('wua_check', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['client_id'], ['client.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('client_id', 'name'),
    sa.UniqueConstraint('enroll_key_hash')
    )
    op.create_index('ix_site_client_id', 'site', ['client_id'])
    op.create_table('device',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('site_id', sa.Integer(), nullable=False),
    sa.Column('machine_guid', sa.String(length=64), nullable=False),
    sa.Column('hostname', sa.String(length=255), nullable=False),
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('agent_version', sa.String(length=32), nullable=True),
    sa.Column('os_caption', sa.String(length=200), nullable=True),
    sa.Column('os_build', sa.String(length=32), nullable=True),
    sa.Column('os_arch', sa.String(length=8), nullable=True),
    sa.Column('is_server', sa.Boolean(), nullable=False),
    sa.Column('server_core', sa.Boolean(), nullable=False),
    sa.Column('os_product', sa.String(length=200), nullable=True),
    sa.Column('inventory_hash', sa.String(length=64), nullable=True),
    sa.Column('enrolled_at', sa.DateTime(), nullable=False),
    sa.Column('last_seen', sa.DateTime(), nullable=True),
    sa.Column('last_inventory_at', sa.DateTime(), nullable=True),
    sa.Column('needs_match', sa.Boolean(), nullable=False),
    sa.Column('last_match_at', sa.DateTime(), nullable=True),
    sa.Column('match_error', sa.Text(), nullable=True),
    sa.Column('rescan_requested', sa.Boolean(), nullable=False),
    sa.Column('wua_checked_at', sa.DateTime(), nullable=True),
    sa.Column('wua_error', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['site_id'], ['site.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('site_id', 'machine_guid'),
    sa.UniqueConstraint('token_hash')
    )
    op.create_index('ix_device_site_id', 'device', ['site_id'])
    op.create_table('device_kb',
    sa.Column('device_id', sa.Integer(), nullable=False),
    sa.Column('kb', sa.String(length=16), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['device.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('device_id', 'kb')
    )
    op.create_table('device_software',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('device_id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=400), nullable=False),
    sa.Column('version', sa.String(length=120), nullable=False),
    sa.Column('publisher', sa.String(length=200), nullable=True),
    sa.Column('scope', sa.String(length=8), nullable=False),
    sa.Column('resolved_by', sa.String(length=12), nullable=True),
    sa.Column('cpe', sa.JSON(), nullable=False),
    sa.Column('winget_id', sa.String(length=200), nullable=True),
    sa.Column('latest_version', sa.String(length=120), nullable=True),
    sa.ForeignKeyConstraint(['device_id'], ['device.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_device_software_device_id', 'device_software', ['device_id'])
    op.create_table('finding',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('device_id', sa.Integer(), nullable=False),
    sa.Column('source', sa.String(length=8), nullable=False),
    sa.Column('subject_key', sa.String(length=200), nullable=False),
    sa.Column('subject', sa.String(length=400), nullable=False),
    sa.Column('subject_version', sa.String(length=200), nullable=True),
    sa.Column('cve_id', sa.String(length=32), nullable=False),
    sa.Column('fix_key', sa.String(length=220), nullable=False),
    sa.Column('fix_label', sa.String(length=400), nullable=False),
    sa.Column('status', sa.String(length=8), nullable=False),
    sa.Column('exploit_tier', sa.Integer(), nullable=False),
    sa.Column('kev', sa.Boolean(), nullable=False),
    sa.Column('epss', sa.Float(), nullable=True),
    sa.Column('cvss', sa.Float(), nullable=True),
    sa.Column('first_seen', sa.DateTime(), nullable=False),
    sa.Column('last_seen', sa.DateTime(), nullable=False),
    sa.Column('fixed_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['device_id'], ['device.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('device_id', 'source', 'subject_key', 'cve_id')
    )
    op.create_index('ix_finding_cve_id', 'finding', ['cve_id'])
    op.create_index('ix_finding_device_id', 'finding', ['device_id'])
    op.create_index('ix_finding_fix_key', 'finding', ['fix_key'])
    op.create_index('ix_finding_status', 'finding', ['status'])
    op.create_table('wua_update',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('device_id', sa.Integer(), nullable=False),
    sa.Column('kb', sa.String(length=16), nullable=True),
    sa.Column('title', sa.String(length=400), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=True),
    sa.Column('is_security', sa.Boolean(), nullable=False),
    sa.Column('cves', sa.JSON(), nullable=False),
    sa.ForeignKeyConstraint(['device_id'], ['device.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_wua_update_device_id', 'wua_update', ['device_id'])
    op.create_table('finding_event',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('finding_id', sa.Integer(), nullable=False),
    sa.Column('device_id', sa.Integer(), nullable=False),
    sa.Column('event', sa.String(length=10), nullable=False),
    sa.Column('at', sa.DateTime(), nullable=False),
    sa.ForeignKeyConstraint(['finding_id'], ['finding.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_finding_event_at', 'finding_event', ['at'])
    op.create_index('ix_finding_event_device_id', 'finding_event', ['device_id'])
    op.create_index('ix_finding_event_finding_id', 'finding_event', ['finding_id'])


def downgrade() -> None:
    op.drop_table('finding_event')
    op.drop_table('wua_update')
    op.drop_table('finding')
    op.drop_table('device_software')
    op.drop_table('device_kb')
    op.drop_table('device')
    op.drop_table('site')
    op.drop_table('client')
    op.drop_index('ix_cpe_match_product', table_name='cpe_match')
