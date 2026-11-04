"""Intel store (Phase 0). Databases built before Alembic are stamped at this revision.

Revision ID: 0001
Revises: 
"""

from alembic import op
import sqlalchemy as sa

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('cpe_match',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('cve_id', sa.String(length=32), nullable=False),
    sa.Column('criteria', sa.String(length=400), nullable=False),
    sa.Column('part', sa.String(length=1), nullable=False),
    sa.Column('vendor', sa.String(length=120), nullable=False),
    sa.Column('product', sa.String(length=200), nullable=False),
    sa.Column('version', sa.String(length=120), nullable=False),
    sa.Column('target_sw', sa.String(length=80), nullable=False),
    sa.Column('version_start_incl', sa.String(length=120), nullable=True),
    sa.Column('version_start_excl', sa.String(length=120), nullable=True),
    sa.Column('version_end_incl', sa.String(length=120), nullable=True),
    sa.Column('version_end_excl', sa.String(length=120), nullable=True),
    sa.Column('platforms', sa.JSON(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_cpe_match_cve_id', 'cpe_match', ['cve_id'])
    op.create_index('ix_cpe_match_vendor_product', 'cpe_match', ['vendor', 'product'])
    op.create_table('cve',
    sa.Column('id', sa.String(length=32), nullable=False),
    sa.Column('published', sa.DateTime(), nullable=True),
    sa.Column('last_modified', sa.DateTime(), nullable=True),
    sa.Column('status', sa.String(length=32), nullable=True),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('cvss_version', sa.String(length=8), nullable=True),
    sa.Column('cvss_score', sa.Float(), nullable=True),
    sa.Column('cvss_vector', sa.String(length=200), nullable=True),
    sa.Column('severity', sa.String(length=16), nullable=True),
    sa.Column('nvd_kev_added', sa.Date(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('epss',
    sa.Column('cve_id', sa.String(length=32), nullable=False),
    sa.Column('score', sa.Float(), nullable=False),
    sa.Column('percentile', sa.Float(), nullable=False),
    sa.Column('score_date', sa.Date(), nullable=True),
    sa.PrimaryKeyConstraint('cve_id')
    )
    op.create_table('kev',
    sa.Column('cve_id', sa.String(length=32), nullable=False),
    sa.Column('source', sa.String(length=16), nullable=False),
    sa.Column('vendor', sa.String(length=200), nullable=True),
    sa.Column('product', sa.String(length=200), nullable=True),
    sa.Column('name', sa.String(length=400), nullable=True),
    sa.Column('date_added', sa.Date(), nullable=True),
    sa.Column('due_date', sa.Date(), nullable=True),
    sa.Column('ransomware', sa.Boolean(), nullable=False),
    sa.PrimaryKeyConstraint('cve_id', 'source')
    )
    op.create_table('msrc_document',
    sa.Column('id', sa.String(length=16), nullable=False),
    sa.Column('title', sa.String(length=200), nullable=True),
    sa.Column('initial_release', sa.DateTime(), nullable=True),
    sa.Column('current_release', sa.DateTime(), nullable=True),
    sa.Column('synced_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('msrc_fix',
    sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
    sa.Column('doc_id', sa.String(length=16), nullable=False),
    sa.Column('cve_id', sa.String(length=32), nullable=False),
    sa.Column('product_id', sa.String(length=32), nullable=False),
    sa.Column('kb', sa.String(length=64), nullable=True),
    sa.Column('fixed_build', sa.String(length=64), nullable=True),
    sa.Column('supersedes', sa.JSON(), nullable=False),
    sa.Column('subtype', sa.String(length=64), nullable=True),
    sa.Column('url', sa.String(length=400), nullable=True),
    sa.Column('severity', sa.String(length=16), nullable=True),
    sa.Column('impact', sa.String(length=64), nullable=True),
    sa.Column('cvss_score', sa.Float(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_msrc_fix_cve_id', 'msrc_fix', ['cve_id'])
    op.create_index('ix_msrc_fix_doc_id', 'msrc_fix', ['doc_id'])
    op.create_index('ix_msrc_fix_kb', 'msrc_fix', ['kb'])
    op.create_index('ix_msrc_fix_product_id', 'msrc_fix', ['product_id'])
    op.create_table('msrc_product',
    sa.Column('product_id', sa.String(length=32), nullable=False),
    sa.Column('name', sa.String(length=400), nullable=False),
    sa.Column('cpe', sa.String(length=400), nullable=True),
    sa.PrimaryKeyConstraint('product_id')
    )
    op.create_index('ix_msrc_product_name', 'msrc_product', ['name'])
    op.create_table('msrc_vuln',
    sa.Column('cve_id', sa.String(length=32), nullable=False),
    sa.Column('doc_id', sa.String(length=16), nullable=False),
    sa.Column('title', sa.String(length=400), nullable=True),
    sa.Column('exploited', sa.Boolean(), nullable=False),
    sa.Column('publicly_disclosed', sa.Boolean(), nullable=False),
    sa.PrimaryKeyConstraint('cve_id')
    )
    op.create_index('ix_msrc_vuln_doc_id', 'msrc_vuln', ['doc_id'])
    op.create_table('ssvc',
    sa.Column('cve_id', sa.String(length=32), nullable=False),
    sa.Column('found', sa.Boolean(), nullable=False),
    sa.Column('exploitation', sa.String(length=16), nullable=True),
    sa.Column('automatable', sa.String(length=8), nullable=True),
    sa.Column('technical_impact', sa.String(length=16), nullable=True),
    sa.Column('fetched_at', sa.DateTime(), nullable=False),
    sa.PrimaryKeyConstraint('cve_id')
    )
    op.create_table('sync_state',
    sa.Column('source', sa.String(length=32), nullable=False),
    sa.Column('last_started', sa.DateTime(), nullable=True),
    sa.Column('last_success', sa.DateTime(), nullable=True),
    sa.Column('last_status', sa.String(length=16), nullable=True),
    sa.Column('last_error', sa.Text(), nullable=True),
    sa.Column('rows', sa.Integer(), nullable=True),
    sa.Column('cursor', sa.String(length=64), nullable=True),
    sa.PrimaryKeyConstraint('source')
    )
    op.create_table('winget_package',
    sa.Column('id', sa.String(length=200), nullable=False),
    sa.Column('name', sa.String(length=400), nullable=False),
    sa.Column('latest_version', sa.String(length=120), nullable=True),
    sa.Column('norm_names', sa.JSON(), nullable=False),
    sa.Column('norm_publishers', sa.JSON(), nullable=False),
    sa.Column('product_codes', sa.JSON(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    op.drop_table('winget_package')
    op.drop_table('sync_state')
    op.drop_table('ssvc')
    op.drop_table('msrc_vuln')
    op.drop_table('msrc_product')
    op.drop_table('msrc_fix')
    op.drop_table('msrc_document')
    op.drop_table('kev')
    op.drop_table('epss')
    op.drop_table('cve')
    op.drop_table('cpe_match')
