"""extend_asset_for_twin_provisioning

Revision ID: 77af561a9597
Revises: tg_20260720_01
Create Date: 2026-07-30 12:29:53.741227
"""

from alembic import op
import sqlalchemy as sa



revision = '77af561a9597'
down_revision = 'tg_20260720_01'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column(
    "assets",
    sa.Column("hostname", sa.String(length=255), nullable=True)
    )

    op.add_column(
    "assets",
    sa.Column("ip_address", sa.String(length=45), nullable=True)
    )

    op.add_column(
    "assets",
    sa.Column("operating_system", sa.String(length=120), nullable=True)
    )

    op.add_column(
    "assets",
    sa.Column("software", sa.String(length=255), nullable=True)
    )

    op.add_column(
    "assets",
    sa.Column("version", sa.String(length=120), nullable=True)
    )


def downgrade():
    op.drop_column("assets", "version")
    op.drop_column("assets", "software")
    op.drop_column("assets", "operating_system")
    op.drop_column("assets", "ip_address")
    op.drop_column("assets", "hostname")