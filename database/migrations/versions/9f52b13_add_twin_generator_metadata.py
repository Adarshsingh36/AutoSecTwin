"""add_twin_generator_metadata

Revision ID: 9f52b13
Revises: <YOUR_PREVIOUS_REVISION>
Create Date: 2026-07-30
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = "9f52b13"
down_revision = "77af561a9597"
branch_labels = None
depends_on = None


def upgrade():

    op.add_column(
        "twins",
        sa.Column("external_twin_id", sa.Integer(), nullable=True),
    )

    op.add_column(
        "twins",
        sa.Column("external_uuid", sa.String(length=64), nullable=True),
    )

    op.add_column(
        "twins",
        sa.Column("environment", sa.String(length=20), nullable=True),
    )

    op.add_column(
        "twins",
        sa.Column("ip_address", sa.String(length=50), nullable=True),
    )

    op.add_column(
        "twins",
        sa.Column("network", sa.String(length=100), nullable=True),
    )

    op.add_column(
        "twins",
        sa.Column("twin_image", sa.String(length=255), nullable=True),
    )

    op.add_column(
        "twins",
        sa.Column("vm_name", sa.String(length=255), nullable=True),
    )

    op.add_column(
        "twins",
        sa.Column("health", sa.String(length=30), nullable=True),
    )

    op.add_column(
        "twins",
        sa.Column("legacy_flag", sa.String(length=30), nullable=True),
    )

    op.add_column(
        "twins",
        sa.Column("destroy_at", sa.DateTime(timezone=True), nullable=True),
    )


def downgrade():

    op.drop_column("twins", "destroy_at")
    op.drop_column("twins", "legacy_flag")
    op.drop_column("twins", "health")
    op.drop_column("twins", "vm_name")
    op.drop_column("twins", "twin_image")
    op.drop_column("twins", "network")
    op.drop_column("twins", "ip_address")
    op.drop_column("twins", "environment")
    op.drop_column("twins", "external_uuid")
    op.drop_column("twins", "external_twin_id")