"""Digital Twin Generator: twin_instances, twin_registry, legacy_profiles, twin_logs

Revision ID: tg_20260720_01
Revises: <SET_TO_CURRENT_HEAD>
Create Date: 2026-07-20

NOTE: Set `down_revision` below to whatever the current head revision is in
the existing AutoSecTwin migration chain before running `alembic upgrade
head`. This migration only adds new tables; it does not touch any existing
schema, per module scope.
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "tg_20260720_01"
down_revision: Union[str, None] = "0002_trust_legacy_extensions"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "twin_instances",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "uuid",
            postgresql.UUID(as_uuid=True),
            nullable=False,
            unique=True,
        ),
        sa.Column("host", sa.String(length=255), nullable=True),
        sa.Column("cve", sa.String(length=32), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="pending"),
        sa.Column("environment", sa.String(length=10), nullable=False),
        sa.Column("twin_image", sa.String(length=255), nullable=True),
        sa.Column("vm_name", sa.String(length=255), nullable=True),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("network", sa.String(length=255), nullable=True),
        sa.Column("health", sa.String(length=10), nullable=False, server_default="unknown"),
        sa.Column("legacy_flag", sa.String(length=10), nullable=False, server_default="unknown"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("destroy_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_twin_instances_cve", "twin_instances", ["cve"])
    op.create_index("ix_twin_instances_status", "twin_instances", ["status"])
    op.create_index("ix_twin_instances_uuid", "twin_instances", ["uuid"], unique=True)

    op.create_table(
        "twin_registry",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("cve", sa.String(length=32), nullable=False),
        sa.Column("image", sa.String(length=255), nullable=False),
        sa.Column("environment", sa.String(length=10), nullable=True),
        sa.Column("version", sa.String(length=64), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.UniqueConstraint("cve", "image", "version", name="uq_twin_registry_cve_image_version"),
    )
    op.create_table(
        "twin_logs",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column(
            "twin_id",
            sa.Integer(),
            sa.ForeignKey("twin_instances.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("event", sa.String(length=32), nullable=False),
        sa.Column("details", sa.Text(), nullable=True),
    )
    op.create_index("ix_twin_logs_twin_id", "twin_logs", ["twin_id"])
    op.create_index("ix_twin_logs_timestamp", "twin_logs", ["timestamp"])


def downgrade() -> None:
    op.drop_index("ix_twin_logs_timestamp", table_name="twin_logs")
    op.drop_index("ix_twin_logs_twin_id", table_name="twin_logs")
    op.drop_table("twin_logs")

    op.drop_index("ix_twin_registry_cve", table_name="twin_registry")
    op.drop_table("twin_registry")

    op.drop_index("ix_twin_instances_uuid", table_name="twin_instances")
    op.drop_index("ix_twin_instances_status", table_name="twin_instances")
    op.drop_index("ix_twin_instances_cve", table_name="twin_instances")
    op.drop_table("twin_instances")
