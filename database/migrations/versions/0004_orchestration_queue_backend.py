"""Add orchestration_jobs.queue_backend for Celery/inline dispatch tracking.

Revision ID: 0004_orchestration_queue_backend
Revises: 0003_closed_loop_orchestration
Create Date: 2026-09-06
"""

from alembic import op
import sqlalchemy as sa


revision = "0004_orchestration_queue_backend"
down_revision = "0003_closed_loop_orchestration"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "orchestration_jobs",
        sa.Column("queue_backend", sa.String(length=20), nullable=False, server_default="inline"),
    )


def downgrade() -> None:
    op.drop_column("orchestration_jobs", "queue_backend")
