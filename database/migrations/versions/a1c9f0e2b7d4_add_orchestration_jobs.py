
"""Add orchestration fields to the existing queue table.

Revision ID: a1c9f0e2b7d4
Revises: 0004_orchestration_queue_backend
"""

from alembic import op
import sqlalchemy as sa

revision = "a1c9f0e2b7d4"
down_revision = "0004_orchestration_queue_backend"
branch_labels = None
depends_on = None


def upgrade():
    # Preserve the existing orchestration_jobs table and its records.
    op.add_column(
        "orchestration_jobs",
        sa.Column(
            "job_type",
            sa.String(80),
            nullable=False,
            server_default="closed_loop_validation",
        ),
    )
    op.add_column(
        "orchestration_jobs",
        sa.Column("dispatch_backend", sa.String(20), nullable=True),
    )
    op.add_column(
        "orchestration_jobs",
        sa.Column("celery_task_id", sa.String(255), nullable=True),
    )
    op.add_column(
        "orchestration_jobs",
        sa.Column("result_summary", sa.JSON(), nullable=True),
    )
    op.add_column(
        "orchestration_jobs",
        sa.Column("error_message", sa.Text(), nullable=True),
    )

    op.create_index(
        "ix_orchestration_jobs_status",
        "orchestration_jobs",
        ["status"],
    )


def downgrade():
    op.drop_index(
        "ix_orchestration_jobs_status",
        table_name="orchestration_jobs",
    )
    op.drop_column("orchestration_jobs", "error_message")
    op.drop_column("orchestration_jobs", "result_summary")
    op.drop_column("orchestration_jobs", "celery_task_id")
    op.drop_column("orchestration_jobs", "dispatch_backend")
    op.drop_column("orchestration_jobs", "job_type")
