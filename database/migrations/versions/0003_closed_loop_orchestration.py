"""Add closed-loop orchestration job tracking and validation phase.

Revision ID: 0003_closed_loop_orchestration
Revises: 9f52b13
Create Date: 2026-09-06
"""

from alembic import op
import sqlalchemy as sa


revision = "0003_closed_loop_orchestration"
down_revision = "9f52b13"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Add orchestration_jobs table and validations.phase column."""

    op.add_column(
        "validations",
        sa.Column("phase", sa.String(length=20), nullable=False, server_default="initial"),
    )

    op.create_table(
        "orchestration_jobs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("job_id", sa.String(length=64), nullable=False),
        sa.Column("vulnerability_id", sa.Integer(), sa.ForeignKey("vulnerabilities.id"), nullable=False),
        sa.Column("status", sa.String(length=20), nullable=False, server_default="queued"),
        sa.Column("stage", sa.String(length=40), nullable=False, server_default="assessment"),
        sa.Column("progress", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("message", sa.Text(), nullable=True),
        sa.Column("mock_mode", sa.String(length=10), nullable=False, server_default="false"),
        sa.Column("result_json", sa.JSON(), nullable=True),
        sa.Column("error", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index(
        "ix_orchestration_jobs_job_id",
        "orchestration_jobs",
        ["job_id"],
        unique=True,
    )
    op.create_index(
        "ix_orchestration_jobs_vulnerability_id",
        "orchestration_jobs",
        ["vulnerability_id"],
    )


def downgrade() -> None:
    """Drop orchestration_jobs table and validations.phase column."""

    op.drop_index("ix_orchestration_jobs_vulnerability_id", table_name="orchestration_jobs")
    op.drop_index("ix_orchestration_jobs_job_id", table_name="orchestration_jobs")
    op.drop_table("orchestration_jobs")
    op.drop_column("validations", "phase")
