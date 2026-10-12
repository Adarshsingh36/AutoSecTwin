
"""Allow new orchestration jobs to omit the legacy job_id.

Revision ID: d4f7a2c9e610
Revises: c3e5b8a1d9f2
"""

from alembic import op
import sqlalchemy as sa

revision = "d4f7a2c9e610"
down_revision = "c3e5b8a1d9f2"
branch_labels = None
depends_on = None


def upgrade():
    op.alter_column(
        "orchestration_jobs",
        "job_id",
        existing_type=sa.String(),
        nullable=True,
    )


def downgrade():
    # Refuse to restore NOT NULL if any new rows have no legacy job_id.
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (
                SELECT 1 FROM orchestration_jobs WHERE job_id IS NULL
            ) THEN
                RAISE EXCEPTION
                    'Cannot restore NOT NULL: orchestration_jobs contains NULL job_id values';
            END IF;
        END $$;
        """
    )
    op.alter_column(
        "orchestration_jobs",
        "job_id",
        existing_type=sa.String(),
        nullable=False,
    )
