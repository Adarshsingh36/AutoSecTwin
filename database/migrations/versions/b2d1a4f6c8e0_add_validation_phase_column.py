
"""Validation phase already exists from migration 0003.

Revision ID: b2d1a4f6c8e0
Revises: a1c9f0e2b7d4
"""

revision = "b2d1a4f6c8e0"
down_revision = "a1c9f0e2b7d4"
branch_labels = None
depends_on = None


def upgrade():
    # Migration 0003_closed_loop_orchestration already adds validations.phase.
    pass


def downgrade():
    # Keep the existing phase column; it belongs to migration 0003.
    pass
