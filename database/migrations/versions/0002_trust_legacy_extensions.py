"""Add trust, drift, legacy, and specialist-review tables.

Revision ID: 0002_trust_legacy_extensions
Revises: 0001_initial_autosectwin_schema
Create Date: 2026-07-20
"""

from alembic import op
import sqlalchemy as sa


revision = "0002_trust_legacy_extensions"
down_revision = "0001_initial_autosectwin_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create additive trust and legacy extension tables."""

    op.create_table(
        "trust_metrics",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("vulnerability_id", sa.Integer(), sa.ForeignKey("vulnerabilities.id"), nullable=True),
        sa.Column("prediction_score", sa.Float(), nullable=False),
        sa.Column("validation_score", sa.Float(), nullable=False),
        sa.Column("agreement", sa.Boolean(), nullable=False),
        sa.Column("trust_score", sa.Float(), nullable=False),
        sa.Column("shap_explanation", sa.JSON(), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "hallucination_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("vulnerability_id", sa.Integer(), sa.ForeignKey("vulnerabilities.id"), nullable=True),
        sa.Column("prediction_score", sa.Float(), nullable=False),
        sa.Column("validation_score", sa.Float(), nullable=False),
        sa.Column("severity", sa.String(length=40), nullable=False),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("review_status", sa.String(length=40), nullable=False, server_default="pending"),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "agreement_history",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("model_name", sa.String(length=120), nullable=False, server_default="exploitability"),
        sa.Column("agreement_rate", sa.Float(), nullable=False),
        sa.Column("sample_size", sa.Integer(), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "model_drift",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("model_name", sa.String(length=120), nullable=False, server_default="exploitability"),
        sa.Column("drift_score", sa.Float(), nullable=False),
        sa.Column("baseline_agreement", sa.Float(), nullable=False),
        sa.Column("current_agreement", sa.Float(), nullable=False),
        sa.Column("retraining_recommended", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "legacy_profiles",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id"), nullable=True),
        sa.Column("vendor", sa.String(length=120), nullable=False),
        sa.Column("product", sa.String(length=160), nullable=False),
        sa.Column("version", sa.String(length=80), nullable=True),
        sa.Column("fingerprint", sa.String(length=255), nullable=False),
        sa.Column("unsupported", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("eol", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("support_status", sa.String(length=80), nullable=False),
        sa.Column("legacy_penalty", sa.Float(), nullable=False),
        sa.Column("compensating_controls", sa.JSON(), nullable=False),
        sa.Column("route_to_specialist", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "specialist_queue",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("legacy_profile_id", sa.Integer(), sa.ForeignKey("legacy_profiles.id"), nullable=True),
        sa.Column("queue_type", sa.String(length=80), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False, server_default="pending"),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )


def downgrade() -> None:
    """Drop additive trust and legacy extension tables."""

    for table in [
        "specialist_queue",
        "legacy_profiles",
        "model_drift",
        "agreement_history",
        "hallucination_logs",
        "trust_metrics",
    ]:
        op.drop_table(table)
