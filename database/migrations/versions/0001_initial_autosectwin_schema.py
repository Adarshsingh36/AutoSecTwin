"""Initial AutoSecTwin ASDE schema.

Revision ID: 0001_initial_autosectwin_schema
Revises:
Create Date: 2026-06-23
"""

from alembic import op
import sqlalchemy as sa


revision = "0001_initial_autosectwin_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create the MySQL schema for the ASDE subsystem."""

    op.create_table(
        "assets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("asset_type", sa.String(length=80), nullable=False),
        sa.Column("owner", sa.String(length=120), nullable=True),
        sa.Column("environment", sa.String(length=80), nullable=True),
        sa.Column("exposure", sa.Float(), nullable=False, server_default="0"),
        sa.Column("criticality", sa.Float(), nullable=False, server_default="0"),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id"), nullable=True),
        sa.Column("cve_id", sa.String(length=50), nullable=False, unique=True),
        sa.Column("title", sa.String(length=255), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("epss_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("severity", sa.String(length=20), nullable=False, server_default="UNKNOWN"),
        sa.Column("exploitability_probability", sa.Float(), nullable=False, server_default="0"),
        sa.Column("threat_intelligence_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("exposure_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("asset_criticality", sa.Float(), nullable=False, server_default="0"),
        sa.Column("kev_listed", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_table(
        "twins",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id"), nullable=True),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("provider", sa.String(length=80), nullable=False),
        sa.Column("status", sa.String(length=40), nullable=False, server_default="requested"),
        sa.Column("topology", sa.JSON(), nullable=True),
        sa.Column("endpoint", sa.String(length=500), nullable=True),
        sa.Column("notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "exploits",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("vulnerability_id", sa.Integer(), sa.ForeignKey("vulnerabilities.id"), nullable=False),
        sa.Column("source", sa.String(length=80), nullable=False),
        sa.Column("external_id", sa.String(length=120), nullable=True),
        sa.Column("module_name", sa.String(length=255), nullable=True),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("reliability_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("requires_auth", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("metadata_json", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "validations",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("vulnerability_id", sa.Integer(), sa.ForeignKey("vulnerabilities.id"), nullable=False),
        sa.Column("exploit_id", sa.Integer(), sa.ForeignKey("exploits.id"), nullable=True),
        sa.Column("twin_id", sa.Integer(), sa.ForeignKey("twins.id"), nullable=True),
        sa.Column("status", sa.String(length=40), nullable=False, server_default="pending"),
        sa.Column("validation_score", sa.Float(), nullable=False, server_default="0"),
        sa.Column("evidence", sa.JSON(), nullable=True),
        sa.Column("analysis", sa.Text(), nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table(
        "confidences",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("vulnerability_id", sa.Integer(), sa.ForeignKey("vulnerabilities.id"), nullable=False),
        sa.Column("exploitability_probability", sa.Float(), nullable=False),
        sa.Column("validation_score", sa.Float(), nullable=False),
        sa.Column("exposure_score", sa.Float(), nullable=False),
        sa.Column("threat_intelligence_score", sa.Float(), nullable=False),
        sa.Column("asset_criticality", sa.Float(), nullable=False),
        sa.Column("fused_confidence", sa.Float(), nullable=False),
        sa.Column("weights", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_table("approvals", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("vulnerability_id", sa.Integer(), sa.ForeignKey("vulnerabilities.id"), nullable=False), sa.Column("requested_action", sa.String(length=120), nullable=False), sa.Column("status", sa.String(length=40), nullable=False, server_default="pending"), sa.Column("requested_by", sa.String(length=120), nullable=True), sa.Column("decided_by", sa.String(length=120), nullable=True), sa.Column("decision_reason", sa.Text(), nullable=True), sa.Column("context", sa.JSON(), nullable=True), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False), sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True))
    op.create_table("recommendations", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("vulnerability_id", sa.Integer(), sa.ForeignKey("vulnerabilities.id"), nullable=False), sa.Column("recommendation_type", sa.String(length=50), nullable=False), sa.Column("title", sa.String(length=255), nullable=False), sa.Column("content", sa.Text(), nullable=False), sa.Column("provider", sa.String(length=80), nullable=False, server_default="rule_based"), sa.Column("metadata_json", sa.JSON(), nullable=True), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False))
    op.create_table("remediations", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("vulnerability_id", sa.Integer(), sa.ForeignKey("vulnerabilities.id"), nullable=False), sa.Column("recommendation_id", sa.Integer(), sa.ForeignKey("recommendations.id"), nullable=True), sa.Column("status", sa.String(length=40), nullable=False, server_default="planned"), sa.Column("action", sa.Text(), nullable=False), sa.Column("applied_by", sa.String(length=120), nullable=True), sa.Column("verification_score", sa.Float(), nullable=False, server_default="0"), sa.Column("evidence", sa.JSON(), nullable=True), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False), sa.Column("applied_at", sa.DateTime(timezone=True), nullable=True), sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True))
    op.create_table("reports", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("vulnerability_id", sa.Integer(), sa.ForeignKey("vulnerabilities.id"), nullable=True), sa.Column("report_type", sa.String(length=60), nullable=False), sa.Column("title", sa.String(length=255), nullable=False), sa.Column("content", sa.Text(), nullable=False), sa.Column("format", sa.String(length=30), nullable=False, server_default="json"), sa.Column("metadata_json", sa.JSON(), nullable=True), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False))
    op.create_table("audits", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("actor", sa.String(length=120), nullable=True), sa.Column("action", sa.String(length=120), nullable=False), sa.Column("entity_type", sa.String(length=80), nullable=False), sa.Column("entity_id", sa.Integer(), nullable=True), sa.Column("details", sa.JSON(), nullable=True), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False))
    op.create_table("learning_events", sa.Column("id", sa.Integer(), primary_key=True), sa.Column("event_type", sa.String(length=80), nullable=False), sa.Column("source", sa.String(length=120), nullable=False), sa.Column("label", sa.String(length=80), nullable=True), sa.Column("confidence_before", sa.Float(), nullable=True), sa.Column("confidence_after", sa.Float(), nullable=True), sa.Column("payload", sa.JSON(), nullable=True), sa.Column("notes", sa.Text(), nullable=True), sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False))


def downgrade() -> None:
    """Drop the ASDE schema."""

    for table in [
        "learning_events",
        "audits",
        "reports",
        "remediations",
        "recommendations",
        "approvals",
        "confidences",
        "validations",
        "exploits",
        "twins",
        "vulnerabilities",
        "assets",
    ]:
        op.drop_table(table)
