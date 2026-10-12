"""remediation_approval_twin_linkage

Revision ID: c3e5b8a1d9f2
Revises: b2d1a4f6c8e0
Create Date: 2026-09-30

Additive only -- no existing column is modified or dropped. Completes the
traceability chain the remediation work depends on:

    Vulnerability -> Recommendation -> Approval -> Remediation
        -> target Twin -> Execution -> Revalidation

remediations gains:
    target_twin_id          (FK -> twins.id, nullable)
    executor, handler       (which executor/handler class actually ran)
    execution_authorized    (first-class, not buried in the evidence JSON)
    target_modified         (first-class -- this is the field the whole
                             "dry-run" problem is about)
    execution_started_at / execution_completed_at

approvals gains:
    recommendation_id, target_twin_id, remediation_id -- so an approval
    request can be traced forward to the remediation it authorized, and a
    remediation traced back to who approved it and against what twin.

All new columns are nullable (or boolean with a safe default) so existing
rows remain valid; the application layer (not the schema) is what refuses
to execute a remediation that has no target_twin_id.

Uses batch_alter_table rather than plain add_column: SQLite cannot ALTER a
table to add a column with an inline FOREIGN KEY constraint directly (only
full-table copy/rebuild, which is what batch mode does for you); Postgres
handles both forms identically, so batch mode is used everywhere for one
code path that behaves correctly on both.
"""

from alembic import op
import sqlalchemy as sa

# revision identifiers
revision = "c3e5b8a1d9f2"
down_revision = "b2d1a4f6c8e0"
branch_labels = None
depends_on = None


def upgrade():

    # --- remediations ---------------------------------------------------

    with op.batch_alter_table("remediations") as batch_op:
        batch_op.add_column(
            sa.Column("target_twin_id", sa.Integer(), nullable=True)
        )
        batch_op.add_column(sa.Column("executor", sa.String(length=120), nullable=True))
        batch_op.add_column(sa.Column("handler", sa.String(length=120), nullable=True))
        batch_op.add_column(
            sa.Column(
                "execution_authorized",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )
        batch_op.add_column(
            sa.Column(
                "target_modified",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )
        batch_op.add_column(
            sa.Column("execution_started_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.add_column(
            sa.Column("execution_completed_at", sa.DateTime(timezone=True), nullable=True)
        )
        batch_op.create_foreign_key(
            "fk_remediations_target_twin_id_twins",
            "twins",
            ["target_twin_id"],
            ["id"],
        )
        batch_op.create_index("ix_remediations_target_twin_id", ["target_twin_id"])
        batch_op.create_index("ix_remediations_status", ["status"])

    # --- approvals --------------------------------------------------------

    with op.batch_alter_table("approvals") as batch_op:
        batch_op.add_column(
            sa.Column("recommendation_id", sa.Integer(), nullable=True)
        )
        batch_op.add_column(sa.Column("target_twin_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("remediation_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_approvals_recommendation_id_recommendations",
            "recommendations",
            ["recommendation_id"],
            ["id"],
        )
        batch_op.create_foreign_key(
            "fk_approvals_target_twin_id_twins",
            "twins",
            ["target_twin_id"],
            ["id"],
        )
        batch_op.create_foreign_key(
            "fk_approvals_remediation_id_remediations",
            "remediations",
            ["remediation_id"],
            ["id"],
        )
        batch_op.create_index("ix_approvals_recommendation_id", ["recommendation_id"])
        batch_op.create_index("ix_approvals_target_twin_id", ["target_twin_id"])
        batch_op.create_index("ix_approvals_remediation_id", ["remediation_id"])


def downgrade():

    with op.batch_alter_table("approvals") as batch_op:
        batch_op.drop_index("ix_approvals_remediation_id")
        batch_op.drop_index("ix_approvals_target_twin_id")
        batch_op.drop_index("ix_approvals_recommendation_id")
        batch_op.drop_constraint(
            "fk_approvals_remediation_id_remediations", type_="foreignkey"
        )
        batch_op.drop_constraint(
            "fk_approvals_target_twin_id_twins", type_="foreignkey"
        )
        batch_op.drop_constraint(
            "fk_approvals_recommendation_id_recommendations", type_="foreignkey"
        )
        batch_op.drop_column("remediation_id")
        batch_op.drop_column("target_twin_id")
        batch_op.drop_column("recommendation_id")

    with op.batch_alter_table("remediations") as batch_op:
        batch_op.drop_index("ix_remediations_status")
        batch_op.drop_index("ix_remediations_target_twin_id")
        batch_op.drop_constraint(
            "fk_remediations_target_twin_id_twins", type_="foreignkey"
        )
        batch_op.drop_column("execution_completed_at")
        batch_op.drop_column("execution_started_at")
        batch_op.drop_column("target_modified")
        batch_op.drop_column("execution_authorized")
        batch_op.drop_column("handler")
        batch_op.drop_column("executor")
        batch_op.drop_column("target_twin_id")
