"""Persist account-scoped threat triage results without submitted content.

Revision ID: 0013
Revises: 0012
"""

from alembic import op
import sqlalchemy as sa


revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "threat_analyses",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("content_sha256", sa.String(64), nullable=False),
        sa.Column("input_kind", sa.String(16), nullable=False),
        sa.Column("verdict", sa.String(16), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False),
        sa.Column("heuristic_score", sa.Integer(), nullable=False),
        sa.Column("completeness", sa.String(16), nullable=False),
        sa.Column("findings", sa.JSON(), nullable=False),
        sa.Column("explanation", sa.Text(), nullable=False),
        sa.Column("remediation", sa.Text(), nullable=False),
        sa.Column(
            "extraction_status", sa.String(16), nullable=False, server_default="not_applicable"
        ),
        sa.Column("extraction_notes", sa.JSON(), nullable=False, server_default="[]"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_threat_analyses_user_id", "threat_analyses", ["user_id"])
    op.create_index("ix_threat_analyses_created_at", "threat_analyses", ["created_at"])
    op.create_index("ix_threat_analyses_verdict", "threat_analyses", ["verdict"])
    op.create_index(
        "ix_threat_analyses_created_verdict", "threat_analyses", ["created_at", "verdict"]
    )
    op.create_table(
        "threat_analysis_feedback",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("analysis_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("candidate_label", sa.String(16), nullable=False),
        sa.Column("reason", sa.String(2000), nullable=False),
        sa.Column("training_sample_encrypted", sa.Text(), nullable=True),
        sa.Column("status", sa.String(16), server_default="pending", nullable=False),
        sa.Column("reviewed_by_id", sa.Uuid(), nullable=True),
        sa.Column("review_note", sa.String(2000), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["analysis_id"], ["threat_analyses.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["reviewed_by_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("analysis_id", "user_id", name="uq_threat_feedback_analysis_user"),
    )
    op.create_index(
        "ix_threat_feedback_status_created", "threat_analysis_feedback", ["status", "created_at"]
    )
    op.create_table(
        "threat_training_jobs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("requested_by_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(16), server_default="queued", nullable=False),
        sa.Column("message", sa.String(500), nullable=False),
        sa.Column("sample_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("metrics", sa.JSON(), nullable=True),
        sa.Column("model_version_id", sa.Uuid(), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(["requested_by_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "threat_model_versions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.String(80), nullable=False, unique=True),
        sa.Column("state", sa.String(16), server_default="candidate", nullable=False),
        sa.Column("artifact_path", sa.String(500), nullable=False),
        sa.Column("sha256", sa.String(64), nullable=False),
        sa.Column("signature", sa.String(64), nullable=False),
        sa.Column("metrics", sa.JSON(), nullable=False),
        sa.Column("created_by_id", sa.Uuid(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["created_by_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_threat_model_versions_state_created",
        "threat_model_versions",
        ["state", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_threat_model_versions_state_created", table_name="threat_model_versions")
    op.drop_table("threat_model_versions")
    op.drop_table("threat_training_jobs")
    op.drop_index("ix_threat_feedback_status_created", table_name="threat_analysis_feedback")
    op.drop_table("threat_analysis_feedback")
    op.drop_index("ix_threat_analyses_created_verdict", table_name="threat_analyses")
    op.drop_index("ix_threat_analyses_verdict", table_name="threat_analyses")
    op.drop_index("ix_threat_analyses_created_at", table_name="threat_analyses")
    op.drop_index("ix_threat_analyses_user_id", table_name="threat_analyses")
    op.drop_table("threat_analyses")
