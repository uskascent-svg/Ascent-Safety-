"""Persist detector provenance for hybrid threat analyses.

Revision ID: 0015
Revises: 0014
"""

from alembic import op
import sqlalchemy as sa


revision = "0015"
down_revision = "0014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "threat_analyses",
        sa.Column("detector_mode", sa.String(16), server_default="rules_only", nullable=False),
    )
    op.add_column("threat_analyses", sa.Column("model_version", sa.String(80), nullable=True))
    op.add_column("threat_analyses", sa.Column("model_family", sa.String(40), nullable=True))
    op.add_column("threat_analyses", sa.Column("model_confidence", sa.Float(), nullable=True))
    op.add_column("threat_analyses", sa.Column("combined_score", sa.Integer(), nullable=True))
    op.add_column("threat_model_versions", sa.Column("model_family", sa.String(40), nullable=True))


def downgrade() -> None:
    op.drop_column("threat_model_versions", "model_family")
    op.drop_column("threat_analyses", "combined_score")
    op.drop_column("threat_analyses", "model_confidence")
    op.drop_column("threat_analyses", "model_family")
    op.drop_column("threat_analyses", "model_version")
    op.drop_column("threat_analyses", "detector_mode")
