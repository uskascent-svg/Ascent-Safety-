"""Cache coarse place-name lookup results.

Revision ID: 0010
Revises: 0009
"""

from alembic import op
import sqlalchemy as sa


revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "geocode_cache",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("query_hash", sa.String(length=64), nullable=False),
        sa.Column("results", sa.JSON(), nullable=False),
        sa.Column("fetched_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("query_hash", name="uq_geocode_cache_query_hash"),
    )
    op.create_index("ix_geocode_cache_expires_at", "geocode_cache", ["expires_at"])


def downgrade() -> None:
    op.drop_index("ix_geocode_cache_expires_at", table_name="geocode_cache")
    op.drop_table("geocode_cache")
