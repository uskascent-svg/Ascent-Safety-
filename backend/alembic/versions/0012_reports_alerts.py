"""Anonymous report tracking and cyber alert declarations.

Revision ID: 0012
Revises: 0011
"""

from alembic import op
import sqlalchemy as sa

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("security_reports") as batch:
        batch.alter_column("reporter_id", existing_type=sa.Uuid(), nullable=True)
        batch.add_column(sa.Column("anonymous_token_hash", sa.String(length=64), nullable=True))
        batch.add_column(sa.Column("published_event_id", sa.Uuid(), nullable=True))
        batch.create_index(
            "ix_security_reports_published_event_id", ["published_event_id"], unique=True
        )
        batch.create_foreign_key(
            "fk_security_reports_published_event_id_security_events",
            "security_events",
            ["published_event_id"],
            ["id"],
            ondelete="SET NULL",
        )

    op.create_table(
        "cyber_alert_declarations",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column("title", sa.String(200), nullable=False),
        sa.Column("severity", sa.String(16), nullable=False, index=True),
        sa.Column("threat_type", sa.String(32), nullable=False, index=True),
        sa.Column("affected_region", sa.String(120), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column("recommended_actions", sa.JSON(), nullable=False),
        sa.Column("related_event_ids", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False, index=True),
        sa.Column(
            "created_by_id",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "approved_by_id",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "published_by_id",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "published_event_id",
            sa.Uuid(),
            sa.ForeignKey("security_events.id", ondelete="SET NULL"),
            nullable=True,
            unique=True,
        ),
        sa.Column("latitude", sa.Float(), nullable=True),
        sa.Column("longitude", sa.Float(), nullable=True),
        sa.Column("location_status", sa.String(20), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False, index=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.Column(
            "updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )
    op.create_table(
        "cyber_alert_activities",
        sa.Column("id", sa.Uuid(), primary_key=True),
        sa.Column(
            "declaration_id",
            sa.Uuid(),
            sa.ForeignKey("cyber_alert_declarations.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
        sa.Column(
            "actor_id",
            sa.Uuid(),
            sa.ForeignKey("users.id", ondelete="SET NULL"),
            nullable=True,
            index=True,
        ),
        sa.Column("action", sa.String(32), nullable=False),
        sa.Column("changes", sa.JSON(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
    )


def downgrade() -> None:
    op.drop_table("cyber_alert_activities")
    op.drop_table("cyber_alert_declarations")
    with op.batch_alter_table("security_reports") as batch:
        batch.drop_constraint(
            "fk_security_reports_published_event_id_security_events", type_="foreignkey"
        )
        batch.drop_index("ix_security_reports_published_event_id")
        batch.drop_column("published_event_id")
        batch.drop_column("anonymous_token_hash")
        batch.alter_column("reporter_id", existing_type=sa.Uuid(), nullable=False)
