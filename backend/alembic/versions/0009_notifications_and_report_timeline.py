"""Persist analyst notifications and report lifecycle history.

Revision ID: 0009
Revises: 0008
"""

from alembic import op
import sqlalchemy as sa


revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "security_report_activities",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("report_id", sa.Uuid(), nullable=False),
        sa.Column("actor_id", sa.Uuid(), nullable=True),
        sa.Column("action", sa.String(length=40), nullable=False),
        sa.Column("summary", sa.String(length=240), nullable=False),
        sa.Column("is_public", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["report_id"], ["security_reports.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["actor_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_security_report_activities_report_id", "security_report_activities", ["report_id"]
    )
    op.create_index(
        "ix_security_report_activities_actor_id", "security_report_activities", ["actor_id"]
    )
    op.create_index(
        "ix_report_activity_report_created",
        "security_report_activities",
        ["report_id", "created_at"],
    )

    op.create_table(
        "user_notifications",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("event_id", sa.Uuid(), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["event_id"], ["security_events.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "event_id", name="uq_user_notifications_user_event"),
    )
    op.create_index("ix_user_notifications_user_id", "user_notifications", ["user_id"])
    op.create_index("ix_user_notifications_event_id", "user_notifications", ["event_id"])
    op.create_index(
        "ix_user_notifications_user_read_created",
        "user_notifications",
        ["user_id", "read_at", "created_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_user_notifications_user_read_created", table_name="user_notifications")
    op.drop_index("ix_user_notifications_event_id", table_name="user_notifications")
    op.drop_index("ix_user_notifications_user_id", table_name="user_notifications")
    op.drop_table("user_notifications")
    op.drop_index("ix_report_activity_report_created", table_name="security_report_activities")
    op.drop_index("ix_security_report_activities_actor_id", table_name="security_report_activities")
    op.drop_index(
        "ix_security_report_activities_report_id", table_name="security_report_activities"
    )
    op.drop_table("security_report_activities")
