"""Track the sanitized event promoted from a reviewed user report.

Revision ID: 0008
Revises: 0007
"""

from alembic import op
import sqlalchemy as sa


revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("security_reports", sa.Column("promoted_event_id", sa.Uuid(), nullable=True))
    op.create_foreign_key(
        "fk_security_reports_promoted_event_id_security_events",
        "security_reports",
        "security_events",
        ["promoted_event_id"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_index(
        "ix_security_reports_promoted_event_id",
        "security_reports",
        ["promoted_event_id"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_security_reports_promoted_event_id", table_name="security_reports")
    op.drop_constraint(
        "fk_security_reports_promoted_event_id_security_events",
        "security_reports",
        type_="foreignkey",
    )
    op.drop_column("security_reports", "promoted_event_id")
