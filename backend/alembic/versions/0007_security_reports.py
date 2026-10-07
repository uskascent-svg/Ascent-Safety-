"""Add private user-submitted security reports and internal analyst notes.

Revision ID: 0007
Revises: 0006
"""

from alembic import op
import sqlalchemy as sa


revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "security_reports",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("report_code", sa.String(length=16), nullable=False),
        sa.Column("reporter_id", sa.Uuid(), nullable=False),
        sa.Column("assigned_to_id", sa.Uuid(), nullable=True),
        sa.Column("issue_type", sa.String(length=32), nullable=False),
        sa.Column("title", sa.String(length=160), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("suspicious_url", sa.String(length=2048), nullable=True),
        sa.Column("source_location", sa.String(length=120), nullable=True),
        sa.Column("reported_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("severity", sa.String(length=16), nullable=False),
        sa.Column("additional_notes", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=24), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.CheckConstraint(
            "issue_type IN ('phishing_website', 'suspicious_url', 'malicious_email', 'scam_message', 'malware', 'credential_theft', 'impersonation', 'suspicious_attachment', 'other')",
            name="ck_security_reports_type",
        ),
        sa.CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name="ck_security_reports_severity",
        ),
        sa.CheckConstraint(
            "status IN ('submitted', 'under_review', 'investigating', 'resolved', 'false_positive', 'reopened')",
            name="ck_security_reports_status",
        ),
        sa.ForeignKeyConstraint(["reporter_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["assigned_to_id"], ["users.id"], ondelete="SET NULL"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("report_code"),
    )
    op.create_index("ix_security_reports_report_code", "security_reports", ["report_code"], unique=True)
    op.create_index("ix_security_reports_reporter_id", "security_reports", ["reporter_id"])
    op.create_index("ix_security_reports_assigned_to_id", "security_reports", ["assigned_to_id"])
    op.create_index("ix_security_reports_issue_type", "security_reports", ["issue_type"])
    op.create_index("ix_security_reports_severity", "security_reports", ["severity"])
    op.create_index("ix_security_reports_status", "security_reports", ["status"])
    op.create_index("ix_security_reports_status_created", "security_reports", ["status", "created_at"])

    op.create_table(
        "security_report_notes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("report_id", sa.Uuid(), nullable=False),
        sa.Column("author_id", sa.Uuid(), nullable=False),
        sa.Column("content", sa.String(length=2000), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["report_id"], ["security_reports.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["author_id"], ["users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_security_report_notes_report_id", "security_report_notes", ["report_id"])
    op.create_index("ix_security_report_notes_author_id", "security_report_notes", ["author_id"])


def downgrade() -> None:
    op.drop_index("ix_security_report_notes_author_id", table_name="security_report_notes")
    op.drop_index("ix_security_report_notes_report_id", table_name="security_report_notes")
    op.drop_table("security_report_notes")
    op.drop_index("ix_security_reports_status_created", table_name="security_reports")
    for name in (
        "ix_security_reports_status",
        "ix_security_reports_severity",
        "ix_security_reports_issue_type",
        "ix_security_reports_assigned_to_id",
        "ix_security_reports_reporter_id",
        "ix_security_reports_report_code",
    ):
        op.drop_index(name, table_name="security_reports")
    op.drop_table("security_reports")
