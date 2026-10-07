"""Add explicit optional security-event route coordinates.

Revision ID: 0006
Revises: 0005
"""

from alembic import op
import sqlalchemy as sa


revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


CONSTRAINTS = (
    ("ck_security_events_origin_pair", "(origin_latitude IS NULL) = (origin_longitude IS NULL)"),
    ("ck_security_events_origin_lat", "origin_latitude BETWEEN -90 AND 90"),
    ("ck_security_events_origin_lng", "origin_longitude BETWEEN -180 AND 180"),
    (
        "ck_security_events_destination_pair",
        "(destination_latitude IS NULL) = (destination_longitude IS NULL)",
    ),
    ("ck_security_events_destination_lat", "destination_latitude BETWEEN -90 AND 90"),
    ("ck_security_events_destination_lng", "destination_longitude BETWEEN -180 AND 180"),
)


def upgrade() -> None:
    op.add_column("security_events", sa.Column("origin_latitude", sa.Float(), nullable=True))
    op.add_column("security_events", sa.Column("origin_longitude", sa.Float(), nullable=True))
    op.add_column("security_events", sa.Column("destination_latitude", sa.Float(), nullable=True))
    op.add_column("security_events", sa.Column("destination_longitude", sa.Float(), nullable=True))

    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("security_events") as batch:
            for name, expression in CONSTRAINTS:
                batch.create_check_constraint(name, expression)
    else:
        for name, expression in CONSTRAINTS:
            op.create_check_constraint(name, "security_events", expression)


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "sqlite":
        with op.batch_alter_table("security_events") as batch:
            for name, _ in reversed(CONSTRAINTS):
                batch.drop_constraint(name, type_="check")
    else:
        for name, _ in reversed(CONSTRAINTS):
            op.drop_constraint(name, "security_events", type_="check")

    op.drop_column("security_events", "destination_longitude")
    op.drop_column("security_events", "destination_latitude")
    op.drop_column("security_events", "origin_longitude")
    op.drop_column("security_events", "origin_latitude")
