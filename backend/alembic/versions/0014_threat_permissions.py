"""Add narrowly scoped threat monitoring and operation roles.

Revision ID: 0014
Revises: 0013
"""

from alembic import op
import sqlalchemy as sa


revision = "0014"
down_revision = "0013"
branch_labels = None
depends_on = None

ROLE_NAMES = ("THREAT_MONITOR", "THREAT_DATA_REVIEWER", "THREAT_MODEL_OPERATOR")


def upgrade() -> None:
    roles = sa.table("roles", sa.column("name", sa.String(32)))
    op.get_bind().execute(sa.insert(roles).values([{"name": name} for name in ROLE_NAMES]))


def downgrade() -> None:
    roles = sa.table("roles", sa.column("name", sa.String(32)))
    op.get_bind().execute(sa.delete(roles).where(roles.c.name.in_(ROLE_NAMES)))
