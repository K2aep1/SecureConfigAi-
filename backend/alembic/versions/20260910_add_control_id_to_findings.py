"""Add stable control identifiers to findings.

Revision ID: 20260910_control_id
Revises: 9d4c2a1e7b10
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "20260910_control_id"
down_revision: str | Sequence[str] | None = "9d4c2a1e7b10"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("findings", sa.Column("control_id", sa.String(length=64), nullable=True))
    op.create_index("ix_findings_control_id", "findings", ["control_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_findings_control_id", table_name="findings")
    op.drop_column("findings", "control_id")
