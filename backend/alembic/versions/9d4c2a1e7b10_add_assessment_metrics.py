"""Add authoritative assessment metrics.

Revision ID: 9d4c2a1e7b10
Revises: 03869f19c868
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "9d4c2a1e7b10"
down_revision: str | Sequence[str] | None = "03869f19c868"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "scan_results", sa.Column("assessment_coverage", sa.Integer(), nullable=False, server_default="0")
    )
    op.add_column(
        "scan_results",
        sa.Column("evidence_quality", sa.String(length=32), nullable=False, server_default="unavailable"),
    )
    op.add_column("scan_results", sa.Column("controls", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("scan_results", "controls")
    op.drop_column("scan_results", "evidence_quality")
    op.drop_column("scan_results", "assessment_coverage")
