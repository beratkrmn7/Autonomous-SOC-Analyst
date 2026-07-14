"""add job cancellation fields

Revision ID: c4b31f7d2a9e
Revises: df0f1324b1ad
Create Date: 2026-07-14 16:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c4b31f7d2a9e"
down_revision: Union[str, Sequence[str], None] = "df0f1324b1ad"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add cancellation state metadata to analysis jobs."""
    op.add_column(
        "ingestion_jobs",
        sa.Column("cancel_requested_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "ingestion_jobs",
        sa.Column("cancelled_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "ingestion_jobs",
        sa.Column("cancel_reason_code", sa.String(), nullable=True),
    )
    op.add_column(
        "ingestion_jobs",
        sa.Column("cancel_requested_by", sa.String(), nullable=True),
    )


def downgrade() -> None:
    """Remove cancellation state metadata from analysis jobs."""
    op.drop_column("ingestion_jobs", "cancel_requested_by")
    op.drop_column("ingestion_jobs", "cancel_reason_code")
    op.drop_column("ingestion_jobs", "cancelled_at")
    op.drop_column("ingestion_jobs", "cancel_requested_at")
