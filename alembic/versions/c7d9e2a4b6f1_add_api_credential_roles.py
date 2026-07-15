"""add API credential roles

Revision ID: c7d9e2a4b6f1
Revises: 8a3f1c9d7e42
Create Date: 2026-07-15 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c7d9e2a4b6f1"
down_revision: Union[str, Sequence[str], None] = "8a3f1c9d7e42"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add one constrained role per API credential and backfill service."""
    with op.batch_alter_table("api_credentials") as batch_op:
        batch_op.add_column(
            sa.Column(
                "role",
                sa.String(length=16),
                server_default="service",
                nullable=False,
            )
        )
        batch_op.create_check_constraint(
            "ck_api_credentials_role",
            "role IN ('viewer', 'analyst', 'service', 'admin')",
        )
        batch_op.create_index(
            op.f("ix_api_credentials_role"),
            ["role"],
            unique=False,
        )


def downgrade() -> None:
    """Remove API credential roles while preserving credential records."""
    with op.batch_alter_table("api_credentials") as batch_op:
        batch_op.drop_index(op.f("ix_api_credentials_role"))
        batch_op.drop_constraint("ck_api_credentials_role", type_="check")
        batch_op.drop_column("role")
