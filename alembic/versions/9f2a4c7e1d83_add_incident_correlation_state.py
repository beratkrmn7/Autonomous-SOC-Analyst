"""add incident correlation state

Revision ID: 9f2a4c7e1d83
Revises: 7b9c2e4f6a81
Create Date: 2026-07-21

Phase 6E.4A: persistent cross-job correlation foundation. Adds the
incident_correlation_states table that tracks the currently active
generation for one deterministic stateful correlation profile. The
feature is disabled by default (stateful_correlation_enabled=False) and
this migration only adds schema - it does not change any existing table.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "9f2a4c7e1d83"
down_revision: str | Sequence[str] | None = "7b9c2e4f6a81"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "incident_correlation_states",
        sa.Column("correlation_key", sa.String(length=128), nullable=False),
        sa.Column("correlation_version", sa.String(length=16), nullable=False),
        sa.Column("strategy", sa.String(length=64), nullable=False),
        sa.Column("incident_id", sa.String(), nullable=False),
        sa.Column("profile", sa.JSON(), nullable=False),
        sa.Column("generation", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["incident_id"],
            ["incidents.incident_id"],
            name="fk_incident_correlation_states_incident_id",
        ),
        sa.CheckConstraint(
            "length(trim(correlation_version)) > 0",
            name="ck_incident_correlation_states_correlation_version",
        ),
        sa.CheckConstraint(
            "length(trim(strategy)) > 0",
            name="ck_incident_correlation_states_strategy",
        ),
        sa.CheckConstraint(
            "generation > 0", name="ck_incident_correlation_states_generation"
        ),
        sa.CheckConstraint(
            "version > 0", name="ck_incident_correlation_states_version"
        ),
        sa.CheckConstraint(
            "expires_at > last_seen",
            name="ck_incident_correlation_states_expiry_after_last_seen",
        ),
        sa.CheckConstraint(
            "last_seen >= first_seen",
            name="ck_incident_correlation_states_last_seen_after_first_seen",
        ),
        sa.PrimaryKeyConstraint("correlation_key"),
    )
    op.create_index(
        "ix_incident_correlation_states_incident_id",
        "incident_correlation_states",
        ["incident_id"],
        unique=False,
    )
    op.create_index(
        "ix_incident_correlation_states_expires_at",
        "incident_correlation_states",
        ["expires_at"],
        unique=False,
    )
    op.create_index(
        "ix_incident_correlation_states_last_seen",
        "incident_correlation_states",
        ["last_seen"],
        unique=False,
    )
    op.create_index(
        "ix_incident_correlation_states_strategy_last_seen",
        "incident_correlation_states",
        ["strategy", "last_seen"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_incident_correlation_states_strategy_last_seen",
        table_name="incident_correlation_states",
    )
    op.drop_index(
        "ix_incident_correlation_states_last_seen",
        table_name="incident_correlation_states",
    )
    op.drop_index(
        "ix_incident_correlation_states_expires_at",
        table_name="incident_correlation_states",
    )
    op.drop_index(
        "ix_incident_correlation_states_incident_id",
        table_name="incident_correlation_states",
    )
    op.drop_table("incident_correlation_states")
