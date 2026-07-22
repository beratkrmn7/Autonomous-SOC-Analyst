"""add canonical event network fields

Revision ID: 4c1d8e6f2a90
Revises: 9f2a4c7e1d83
Create Date: 2026-07-22

Persist the bounded, explicit canonical fields needed by hydrated detection
and triage views. All columns are nullable so existing events remain valid;
there is intentionally no data backfill.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "4c1d8e6f2a90"
down_revision: str | Sequence[str] | None = "9f2a4c7e1d83"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "canonical_events",
        sa.Column("action_reason", sa.String(length=256), nullable=True),
    )
    op.add_column(
        "canonical_events",
        sa.Column("tcp_flags", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "canonical_events",
        sa.Column("inbound_interface", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "canonical_events",
        sa.Column("outbound_interface", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "canonical_events",
        sa.Column("inbound_zone", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "canonical_events",
        sa.Column("outbound_zone", sa.String(length=128), nullable=True),
    )
    op.add_column(
        "canonical_events", sa.Column("source_fqdns", sa.JSON(), nullable=True)
    )
    op.add_column(
        "canonical_events",
        sa.Column("destination_fqdns", sa.JSON(), nullable=True),
    )
    op.add_column(
        "canonical_events", sa.Column("bytes", sa.Integer(), nullable=True)
    )
    op.add_column(
        "canonical_events", sa.Column("packets", sa.Integer(), nullable=True)
    )
    op.add_column(
        "canonical_events", sa.Column("duration_ms", sa.Integer(), nullable=True)
    )
    op.add_column(
        "canonical_events",
        sa.Column("nat_type", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "canonical_events",
        sa.Column("translated_src_ip", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "canonical_events",
        sa.Column("translated_dst_ip", sa.String(length=64), nullable=True),
    )
    op.add_column(
        "canonical_events",
        sa.Column("translated_src_port", sa.Integer(), nullable=True),
    )
    op.add_column(
        "canonical_events",
        sa.Column("translated_dst_port", sa.Integer(), nullable=True),
    )
    op.add_column(
        "canonical_events", sa.Column("parser_metadata", sa.JSON(), nullable=True)
    )
    op.create_index(
        "ix_canonical_events_inbound_zone",
        "canonical_events",
        ["inbound_zone"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(
        "ix_canonical_events_inbound_zone", table_name="canonical_events"
    )
    op.drop_column("canonical_events", "parser_metadata")
    op.drop_column("canonical_events", "translated_dst_port")
    op.drop_column("canonical_events", "translated_src_port")
    op.drop_column("canonical_events", "translated_dst_ip")
    op.drop_column("canonical_events", "translated_src_ip")
    op.drop_column("canonical_events", "nat_type")
    op.drop_column("canonical_events", "duration_ms")
    op.drop_column("canonical_events", "packets")
    op.drop_column("canonical_events", "bytes")
    op.drop_column("canonical_events", "destination_fqdns")
    op.drop_column("canonical_events", "source_fqdns")
    op.drop_column("canonical_events", "outbound_zone")
    op.drop_column("canonical_events", "inbound_zone")
    op.drop_column("canonical_events", "outbound_interface")
    op.drop_column("canonical_events", "inbound_interface")
    op.drop_column("canonical_events", "tcp_flags")
    op.drop_column("canonical_events", "action_reason")
