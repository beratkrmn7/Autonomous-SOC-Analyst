"""add bounded retention cleanup runs

Revision ID: 5d2c9a7e4b10
Revises: 5d2b8f6a1c42
Create Date: 2026-07-16
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "5d2c9a7e4b10"
down_revision: str | Sequence[str] | None = "5d2b8f6a1c42"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "retention_cleanup_runs",
        sa.Column("cleanup_run_id", sa.String(length=45), nullable=False),
        sa.Column("archive_id", sa.String(length=45), nullable=False),
        sa.Column(
            "status",
            sa.String(length=16),
            server_default="pending",
            nullable=False,
        ),
        sa.Column("policy_version", sa.String(length=32), nullable=False),
        sa.Column("archive_schema_version", sa.String(length=64), nullable=False),
        sa.Column("manifest_sha256", sa.String(length=64), nullable=False),
        sa.Column("archive_as_of", sa.DateTime(timezone=True), nullable=False),
        sa.Column("archive_snapshot", sa.JSON(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "current_phase",
            sa.String(length=32),
            server_default="pending",
            nullable=False,
        ),
        sa.Column("current_entity_type", sa.String(length=32), nullable=True),
        sa.Column("lease_owner", sa.String(length=64), nullable=True),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempt_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column(
            "deleted_record_count",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
        sa.Column(
            "protected_record_count",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
        sa.Column(
            "missing_record_count",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
        sa.Column(
            "skipped_record_count",
            sa.Integer(),
            server_default="0",
            nullable=False,
        ),
        sa.Column("sanitized_error_code", sa.String(length=64), nullable=True),
        sa.Column("version", sa.Integer(), server_default="1", nullable=False),
        sa.CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'failed')",
            name="ck_retention_cleanup_runs_status",
        ),
        sa.CheckConstraint(
            "attempt_count >= 0 AND deleted_record_count >= 0 "
            "AND protected_record_count >= 0 AND missing_record_count >= 0 "
            "AND skipped_record_count >= 0",
            name="ck_retention_cleanup_runs_nonnegative_counts",
        ),
        sa.CheckConstraint(
            "version >= 1",
            name="ck_retention_cleanup_runs_version",
        ),
        sa.CheckConstraint(
            "length(manifest_sha256) = 64",
            name="ck_retention_cleanup_runs_manifest_sha256",
        ),
        sa.ForeignKeyConstraint(
            ["archive_id"],
            ["retention_archive_runs.archive_id"],
        ),
        sa.PrimaryKeyConstraint("cleanup_run_id"),
        sa.UniqueConstraint("archive_id"),
    )
    op.create_index(
        "ix_retention_cleanup_runs_status_lease",
        "retention_cleanup_runs",
        ["status", "lease_expires_at"],
        unique=False,
    )

    op.create_table(
        "retention_cleanup_progress",
        sa.Column("cleanup_run_id", sa.String(length=45), nullable=False),
        sa.Column("entity_type", sa.String(length=32), nullable=False),
        sa.Column(
            "status",
            sa.String(length=16),
            server_default="pending",
            nullable=False,
        ),
        sa.Column("last_recorded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_entity_id", sa.String(length=512), nullable=True),
        sa.Column("scanned_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("deleted_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("protected_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("missing_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("skipped_count", sa.Integer(), server_default="0", nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "entity_type IN ('audit_event', 'incident', 'ingestion_job', "
            "'detection_signal', 'canonical_event')",
            name="ck_retention_cleanup_progress_entity_type",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'running', 'completed')",
            name="ck_retention_cleanup_progress_status",
        ),
        sa.CheckConstraint(
            "scanned_count >= 0 AND deleted_count >= 0 "
            "AND protected_count >= 0 AND missing_count >= 0 "
            "AND skipped_count >= 0",
            name="ck_retention_cleanup_progress_nonnegative_counts",
        ),
        sa.ForeignKeyConstraint(
            ["cleanup_run_id"],
            ["retention_cleanup_runs.cleanup_run_id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("cleanup_run_id", "entity_type"),
    )


def downgrade() -> None:
    op.drop_table("retention_cleanup_progress")
    op.drop_index(
        "ix_retention_cleanup_runs_status_lease",
        table_name="retention_cleanup_runs",
    )
    op.drop_table("retention_cleanup_runs")
