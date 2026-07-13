"""Add idempotency fields and job relationships

Revision ID: d2e1aa12897a
Revises: 70966a52d1b7
Create Date: 2026-07-13 09:59:43.298548

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd2e1aa12897a'
down_revision: Union[str, Sequence[str], None] = '70966a52d1b7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('detection_signals', schema=None) as batch_op:
        batch_op.add_column(sa.Column('job_id', sa.String(), nullable=True))
        batch_op.create_index(batch_op.f('ix_detection_signals_job_id'), ['job_id'], unique=False)
        batch_op.create_foreign_key('fk_detection_signals_job_id', 'ingestion_jobs', ['job_id'], ['id'])

    with op.batch_alter_table('evidence_items', schema=None) as batch_op:
        batch_op.add_column(sa.Column('job_id', sa.String(), nullable=True))
        batch_op.create_index(batch_op.f('ix_evidence_items_job_id'), ['job_id'], unique=False)
        batch_op.create_foreign_key('fk_evidence_items_job_id', 'ingestion_jobs', ['job_id'], ['id'])

    with op.batch_alter_table('incidents', schema=None) as batch_op:
        batch_op.add_column(sa.Column('job_id', sa.String(), nullable=True))
        batch_op.create_index(batch_op.f('ix_incidents_job_id'), ['job_id'], unique=False)
        batch_op.create_foreign_key('fk_incidents_job_id', 'ingestion_jobs', ['job_id'], ['id'])

    with op.batch_alter_table('ingestion_jobs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('idempotency_key', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('pipeline_version', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('analysis_mode', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('reused_count', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('last_requested_at', sa.DateTime(timezone=True), nullable=True))
        batch_op.create_index(batch_op.f('ix_ingestion_jobs_idempotency_key'), ['idempotency_key'], unique=True)

    with op.batch_alter_table('reports', schema=None) as batch_op:
        batch_op.add_column(sa.Column('job_id', sa.String(), nullable=True))
        batch_op.create_index(batch_op.f('ix_reports_job_id'), ['job_id'], unique=False)
        batch_op.create_foreign_key('fk_reports_job_id', 'ingestion_jobs', ['job_id'], ['id'])

    with op.batch_alter_table('triage_runs', schema=None) as batch_op:
        batch_op.add_column(sa.Column('job_id', sa.String(), nullable=True))
        batch_op.create_index(batch_op.f('ix_triage_runs_job_id'), ['job_id'], unique=False)
        batch_op.create_foreign_key('fk_triage_runs_job_id', 'ingestion_jobs', ['job_id'], ['id'])
    # ### end Alembic commands ###


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table('triage_runs', schema=None) as batch_op:
        batch_op.drop_constraint('fk_triage_runs_job_id', type_='foreignkey')
        batch_op.drop_index(batch_op.f('ix_triage_runs_job_id'))
        batch_op.drop_column('job_id')

    with op.batch_alter_table('reports', schema=None) as batch_op:
        batch_op.drop_constraint('fk_reports_job_id', type_='foreignkey')
        batch_op.drop_index(batch_op.f('ix_reports_job_id'))
        batch_op.drop_column('job_id')

    with op.batch_alter_table('ingestion_jobs', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_ingestion_jobs_idempotency_key'))
        batch_op.drop_column('last_requested_at')
        batch_op.drop_column('reused_count')
        batch_op.drop_column('analysis_mode')
        batch_op.drop_column('pipeline_version')
        batch_op.drop_column('idempotency_key')

    with op.batch_alter_table('incidents', schema=None) as batch_op:
        batch_op.drop_constraint('fk_incidents_job_id', type_='foreignkey')
        batch_op.drop_index(batch_op.f('ix_incidents_job_id'))
        batch_op.drop_column('job_id')

    with op.batch_alter_table('evidence_items', schema=None) as batch_op:
        batch_op.drop_constraint('fk_evidence_items_job_id', type_='foreignkey')
        batch_op.drop_index(batch_op.f('ix_evidence_items_job_id'))
        batch_op.drop_column('job_id')

    with op.batch_alter_table('detection_signals', schema=None) as batch_op:
        batch_op.drop_constraint('fk_detection_signals_job_id', type_='foreignkey')
        batch_op.drop_index(batch_op.f('ix_detection_signals_job_id'))
        batch_op.drop_column('job_id')
    # ### end Alembic commands ###
