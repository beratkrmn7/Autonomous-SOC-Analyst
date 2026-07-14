"""add worker heartbeat model

Revision ID: df0f1324b1ad
Revises: 554b54ed15b4
Create Date: 2026-07-14 12:16:49.519801

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'df0f1324b1ad'
down_revision: Union[str, Sequence[str], None] = '554b54ed15b4'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('worker_heartbeats',
    sa.Column('worker_id', sa.String(), nullable=False),
    sa.Column('worker_type', sa.String(), nullable=False),
    sa.Column('status', sa.String(), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_heartbeat_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('current_job_id', sa.String(), nullable=True),
    sa.Column('hostname_hash', sa.String(), nullable=False),
    sa.Column('version', sa.String(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('worker_id')
    )
    op.create_index(op.f('ix_worker_heartbeats_worker_type'), 'worker_heartbeats', ['worker_type'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_worker_heartbeats_worker_type'), table_name='worker_heartbeats')
    op.drop_table('worker_heartbeats')
