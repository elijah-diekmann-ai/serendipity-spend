"""add supporting_pdf_key column

Revision ID: add_pdf_key_001
Revises: 243ff3aab6e1
Create Date: 2026-01-16

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'add_pdf_key_001'
down_revision: Union[str, Sequence[str], None] = '243ff3aab6e1'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('exports_export_run', sa.Column('supporting_pdf_key', sa.String(length=500), nullable=True))


def downgrade() -> None:
    op.drop_column('exports_export_run', 'supporting_pdf_key')

