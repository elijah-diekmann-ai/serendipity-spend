"""add supporting pdf export

Revision ID: f971b58591ce
Revises: 243ff3aab6e1
Create Date: 2026-01-16

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "f971b58591ce"
down_revision: Union[str, Sequence[str], None] = "243ff3aab6e1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "exports_export_run", sa.Column("supporting_pdf_key", sa.String(length=1024), nullable=True)
    )


def downgrade() -> None:
    op.drop_column("exports_export_run", "supporting_pdf_key")

