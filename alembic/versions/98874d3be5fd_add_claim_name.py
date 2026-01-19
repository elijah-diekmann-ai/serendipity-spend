"""add claim name

Revision ID: 98874d3be5fd
Revises: 9b1e8c7c2f2a
Create Date: 2026-01-19

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "98874d3be5fd"
down_revision: Union[str, Sequence[str], None] = "9b1e8c7c2f2a"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("claims_claim", sa.Column("name", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("claims_claim", "name")

