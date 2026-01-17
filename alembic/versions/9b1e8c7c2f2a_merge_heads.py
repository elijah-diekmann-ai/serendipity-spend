"""merge heads

Revision ID: 9b1e8c7c2f2a
Revises: d6c4a9f1e2b3, 6a0a0c0d3df2
Create Date: 2026-01-17

"""

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "9b1e8c7c2f2a"
down_revision: Union[str, Sequence[str], None] = ("d6c4a9f1e2b3", "6a0a0c0d3df2")
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    pass


def downgrade() -> None:
    pass
