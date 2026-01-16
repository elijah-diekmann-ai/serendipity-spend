"""add extraction ai cache

Revision ID: 6a0a0c0d3df2
Revises: f971b58591ce
Create Date: 2026-01-16

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "6a0a0c0d3df2"
down_revision: Union[str, Sequence[str], None] = "f971b58591ce"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "extraction_ai_cache",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("text_hash", sa.String(length=64), nullable=False),
        sa.Column("provider", sa.String(length=50), nullable=False),
        sa.Column("model", sa.String(length=100), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("response_json", sa.JSON(), nullable=False),
        sa.UniqueConstraint("text_hash", name="uq_extraction_ai_cache_text_hash"),
    )
    op.create_index(
        "ix_extraction_ai_cache_text_hash",
        "extraction_ai_cache",
        ["text_hash"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index("ix_extraction_ai_cache_text_hash", table_name="extraction_ai_cache")
    op.drop_table("extraction_ai_cache")

