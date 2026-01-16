"""add policy exceptions

Revision ID: d6c4a9f1e2b3
Revises: 2f6f5369906b
Create Date: 2026-01-16

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d6c4a9f1e2b3"
down_revision: Union[str, Sequence[str], None] = "2f6f5369906b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "policy_exception",
        sa.Column("claim_id", sa.Uuid(), nullable=False),
        sa.Column("expense_item_id", sa.Uuid(), nullable=True),
        sa.Column("rule_id", sa.String(length=20), nullable=False),
        sa.Column("rule_version", sa.String(length=20), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "REQUESTED",
                "APPROVED",
                "REJECTED",
                name="policyexceptionstatus",
                native_enum=False,
            ),
            nullable=False,
        ),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("requested_by_user_id", sa.Uuid(), nullable=False),
        sa.Column("decided_by_user_id", sa.Uuid(), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("decision_comment", sa.Text(), nullable=True),
        sa.Column("dedupe_key", sa.String(length=120), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["claim_id"], ["claims_claim.id"]),
        sa.ForeignKeyConstraint(["expense_item_id"], ["expenses_expense_item.id"]),
        sa.ForeignKeyConstraint(["requested_by_user_id"], ["identity_user.id"]),
        sa.ForeignKeyConstraint(["decided_by_user_id"], ["identity_user.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("dedupe_key", name="uq_policy_exception_dedupe"),
    )
    op.create_index(op.f("ix_policy_exception_claim_id"), "policy_exception", ["claim_id"])
    op.create_index(op.f("ix_policy_exception_rule_id"), "policy_exception", ["rule_id"])
    op.create_index(op.f("ix_policy_exception_status"), "policy_exception", ["status"])
    op.create_index(
        op.f("ix_policy_exception_requested_by_user_id"),
        "policy_exception",
        ["requested_by_user_id"],
    )


def downgrade() -> None:
    op.drop_index(op.f("ix_policy_exception_requested_by_user_id"), table_name="policy_exception")
    op.drop_index(op.f("ix_policy_exception_status"), table_name="policy_exception")
    op.drop_index(op.f("ix_policy_exception_rule_id"), table_name="policy_exception")
    op.drop_index(op.f("ix_policy_exception_claim_id"), table_name="policy_exception")
    op.drop_table("policy_exception")
