"""scope vendor reference uniqueness to claim

Revision ID: 2f6f5369906b
Revises: f971b58591ce
Create Date: 2026-01-16

"""

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "2f6f5369906b"
down_revision: Union[str, Sequence[str], None] = "f971b58591ce"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("expenses_expense_item") as batch_op:
        batch_op.drop_constraint("uq_expense_vendor_reference", type_="unique")
        batch_op.create_unique_constraint(
            "uq_expense_claim_vendor_reference",
            ["claim_id", "vendor", "vendor_reference"],
        )


def downgrade() -> None:
    with op.batch_alter_table("expenses_expense_item") as batch_op:
        batch_op.drop_constraint("uq_expense_claim_vendor_reference", type_="unique")
        batch_op.create_unique_constraint(
            "uq_expense_vendor_reference",
            ["vendor", "vendor_reference"],
        )

