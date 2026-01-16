from __future__ import annotations

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from serendipity_spend.modules.expenses.models import ExpenseItem


def list_items(session: Session, *, claim_id: uuid.UUID) -> list[ExpenseItem]:
    return list(
        session.scalars(
            select(ExpenseItem)
            .where(ExpenseItem.claim_id == claim_id)
            .order_by(ExpenseItem.transaction_date)
        )
    )
