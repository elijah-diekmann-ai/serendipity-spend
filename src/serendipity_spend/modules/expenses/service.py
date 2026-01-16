from __future__ import annotations

import uuid
from datetime import date
from decimal import Decimal

from fastapi import HTTPException, status
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from serendipity_spend.modules.claims.models import Claim, ClaimStatus
from serendipity_spend.modules.expenses.models import ExpenseItem, ExpenseItemEvidence
from serendipity_spend.modules.fx.models import FxRate
from serendipity_spend.modules.identity.models import User, UserRole


def list_items(session: Session, *, claim_id: uuid.UUID) -> list[ExpenseItem]:
    return list(
        session.scalars(
            select(ExpenseItem)
            .where(ExpenseItem.claim_id == claim_id)
            .order_by(ExpenseItem.transaction_date)
        )
    )


def create_manual_item(
    session: Session,
    *,
    claim: Claim,
    user: User,
    vendor: str,
    category: str | None,
    description: str | None,
    transaction_date: date | None,
    amount_original_amount: Decimal,
    amount_original_currency: str,
    metadata_json: dict | None = None,
) -> ExpenseItem:
    _assert_claim_editable(claim=claim, user=user)

    vendor = vendor.strip()
    if not vendor:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Vendor is required")

    amount_original_currency = amount_original_currency.strip().upper()
    if not amount_original_currency:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Currency is required")

    amount_home_amount, fx_rate_to_home = _convert_to_home(
        session=session,
        claim_id=claim.id,
        from_currency=amount_original_currency,
        to_currency=claim.home_currency,
        amount=amount_original_amount,
    )

    clean_category = category.strip() if isinstance(category, str) and category.strip() else None
    clean_description = (
        description.strip() if isinstance(description, str) and description.strip() else None
    )

    item = ExpenseItem(
        claim_id=claim.id,
        vendor=vendor,
        vendor_reference=None,
        receipt_type="manual",
        category=clean_category,
        description=clean_description,
        transaction_date=transaction_date,
        transaction_at=None,
        amount_original_amount=amount_original_amount,
        amount_original_currency=amount_original_currency,
        amount_home_amount=amount_home_amount,
        amount_home_currency=claim.home_currency,
        fx_rate_to_home=fx_rate_to_home,
        metadata_json=metadata_json or {"employee_reviewed": True},
        dedupe_key=f"manual:{uuid.uuid4().hex}"[:80],
    )
    session.add(item)
    session.commit()
    session.refresh(item)
    return item


def update_expense_item(
    session: Session,
    *,
    claim: Claim,
    user: User,
    item_id: uuid.UUID,
    changes: dict,
) -> ExpenseItem:
    _assert_claim_editable(claim=claim, user=user)

    item = session.scalar(
        select(ExpenseItem).where(ExpenseItem.id == item_id, ExpenseItem.claim_id == claim.id)
    )
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Expense item not found")

    if "vendor" in changes:
        vendor = str(changes["vendor"] or "").strip()
        if not vendor:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Vendor is required"
            )
        item.vendor = vendor
    if "category" in changes:
        category = changes["category"]
        if category is None or not str(category).strip():
            item.category = None
        else:
            item.category = str(category).strip()
    if "description" in changes:
        description = changes["description"]
        if description is None or not str(description).strip():
            item.description = None
        else:
            item.description = str(description).strip()
    if "transaction_date" in changes:
        item.transaction_date = changes["transaction_date"]

    recalc_fx = False
    if "amount_original_amount" in changes:
        item.amount_original_amount = changes["amount_original_amount"]
        recalc_fx = True
    if "amount_original_currency" in changes:
        currency = str(changes["amount_original_currency"] or "").strip().upper()
        if not currency:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Currency is required"
            )
        item.amount_original_currency = currency
        recalc_fx = True

    if "metadata_json" in changes:
        desired = changes["metadata_json"] or {}
        merged = dict(item.metadata_json or {})
        for key, value in desired.items():
            if value is None:
                merged.pop(key, None)
            else:
                merged[key] = value
        item.metadata_json = merged

    if recalc_fx:
        amount_home_amount, fx_rate_to_home = _convert_to_home(
            session=session,
            claim_id=claim.id,
            from_currency=item.amount_original_currency,
            to_currency=claim.home_currency,
            amount=item.amount_original_amount,
        )
        item.amount_home_amount = amount_home_amount
        item.amount_home_currency = claim.home_currency
        item.fx_rate_to_home = fx_rate_to_home

    session.add(item)
    session.commit()
    session.refresh(item)
    return item


def delete_expense_item(
    session: Session, *, claim: Claim, user: User, item_id: uuid.UUID
) -> None:
    _assert_claim_editable(claim=claim, user=user)

    item = session.scalar(
        select(ExpenseItem).where(ExpenseItem.id == item_id, ExpenseItem.claim_id == claim.id)
    )
    if not item:
        return

    session.execute(
        delete(ExpenseItemEvidence).where(ExpenseItemEvidence.expense_item_id == item.id)
    )
    session.delete(item)
    session.commit()


def _assert_claim_editable(*, claim: Claim, user: User) -> None:
    if user.role == UserRole.ADMIN:
        return
    if claim.employee_id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed")
    if claim.status not in {
        ClaimStatus.DRAFT,
        ClaimStatus.NEEDS_EMPLOYEE_REVIEW,
        ClaimStatus.CHANGES_REQUESTED,
    }:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Claim not editable in this status"
        )


def _convert_to_home(
    *,
    session: Session,
    claim_id: uuid.UUID,
    from_currency: str,
    to_currency: str,
    amount: Decimal,
) -> tuple[Decimal | None, Decimal | None]:
    from_currency = from_currency.upper()
    to_currency = to_currency.upper()
    if from_currency == to_currency:
        return amount, Decimal("1")

    fx = session.scalar(
        select(FxRate).where(
            FxRate.claim_id == claim_id,
            FxRate.from_currency == from_currency,
            FxRate.to_currency == to_currency,
        )
    )
    if not fx:
        return None, None
    return (amount * fx.rate).quantize(Decimal("0.01")), fx.rate
