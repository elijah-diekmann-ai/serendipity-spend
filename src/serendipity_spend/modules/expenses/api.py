from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Response
from sqlalchemy.orm import Session

from serendipity_spend.api.deps import get_current_user
from serendipity_spend.core.db import db_session
from serendipity_spend.modules.claims.service import get_claim_for_user
from serendipity_spend.modules.expenses.schemas import (
    ExpenseItemCreateIn,
    ExpenseItemOut,
    ExpenseItemUpdateIn,
)
from serendipity_spend.modules.expenses.service import (
    create_manual_item,
    delete_expense_item,
    list_items,
    update_expense_item,
)
from serendipity_spend.modules.identity.models import User

router = APIRouter(tags=["expenses"])


@router.post("/claims/{claim_id}/items", response_model=ExpenseItemOut)
def create_item_endpoint(
    claim_id: uuid.UUID,
    payload: ExpenseItemCreateIn,
    session: Session = Depends(db_session),
    user: User = Depends(get_current_user),
) -> ExpenseItemOut:
    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    item = create_manual_item(session, claim=claim, user=user, **payload.model_dump())
    return ExpenseItemOut.model_validate(item, from_attributes=True)


@router.patch("/claims/{claim_id}/items/{item_id}", response_model=ExpenseItemOut)
def update_item_endpoint(
    claim_id: uuid.UUID,
    item_id: uuid.UUID,
    payload: ExpenseItemUpdateIn,
    session: Session = Depends(db_session),
    user: User = Depends(get_current_user),
) -> ExpenseItemOut:
    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    item = update_expense_item(
        session,
        claim=claim,
        user=user,
        item_id=item_id,
        changes=payload.model_dump(exclude_unset=True),
    )
    return ExpenseItemOut.model_validate(item, from_attributes=True)


@router.delete("/claims/{claim_id}/items/{item_id}")
def delete_item_endpoint(
    claim_id: uuid.UUID,
    item_id: uuid.UUID,
    session: Session = Depends(db_session),
    user: User = Depends(get_current_user),
) -> Response:
    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    delete_expense_item(session, claim=claim, user=user, item_id=item_id)
    return Response(status_code=204)


@router.get("/claims/{claim_id}/items", response_model=list[ExpenseItemOut])
def list_items_endpoint(
    claim_id: uuid.UUID,
    session: Session = Depends(db_session),
    user: User = Depends(get_current_user),
) -> list[ExpenseItemOut]:
    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    items = list_items(session, claim_id=claim.id)
    return [ExpenseItemOut.model_validate(i, from_attributes=True) for i in items]
