from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from serendipity_spend.api.deps import get_current_user
from serendipity_spend.core.db import db_session
from serendipity_spend.modules.claims.service import get_claim_for_user
from serendipity_spend.modules.expenses.schemas import ExpenseItemOut
from serendipity_spend.modules.expenses.service import list_items
from serendipity_spend.modules.identity.models import User

router = APIRouter(tags=["expenses"])


@router.get("/claims/{claim_id}/items", response_model=list[ExpenseItemOut])
def list_items_endpoint(
    claim_id: uuid.UUID,
    session: Session = Depends(db_session),
    user: User = Depends(get_current_user),
) -> list[ExpenseItemOut]:
    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    items = list_items(session, claim_id=claim.id)
    return [ExpenseItemOut.model_validate(i, from_attributes=True) for i in items]
