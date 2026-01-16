from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from serendipity_spend.api.deps import get_current_user
from serendipity_spend.core.db import db_session
from serendipity_spend.modules.claims.service import get_claim_for_user
from serendipity_spend.modules.identity.models import User
from serendipity_spend.modules.policy.models import PolicyViolation
from serendipity_spend.modules.policy.schemas import PolicyViolationOut
from serendipity_spend.modules.policy.service import evaluate_claim

router = APIRouter(tags=["policy"])


@router.post("/claims/{claim_id}/policy/evaluate")
def evaluate_policy_endpoint(
    claim_id: uuid.UUID,
    session: Session = Depends(db_session),
    user: User = Depends(get_current_user),
) -> dict[str, str]:
    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    evaluate_claim(session, claim_id=claim.id)
    return {"status": "ok"}


@router.get("/claims/{claim_id}/policy", response_model=list[PolicyViolationOut])
def list_policy_endpoint(
    claim_id: uuid.UUID,
    session: Session = Depends(db_session),
    user: User = Depends(get_current_user),
) -> list[PolicyViolationOut]:
    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    violations = list(
        session.scalars(
            select(PolicyViolation)
            .where(PolicyViolation.claim_id == claim.id)
            .order_by(PolicyViolation.created_at.desc())
        )
    )
    return [PolicyViolationOut.model_validate(v, from_attributes=True) for v in violations]
