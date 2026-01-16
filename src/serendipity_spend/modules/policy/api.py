from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from serendipity_spend.api.deps import get_current_user
from serendipity_spend.core.db import db_session
from serendipity_spend.modules.claims.service import get_claim_for_user
from serendipity_spend.modules.identity.models import User
from serendipity_spend.modules.policy.models import PolicyViolation
from serendipity_spend.modules.policy.schemas import (
    PolicyExceptionDecision,
    PolicyExceptionOut,
    PolicyExceptionRequest,
    PolicyViolationOut,
)
from serendipity_spend.modules.policy.service import (
    decide_policy_exception,
    evaluate_claim,
    request_policy_exception,
)

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


@router.post("/claims/{claim_id}/policy/exceptions", response_model=PolicyExceptionOut)
def request_policy_exception_endpoint(
    claim_id: uuid.UUID,
    payload: PolicyExceptionRequest,
    session: Session = Depends(db_session),
    user: User = Depends(get_current_user),
) -> PolicyExceptionOut:
    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    violation = session.scalar(
        select(PolicyViolation).where(PolicyViolation.id == payload.violation_id)
    )
    if not violation or violation.claim_id != claim.id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy violation not found",
        )
    exc = request_policy_exception(
        session,
        violation_id=violation.id,
        user=user,
        justification=payload.justification,
    )
    return PolicyExceptionOut.model_validate(exc, from_attributes=True)


@router.post("/policy/exceptions/{exception_id}/decide", response_model=PolicyExceptionOut)
def decide_policy_exception_endpoint(
    exception_id: uuid.UUID,
    payload: PolicyExceptionDecision,
    session: Session = Depends(db_session),
    user: User = Depends(get_current_user),
) -> PolicyExceptionOut:
    exc = decide_policy_exception(
        session,
        exception_id=exception_id,
        user=user,
        decision=payload.decision,
        comment=payload.comment,
    )
    return PolicyExceptionOut.model_validate(exc, from_attributes=True)
