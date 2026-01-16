from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from serendipity_spend.api.deps import get_current_user, require_role
from serendipity_spend.core.db import db_session
from serendipity_spend.modules.claims.schemas import ClaimCreate, ClaimOut, ClaimUpdate
from serendipity_spend.modules.claims.service import (
    create_claim,
    get_claim_for_user,
    list_claims_for_user,
    route_claim,
    submit_claim,
    update_claim,
)
from serendipity_spend.modules.identity.models import User, UserRole

router = APIRouter(tags=["claims"])


@router.post("/claims", response_model=ClaimOut)
def create_claim_endpoint(
    payload: ClaimCreate,
    session: Session = Depends(db_session),
    user: User = Depends(get_current_user),
) -> ClaimOut:
    claim = create_claim(session, employee_id=user.id, home_currency=payload.home_currency)
    return ClaimOut.model_validate(claim, from_attributes=True)


@router.get("/claims", response_model=list[ClaimOut])
def list_claims_endpoint(
    session: Session = Depends(db_session),
    user: User = Depends(get_current_user),
) -> list[ClaimOut]:
    claims = list_claims_for_user(session, user=user)
    return [ClaimOut.model_validate(c, from_attributes=True) for c in claims]


@router.get("/claims/{claim_id}", response_model=ClaimOut)
def get_claim_endpoint(
    claim_id: uuid.UUID,
    session: Session = Depends(db_session),
    user: User = Depends(get_current_user),
) -> ClaimOut:
    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    return ClaimOut.model_validate(claim, from_attributes=True)


@router.patch("/claims/{claim_id}", response_model=ClaimOut)
def update_claim_endpoint(
    claim_id: uuid.UUID,
    payload: ClaimUpdate,
    session: Session = Depends(db_session),
    user: User = Depends(get_current_user),
) -> ClaimOut:
    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    updated = update_claim(
        session, claim=claim, user=user, **payload.model_dump(exclude_unset=True)
    )
    from serendipity_spend.modules.policy.service import evaluate_claim

    evaluate_claim(session, claim_id=updated.id)
    return ClaimOut.model_validate(updated, from_attributes=True)


@router.post("/claims/{claim_id}/submit", response_model=ClaimOut)
def submit_claim_endpoint(
    claim_id: uuid.UUID,
    session: Session = Depends(db_session),
    user: User = Depends(get_current_user),
) -> ClaimOut:
    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    submitted = submit_claim(session, claim=claim, user=user)
    return ClaimOut.model_validate(submitted, from_attributes=True)


@router.post("/claims/{claim_id}/route", response_model=ClaimOut)
def route_claim_endpoint(
    claim_id: uuid.UUID,
    approver_id: uuid.UUID,
    session: Session = Depends(db_session),
    admin_user: User = Depends(require_role(UserRole.ADMIN)),
) -> ClaimOut:
    claim = get_claim_for_user(session, claim_id=claim_id, user=admin_user)
    routed = route_claim(session, claim=claim, approver_id=approver_id)
    return ClaimOut.model_validate(routed, from_attributes=True)
