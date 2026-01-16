from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from serendipity_spend.modules.claims.models import Claim, ClaimStatus
from serendipity_spend.modules.identity.models import User, UserRole
from serendipity_spend.modules.policy.models import PolicySeverity, PolicyViolation, ViolationStatus


def create_claim(session: Session, *, employee_id: uuid.UUID, home_currency: str) -> Claim:
    claim = Claim(
        employee_id=employee_id,
        approver_id=None,
        home_currency=home_currency.upper(),
        status=ClaimStatus.DRAFT,
    )
    session.add(claim)
    session.commit()
    session.refresh(claim)
    return claim


def list_claims_for_user(session: Session, *, user: User) -> list[Claim]:
    if user.role == UserRole.ADMIN:
        return list(session.scalars(select(Claim).order_by(Claim.created_at.desc())))
    if user.role == UserRole.APPROVER:
        return list(
            session.scalars(
                select(Claim).where(Claim.approver_id == user.id).order_by(Claim.created_at.desc())
            )
        )
    return list(
        session.scalars(
            select(Claim).where(Claim.employee_id == user.id).order_by(Claim.created_at.desc())
        )
    )


def get_claim_for_user(session: Session, *, claim_id: uuid.UUID, user: User) -> Claim:
    claim = session.scalar(select(Claim).where(Claim.id == claim_id))
    if not claim:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Claim not found")

    if user.role == UserRole.ADMIN:
        return claim

    if user.role == UserRole.APPROVER and claim.approver_id == user.id:
        return claim

    if user.role == UserRole.EMPLOYEE and claim.employee_id == user.id:
        return claim

    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed")


def update_claim(session: Session, *, claim: Claim, user: User, **changes) -> Claim:
    if user.role != UserRole.ADMIN and claim.employee_id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed")

    if claim.status not in {
        ClaimStatus.DRAFT,
        ClaimStatus.NEEDS_EMPLOYEE_REVIEW,
        ClaimStatus.CHANGES_REQUESTED,
    }:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Claim not editable in this status"
        )

    for field, value in changes.items():
        if value is None:
            continue
        setattr(claim, field, value)
    session.add(claim)
    session.commit()
    session.refresh(claim)
    return claim


def route_claim(session: Session, *, claim: Claim, approver_id: uuid.UUID) -> Claim:
    claim.approver_id = approver_id
    session.add(claim)
    session.commit()
    session.refresh(claim)
    return claim


def submit_claim(session: Session, *, claim: Claim, user: User) -> Claim:
    if user.role != UserRole.ADMIN and claim.employee_id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed")

    if claim.status not in {
        ClaimStatus.DRAFT,
        ClaimStatus.NEEDS_EMPLOYEE_REVIEW,
        ClaimStatus.CHANGES_REQUESTED,
    }:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Claim not submittable in this status"
        )

    from serendipity_spend.modules.policy.service import evaluate_claim

    evaluate_claim(session, claim_id=claim.id)

    blocking = list(
        session.scalars(
            select(PolicyViolation).where(
                PolicyViolation.claim_id == claim.id,
                PolicyViolation.status == ViolationStatus.OPEN,
                PolicyViolation.severity == PolicySeverity.FAIL,
            )
        )
    )
    if blocking:
        claim.status = ClaimStatus.NEEDS_EMPLOYEE_REVIEW
        session.add(claim)
        session.commit()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": "Claim has blocking policy failures and cannot be submitted.",
                "blocking_rules": [v.rule_id for v in blocking],
            },
        )

    claim.submitted_at = datetime.now(UTC)
    claim.status = ClaimStatus.SUBMITTED
    if claim.approver_id:
        claim.status = ClaimStatus.NEEDS_APPROVER_REVIEW

    session.add(claim)
    session.commit()
    session.refresh(claim)
    return claim
