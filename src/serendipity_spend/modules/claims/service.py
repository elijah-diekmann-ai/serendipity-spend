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
    approver = session.scalar(select(User).where(User.id == approver_id))
    if not approver:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Approver not found")
    if not approver.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Approver is inactive"
        )
    if approver.role not in {UserRole.APPROVER, UserRole.ADMIN}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="User is not an approver"
        )
    claim.approver_id = approver_id
    if claim.status == ClaimStatus.SUBMITTED:
        claim.status = ClaimStatus.NEEDS_APPROVER_REVIEW
    session.add(claim)
    session.commit()
    session.refresh(claim)
    return claim


def delete_claim(session: Session, *, claim: Claim, user: User) -> None:
    if user.role != UserRole.ADMIN and claim.employee_id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed")

    if claim.status not in (ClaimStatus.DRAFT, ClaimStatus.PROCESSING):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Only draft or processing claims can be deleted"
        )

    # Delete related records first (foreign key constraints)
    from serendipity_spend.modules.audit.models import AuditEvent
    from serendipity_spend.modules.documents.models import EvidenceDocument, SourceFile
    from serendipity_spend.modules.expenses.models import ExpenseItem, ExpenseItemEvidence
    from serendipity_spend.modules.exports.models import ExportRun
    from serendipity_spend.modules.fx.models import FxRate
    from serendipity_spend.modules.workflow.models import Approval, Task

    # Get expense item IDs for evidence cleanup
    item_ids = [
        i.id
        for i in session.scalars(select(ExpenseItem).where(ExpenseItem.claim_id == claim.id))
    ]
    if item_ids:
        session.execute(ExpenseItemEvidence.__table__.delete().where(ExpenseItemEvidence.expense_item_id.in_(item_ids)))

    # Get source file IDs for evidence cleanup
    source_ids = [
        s.id
        for s in session.scalars(select(SourceFile).where(SourceFile.claim_id == claim.id))
    ]
    if source_ids:
        session.execute(EvidenceDocument.__table__.delete().where(EvidenceDocument.source_file_id.in_(source_ids)))

    # Delete related records
    session.execute(ExpenseItem.__table__.delete().where(ExpenseItem.claim_id == claim.id))
    session.execute(SourceFile.__table__.delete().where(SourceFile.claim_id == claim.id))
    session.execute(FxRate.__table__.delete().where(FxRate.claim_id == claim.id))
    session.execute(PolicyViolation.__table__.delete().where(PolicyViolation.claim_id == claim.id))
    session.execute(Task.__table__.delete().where(Task.claim_id == claim.id))
    session.execute(Approval.__table__.delete().where(Approval.claim_id == claim.id))
    session.execute(ExportRun.__table__.delete().where(ExportRun.claim_id == claim.id))
    session.execute(AuditEvent.__table__.delete().where(AuditEvent.claim_id == claim.id))

    session.delete(claim)
    session.commit()


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

    open_violations = list(
        session.scalars(
            select(PolicyViolation).where(
                PolicyViolation.claim_id == claim.id,
                PolicyViolation.status == ViolationStatus.OPEN,
            )
        )
    )
    blocking = [
        v
        for v in open_violations
        if v.severity == PolicySeverity.FAIL or bool((v.data_json or {}).get("submit_blocking"))
    ]
    if blocking:
        claim.status = ClaimStatus.NEEDS_EMPLOYEE_REVIEW
        session.add(claim)
        session.commit()
        blocking_rules = sorted({v.rule_id for v in blocking})
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "message": "Claim has blocking policy items and cannot be submitted.",
                "blocking_rules": blocking_rules,
                "blocking": [
                    {
                        "rule_id": v.rule_id,
                        "severity": v.severity.value,
                        "title": v.title,
                        "message": v.message,
                    }
                    for v in blocking
                ],
            },
        )

    claim.submitted_at = datetime.now(UTC)

    if not claim.approver_id:
        approvers = list(
            session.scalars(
                select(User)
                .where(User.role == UserRole.APPROVER, User.is_active.is_(True))
                .order_by(User.email.asc())
            )
        )
        if len(approvers) == 1:
            claim.approver_id = approvers[0].id
        elif len(approvers) == 0:
            admins = list(
                session.scalars(
                    select(User)
                    .where(User.role == UserRole.ADMIN, User.is_active.is_(True))
                    .order_by(User.email.asc())
                )
            )
            if len(admins) == 1:
                claim.approver_id = admins[0].id

    claim.status = ClaimStatus.NEEDS_APPROVER_REVIEW if claim.approver_id else ClaimStatus.SUBMITTED

    session.add(claim)
    session.commit()
    session.refresh(claim)
    return claim
