from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from serendipity_spend.modules.claims.models import Claim, ClaimStatus
from serendipity_spend.modules.identity.models import User, UserRole
from serendipity_spend.modules.workflow.models import Approval, ApprovalDecision, Task, TaskStatus


def list_tasks(session: Session, *, claim_id: uuid.UUID) -> list[Task]:
    return list(
        session.scalars(
            select(Task).where(Task.claim_id == claim_id).order_by(Task.created_at.desc())
        )
    )


def resolve_task(session: Session, *, task_id: uuid.UUID, user: User) -> Task:
    task = session.scalar(select(Task).where(Task.id == task_id))
    if not task:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")

    claim = session.scalar(select(Claim).where(Claim.id == task.claim_id))
    if not claim:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Claim not found")

    if user.role != UserRole.ADMIN:
        if task.assigned_to_user_id == user.id:
            pass
        elif task.assigned_to_user_id is None and claim.employee_id == user.id:
            pass
        else:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed")

    if task.status == TaskStatus.RESOLVED:
        return task

    task.status = TaskStatus.RESOLVED
    task.resolved_at = datetime.now(UTC)
    session.add(task)
    session.commit()
    session.refresh(task)
    return task


def approve_claim(
    session: Session, *, claim: Claim, user: User, decision: ApprovalDecision, comment: str | None
) -> Claim:
    if user.role not in {UserRole.APPROVER, UserRole.ADMIN}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed")

    if user.role == UserRole.APPROVER and claim.approver_id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed")

    if claim.status != ClaimStatus.NEEDS_APPROVER_REVIEW:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="Claim not in approver review"
        )

    if decision == ApprovalDecision.APPROVED:
        from serendipity_spend.modules.policy.blocking import is_violation_blocking
        from serendipity_spend.modules.policy.models import PolicyViolation, ViolationStatus
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
            if is_violation_blocking(v, allow_pending_exceptions=False)
        ]
        if blocking:
            blocking_rules = sorted({v.rule_id for v in blocking})
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "message": "Claim has unresolved policy items and cannot be approved.",
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

    now = datetime.now(UTC)
    if decision == ApprovalDecision.APPROVED:
        claim.status = ClaimStatus.APPROVED
        claim.approved_at = now
    elif decision == ApprovalDecision.CHANGES_REQUESTED:
        claim.status = ClaimStatus.CHANGES_REQUESTED
    else:
        claim.status = ClaimStatus.REJECTED

    approval = Approval(
        claim_id=claim.id,
        approver_user_id=user.id,
        decision=decision,
        comment=comment,
        decided_at=now,
    )
    session.add_all([claim, approval])
    session.commit()
    session.refresh(claim)
    return claim
