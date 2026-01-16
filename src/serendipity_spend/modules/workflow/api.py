from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from serendipity_spend.api.deps import get_current_user
from serendipity_spend.core.db import db_session
from serendipity_spend.modules.claims.models import Claim, ClaimStatus
from serendipity_spend.modules.claims.schemas import ClaimOut
from serendipity_spend.modules.claims.service import get_claim_for_user
from serendipity_spend.modules.identity.models import User, UserRole
from serendipity_spend.modules.workflow.models import ApprovalDecision
from serendipity_spend.modules.workflow.schemas import ApprovalRequest, TaskOut
from serendipity_spend.modules.workflow.service import approve_claim, list_tasks, resolve_task

router = APIRouter(tags=["workflow"])


@router.get("/claims/{claim_id}/tasks", response_model=list[TaskOut])
def list_tasks_endpoint(
    claim_id: uuid.UUID,
    session: Session = Depends(db_session),
    user: User = Depends(get_current_user),
) -> list[TaskOut]:
    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    tasks = list_tasks(session, claim_id=claim.id)
    return [TaskOut.model_validate(t, from_attributes=True) for t in tasks]


@router.post("/tasks/{task_id}/resolve", response_model=TaskOut)
def resolve_task_endpoint(
    task_id: uuid.UUID,
    session: Session = Depends(db_session),
    user: User = Depends(get_current_user),
) -> TaskOut:
    task = resolve_task(session, task_id=task_id, user=user)
    return TaskOut.model_validate(task, from_attributes=True)


@router.get("/approvals/inbox", response_model=list[ClaimOut])
def approver_inbox(
    session: Session = Depends(db_session),
    user: User = Depends(get_current_user),
) -> list[ClaimOut]:
    if user.role not in {UserRole.APPROVER, UserRole.ADMIN}:
        return []
    q = select(Claim).where(Claim.status == ClaimStatus.NEEDS_APPROVER_REVIEW)
    if user.role == UserRole.APPROVER:
        q = q.where(Claim.approver_id == user.id)
    claims = list(session.scalars(q.order_by(Claim.created_at.desc())))
    return [ClaimOut.model_validate(c, from_attributes=True) for c in claims]


@router.post("/claims/{claim_id}/approve", response_model=ClaimOut)
def approve_claim_endpoint(
    claim_id: uuid.UUID,
    payload: ApprovalRequest,
    session: Session = Depends(db_session),
    user: User = Depends(get_current_user),
) -> ClaimOut:
    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    claim = approve_claim(
        session, claim=claim, user=user, decision=ApprovalDecision.APPROVED, comment=payload.comment
    )
    return ClaimOut.model_validate(claim, from_attributes=True)


@router.post("/claims/{claim_id}/request-changes", response_model=ClaimOut)
def request_changes_endpoint(
    claim_id: uuid.UUID,
    payload: ApprovalRequest,
    session: Session = Depends(db_session),
    user: User = Depends(get_current_user),
) -> ClaimOut:
    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    claim = approve_claim(
        session,
        claim=claim,
        user=user,
        decision=ApprovalDecision.CHANGES_REQUESTED,
        comment=payload.comment,
    )
    return ClaimOut.model_validate(claim, from_attributes=True)


@router.post("/claims/{claim_id}/reject", response_model=ClaimOut)
def reject_endpoint(
    claim_id: uuid.UUID,
    payload: ApprovalRequest,
    session: Session = Depends(db_session),
    user: User = Depends(get_current_user),
) -> ClaimOut:
    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    claim = approve_claim(
        session, claim=claim, user=user, decision=ApprovalDecision.REJECTED, comment=payload.comment
    )
    return ClaimOut.model_validate(claim, from_attributes=True)
