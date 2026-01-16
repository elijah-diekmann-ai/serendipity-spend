from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel

from serendipity_spend.modules.workflow.models import ApprovalDecision, TaskStatus


class TaskOut(BaseModel):
    id: uuid.UUID
    claim_id: uuid.UUID
    expense_item_id: uuid.UUID | None
    type: str
    title: str
    description: str | None
    status: TaskStatus
    assigned_to_user_id: uuid.UUID | None
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None


class ApprovalOut(BaseModel):
    id: uuid.UUID
    claim_id: uuid.UUID
    approver_user_id: uuid.UUID
    decision: ApprovalDecision
    comment: str | None
    decided_at: datetime
    created_at: datetime
    updated_at: datetime


class ApprovalRequest(BaseModel):
    comment: str | None = None
