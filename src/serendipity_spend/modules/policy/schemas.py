from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel

from serendipity_spend.modules.policy.models import (
    PolicyExceptionStatus,
    PolicySeverity,
    ViolationStatus,
)


class PolicyViolationOut(BaseModel):
    id: uuid.UUID
    claim_id: uuid.UUID
    expense_item_id: uuid.UUID | None
    rule_id: str
    rule_version: str
    severity: PolicySeverity
    status: ViolationStatus
    title: str
    message: str
    data_json: dict
    created_at: datetime
    updated_at: datetime
    resolved_at: datetime | None


class PolicyExceptionRequest(BaseModel):
    violation_id: uuid.UUID
    justification: str


class PolicyExceptionDecision(BaseModel):
    decision: PolicyExceptionStatus
    comment: str | None = None


class PolicyExceptionOut(BaseModel):
    id: uuid.UUID
    claim_id: uuid.UUID
    expense_item_id: uuid.UUID | None
    rule_id: str
    rule_version: str
    status: PolicyExceptionStatus
    justification: str
    requested_by_user_id: uuid.UUID
    decided_by_user_id: uuid.UUID | None
    decided_at: datetime | None
    decision_comment: str | None
    dedupe_key: str
    created_at: datetime
    updated_at: datetime
