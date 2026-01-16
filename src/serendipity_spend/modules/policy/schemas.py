from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel

from serendipity_spend.modules.policy.models import PolicySeverity, ViolationStatus


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
