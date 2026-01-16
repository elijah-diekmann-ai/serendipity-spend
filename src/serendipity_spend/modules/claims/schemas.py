from __future__ import annotations

import uuid
from datetime import date, datetime

from pydantic import BaseModel

from serendipity_spend.modules.claims.models import ClaimStatus


class ClaimCreate(BaseModel):
    home_currency: str = "SGD"


class ClaimUpdate(BaseModel):
    home_currency: str | None = None
    travel_start_date: date | None = None
    travel_end_date: date | None = None
    purpose: str | None = None


class ClaimOut(BaseModel):
    id: uuid.UUID
    employee_id: uuid.UUID
    approver_id: uuid.UUID | None
    home_currency: str
    travel_start_date: date | None
    travel_end_date: date | None
    purpose: str | None
    status: ClaimStatus
    submitted_at: datetime | None
    approved_at: datetime | None
    paid_at: datetime | None
    created_at: datetime
    updated_at: datetime
