from __future__ import annotations

import uuid
from datetime import date, datetime
from decimal import Decimal

from pydantic import BaseModel


class FxRateUpsert(BaseModel):
    from_currency: str
    to_currency: str
    rate: Decimal
    as_of_date: date | None = None
    source: str | None = None


class FxRateOut(BaseModel):
    id: uuid.UUID
    claim_id: uuid.UUID
    from_currency: str
    to_currency: str
    rate: Decimal
    as_of_date: date | None
    source: str | None
    created_at: datetime
    updated_at: datetime
