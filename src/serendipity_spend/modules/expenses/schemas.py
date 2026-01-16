from __future__ import annotations

import uuid
from datetime import date, datetime
from decimal import Decimal

from pydantic import BaseModel, Field


class ExpenseItemCreateIn(BaseModel):
    vendor: str
    category: str | None = None
    description: str | None = None
    transaction_date: date | None = None
    amount_original_amount: Decimal
    amount_original_currency: str
    metadata_json: dict = Field(default_factory=dict)


class ExpenseItemUpdateIn(BaseModel):
    vendor: str | None = None
    category: str | None = None
    description: str | None = None
    transaction_date: date | None = None
    amount_original_amount: Decimal | None = None
    amount_original_currency: str | None = None
    metadata_json: dict | None = None


class ExpenseItemOut(BaseModel):
    id: uuid.UUID
    claim_id: uuid.UUID
    vendor: str
    vendor_reference: str | None
    receipt_type: str
    category: str | None
    description: str | None
    transaction_date: date | None
    amount_original_amount: Decimal
    amount_original_currency: str
    amount_home_amount: Decimal | None
    amount_home_currency: str
    fx_rate_to_home: Decimal | None
    metadata_json: dict
    created_at: datetime
    updated_at: datetime
