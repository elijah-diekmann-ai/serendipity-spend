from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import JSON, DateTime, Enum, ForeignKey, String, Text, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from serendipity_spend.core.models import Base, Timestamped, UUIDPrimaryKey


class PolicySeverity(str, enum.Enum):
    PASS = "PASS"
    WARN = "WARN"
    FAIL = "FAIL"
    NEEDS_INFO = "NEEDS_INFO"


class ViolationStatus(str, enum.Enum):
    OPEN = "OPEN"
    RESOLVED = "RESOLVED"


class PolicyViolation(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "policy_violation"
    __table_args__ = (UniqueConstraint("dedupe_key", name="uq_policy_violation_dedupe"),)

    claim_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("claims_claim.id"), index=True
    )
    expense_item_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("expenses_expense_item.id"), nullable=True
    )

    rule_id: Mapped[str] = mapped_column(String(20))
    rule_version: Mapped[str] = mapped_column(String(20), default="1")
    severity: Mapped[PolicySeverity] = mapped_column(
        Enum(PolicySeverity, native_enum=False), index=True
    )
    status: Mapped[ViolationStatus] = mapped_column(
        Enum(ViolationStatus, native_enum=False), index=True
    )

    title: Mapped[str] = mapped_column(String(200))
    message: Mapped[str] = mapped_column(Text)
    data_json: Mapped[dict] = mapped_column(JSON, default=dict)
    dedupe_key: Mapped[str] = mapped_column(String(120))

    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    claim = relationship("Claim")
    expense_item = relationship("ExpenseItem")
