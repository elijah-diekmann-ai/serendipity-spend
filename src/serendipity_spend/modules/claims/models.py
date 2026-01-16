from __future__ import annotations

import enum
import uuid
from datetime import date, datetime

from sqlalchemy import Date, DateTime, Enum, ForeignKey, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from serendipity_spend.core.models import Base, Timestamped, UUIDPrimaryKey


class ClaimStatus(str, enum.Enum):
    DRAFT = "DRAFT"
    PROCESSING = "PROCESSING"
    NEEDS_EMPLOYEE_REVIEW = "NEEDS_EMPLOYEE_REVIEW"
    SUBMITTED = "SUBMITTED"
    NEEDS_APPROVER_REVIEW = "NEEDS_APPROVER_REVIEW"
    CHANGES_REQUESTED = "CHANGES_REQUESTED"
    APPROVED = "APPROVED"
    READY_FOR_PAYMENT = "READY_FOR_PAYMENT"
    PAID = "PAID"
    REJECTED = "REJECTED"


class Claim(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "claims_claim"

    employee_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("identity_user.id")
    )
    approver_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("identity_user.id"), nullable=True
    )

    home_currency: Mapped[str] = mapped_column(String(3), default="SGD")
    travel_start_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    travel_end_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    purpose: Mapped[str | None] = mapped_column(Text, nullable=True)

    status: Mapped[ClaimStatus] = mapped_column(Enum(ClaimStatus, native_enum=False), index=True)
    submitted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    paid_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    employee = relationship("User", foreign_keys=[employee_id])
    approver = relationship("User", foreign_keys=[approver_id])
