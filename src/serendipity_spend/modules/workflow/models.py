from __future__ import annotations

import enum
import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, Enum, ForeignKey, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from serendipity_spend.core.models import Base, Timestamped, UUIDPrimaryKey


class TaskStatus(str, enum.Enum):
    OPEN = "OPEN"
    RESOLVED = "RESOLVED"


class ApprovalDecision(str, enum.Enum):
    APPROVED = "APPROVED"
    CHANGES_REQUESTED = "CHANGES_REQUESTED"
    REJECTED = "REJECTED"


class Task(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "workflow_task"

    claim_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("claims_claim.id"), index=True
    )
    expense_item_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("expenses_expense_item.id"), nullable=True
    )
    created_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("identity_user.id"), nullable=True
    )
    assigned_to_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("identity_user.id"), nullable=True
    )

    type: Mapped[str] = mapped_column(String(50), index=True)
    title: Mapped[str] = mapped_column(String(200))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[TaskStatus] = mapped_column(Enum(TaskStatus, native_enum=False), index=True)

    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    claim = relationship("Claim")
    expense_item = relationship("ExpenseItem")
    created_by = relationship("User", foreign_keys=[created_by_user_id])
    assigned_to = relationship("User", foreign_keys=[assigned_to_user_id])


class Approval(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "workflow_approval"

    claim_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("claims_claim.id"), index=True
    )
    approver_user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("identity_user.id")
    )
    decision: Mapped[ApprovalDecision] = mapped_column(
        Enum(ApprovalDecision, native_enum=False), index=True
    )
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    claim = relationship("Claim")
    approver = relationship("User")
