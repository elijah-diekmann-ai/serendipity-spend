from __future__ import annotations

import uuid
from datetime import date, datetime
from decimal import Decimal

from sqlalchemy import (
    JSON,
    Date,
    DateTime,
    ForeignKey,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from serendipity_spend.core.models import Base, Timestamped, UUIDPrimaryKey


class ExpenseItem(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "expenses_expense_item"
    __table_args__ = (
        UniqueConstraint("vendor", "vendor_reference", name="uq_expense_vendor_reference"),
        UniqueConstraint("claim_id", "dedupe_key", name="uq_expense_claim_dedupe"),
    )

    claim_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("claims_claim.id"), index=True
    )

    vendor: Mapped[str] = mapped_column(String(100), index=True)
    vendor_reference: Mapped[str | None] = mapped_column(String(200), nullable=True)
    receipt_type: Mapped[str] = mapped_column(String(50), index=True)

    category: Mapped[str | None] = mapped_column(String(50), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    transaction_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    transaction_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    amount_original_amount: Mapped[Decimal] = mapped_column(Numeric(12, 2))
    amount_original_currency: Mapped[str] = mapped_column(String(3))
    amount_home_amount: Mapped[Decimal | None] = mapped_column(Numeric(12, 2), nullable=True)
    amount_home_currency: Mapped[str] = mapped_column(String(3))
    fx_rate_to_home: Mapped[Decimal | None] = mapped_column(Numeric(18, 8), nullable=True)

    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict)
    dedupe_key: Mapped[str] = mapped_column(String(80))

    claim = relationship("Claim")
    evidences = relationship(
        "ExpenseItemEvidence", back_populates="expense_item", cascade="all, delete-orphan"
    )


class ExpenseItemEvidence(Base):
    __tablename__ = "expenses_expense_item_evidence"
    __table_args__ = (
        UniqueConstraint("expense_item_id", "evidence_document_id", name="uq_item_evidence"),
    )

    expense_item_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("expenses_expense_item.id"), primary_key=True
    )
    evidence_document_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("documents_evidence_document.id"), primary_key=True
    )

    expense_item = relationship("ExpenseItem", back_populates="evidences")
    evidence_document = relationship("EvidenceDocument")
