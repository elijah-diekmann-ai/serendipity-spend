from __future__ import annotations

import uuid
from datetime import date
from decimal import Decimal

from sqlalchemy import Date, ForeignKey, Numeric, String, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from serendipity_spend.core.models import Base, Timestamped, UUIDPrimaryKey


class FxRate(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "fx_rate"
    __table_args__ = (
        UniqueConstraint("claim_id", "from_currency", "to_currency", name="uq_fx_claim_pair"),
    )

    claim_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("claims_claim.id"), index=True
    )
    from_currency: Mapped[str] = mapped_column(String(3))
    to_currency: Mapped[str] = mapped_column(String(3))
    rate: Mapped[Decimal] = mapped_column(Numeric(18, 8))
    as_of_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    source: Mapped[str | None] = mapped_column(String(100), nullable=True)

    claim = relationship("Claim")
