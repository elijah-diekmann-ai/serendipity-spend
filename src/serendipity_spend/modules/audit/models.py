from __future__ import annotations

import uuid
from datetime import UTC, datetime

from sqlalchemy import JSON, DateTime, ForeignKey, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from serendipity_spend.core.models import Base, UUIDPrimaryKey


class AuditEvent(UUIDPrimaryKey, Base):
    __tablename__ = "audit_event"

    claim_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("claims_claim.id"), nullable=True, index=True
    )
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("identity_user.id"), nullable=True, index=True
    )

    event_type: Mapped[str] = mapped_column(String(50), index=True)
    payload_json: Mapped[dict] = mapped_column(JSON, default=dict)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(UTC)
    )

    claim = relationship("Claim")
    actor = relationship("User")
