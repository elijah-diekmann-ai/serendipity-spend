from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import DateTime, Enum, ForeignKey, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from serendipity_spend.core.models import Base, Timestamped, UUIDPrimaryKey


class ExportStatus(str, enum.Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ExportRun(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "exports_export_run"

    claim_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("claims_claim.id"), index=True
    )
    requested_by_user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("identity_user.id")
    )
    status: Mapped[ExportStatus] = mapped_column(Enum(ExportStatus, native_enum=False), index=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    summary_xlsx_key: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    supporting_pdf_key: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    supporting_zip_key: Mapped[str | None] = mapped_column(String(1024), nullable=True)

    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    claim = relationship("Claim")
    requested_by = relationship("User")
