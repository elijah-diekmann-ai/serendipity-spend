from __future__ import annotations

import enum
import uuid

from sqlalchemy import Enum, ForeignKey, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from serendipity_spend.core.models import Base, Timestamped, UUIDPrimaryKey


class SourceFileStatus(str, enum.Enum):
    UPLOADED = "UPLOADED"
    PROCESSING = "PROCESSING"
    PROCESSED = "PROCESSED"
    FAILED = "FAILED"


class SourceFile(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "documents_source_file"

    claim_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("claims_claim.id"), index=True
    )
    uploader_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("identity_user.id")
    )

    filename: Mapped[str] = mapped_column(String(512))
    content_type: Mapped[str | None] = mapped_column(String(200), nullable=True)
    byte_size: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    storage_key: Mapped[str] = mapped_column(String(1024), unique=True)

    status: Mapped[SourceFileStatus] = mapped_column(
        Enum(SourceFileStatus, native_enum=False), index=True
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    claim = relationship("Claim")
    uploader = relationship("User")


class EvidenceDocument(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "documents_evidence_document"

    source_file_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("documents_source_file.id"), index=True
    )
    page_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    page_end: Mapped[int | None] = mapped_column(Integer, nullable=True)

    vendor: Mapped[str] = mapped_column(String(100), index=True)
    receipt_type: Mapped[str] = mapped_column(String(50), index=True)

    extracted_text: Mapped[str] = mapped_column(Text)
    text_hash: Mapped[str] = mapped_column(String(64), index=True)
    classification_confidence: Mapped[float] = mapped_column(default=1.0)

    source_file = relationship("SourceFile")
