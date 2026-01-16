from __future__ import annotations

from sqlalchemy import JSON, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from serendipity_spend.core.models import Base, Timestamped, UUIDPrimaryKey


class ExtractionAICache(UUIDPrimaryKey, Timestamped, Base):
    __tablename__ = "extraction_ai_cache"

    text_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    provider: Mapped[str] = mapped_column(String(50), default="openai")
    model: Mapped[str] = mapped_column(String(100), default="")
    schema_version: Mapped[int] = mapped_column(Integer, default=1)
    response_json: Mapped[dict] = mapped_column(JSON, default=dict)

