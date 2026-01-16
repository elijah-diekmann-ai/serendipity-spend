from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel

from serendipity_spend.modules.documents.models import SourceFileStatus


class SourceFileOut(BaseModel):
    id: uuid.UUID
    claim_id: uuid.UUID
    uploader_id: uuid.UUID
    filename: str
    content_type: str | None
    byte_size: int
    sha256: str
    status: SourceFileStatus
    error_message: str | None
    created_at: datetime
    updated_at: datetime
