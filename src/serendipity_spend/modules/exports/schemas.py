from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel

from serendipity_spend.modules.exports.models import ExportStatus


class ExportRunOut(BaseModel):
    id: uuid.UUID
    claim_id: uuid.UUID
    requested_by_user_id: uuid.UUID
    status: ExportStatus
    error_message: str | None
    summary_xlsx_key: str | None
    supporting_pdf_key: str | None
    supporting_zip_key: str | None
    completed_at: datetime | None
    created_at: datetime
    updated_at: datetime
