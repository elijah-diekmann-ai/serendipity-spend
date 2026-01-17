from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, File, UploadFile
from fastapi.responses import Response
from sqlalchemy.orm import Session

from serendipity_spend.api.deps import get_current_user
from serendipity_spend.core.db import db_session
from serendipity_spend.core.logging import get_logger, log_event
from serendipity_spend.core.storage import get_storage
from serendipity_spend.modules.claims.service import get_claim_for_user
from serendipity_spend.modules.documents.schemas import SourceFileOut
from serendipity_spend.modules.documents.service import (
    create_source_file,
    create_source_files_from_upload,
    list_source_files,
)
from serendipity_spend.modules.identity.models import User
from serendipity_spend.worker.tasks import extract_source_file_task

router = APIRouter(tags=["documents"])
logger = get_logger(__name__)


@router.post("/claims/{claim_id}/documents", response_model=SourceFileOut)
async def upload_document(
    claim_id: uuid.UUID,
    upload: UploadFile = File(...),
    session: Session = Depends(db_session),
    user: User = Depends(get_current_user),
) -> SourceFileOut:
    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    body = await upload.read()
    log_event(
        logger,
        "upload.received",
        claim_id=str(claim.id),
        filename=upload.filename or "upload.bin",
        content_type=upload.content_type,
        byte_size=len(body),
    )
    source = create_source_file(
        session,
        claim=claim,
        user=user,
        filename=upload.filename or "upload.bin",
        content_type=upload.content_type,
        body=body,
    )
    async_result = extract_source_file_task.delay(str(source.id))
    log_event(
        logger,
        "celery.task.enqueued",
        task_name="extract_source_file",
        celery_task_id=async_result.id,
        claim_id=str(claim.id),
        source_file_id=str(source.id),
    )
    return SourceFileOut.model_validate(source, from_attributes=True)


@router.post("/claims/{claim_id}/documents/batch", response_model=list[SourceFileOut])
async def upload_documents_batch(
    claim_id: uuid.UUID,
    uploads: list[UploadFile] = File(...),
    session: Session = Depends(db_session),
    user: User = Depends(get_current_user),
) -> list[SourceFileOut]:
    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    out: list[SourceFileOut] = []
    for upload in uploads:
        body = await upload.read()
        log_event(
            logger,
            "upload.received",
            claim_id=str(claim.id),
            filename=upload.filename or "upload.bin",
            content_type=upload.content_type,
            byte_size=len(body),
        )
        sources = create_source_files_from_upload(
            session,
            claim=claim,
            user=user,
            filename=upload.filename or "upload.bin",
            content_type=upload.content_type,
            body=body,
        )
        for source in sources:
            async_result = extract_source_file_task.delay(str(source.id))
            log_event(
                logger,
                "celery.task.enqueued",
                task_name="extract_source_file",
                celery_task_id=async_result.id,
                claim_id=str(claim.id),
                source_file_id=str(source.id),
            )
            out.append(SourceFileOut.model_validate(source, from_attributes=True))
    return out


@router.get("/claims/{claim_id}/documents", response_model=list[SourceFileOut])
def list_documents(
    claim_id: uuid.UUID,
    session: Session = Depends(db_session),
    user: User = Depends(get_current_user),
) -> list[SourceFileOut]:
    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    docs = list_source_files(session, claim=claim, user=user)
    return [SourceFileOut.model_validate(d, from_attributes=True) for d in docs]


@router.get("/documents/{source_file_id}/download")
def download_document(
    source_file_id: uuid.UUID,
    session: Session = Depends(db_session),
    user: User = Depends(get_current_user),
) -> Response:
    from sqlalchemy import select

    from serendipity_spend.modules.documents.models import SourceFile
    from serendipity_spend.modules.documents.service import assert_claim_access

    source = session.scalar(select(SourceFile).where(SourceFile.id == source_file_id))
    if not source:
        return Response(status_code=404)
    claim = get_claim_for_user(session, claim_id=source.claim_id, user=user)
    assert_claim_access(claim=claim, user=user)
    body = get_storage().get(key=source.storage_key)
    return Response(content=body, media_type=source.content_type or "application/octet-stream")
