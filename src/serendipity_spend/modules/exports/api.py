from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from serendipity_spend.api.deps import get_current_user
from serendipity_spend.core.db import db_session
from serendipity_spend.core.logging import get_logger, log_event
from serendipity_spend.core.storage import get_storage
from serendipity_spend.modules.claims.service import get_claim_for_user
from serendipity_spend.modules.exports.models import ExportRun
from serendipity_spend.modules.exports.schemas import ExportRunOut
from serendipity_spend.modules.exports.service import create_export_run
from serendipity_spend.modules.identity.models import User
from serendipity_spend.worker.tasks import generate_export_task

router = APIRouter(tags=["exports"])
logger = get_logger(__name__)


@router.post("/claims/{claim_id}/exports", response_model=ExportRunOut)
def create_export(
    claim_id: uuid.UUID,
    session: Session = Depends(db_session),
    user: User = Depends(get_current_user),
) -> ExportRunOut:
    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    run = create_export_run(claim_id=claim.id, requested_by_user_id=user.id)
    async_result = generate_export_task.delay(str(run.id))
    log_event(
        logger,
        "celery.task.enqueued",
        task_name="generate_export",
        celery_task_id=async_result.id,
        claim_id=str(claim.id),
        export_run_id=str(run.id),
    )
    return ExportRunOut.model_validate(run, from_attributes=True)


@router.get("/claims/{claim_id}/exports", response_model=list[ExportRunOut])
def list_exports(
    claim_id: uuid.UUID,
    session: Session = Depends(db_session),
    user: User = Depends(get_current_user),
) -> list[ExportRunOut]:
    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    runs = list(
        session.scalars(
            select(ExportRun)
            .where(ExportRun.claim_id == claim.id)
            .order_by(ExportRun.created_at.desc())
        )
    )
    return [ExportRunOut.model_validate(r, from_attributes=True) for r in runs]


@router.get("/exports/{export_run_id}", response_model=ExportRunOut)
def get_export(
    export_run_id: uuid.UUID,
    session: Session = Depends(db_session),
    user: User = Depends(get_current_user),
) -> ExportRunOut:
    run = session.scalar(select(ExportRun).where(ExportRun.id == export_run_id))
    if not run:
        return Response(status_code=404)  # type: ignore[return-value]
    _ = get_claim_for_user(session, claim_id=run.claim_id, user=user)
    return ExportRunOut.model_validate(run, from_attributes=True)


@router.get("/exports/{export_run_id}/download/summary")
def download_summary(
    export_run_id: uuid.UUID,
    session: Session = Depends(db_session),
    user: User = Depends(get_current_user),
) -> Response:
    run = session.scalar(select(ExportRun).where(ExportRun.id == export_run_id))
    if not run or not run.summary_xlsx_key:
        return Response(status_code=404)
    _ = get_claim_for_user(session, claim_id=run.claim_id, user=user)
    body = get_storage().get(key=run.summary_xlsx_key)
    return Response(
        content=body, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )


@router.get("/exports/{export_run_id}/download/supporting")
def download_supporting(
    export_run_id: uuid.UUID,
    session: Session = Depends(db_session),
    user: User = Depends(get_current_user),
) -> Response:
    run = session.scalar(select(ExportRun).where(ExportRun.id == export_run_id))
    if not run or (not run.supporting_pdf_key and not run.supporting_zip_key):
        return Response(status_code=404)
    _ = get_claim_for_user(session, claim_id=run.claim_id, user=user)
    if run.supporting_pdf_key:
        body = get_storage().get(key=run.supporting_pdf_key)
        return Response(
            content=body,
            media_type="application/pdf",
            headers={"Content-Disposition": 'attachment; filename="Supporting_Documents.pdf"'},
        )

    body = get_storage().get(key=run.supporting_zip_key)
    return Response(
        content=body,
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="Supporting_Documents.zip"'},
    )
