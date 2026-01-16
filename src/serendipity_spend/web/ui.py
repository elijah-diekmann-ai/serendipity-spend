from __future__ import annotations

import uuid
from decimal import Decimal
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from serendipity_spend.core.db import db_session
from serendipity_spend.core.security import create_access_token, decode_access_token
from serendipity_spend.core.storage import get_storage
from serendipity_spend.modules.claims.schemas import ClaimUpdate
from serendipity_spend.modules.claims.service import (
    create_claim,
    get_claim_for_user,
    list_claims_for_user,
    route_claim,
    update_claim,
)
from serendipity_spend.modules.documents.models import SourceFile
from serendipity_spend.modules.documents.service import create_source_file, list_source_files
from serendipity_spend.modules.expenses.service import list_items
from serendipity_spend.modules.exports.models import ExportRun
from serendipity_spend.modules.exports.service import create_export_run
from serendipity_spend.modules.fx.service import apply_fx_to_claim_items, upsert_fx_rate
from serendipity_spend.modules.identity.models import User
from serendipity_spend.modules.identity.service import authenticate_user
from serendipity_spend.modules.policy.models import PolicyViolation
from serendipity_spend.modules.policy.service import evaluate_claim
from serendipity_spend.modules.workflow.models import ApprovalDecision
from serendipity_spend.modules.workflow.service import approve_claim, list_tasks, resolve_task
from serendipity_spend.worker.tasks import extract_source_file_task, generate_export_task

WEB_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(WEB_DIR / "templates"))

router = APIRouter(include_in_schema=False)
router.mount("/static", StaticFiles(directory=str(WEB_DIR / "static")), name="static")


def _get_optional_user(request: Request, session: Session) -> User | None:
    token = request.cookies.get("access_token")
    if not token:
        return None
    subject = decode_access_token(token)
    if not subject:
        return None
    try:
        user_id = uuid.UUID(subject)
    except ValueError:
        return None
    return session.scalar(select(User).where(User.id == user_id, User.is_active.is_(True)))


@router.get("/", response_class=RedirectResponse)
def root() -> RedirectResponse:
    return RedirectResponse(url="/app", status_code=302)


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@router.post("/login", response_class=RedirectResponse)
def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    session: Session = Depends(db_session),
) -> RedirectResponse:
    try:
        user = authenticate_user(session, email=email, password=password)
    except Exception:  # noqa: BLE001
        return templates.TemplateResponse(
            "login.html", {"request": request, "error": "Invalid credentials"}, status_code=401
        )

    token = create_access_token(subject=str(user.id))
    resp = RedirectResponse(url="/app", status_code=303)
    resp.set_cookie("access_token", token, httponly=True, samesite="lax")
    return resp


@router.post("/logout", response_class=RedirectResponse)
def logout() -> RedirectResponse:
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie("access_token")
    return resp


@router.get("/app", response_class=HTMLResponse)
def dashboard(request: Request, session: Session = Depends(db_session)) -> HTMLResponse:
    user = _get_optional_user(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    claims = list_claims_for_user(session, user=user)
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "user": user, "claims": claims},
    )


@router.post("/app/claims/new", response_class=RedirectResponse)
def create_claim_ui(request: Request, session: Session = Depends(db_session)) -> RedirectResponse:
    user = _get_optional_user(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    claim = create_claim(session, employee_id=user.id, home_currency="SGD")
    evaluate_claim(session, claim_id=claim.id)
    return RedirectResponse(url=f"/app/claims/{claim.id}", status_code=303)


@router.get("/app/claims/{claim_id}", response_class=HTMLResponse)
def claim_detail(
    claim_id: uuid.UUID,
    request: Request,
    session: Session = Depends(db_session),
) -> HTMLResponse:
    user = _get_optional_user(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    docs = list_source_files(session, claim=claim, user=user)
    items = list_items(session, claim_id=claim.id)
    tasks = list_tasks(session, claim_id=claim.id)
    violations = list(
        session.scalars(select(PolicyViolation).where(PolicyViolation.claim_id == claim.id))
    )
    exports = list(
        session.scalars(
            select(ExportRun)
            .where(ExportRun.claim_id == claim.id)
            .order_by(ExportRun.created_at.desc())
        )
    )

    return templates.TemplateResponse(
        "claim_detail.html",
        {
            "request": request,
            "user": user,
            "claim": claim,
            "docs": docs,
            "items": items,
            "tasks": tasks,
            "violations": violations,
            "exports": exports,
        },
    )


@router.post("/app/claims/{claim_id}/route-to-me", response_class=RedirectResponse)
def route_to_me(
    claim_id: uuid.UUID,
    request: Request,
    session: Session = Depends(db_session),
) -> RedirectResponse:
    user = _get_optional_user(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    try:
        route_claim(session, claim=claim, approver_id=user.id)
    except Exception:  # noqa: BLE001
        pass
    return RedirectResponse(url=f"/app/claims/{claim.id}", status_code=303)


@router.post("/app/claims/{claim_id}/update", response_class=RedirectResponse)
def claim_update(
    claim_id: uuid.UUID,
    request: Request,
    travel_start_date: str = Form(""),
    travel_end_date: str = Form(""),
    purpose: str = Form(""),
    session: Session = Depends(db_session),
) -> RedirectResponse:
    user = _get_optional_user(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    payload = ClaimUpdate(
        travel_start_date=travel_start_date or None,
        travel_end_date=travel_end_date or None,
        purpose=purpose or None,
    )
    update_claim(session, claim=claim, user=user, **payload.model_dump())
    evaluate_claim(session, claim_id=claim.id)
    return RedirectResponse(url=f"/app/claims/{claim.id}", status_code=303)


@router.post("/app/claims/{claim_id}/upload", response_class=RedirectResponse)
async def upload_document_ui(
    claim_id: uuid.UUID,
    request: Request,
    upload: UploadFile = File(...),
    session: Session = Depends(db_session),
) -> RedirectResponse:
    user = _get_optional_user(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    body = await upload.read()
    source = create_source_file(
        session,
        claim=claim,
        user=user,
        filename=upload.filename or "upload.bin",
        content_type=upload.content_type,
        body=body,
    )
    extract_source_file_task.delay(str(source.id))
    return RedirectResponse(url=f"/app/claims/{claim.id}", status_code=303)


@router.get("/app/documents/{source_file_id}/download")
def ui_download_document(
    source_file_id: uuid.UUID,
    request: Request,
    session: Session = Depends(db_session),
) -> Response:
    user = _get_optional_user(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    source = session.scalar(select(SourceFile).where(SourceFile.id == source_file_id))
    if not source:
        return Response(status_code=404)
    _ = get_claim_for_user(session, claim_id=source.claim_id, user=user)
    body = get_storage().get(key=source.storage_key)
    return Response(content=body, media_type=source.content_type or "application/octet-stream")


@router.post("/app/claims/{claim_id}/submit", response_class=RedirectResponse)
def submit_claim_ui(
    claim_id: uuid.UUID, request: Request, session: Session = Depends(db_session)
) -> RedirectResponse:
    user = _get_optional_user(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    try:
        from serendipity_spend.modules.claims.service import submit_claim

        submit_claim(session, claim=claim, user=user)
    except Exception:
        pass
    return RedirectResponse(url=f"/app/claims/{claim.id}", status_code=303)


@router.post("/app/tasks/{task_id}/resolve", response_class=RedirectResponse)
def resolve_task_ui(
    task_id: uuid.UUID,
    claim_id: uuid.UUID,
    request: Request,
    session: Session = Depends(db_session),
) -> RedirectResponse:
    user = _get_optional_user(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    try:
        resolve_task(session, task_id=task_id, user=user)
    except Exception:
        pass
    return RedirectResponse(url=f"/app/claims/{claim_id}", status_code=303)


@router.post("/app/claims/{claim_id}/fx", response_class=RedirectResponse)
def set_fx_ui(
    claim_id: uuid.UUID,
    request: Request,
    usd_to_home: str = Form(""),
    cad_to_home: str = Form(""),
    session: Session = Depends(db_session),
) -> RedirectResponse:
    user = _get_optional_user(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    if usd_to_home:
        upsert_fx_rate(
            session,
            claim_id=claim.id,
            from_currency="USD",
            to_currency=claim.home_currency,
            rate=Decimal(usd_to_home),
        )
    if cad_to_home:
        upsert_fx_rate(
            session,
            claim_id=claim.id,
            from_currency="CAD",
            to_currency=claim.home_currency,
            rate=Decimal(cad_to_home),
        )
    apply_fx_to_claim_items(session, claim_id=claim.id)
    evaluate_claim(session, claim_id=claim.id)
    return RedirectResponse(url=f"/app/claims/{claim.id}", status_code=303)


@router.post("/app/claims/{claim_id}/export", response_class=RedirectResponse)
def create_export_ui(
    claim_id: uuid.UUID,
    request: Request,
    session: Session = Depends(db_session),
) -> RedirectResponse:
    user = _get_optional_user(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    run = create_export_run(claim_id=claim.id, requested_by_user_id=user.id)
    generate_export_task.delay(str(run.id))
    return RedirectResponse(url=f"/app/claims/{claim.id}", status_code=303)


@router.get("/app/exports/{export_run_id}/download/summary")
def ui_download_export_summary(
    export_run_id: uuid.UUID,
    request: Request,
    session: Session = Depends(db_session),
) -> Response:
    user = _get_optional_user(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    run = session.scalar(select(ExportRun).where(ExportRun.id == export_run_id))
    if not run or not run.summary_xlsx_key:
        return Response(status_code=404)
    _ = get_claim_for_user(session, claim_id=run.claim_id, user=user)
    body = get_storage().get(key=run.summary_xlsx_key)
    return Response(
        content=body, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )


@router.get("/app/exports/{export_run_id}/download/supporting")
def ui_download_export_supporting(
    export_run_id: uuid.UUID,
    request: Request,
    session: Session = Depends(db_session),
) -> Response:
    user = _get_optional_user(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    run = session.scalar(select(ExportRun).where(ExportRun.id == export_run_id))
    if not run or not run.supporting_zip_key:
        return Response(status_code=404)
    _ = get_claim_for_user(session, claim_id=run.claim_id, user=user)
    body = get_storage().get(key=run.supporting_zip_key)
    return Response(content=body, media_type="application/zip")


@router.post("/app/claims/{claim_id}/approve", response_class=RedirectResponse)
def approve_ui(
    claim_id: uuid.UUID,
    request: Request,
    session: Session = Depends(db_session),
) -> RedirectResponse:
    user = _get_optional_user(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    try:
        approve_claim(
            session, claim=claim, user=user, decision=ApprovalDecision.APPROVED, comment=None
        )
    except Exception:
        pass
    return RedirectResponse(url=f"/app/claims/{claim.id}", status_code=303)


@router.post("/app/claims/{claim_id}/request-changes", response_class=RedirectResponse)
def request_changes_ui(
    claim_id: uuid.UUID,
    request: Request,
    session: Session = Depends(db_session),
) -> RedirectResponse:
    user = _get_optional_user(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    try:
        approve_claim(
            session,
            claim=claim,
            user=user,
            decision=ApprovalDecision.CHANGES_REQUESTED,
            comment=None,
        )
    except Exception:
        pass
    return RedirectResponse(url=f"/app/claims/{claim.id}", status_code=303)


@router.post("/app/claims/{claim_id}/reject", response_class=RedirectResponse)
def reject_ui(
    claim_id: uuid.UUID,
    request: Request,
    session: Session = Depends(db_session),
) -> RedirectResponse:
    user = _get_optional_user(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    try:
        approve_claim(
            session, claim=claim, user=user, decision=ApprovalDecision.REJECTED, comment=None
        )
    except Exception:
        pass
    return RedirectResponse(url=f"/app/claims/{claim.id}", status_code=303)
