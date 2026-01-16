from __future__ import annotations

import secrets
import uuid
from decimal import Decimal
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.datastructures import URL

from serendipity_spend.core.config import settings
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
from serendipity_spend.modules.documents.service import (
    create_source_file,
    create_source_files_from_upload,
    list_source_files,
)
from serendipity_spend.modules.expenses.service import list_items
from serendipity_spend.modules.exports.models import ExportRun
from serendipity_spend.modules.exports.service import create_export_run
from serendipity_spend.modules.fx.service import apply_fx_to_claim_items, upsert_fx_rate
from serendipity_spend.modules.identity.google_oauth import (
    build_google_authorize_url,
    exchange_google_code,
    google_oauth_enabled,
    verify_google_id_token,
)
from serendipity_spend.modules.identity.models import User
from serendipity_spend.modules.identity.service import authenticate_user, get_or_create_google_user
from serendipity_spend.modules.policy.models import PolicyViolation
from serendipity_spend.modules.policy.service import evaluate_claim
from serendipity_spend.modules.workflow.models import ApprovalDecision
from serendipity_spend.modules.workflow.service import approve_claim, list_tasks, resolve_task
from serendipity_spend.worker.tasks import extract_source_file_task, generate_export_task

WEB_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(WEB_DIR / "templates"))

router = APIRouter(include_in_schema=False)

# Static files path for mounting in main.py
STATIC_DIR = WEB_DIR / "static"


def _external_url(request: Request, url: URL) -> str:
    forwarded_proto = request.headers.get("x-forwarded-proto")
    forwarded_host = request.headers.get("x-forwarded-host") or request.headers.get("host")
    if forwarded_proto:
        url = url.replace(scheme=forwarded_proto.split(",")[0].strip())
    if forwarded_host:
        url = url.replace(netloc=forwarded_host.split(",")[0].strip())
    return str(url)


def _is_https_request(request: Request) -> bool:
    forwarded_proto = request.headers.get("x-forwarded-proto") or ""
    if forwarded_proto.split(",")[0].strip().lower() == "https":
        return True
    return request.url.scheme == "https"


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
    user = session.scalar(select(User).where(User.id == user_id, User.is_active.is_(True)))
    if not user:
        return None
    allowed_domain = (settings.google_oauth_allowed_domain or "").strip().lower()
    if google_oauth_enabled() and allowed_domain and not user.email.lower().endswith(
        f"@{allowed_domain}"
    ):
        return None
    return user


@router.get("/", response_class=RedirectResponse)
def root() -> RedirectResponse:
    return RedirectResponse(url="/app", status_code=302)


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            "error": None,
            "google_enabled": google_oauth_enabled(),
            "password_enabled": not google_oauth_enabled(),
        },
    )


@router.post("/login", response_class=RedirectResponse)
def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    session: Session = Depends(db_session),
) -> RedirectResponse:
    if google_oauth_enabled():
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": "Password login is disabled (use Google).",
                "google_enabled": True,
                "password_enabled": False,
            },
            status_code=400,
        )

    try:
        user = authenticate_user(session, email=email, password=password)
    except Exception:  # noqa: BLE001
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": "Invalid credentials",
                "google_enabled": False,
                "password_enabled": True,
            },
            status_code=401,
        )

    token = create_access_token(subject=str(user.id))
    resp = RedirectResponse(url="/app", status_code=303)
    resp.set_cookie(
        "access_token",
        token,
        httponly=True,
        samesite="lax",
        secure=_is_https_request(request),
    )
    return resp


@router.post("/logout", response_class=RedirectResponse)
def logout() -> RedirectResponse:
    resp = RedirectResponse(url="/login", status_code=303)
    resp.delete_cookie("access_token")
    resp.delete_cookie("google_oauth_state")
    return resp


@router.get("/auth/google/login", response_class=RedirectResponse)
def google_oauth_login(request: Request) -> RedirectResponse:
    if not google_oauth_enabled():
        return RedirectResponse(url="/login", status_code=303)

    state = secrets.token_urlsafe(32)
    callback_url = URL(str(request.url_for("google_oauth_callback")))
    redirect_uri = _external_url(request, callback_url)
    auth_url = build_google_authorize_url(state=state, redirect_uri=redirect_uri)

    resp = RedirectResponse(url=auth_url, status_code=302)
    resp.set_cookie(
        "google_oauth_state",
        state,
        httponly=True,
        samesite="lax",
        max_age=600,
        secure=_is_https_request(request),
    )
    return resp


@router.get("/auth/google/callback", name="google_oauth_callback", response_class=RedirectResponse)
def google_oauth_callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    session: Session = Depends(db_session),
) -> RedirectResponse:
    if not google_oauth_enabled():
        return RedirectResponse(url="/login", status_code=303)

    cookie_state = request.cookies.get("google_oauth_state")
    if error:
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": f"Google login failed: {error}",
                "google_enabled": True,
                "password_enabled": False,
            },
            status_code=401,
        )
    if not code or not state or not cookie_state or state != cookie_state:
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": "Google login failed: invalid state",
                "google_enabled": True,
                "password_enabled": False,
            },
            status_code=401,
        )

    try:
        callback_url = URL(str(request.url_for("google_oauth_callback")))
        redirect_uri = _external_url(request, callback_url)
        tokens = exchange_google_code(code=code, redirect_uri=redirect_uri)
        id_token = tokens.get("id_token")
        if not isinstance(id_token, str) or not id_token:
            raise ValueError("Missing id_token in Google response")
        claims = verify_google_id_token(id_token)
        email = str(claims.get("email"))
        full_name = claims.get("name") if isinstance(claims.get("name"), str) else None
        user = get_or_create_google_user(session, email=email, full_name=full_name)
    except Exception as e:  # noqa: BLE001
        return templates.TemplateResponse(
            "login.html",
            {
                "request": request,
                "error": f"Google login failed: {e}",
                "google_enabled": True,
                "password_enabled": False,
            },
            status_code=401,
        )

    token = create_access_token(subject=str(user.id))
    resp = RedirectResponse(url="/app", status_code=303)
    resp.delete_cookie("google_oauth_state")
    resp.set_cookie(
        "access_token",
        token,
        httponly=True,
        samesite="lax",
        secure=_is_https_request(request),
    )
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
    upload: UploadFile | None = File(None),
    uploads: list[UploadFile] | None = File(None),
    session: Session = Depends(db_session),
) -> RedirectResponse:
    user = _get_optional_user(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    batch = uploads or ([upload] if upload is not None else [])
    for f in batch:
        body = await f.read()
        sources = create_source_files_from_upload(
            session,
            claim=claim,
            user=user,
            filename=f.filename or "upload.bin",
            content_type=f.content_type,
            body=body,
        )
        for source in sources:
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
