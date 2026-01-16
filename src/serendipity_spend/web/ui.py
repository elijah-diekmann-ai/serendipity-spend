from __future__ import annotations

import secrets
import uuid
from datetime import date
from decimal import Decimal
from pathlib import Path
from urllib.parse import quote

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.datastructures import URL

from serendipity_spend.core.config import settings
from serendipity_spend.core.currencies import all_currency_codes, normalize_currency
from serendipity_spend.core.db import db_session
from serendipity_spend.core.security import create_access_token, decode_access_token
from serendipity_spend.core.storage import get_storage
from serendipity_spend.modules.claims.models import ClaimStatus
from serendipity_spend.modules.claims.schemas import ClaimUpdate
from serendipity_spend.modules.claims.service import (
    create_claim,
    delete_claim,
    get_claim_for_user,
    list_claims_for_user,
    route_claim,
    update_claim,
)
from serendipity_spend.modules.documents.models import SourceFile
from serendipity_spend.modules.documents.service import (
    create_source_files_from_upload,
    list_source_files,
)
from serendipity_spend.modules.expenses.service import (
    create_manual_item,
    delete_expense_item,
    list_items,
    update_expense_item,
)
from serendipity_spend.modules.exports.models import ExportRun
from serendipity_spend.modules.exports.service import create_export_run
from serendipity_spend.modules.fx.models import FxRate
from serendipity_spend.modules.fx.service import (
    apply_fx_to_claim_items,
    auto_upsert_fx_rates,
    upsert_fx_rate,
)
from serendipity_spend.modules.identity.google_oauth import (
    build_google_authorize_url,
    exchange_google_code,
    google_oauth_enabled,
    verify_google_id_token,
)
from serendipity_spend.modules.identity.models import User, UserRole
from serendipity_spend.modules.identity.service import authenticate_user, get_or_create_google_user
from serendipity_spend.modules.policy.blocking import is_violation_blocking
from serendipity_spend.modules.policy.models import (
    PolicyException,
    PolicyExceptionStatus,
    PolicySeverity,
    PolicyViolation,
    ViolationStatus,
)
from serendipity_spend.modules.policy.service import evaluate_claim
from serendipity_spend.modules.workflow.models import ApprovalDecision, Task, TaskStatus
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


def _policy_task_key(task: Task) -> str | None:
    if not task.type.startswith("POLICY_"):
        return None
    rule_id = task.type[len("POLICY_") :]
    if task.expense_item_id:
        return f"item:{task.expense_item_id}:{rule_id}"
    return f"claim:{task.claim_id}:{rule_id}"


def _is_blocking_violation(v: PolicyViolation, *, allow_pending_exceptions: bool) -> bool:
    return is_violation_blocking(v, allow_pending_exceptions=allow_pending_exceptions)


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


@router.get("/app/claims/new", response_class=HTMLResponse)
def new_claim_page(request: Request, session: Session = Depends(db_session)) -> HTMLResponse:
    user = _get_optional_user(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    return templates.TemplateResponse(
        "new_claim.html",
        {
            "request": request,
            "user": user,
            "currency_options": ["SGD", "USD", "CAD", "GBP", "EUR"],
            "default_home_currency": "SGD",
        },
    )


@router.post("/app/claims/new", response_class=RedirectResponse)
def create_claim_ui(
    request: Request,
    home_currency: str = Form("SGD"),
    session: Session = Depends(db_session),
) -> RedirectResponse:
    user = _get_optional_user(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    claim = create_claim(session, employee_id=user.id, home_currency=(home_currency or "SGD"))
    evaluate_claim(session, claim_id=claim.id)
    return RedirectResponse(url=f"/app/claims/{claim.id}", status_code=303)


@router.get("/app/tasks", response_class=HTMLResponse)
def tasks_page(request: Request, session: Session = Depends(db_session)) -> HTMLResponse:
    user = _get_optional_user(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    tasks = list(
        session.scalars(
            select(Task)
            .where(Task.assigned_to_user_id == user.id, Task.status == TaskStatus.OPEN)
            .order_by(Task.created_at.desc())
        )
    )
    return templates.TemplateResponse(
        "tasks.html",
        {"request": request, "user": user, "tasks": tasks},
    )


@router.get("/app/inbox", response_class=HTMLResponse)
def inbox_page(request: Request, session: Session = Depends(db_session)) -> HTMLResponse:
    user = _get_optional_user(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    if user.role.value not in {"APPROVER", "ADMIN"}:
        return RedirectResponse(url="/app", status_code=303)

    from sqlalchemy.orm import selectinload

    from serendipity_spend.modules.claims.models import Claim, ClaimStatus

    review_q = (
        select(Claim)
        .options(selectinload(Claim.employee))
        .where(Claim.status == ClaimStatus.NEEDS_APPROVER_REVIEW)
        .order_by(Claim.created_at.desc())
    )
    routing_q = (
        select(Claim)
        .options(selectinload(Claim.employee))
        .where(Claim.status == ClaimStatus.SUBMITTED)
        .order_by(Claim.created_at.desc())
    )
    if user.role.value == "APPROVER":
        review_q = review_q.where(Claim.approver_id == user.id)
        routing_claims: list[Claim] = []
    else:
        routing_claims = list(session.scalars(routing_q))

    review_claims = list(session.scalars(review_q))
    return templates.TemplateResponse(
        "inbox.html",
        {
            "request": request,
            "user": user,
            "review_claims": review_claims,
            "routing_claims": routing_claims,
        },
    )


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
    route_targets: list[User] = []
    if user.role == UserRole.ADMIN:
        route_targets = list(
            session.scalars(
                select(User)
                .where(
                    User.is_active.is_(True),
                    User.role.in_([UserRole.APPROVER, UserRole.ADMIN]),
                )
                .order_by(User.email.asc())
            )
        )

    fx_values = {
        fx.from_currency: str(fx.rate)
        for fx in session.scalars(
            select(FxRate).where(
                FxRate.claim_id == claim.id,
                FxRate.to_currency == claim.home_currency,
            )
        )
    }
    home_cur = str(claim.home_currency or "").upper()
    fx_currency_set: set[str] = set()
    for item in items:
        cur = normalize_currency(getattr(item, "amount_original_currency", None))
        if cur and cur != home_cur:
            fx_currency_set.add(cur)
    for cur in fx_values.keys():
        cur_norm = normalize_currency(cur)
        if cur_norm and cur_norm != home_cur:
            fx_currency_set.add(cur_norm)
    fx_currencies = sorted(fx_currency_set)

    edit_item = None
    edit_item_id = request.query_params.get("edit_item_id")
    if edit_item_id:
        try:
            edit_uuid = uuid.UUID(edit_item_id)
        except ValueError:
            edit_uuid = None
        if edit_uuid:
            edit_item = next((i for i in items if i.id == edit_uuid), None)
    tasks = list_tasks(session, claim_id=claim.id)
    violations = list(
        session.scalars(select(PolicyViolation).where(PolicyViolation.claim_id == claim.id))
    )

    items_by_id = {i.id: i for i in items}

    policy_tasks_by_key: dict[str, Task] = {}
    for t in tasks:
        key = _policy_task_key(t)
        if not key:
            continue
        existing = policy_tasks_by_key.get(key)
        if not existing or t.created_at > existing.created_at:
            policy_tasks_by_key[key] = t

    open_violations = [v for v in violations if v.status == ViolationStatus.OPEN]
    resolved_violations = [v for v in violations if v.status == ViolationStatus.RESOLVED]

    policy_exceptions = list(
        session.scalars(select(PolicyException).where(PolicyException.claim_id == claim.id))
    )
    policy_exceptions_by_key = {e.dedupe_key: e for e in policy_exceptions}

    allow_pending_exceptions = True
    if (
        user.role in {UserRole.APPROVER, UserRole.ADMIN}
        and claim.status == ClaimStatus.NEEDS_APPROVER_REVIEW
    ):
        allow_pending_exceptions = False

    severity_rank = {
        PolicySeverity.FAIL: 0,
        PolicySeverity.NEEDS_INFO: 1,
        PolicySeverity.WARN: 2,
        PolicySeverity.PASS: 3,
    }
    open_violations.sort(
        key=lambda v: (
            0
            if _is_blocking_violation(v, allow_pending_exceptions=allow_pending_exceptions)
            else 1,
            0 if v.expense_item_id is None else 1,
            severity_rank.get(v.severity, 99),
            v.rule_id,
            v.created_at,
        )
    )
    resolved_violations.sort(key=lambda v: v.resolved_at or v.updated_at, reverse=True)

    violation_counts: dict[str, int] = {}
    blocking_count = 0
    for v in open_violations:
        key = v.severity.value
        violation_counts[key] = violation_counts.get(key, 0) + 1
        if _is_blocking_violation(v, allow_pending_exceptions=allow_pending_exceptions):
            blocking_count += 1

    open_other_tasks = [
        t
        for t in tasks
        if t.status == TaskStatus.OPEN and not t.type.startswith("POLICY_")
    ]

    exports = list(
        session.scalars(
            select(ExportRun)
            .where(ExportRun.claim_id == claim.id)
            .order_by(ExportRun.created_at.desc())
        )
    )

    submit_error = request.query_params.get("submit_error")
    submit_ok = request.query_params.get("submit_ok")
    route_error = request.query_params.get("route_error")
    route_ok = request.query_params.get("route_ok")
    policy_error = request.query_params.get("policy_error")
    policy_ok = request.query_params.get("policy_ok")
    approve_error = request.query_params.get("approve_error")
    approve_ok = request.query_params.get("approve_ok")
    delete_error = request.query_params.get("delete_error")
    fx_error = request.query_params.get("fx_error")
    fx_invalid = request.query_params.get("fx_invalid")
    fx_skipped = request.query_params.get("fx_skipped")

    return templates.TemplateResponse(
        "claim_detail.html",
        {
            "request": request,
            "user": user,
            "claim": claim,
            "docs": docs,
            "items": items,
            "items_by_id": items_by_id,
            "edit_item": edit_item,
            "tasks": tasks,
            "violations": violations,
            "policy_tasks_by_key": policy_tasks_by_key,
            "policy_exceptions_by_key": policy_exceptions_by_key,
            "policy_summary": {
                "open": open_violations,
                "resolved": resolved_violations,
                "counts": violation_counts,
                "open_count": len(open_violations),
                "blocking_count": blocking_count,
            },
            "open_other_tasks": open_other_tasks,
            "exports": exports,
            "fx_values": fx_values,
            "fx_currencies": fx_currencies,
            "submit_error": submit_error,
            "submit_ok": submit_ok,
            "route_error": route_error,
            "route_ok": route_ok,
            "policy_error": policy_error,
            "policy_ok": policy_ok,
            "approve_error": approve_error,
            "approve_ok": approve_ok,
            "delete_error": delete_error,
            "fx_error": fx_error,
            "fx_invalid": fx_invalid,
            "fx_skipped": fx_skipped,
            "route_targets": route_targets,
            "expense_categories": [
                "transport",
                "lodging",
                "airfare",
                "meals",
                "travel_ancillary",
                "airline_fee",
                "other",
            ],
            "currency_options": [
                home_cur,
                *[c for c in all_currency_codes() if c != home_cur],
            ],
        },
    )


@router.post("/app/claims/{claim_id}/items/new", response_class=RedirectResponse)
def create_expense_item_ui(
    claim_id: uuid.UUID,
    request: Request,
    vendor: str = Form(...),
    transaction_date: str = Form(""),
    amount_original_amount: str = Form(...),
    amount_original_currency: str = Form(...),
    category: str = Form(""),
    description: str = Form(""),
    hotel_nights: str = Form(""),
    flight_duration_hours: str = Form(""),
    flight_cabin_class: str = Form(""),
    attendees: str = Form(""),
    employee_reviewed: str = Form(""),
    session: Session = Depends(db_session),
) -> RedirectResponse:
    user = _get_optional_user(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    claim = get_claim_for_user(session, claim_id=claim_id, user=user)

    tx_date = date.fromisoformat(transaction_date) if transaction_date else None
    amt = Decimal(amount_original_amount)

    metadata: dict = {}
    if hotel_nights:
        try:
            metadata["hotel_nights"] = int(hotel_nights)
        except ValueError:
            pass
    if flight_duration_hours:
        try:
            metadata["flight_duration_hours"] = float(flight_duration_hours)
        except ValueError:
            pass
    if flight_cabin_class.strip():
        metadata["flight_cabin_class"] = flight_cabin_class.strip()
    if attendees.strip():
        metadata["attendees"] = attendees.strip()
    metadata["employee_reviewed"] = bool(employee_reviewed)

    create_manual_item(
        session,
        claim=claim,
        user=user,
        vendor=vendor,
        category=category or None,
        description=description or None,
        transaction_date=tx_date,
        amount_original_amount=amt,
        amount_original_currency=amount_original_currency,
        metadata_json=metadata,
    )
    apply_fx_to_claim_items(session, claim_id=claim.id)
    evaluate_claim(session, claim_id=claim.id)
    return RedirectResponse(url=f"/app/claims/{claim.id}", status_code=303)


@router.post("/app/claims/{claim_id}/items/{item_id}/update", response_class=RedirectResponse)
def update_expense_item_ui(
    claim_id: uuid.UUID,
    item_id: uuid.UUID,
    request: Request,
    vendor: str = Form(...),
    transaction_date: str = Form(""),
    amount_original_amount: str = Form(...),
    amount_original_currency: str = Form(...),
    category: str = Form(""),
    description: str = Form(""),
    hotel_nights: str = Form(""),
    flight_duration_hours: str = Form(""),
    flight_cabin_class: str = Form(""),
    attendees: str = Form(""),
    employee_reviewed: str = Form(""),
    session: Session = Depends(db_session),
) -> RedirectResponse:
    user = _get_optional_user(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    claim = get_claim_for_user(session, claim_id=claim_id, user=user)

    metadata: dict = {}
    if hotel_nights:
        try:
            metadata["hotel_nights"] = int(hotel_nights)
        except ValueError:
            metadata["hotel_nights"] = None
    else:
        metadata["hotel_nights"] = None

    if flight_duration_hours:
        try:
            metadata["flight_duration_hours"] = float(flight_duration_hours)
        except ValueError:
            metadata["flight_duration_hours"] = None
    else:
        metadata["flight_duration_hours"] = None

    metadata["flight_cabin_class"] = flight_cabin_class.strip() or None
    metadata["attendees"] = attendees.strip() or None
    metadata["employee_reviewed"] = bool(employee_reviewed)

    changes = {
        "vendor": vendor,
        "category": category,
        "description": description,
        "transaction_date": date.fromisoformat(transaction_date) if transaction_date else None,
        "amount_original_amount": Decimal(amount_original_amount),
        "amount_original_currency": amount_original_currency,
        "metadata_json": metadata,
    }
    update_expense_item(session, claim=claim, user=user, item_id=item_id, changes=changes)
    apply_fx_to_claim_items(session, claim_id=claim.id)
    evaluate_claim(session, claim_id=claim.id)
    return RedirectResponse(url=f"/app/claims/{claim.id}", status_code=303)


@router.post("/app/claims/{claim_id}/items/{item_id}/delete", response_class=RedirectResponse)
def delete_expense_item_ui(
    claim_id: uuid.UUID,
    item_id: uuid.UUID,
    request: Request,
    session: Session = Depends(db_session),
) -> RedirectResponse:
    user = _get_optional_user(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    delete_expense_item(session, claim=claim, user=user, item_id=item_id)
    evaluate_claim(session, claim_id=claim.id)
    return RedirectResponse(url=f"/app/claims/{claim.id}", status_code=303)


@router.post("/app/claims/{claim_id}/route-to-me", response_class=RedirectResponse)
def route_to_me(
    claim_id: uuid.UUID,
    request: Request,
    session: Session = Depends(db_session),
) -> RedirectResponse:
    user = _get_optional_user(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    if user.role != UserRole.ADMIN:
        return RedirectResponse(url=f"/app/claims/{claim_id}", status_code=303)

    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    try:
        route_claim(session, claim=claim, approver_id=user.id)
    except Exception:  # noqa: BLE001
        pass
    return RedirectResponse(url=f"/app/claims/{claim.id}", status_code=303)


@router.post("/app/claims/{claim_id}/route", response_class=RedirectResponse)
def route_claim_ui(
    claim_id: uuid.UUID,
    request: Request,
    approver_id: str = Form(...),
    session: Session = Depends(db_session),
) -> RedirectResponse:
    user = _get_optional_user(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    if user.role != UserRole.ADMIN:
        return RedirectResponse(url=f"/app/claims/{claim_id}", status_code=303)

    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    try:
        route_claim(session, claim=claim, approver_id=uuid.UUID(approver_id))
        return RedirectResponse(url=f"/app/claims/{claim.id}?route_ok=1", status_code=303)
    except HTTPException as e:
        detail = e.detail
        message = "Claim could not be routed."
        if isinstance(detail, str):
            message = detail
        return RedirectResponse(
            url=f"/app/claims/{claim.id}?route_error={quote(message)}", status_code=303
        )
    except Exception:
        return RedirectResponse(
            url=f"/app/claims/{claim.id}?route_error={quote('Claim could not be routed.')}",
            status_code=303,
        )

@router.post("/app/claims/{claim_id}/delete", response_class=RedirectResponse)
def delete_claim_ui(
    claim_id: uuid.UUID,
    request: Request,
    session: Session = Depends(db_session),
) -> RedirectResponse:
    user = _get_optional_user(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)

    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    try:
        delete_claim(session, claim=claim, user=user)
    except HTTPException as e:
        detail = e.detail if isinstance(e.detail, str) else "Could not delete claim."
        return RedirectResponse(
            url=f"/app/claims/{claim.id}?delete_error={quote(detail)}",
            status_code=303,
        )
    except Exception as e:  # noqa: BLE001
        return RedirectResponse(
            url=f"/app/claims/{claim.id}?delete_error={quote(str(e))}",
            status_code=303,
        )
    return RedirectResponse(url="/app", status_code=303)


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
        return RedirectResponse(url=f"/app/claims/{claim.id}?submit_ok=1", status_code=303)
    except HTTPException as e:
        detail = e.detail
        message = "Claim could not be submitted."
        if isinstance(detail, dict):
            message = str(detail.get("message") or message)
            rules = detail.get("blocking_rules") or []
            if rules:
                message = f"{message} Blocking: {', '.join(rules)}."
        elif isinstance(detail, str):
            message = detail
        return RedirectResponse(
            url=f"/app/claims/{claim.id}?submit_error={quote(message)}", status_code=303
        )
    except Exception:
        return RedirectResponse(
            url=f"/app/claims/{claim.id}?submit_error={quote('Claim could not be submitted.')}",
            status_code=303,
        )


@router.post("/app/claims/{claim_id}/policy/exceptions/request", response_class=RedirectResponse)
def request_policy_exception_ui(
    claim_id: uuid.UUID,
    request: Request,
    violation_id: uuid.UUID = Form(...),
    justification: str = Form(""),
    session: Session = Depends(db_session),
) -> RedirectResponse:
    user = _get_optional_user(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    try:
        from serendipity_spend.modules.policy.service import request_policy_exception

        request_policy_exception(
            session,
            violation_id=violation_id,
            user=user,
            justification=justification,
        )
        return RedirectResponse(url=f"/app/claims/{claim.id}?policy_ok=1#policy", status_code=303)
    except HTTPException as e:
        detail = e.detail
        message = "Exception request failed."
        if isinstance(detail, str):
            message = detail
        return RedirectResponse(
            url=f"/app/claims/{claim.id}?policy_error={quote(message)}#policy", status_code=303
        )
    except Exception:
        return RedirectResponse(
            url=f"/app/claims/{claim.id}?policy_error={quote('Exception request failed.')}#policy",
            status_code=303,
        )


@router.post("/app/policy/exceptions/{exception_id}/decide", response_class=RedirectResponse)
def decide_policy_exception_ui(
    exception_id: uuid.UUID,
    request: Request,
    claim_id: uuid.UUID = Form(...),
    decision: str = Form(...),
    comment: str = Form(""),
    session: Session = Depends(db_session),
) -> RedirectResponse:
    user = _get_optional_user(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    try:
        from serendipity_spend.modules.policy.service import decide_policy_exception

        decide_policy_exception(
            session,
            exception_id=exception_id,
            user=user,
            decision=PolicyExceptionStatus(decision),
            comment=comment,
        )
        return RedirectResponse(url=f"/app/claims/{claim.id}?policy_ok=1#policy", status_code=303)
    except HTTPException as e:
        detail = e.detail
        message = "Decision failed."
        if isinstance(detail, dict):
            message = str(detail.get("message") or message)
        elif isinstance(detail, str):
            message = detail
        return RedirectResponse(
            url=f"/app/claims/{claim.id}?policy_error={quote(message)}#policy", status_code=303
        )
    except Exception:
        return RedirectResponse(
            url=f"/app/claims/{claim.id}?policy_error={quote('Decision failed.')}#policy",
            status_code=303,
        )


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
    redirect_claim_id = claim_id
    try:
        task = resolve_task(session, task_id=task_id, user=user)
        redirect_claim_id = task.claim_id
        if task.type.startswith("POLICY_"):
            evaluate_claim(session, claim_id=task.claim_id)
    except Exception:
        pass
    return RedirectResponse(url=f"/app/claims/{redirect_claim_id}", status_code=303)


@router.post("/app/claims/{claim_id}/fx", response_class=RedirectResponse)
async def set_fx_ui(
    claim_id: uuid.UUID,
    request: Request,
    session: Session = Depends(db_session),
) -> RedirectResponse:
    user = _get_optional_user(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    claim = get_claim_for_user(session, claim_id=claim_id, user=user)

    form = await request.form()
    invalid: list[str] = []
    for key, value in form.multi_items():
        val = str(value or "").strip()
        if not val:
            continue

        cur = None
        if key.startswith("fx_rate_"):
            cur = key.removeprefix("fx_rate_").strip().upper()
        elif key.lower().endswith("_to_home") and len(key) >= 3:
            cur = key[:3].strip().upper()

        cur_norm = normalize_currency(cur) if cur else None
        if not cur_norm:
            if cur:
                invalid.append(cur)
            continue

        try:
            rate = Decimal(val)
        except Exception:
            invalid.append(cur_norm)
            continue

        try:
            upsert_fx_rate(
                session,
                claim_id=claim.id,
                from_currency=cur_norm,
                to_currency=claim.home_currency,
                rate=rate,
            )
        except ValueError:
            invalid.append(cur_norm)
            continue

    apply_fx_to_claim_items(session, claim_id=claim.id)
    evaluate_claim(session, claim_id=claim.id)
    if invalid:
        msg = quote("Invalid FX inputs: " + ", ".join(sorted(set(invalid))))
        return RedirectResponse(url=f"/app/claims/{claim.id}?fx_invalid={msg}", status_code=303)
    return RedirectResponse(url=f"/app/claims/{claim.id}", status_code=303)


@router.post("/app/claims/{claim_id}/fx/auto", response_class=RedirectResponse)
def auto_fx_ui(
    claim_id: uuid.UUID,
    request: Request,
    session: Session = Depends(db_session),
) -> RedirectResponse:
    user = _get_optional_user(request, session)
    if not user:
        return RedirectResponse(url="/login", status_code=303)
    claim = get_claim_for_user(session, claim_id=claim_id, user=user)

    from serendipity_spend.modules.expenses.models import ExpenseItem

    currencies = {
        str(c).upper()
        for c in session.scalars(
            select(ExpenseItem.amount_original_currency).where(ExpenseItem.claim_id == claim.id)
        )
        if c
    }
    currencies.discard(claim.home_currency.upper())

    try:
        _rates, skipped = auto_upsert_fx_rates(
            session,
            claim_id=claim.id,
            to_currency=claim.home_currency,
            from_currencies=currencies,
        )
        evaluate_claim(session, claim_id=claim.id)
        if skipped:
            return RedirectResponse(
                url=f"/app/claims/{claim.id}?fx_skipped={quote(','.join(sorted(skipped)))}",
                status_code=303,
            )
        return RedirectResponse(url=f"/app/claims/{claim.id}", status_code=303)
    except Exception:  # noqa: BLE001
        # Fall back to manual entry if the external FX service is unavailable.
        return RedirectResponse(url=f"/app/claims/{claim.id}?fx_error=1", status_code=303)


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
        return RedirectResponse(url=f"/app/claims/{claim.id}?approve_ok=1", status_code=303)
    except HTTPException as e:
        detail = e.detail
        message = "Claim could not be approved."
        if isinstance(detail, dict):
            message = str(detail.get("message") or message)
            rules = detail.get("blocking_rules") or []
            if rules:
                message = f"{message} Blocking: {', '.join(rules)}."
        elif isinstance(detail, str):
            message = detail
        return RedirectResponse(
            url=f"/app/claims/{claim.id}?approve_error={quote(message)}", status_code=303
        )
    except Exception:
        return RedirectResponse(
            url=f"/app/claims/{claim.id}?approve_error={quote('Claim could not be approved.')}",
            status_code=303,
        )


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
        return RedirectResponse(url=f"/app/claims/{claim.id}?approve_ok=1", status_code=303)
    except HTTPException as e:
        detail = e.detail
        message = "Decision failed."
        if isinstance(detail, str):
            message = detail
        return RedirectResponse(
            url=f"/app/claims/{claim.id}?approve_error={quote(message)}", status_code=303
        )
    except Exception:
        return RedirectResponse(
            url=f"/app/claims/{claim.id}?approve_error={quote('Decision failed.')}",
            status_code=303,
        )


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
        return RedirectResponse(url=f"/app/claims/{claim.id}?approve_ok=1", status_code=303)
    except HTTPException as e:
        detail = e.detail
        message = "Decision failed."
        if isinstance(detail, str):
            message = detail
        return RedirectResponse(
            url=f"/app/claims/{claim.id}?approve_error={quote(message)}", status_code=303
        )
    except Exception:
        return RedirectResponse(
            url=f"/app/claims/{claim.id}?approve_error={quote('Decision failed.')}",
            status_code=303,
        )
