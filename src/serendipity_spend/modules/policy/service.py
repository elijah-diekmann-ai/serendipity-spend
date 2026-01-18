from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from serendipity_spend.core.currencies import is_iso4217_currency
from serendipity_spend.core.logging import get_logger, log_event
from serendipity_spend.modules.claims.models import Claim
from serendipity_spend.modules.expenses.models import ExpenseItem
from serendipity_spend.modules.fx.models import FxRate
from serendipity_spend.modules.identity.models import User, UserRole
from serendipity_spend.modules.policy.blocking import EXCEPTION_ELIGIBLE_RULE_IDS
from serendipity_spend.modules.policy.models import (
    PolicyException,
    PolicyExceptionStatus,
    PolicySeverity,
    PolicyViolation,
    ViolationStatus,
)
from serendipity_spend.modules.workflow.models import Task, TaskStatus

logger = get_logger(__name__)


@dataclass(frozen=True)
class Issue:
    dedupe_key: str
    claim_id: uuid.UUID
    expense_item_id: uuid.UUID | None
    rule_id: str
    severity: PolicySeverity
    title: str
    message: str
    data: dict


def _is_generic_extraction(item: ExpenseItem) -> bool:
    metadata = item.metadata_json or {}
    family = str(metadata.get("extraction_family") or "").strip().lower()
    if family == "generic":
        return True

    method = str(metadata.get("extraction_method") or "").strip().lower()
    if method.startswith("generic"):
        return True

    return str(item.receipt_type or "").strip().lower() == "generic_receipt"


def _exception_data(exc: PolicyException) -> dict:
    return {
        "id": str(exc.id),
        "status": exc.status.value,
        "justification": exc.justification,
        "requested_by_user_id": str(exc.requested_by_user_id),
        "decided_by_user_id": str(exc.decided_by_user_id) if exc.decided_by_user_id else None,
        "decided_at": exc.decided_at.isoformat() if exc.decided_at else None,
        "decision_comment": exc.decision_comment,
    }


def evaluate_claim(session: Session, *, claim_id: uuid.UUID) -> None:
    claim = session.scalar(select(Claim).where(Claim.id == claim_id))
    if not claim:
        return

    items = list(session.scalars(select(ExpenseItem).where(ExpenseItem.claim_id == claim.id)))
    exceptions = list(
        session.scalars(select(PolicyException).where(PolicyException.claim_id == claim.id))
    )
    exceptions_by_key = {e.dedupe_key: e for e in exceptions}
    log_event(
        logger,
        "policy.evaluate.start",
        claim_id=str(claim.id),
        items_count=len(items),
        exceptions_count=len(exceptions),
    )

    issues: list[Issue] = []

    if not claim.purpose or not claim.purpose.strip():
        issues.append(
            Issue(
                dedupe_key=f"claim:{claim.id}:R001",
                claim_id=claim.id,
                expense_item_id=None,
                rule_id="R001",
                severity=PolicySeverity.FAIL,
                title="Claim purpose required",
                message="Add a purpose of the trip before submitting the claim.",
                data={"submit_blocking": True},
            )
        )

    if not claim.travel_start_date or not claim.travel_end_date:
        issues.append(
            Issue(
                dedupe_key=f"claim:{claim.id}:R002",
                claim_id=claim.id,
                expense_item_id=None,
                rule_id="R002",
                severity=PolicySeverity.FAIL,
                title="Travel period required",
                message="Add a travel start and end date before submitting the claim.",
                data={"submit_blocking": True},
            )
        )

    usd_to_home: Decimal | None = None
    if claim.home_currency.upper() == "USD":
        usd_to_home = Decimal("1")
    else:
        fx = session.scalar(
            select(FxRate).where(
                FxRate.claim_id == claim.id,
                FxRate.from_currency == "USD",
                FxRate.to_currency == claim.home_currency.upper(),
            )
        )
        if fx:
            usd_to_home = fx.rate

    for item in items:
        if item.vendor == "Uber" and item.receipt_type == "trip_summary":
            issues.append(
                Issue(
                    dedupe_key=f"item:{item.id}:R010",
                    claim_id=claim.id,
                    expense_item_id=item.id,
                    rule_id="R010",
                    severity=PolicySeverity.NEEDS_INFO,
                    title="Uber trip summary may be insufficient",
                    message=(
                        "This document indicates it is not a payment receipt. "
                        "Upload a payment receipt or provide justification."
                    ),
                    data={
                        "vendor": "Uber",
                        "receipt_type": "trip_summary",
                        "submit_blocking": False,
                    },
                )
            )

        if (
            item.vendor == "Grab"
            and str(item.metadata_json.get("profile", "")).upper() == "PERSONAL"
        ):
            issues.append(
                Issue(
                    dedupe_key=f"item:{item.id}:R020",
                    claim_id=claim.id,
                    expense_item_id=item.id,
                    rule_id="R020",
                    severity=PolicySeverity.WARN,
                    title="Receipt indicates PERSONAL profile",
                    message=(
                        "Confirm this expense is reimbursable and provide business context "
                        "if needed."
                    ),
                    data={"profile": "PERSONAL", "submit_blocking": False},
                )
            )

        if not is_iso4217_currency(item.amount_original_currency):
            issues.append(
                Issue(
                    dedupe_key=f"item:{item.id}:R031",
                    claim_id=claim.id,
                    expense_item_id=item.id,
                    rule_id="R031",
                    severity=PolicySeverity.NEEDS_INFO,
                    title="Invalid currency code",
                    message=(
                        f"'{item.amount_original_currency}' is not a valid ISO-4217 currency. "
                        "Edit the item and set the correct currency."
                    ),
                    data={
                        "currency": item.amount_original_currency,
                        "submit_blocking": True,
                    },
                )
            )
            # Avoid misleading downstream FX messaging (e.g., R030) on invalid codes.
            continue

        if item.amount_home_amount is None and item.amount_original_currency != claim.home_currency:
            issues.append(
                Issue(
                    dedupe_key=f"item:{item.id}:R030",
                    claim_id=claim.id,
                    expense_item_id=item.id,
                    rule_id="R030",
                    severity=PolicySeverity.NEEDS_INFO,
                    title="Missing FX rate",
                    message=(
                        f"Set an FX rate to convert {item.amount_original_currency} "
                        f"to {claim.home_currency}."
                    ),
                    data={
                        "from_currency": item.amount_original_currency,
                        "to_currency": claim.home_currency,
                        "submit_blocking": True,
                    },
                )
            )

        # R040: generic extraction requires employee confirmation
        if (
            _is_generic_extraction(item)
            and not bool(item.metadata_json.get("employee_reviewed"))
        ):
            metadata = item.metadata_json or {}
            extraction_family = str(metadata.get("extraction_family") or "").strip() or "generic"
            extraction_method = str(metadata.get("extraction_method") or "").strip() or "generic"
            issues.append(
                Issue(
                    dedupe_key=f"item:{item.id}:R040",
                    claim_id=claim.id,
                    expense_item_id=item.id,
                    rule_id="R040",
                    severity=PolicySeverity.NEEDS_INFO,
                    title="Confirm auto-extracted receipt details",
                    message=(
                        "This receipt was parsed using a generic heuristic. "
                        "Review the vendor/date/amount and mark it reviewed."
                    ),
                    data={
                        "extraction_family": extraction_family,
                        "extraction_method": extraction_method,
                        "submit_blocking": True,
                    },
                )
            )

        # R101/R102: hotel nightly cap (USD 300/night)
        if str(item.category or "").lower() in {"lodging", "hotel"}:
            nights = item.metadata_json.get("hotel_nights")
            try:
                nights_int = int(nights)
            except Exception:
                nights_int = 0

            if nights_int <= 0:
                issues.append(
                    Issue(
                        dedupe_key=f"item:{item.id}:R101",
                        claim_id=claim.id,
                        expense_item_id=item.id,
                        rule_id="R101",
                        severity=PolicySeverity.NEEDS_INFO,
                        title="Hotel nights required",
                        message="Enter the number of hotel nights to check the nightly cap.",
                        data={"submit_blocking": True},
                    )
                )
            else:
                per_night_usd = _amount_usd(item=item, claim=claim, usd_to_home=usd_to_home)
                if per_night_usd is None:
                    issues.append(
                        Issue(
                            dedupe_key=f"item:{item.id}:R102",
                            claim_id=claim.id,
                            expense_item_id=item.id,
                            rule_id="R102",
                            severity=PolicySeverity.NEEDS_INFO,
                            title="USD conversion needed for hotel cap",
                            message=(
                                "Set FX rates so the system can convert this hotel total to USD "
                                "and check the USD 300/night cap."
                            ),
                            data={"submit_blocking": True},
                        )
                    )
                else:
                    nightly = (per_night_usd / Decimal(nights_int)).quantize(Decimal("0.01"))
                    if nightly > Decimal("300.00"):
                        dedupe_key = f"item:{item.id}:R103"
                        exc = exceptions_by_key.get(dedupe_key)
                        exc_data = _exception_data(exc) if exc else None
                        issues.append(
                            Issue(
                                dedupe_key=dedupe_key,
                                claim_id=claim.id,
                                expense_item_id=item.id,
                                rule_id="R103",
                                severity=PolicySeverity.FAIL,
                                title="Hotel nightly rate exceeds USD 300",
                                message=(
                                    f"Nightly rate is approx USD {nightly} (cap is USD 300). "
                                    "Provide justification or adjust the claim."
                                ),
                                data={
                                    "nightly_usd": str(nightly),
                                    "cap_usd": "300.00",
                                    "submit_blocking": True,
                                    "exception": exc_data,
                                },
                            )
                        )

        # R111: meals over USD 100 require attendees
        if str(item.category or "").lower() in {"meals", "food", "food_and_beverage"}:
            amount_usd = _amount_usd(item=item, claim=claim, usd_to_home=usd_to_home)
            if amount_usd is None:
                issues.append(
                    Issue(
                        dedupe_key=f"item:{item.id}:R111",
                        claim_id=claim.id,
                        expense_item_id=item.id,
                        rule_id="R111",
                        severity=PolicySeverity.NEEDS_INFO,
                        title="USD conversion needed for meal threshold",
                        message=(
                            "Set FX rates so the system can determine whether this meal exceeds "
                            "USD 100 and requires attendee names."
                        ),
                        data={"submit_blocking": True},
                    )
                )
            elif amount_usd >= Decimal("100.00"):
                attendees = str(item.metadata_json.get("attendees") or "").strip()
                if not attendees:
                    issues.append(
                        Issue(
                            dedupe_key=f"item:{item.id}:R112",
                            claim_id=claim.id,
                            expense_item_id=item.id,
                            rule_id="R112",
                            severity=PolicySeverity.NEEDS_INFO,
                            title="Meal attendees required (USD 100+)",
                            message="Enter attendee names (or a count) for meals over USD 100.",
                            data={"threshold_usd": "100.00", "submit_blocking": True},
                        )
                    )

        # R121/R122/R123: flights under 6 hours must be economy
        if str(item.category or "").lower() in {"airfare", "flight"}:
            duration = item.metadata_json.get("flight_duration_hours")
            cabin = str(item.metadata_json.get("flight_cabin_class") or "").strip().lower()
            try:
                duration_hours = Decimal(str(duration))
            except Exception:
                duration_hours = None

            if duration_hours is None:
                issues.append(
                    Issue(
                        dedupe_key=f"item:{item.id}:R121",
                        claim_id=claim.id,
                        expense_item_id=item.id,
                        rule_id="R121",
                        severity=PolicySeverity.NEEDS_INFO,
                        title="Flight duration required",
                        message="Enter the flight duration in hours to check cabin class rules.",
                        data={"submit_blocking": True},
                    )
                )
            if not cabin:
                issues.append(
                    Issue(
                        dedupe_key=f"item:{item.id}:R122",
                        claim_id=claim.id,
                        expense_item_id=item.id,
                        rule_id="R122",
                        severity=PolicySeverity.NEEDS_INFO,
                        title="Flight cabin class required",
                        message="Select the booked cabin class (economy, business, etc.).",
                        data={"submit_blocking": True},
                    )
                )
            if duration_hours is not None and cabin and duration_hours < Decimal("6"):
                if cabin != "economy":
                    dedupe_key = f"item:{item.id}:R123"
                    exc = exceptions_by_key.get(dedupe_key)
                    exc_data = _exception_data(exc) if exc else None
                    issues.append(
                        Issue(
                            dedupe_key=dedupe_key,
                            claim_id=claim.id,
                            expense_item_id=item.id,
                            rule_id="R123",
                            severity=PolicySeverity.FAIL,
                            title="Short flight must be economy",
                            message=(
                                "Flights under 6 hours must be booked in economy class. "
                                "Provide justification or adjust the claim."
                            ),
                            data={
                                "duration_hours": str(duration_hours),
                                "cabin": cabin,
                                "submit_blocking": True,
                                "exception": exc_data,
                            },
                        )
                    )

    issues_by_severity: dict[str, int] = {}
    for issue in issues:
        key = issue.severity.value
        issues_by_severity[key] = issues_by_severity.get(key, 0) + 1

    issues_by_rule: dict[str, int] = {}
    for issue in issues:
        issues_by_rule[issue.rule_id] = issues_by_rule.get(issue.rule_id, 0) + 1

    _sync_violations(session=session, claim_id=claim.id, issues=issues)
    _sync_tasks(session=session, claim=claim, issues=issues)
    log_event(
        logger,
        "policy.evaluate.summary",
        claim_id=str(claim.id),
        issues_total=len(issues),
        issues_by_severity=issues_by_severity,
        issues_by_rule=issues_by_rule,
    )


def _amount_usd(*, item: ExpenseItem, claim: Claim, usd_to_home: Decimal | None) -> Decimal | None:
    cur = item.amount_original_currency.upper()
    if cur == "USD":
        return item.amount_original_amount

    # If the extractor captured explicit multi-currency totals, prefer a direct USD value
    # over a derived home->USD conversion.
    metadata = item.metadata_json or {}
    amounts = metadata.get("amounts_by_currency")
    if isinstance(amounts, dict):
        for k, v in amounts.items():
            if str(k or "").strip().upper() != "USD":
                continue
            try:
                usd = Decimal(str(v)).quantize(Decimal("0.01"))
            except Exception:
                usd = None
            if usd is not None:
                return usd

    # If claim is in USD, we can rely on home amount.
    if claim.home_currency.upper() == "USD":
        return item.amount_home_amount

    # Otherwise, convert home->USD if we have USD->home.
    if item.amount_home_amount is None or usd_to_home in {None, Decimal("0")}:
        return None

    try:
        return (item.amount_home_amount / usd_to_home).quantize(Decimal("0.01"))
    except Exception:
        return None


def _sync_violations(*, session: Session, claim_id: uuid.UUID, issues: list[Issue]) -> None:
    now = datetime.now(UTC)
    desired = {i.dedupe_key: i for i in issues}

    existing = list(
        session.scalars(select(PolicyViolation).where(PolicyViolation.claim_id == claim_id))
    )
    existing_by_key = {v.dedupe_key: v for v in existing}
    created: list[PolicyViolation] = []
    updated: list[PolicyViolation] = []
    resolved: list[PolicyViolation] = []

    for key, issue in desired.items():
        v = existing_by_key.get(key)
        if not v:
            v = PolicyViolation(
                claim_id=issue.claim_id,
                expense_item_id=issue.expense_item_id,
                rule_id=issue.rule_id,
                rule_version="1",
                severity=issue.severity,
                status=ViolationStatus.OPEN,
                title=issue.title,
                message=issue.message,
                data_json=issue.data,
                dedupe_key=issue.dedupe_key,
                resolved_at=None,
            )
            session.add(v)
            created.append(v)
        else:
            v.severity = issue.severity
            v.title = issue.title
            v.message = issue.message
            v.data_json = issue.data
            v.expense_item_id = issue.expense_item_id
            v.status = ViolationStatus.OPEN
            v.resolved_at = None
            session.add(v)
            updated.append(v)

    for v in existing:
        if v.dedupe_key in desired:
            continue
        if v.status == ViolationStatus.RESOLVED:
            continue
        v.status = ViolationStatus.RESOLVED
        v.resolved_at = now
        session.add(v)
        resolved.append(v)

    session.commit()
    for v in created:
        log_event(
            logger,
            "policy.violation.upsert",
            claim_id=str(v.claim_id),
            policy_violation_id=str(v.id),
            expense_item_id=str(v.expense_item_id) if v.expense_item_id else None,
            rule_id=v.rule_id,
            severity=v.severity.value,
            status=v.status.value,
            action="created",
        )
    for v in updated:
        log_event(
            logger,
            "policy.violation.upsert",
            claim_id=str(v.claim_id),
            policy_violation_id=str(v.id),
            expense_item_id=str(v.expense_item_id) if v.expense_item_id else None,
            rule_id=v.rule_id,
            severity=v.severity.value,
            status=v.status.value,
            action="updated",
        )
    for v in resolved:
        log_event(
            logger,
            "policy.violation.resolved",
            claim_id=str(v.claim_id),
            policy_violation_id=str(v.id),
            expense_item_id=str(v.expense_item_id) if v.expense_item_id else None,
            rule_id=v.rule_id,
            severity=v.severity.value,
            status=v.status.value,
        )


def _sync_tasks(*, session: Session, claim: Claim, issues: list[Issue]) -> None:
    now = datetime.now(UTC)

    desired_keys: set[tuple[uuid.UUID, uuid.UUID | None, str]] = set()
    created: list[Task] = []
    updated: list[Task] = []
    resolved: list[Task] = []
    for issue in issues:
        exc = (issue.data or {}).get("exception") or {}
        exc_status = str(exc.get("status") or "").upper()
        exc_justification = str(exc.get("justification") or "").strip()

        if (
            issue.rule_id in EXCEPTION_ELIGIBLE_RULE_IDS
            and exc_status == PolicyExceptionStatus.APPROVED.value
        ):
            continue

        task_type = f"POLICY_{issue.rule_id}"
        desired_keys.add((issue.claim_id, issue.expense_item_id, task_type))

        assigned_to_user_id = claim.employee_id
        description = issue.message
        if issue.rule_id in EXCEPTION_ELIGIBLE_RULE_IDS:
            if exc_status == PolicyExceptionStatus.REQUESTED.value and claim.approver_id:
                assigned_to_user_id = claim.approver_id
                if exc_justification:
                    description = f"{issue.message}\n\nJustification: {exc_justification}"

        task = session.scalar(
            select(Task)
            .where(
                Task.claim_id == issue.claim_id,
                Task.expense_item_id == issue.expense_item_id,
                Task.type == task_type,
            )
            .order_by(Task.created_at.desc())
        )
        if not task:
            task = Task(
                claim_id=issue.claim_id,
                expense_item_id=issue.expense_item_id,
                created_by_user_id=None,
                assigned_to_user_id=assigned_to_user_id,
                type=task_type,
                title=issue.title,
                description=description,
                status=TaskStatus.OPEN,
                resolved_at=None,
            )
            session.add(task)
            created.append(task)
        else:
            task.title = issue.title
            task.description = description
            task.assigned_to_user_id = assigned_to_user_id
            if task.status == TaskStatus.RESOLVED:
                task.status = TaskStatus.OPEN
                task.resolved_at = None
            session.add(task)
            updated.append(task)

    # auto-resolve stale policy tasks
    existing_tasks = list(
        session.scalars(
            select(Task)
            .where(Task.claim_id == claim.id, Task.type.like("POLICY_%"))
            .order_by(Task.created_at.desc())
        )
    )
    for t in existing_tasks:
        key = (t.claim_id, t.expense_item_id, t.type)
        if key in desired_keys:
            continue
        if t.status == TaskStatus.RESOLVED:
            continue
        t.status = TaskStatus.RESOLVED
        t.resolved_at = now
        session.add(t)
        resolved.append(t)

    session.commit()
    for task in created:
        log_event(
            logger,
            "policy.task.upsert",
            claim_id=str(task.claim_id),
            task_id=str(task.id),
            expense_item_id=str(task.expense_item_id) if task.expense_item_id else None,
            task_type=task.type,
            task_status=task.status.value,
            assigned_to_user_id=str(task.assigned_to_user_id)
            if task.assigned_to_user_id
            else None,
            action="created",
        )
    for task in updated:
        log_event(
            logger,
            "policy.task.upsert",
            claim_id=str(task.claim_id),
            task_id=str(task.id),
            expense_item_id=str(task.expense_item_id) if task.expense_item_id else None,
            task_type=task.type,
            task_status=task.status.value,
            assigned_to_user_id=str(task.assigned_to_user_id)
            if task.assigned_to_user_id
            else None,
            action="updated",
        )
    for task in resolved:
        log_event(
            logger,
            "policy.task.resolved",
            claim_id=str(task.claim_id),
            task_id=str(task.id),
            expense_item_id=str(task.expense_item_id) if task.expense_item_id else None,
            task_type=task.type,
            task_status=task.status.value,
        )


def request_policy_exception(
    session: Session, *, violation_id: uuid.UUID, user: User, justification: str
) -> PolicyException:
    violation = session.scalar(select(PolicyViolation).where(PolicyViolation.id == violation_id))
    if not violation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy violation not found",
        )

    if violation.rule_id not in EXCEPTION_ELIGIBLE_RULE_IDS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This policy rule does not support exceptions.",
        )
    if violation.severity != PolicySeverity.FAIL:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only FAIL violations can be requested as exceptions.",
        )
    if violation.status != ViolationStatus.OPEN:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This policy violation is not open.",
        )

    claim = session.scalar(select(Claim).where(Claim.id == violation.claim_id))
    if not claim:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Claim not found")

    if user.role != UserRole.ADMIN and claim.employee_id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed")

    justification_clean = (justification or "").strip()
    if not justification_clean:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Justification is required."
        )

    exc = session.scalar(
        select(PolicyException).where(PolicyException.dedupe_key == violation.dedupe_key)
    )
    if not exc:
        exc = PolicyException(
            claim_id=violation.claim_id,
            expense_item_id=violation.expense_item_id,
            rule_id=violation.rule_id,
            rule_version=violation.rule_version,
            status=PolicyExceptionStatus.REQUESTED,
            justification=justification_clean,
            requested_by_user_id=user.id,
            decided_by_user_id=None,
            decided_at=None,
            decision_comment=None,
            dedupe_key=violation.dedupe_key,
        )
    else:
        exc.expense_item_id = violation.expense_item_id
        exc.rule_id = violation.rule_id
        exc.rule_version = violation.rule_version
        exc.status = PolicyExceptionStatus.REQUESTED
        exc.justification = justification_clean
        exc.requested_by_user_id = user.id
        exc.decided_by_user_id = None
        exc.decided_at = None
        exc.decision_comment = None

    session.add(exc)
    session.commit()
    session.refresh(exc)

    evaluate_claim(session, claim_id=violation.claim_id)
    session.refresh(exc)
    return exc


def decide_policy_exception(
    session: Session,
    *,
    exception_id: uuid.UUID,
    user: User,
    decision: PolicyExceptionStatus,
    comment: str | None,
) -> PolicyException:
    exc = session.scalar(select(PolicyException).where(PolicyException.id == exception_id))
    if not exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Policy exception not found",
        )

    claim = session.scalar(select(Claim).where(Claim.id == exc.claim_id))
    if not claim:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Claim not found")

    if user.role not in {UserRole.APPROVER, UserRole.ADMIN}:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed")
    if user.role == UserRole.APPROVER and claim.approver_id != user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed")

    if decision not in {PolicyExceptionStatus.APPROVED, PolicyExceptionStatus.REJECTED}:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Decision must be APPROVED or REJECTED.",
        )

    now = datetime.now(UTC)
    exc.status = decision
    exc.decided_by_user_id = user.id
    exc.decided_at = now
    exc.decision_comment = (comment or "").strip() or None
    session.add(exc)
    session.commit()
    session.refresh(exc)

    evaluate_claim(session, claim_id=exc.claim_id)
    session.refresh(exc)
    return exc
