from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.orm import Session

from serendipity_spend.modules.claims.models import Claim
from serendipity_spend.modules.expenses.models import ExpenseItem
from serendipity_spend.modules.fx.models import FxRate
from serendipity_spend.modules.policy.models import PolicySeverity, PolicyViolation, ViolationStatus
from serendipity_spend.modules.workflow.models import Task, TaskStatus


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


def evaluate_claim(session: Session, *, claim_id: uuid.UUID) -> None:
    claim = session.scalar(select(Claim).where(Claim.id == claim_id))
    if not claim:
        return

    items = list(session.scalars(select(ExpenseItem).where(ExpenseItem.claim_id == claim.id)))

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
            str(item.metadata_json.get("extraction_method")) == "generic"
            and not bool(item.metadata_json.get("employee_reviewed"))
        ):
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
                    data={"extraction_method": "generic", "submit_blocking": True},
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
                        issues.append(
                            Issue(
                                dedupe_key=f"item:{item.id}:R103",
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
                    issues.append(
                        Issue(
                            dedupe_key=f"item:{item.id}:R123",
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
                            },
                        )
                    )

    _sync_violations(session=session, claim_id=claim.id, issues=issues)
    _sync_tasks(session=session, claim=claim, issues=issues)


def _amount_usd(*, item: ExpenseItem, claim: Claim, usd_to_home: Decimal | None) -> Decimal | None:
    cur = item.amount_original_currency.upper()
    if cur == "USD":
        return item.amount_original_amount

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
        else:
            v.severity = issue.severity
            v.title = issue.title
            v.message = issue.message
            v.data_json = issue.data
            v.expense_item_id = issue.expense_item_id
            v.status = ViolationStatus.OPEN
            v.resolved_at = None
            session.add(v)

    for v in existing:
        if v.dedupe_key in desired:
            continue
        if v.status == ViolationStatus.RESOLVED:
            continue
        v.status = ViolationStatus.RESOLVED
        v.resolved_at = now
        session.add(v)

    session.commit()


def _sync_tasks(*, session: Session, claim: Claim, issues: list[Issue]) -> None:
    now = datetime.now(UTC)

    desired_keys: set[tuple[uuid.UUID, uuid.UUID | None, str]] = set()
    for issue in issues:
        task_type = f"POLICY_{issue.rule_id}"
        desired_keys.add((issue.claim_id, issue.expense_item_id, task_type))

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
                assigned_to_user_id=claim.employee_id,
                type=task_type,
                title=issue.title,
                description=issue.message,
                status=TaskStatus.OPEN,
                resolved_at=None,
            )
            session.add(task)
        else:
            task.title = issue.title
            task.description = issue.message
            if task.status == TaskStatus.RESOLVED:
                task.status = TaskStatus.OPEN
                task.resolved_at = None
            session.add(task)

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

    session.commit()
