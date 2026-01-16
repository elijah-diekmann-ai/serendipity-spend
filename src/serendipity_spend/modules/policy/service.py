from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from serendipity_spend.modules.claims.models import Claim
from serendipity_spend.modules.expenses.models import ExpenseItem
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
                data={},
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
                data={},
            )
        )

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
                    data={"vendor": "Uber", "receipt_type": "trip_summary"},
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
                    data={"profile": "PERSONAL"},
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
                    },
                )
            )

    _sync_violations(session=session, claim_id=claim.id, issues=issues)
    _sync_tasks(session=session, claim=claim, issues=issues)


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
