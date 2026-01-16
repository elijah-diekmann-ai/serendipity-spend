from __future__ import annotations

from datetime import date
from decimal import Decimal

from sqlalchemy import select

from serendipity_spend.core.db import SessionLocal
from serendipity_spend.modules.claims.models import ClaimStatus
from serendipity_spend.modules.claims.service import (
    create_claim,
    route_claim,
    submit_claim,
    update_claim,
)
from serendipity_spend.modules.documents.service import create_source_file
from serendipity_spend.modules.expenses.models import ExpenseItem
from serendipity_spend.modules.extraction.service import extract_source_file
from serendipity_spend.modules.fx.service import apply_fx_to_claim_items, upsert_fx_rate
from serendipity_spend.modules.identity.models import UserRole
from serendipity_spend.modules.identity.service import create_user
from serendipity_spend.modules.policy.models import PolicyViolation
from serendipity_spend.modules.policy.service import evaluate_claim
from serendipity_spend.modules.workflow.models import Task, TaskStatus


def test_end_to_end_sample_pdf_extraction_and_policy():
    with SessionLocal() as session:
        employee = create_user(
            session,
            email="employee@example.com",
            password="pw",
            role=UserRole.EMPLOYEE,
            full_name="Employee",
        )
        approver = create_user(
            session,
            email="approver@example.com",
            password="pw",
            role=UserRole.APPROVER,
            full_name="Approver",
        )
        claim = create_claim(session, employee_id=employee.id, home_currency="SGD")
        route_claim(session, claim=claim, approver_id=approver.id)

        pdf_bytes = open("Data/DC__OOP__05 Sep 2025.pdf", "rb").read()
        source = create_source_file(
            session,
            claim=claim,
            user=employee,
            filename="DC__OOP__05 Sep 2025.pdf",
            content_type="application/pdf",
            body=pdf_bytes,
        )

        extract_source_file(source_file_id=str(source.id))

        items = list(session.scalars(select(ExpenseItem).where(ExpenseItem.claim_id == claim.id)))
        assert len(items) == 17
        assert sum(1 for i in items if i.vendor == "Grab") == 4
        assert sum(1 for i in items if i.vendor == "United Airlines") == 3
        assert sum(1 for i in items if i.vendor == "Uber") == 9
        assert sum(1 for i in items if i.vendor == "Airline") == 1

        # Policy evaluation runs after extraction
        violations = list(
            session.scalars(select(PolicyViolation).where(PolicyViolation.claim_id == claim.id))
        )
        assert any(v.rule_id == "R010" for v in violations)  # Uber trip summary warning

        tasks = list(session.scalars(select(Task).where(Task.claim_id == claim.id)))
        assert any(t.type == "POLICY_R001" for t in tasks)  # purpose required
        assert any(t.type == "POLICY_R002" for t in tasks)  # travel period required

        # Fill claim metadata and FX, re-evaluate and submit
        update_claim(
            session,
            claim=claim,
            user=employee,
            travel_start_date=date(2025, 8, 26),
            travel_end_date=date(2025, 9, 4),
            purpose="Investor meetings",
        )

        upsert_fx_rate(
            session, claim_id=claim.id, from_currency="USD", to_currency="SGD", rate=Decimal("1.35")
        )
        upsert_fx_rate(
            session, claim_id=claim.id, from_currency="CAD", to_currency="SGD", rate=Decimal("1.00")
        )
        apply_fx_to_claim_items(session, claim_id=claim.id)
        evaluate_claim(session, claim_id=claim.id)

        # Uber trip summary tasks still block submit unless resolved; resolve all tasks for test
        for t in session.scalars(select(Task).where(Task.claim_id == claim.id)):
            t.status = TaskStatus.RESOLVED
        session.commit()

        submitted = submit_claim(session, claim=claim, user=employee)
        assert submitted.status in {ClaimStatus.SUBMITTED, ClaimStatus.NEEDS_APPROVER_REVIEW}
