from __future__ import annotations

from decimal import Decimal

from sqlalchemy import select

from serendipity_spend.core.db import SessionLocal
from serendipity_spend.modules.claims.service import create_claim
from serendipity_spend.modules.expenses.models import ExpenseItem
from serendipity_spend.modules.identity.models import UserRole
from serendipity_spend.modules.identity.service import create_user


def test_vendor_reference_can_repeat_across_claims():
    with SessionLocal() as session:
        employee = create_user(
            session,
            email="employee@example.com",
            password="pw",
            role=UserRole.EMPLOYEE,
            full_name="Employee",
        )
        claim_a = create_claim(session, employee_id=employee.id, home_currency="USD")
        claim_b = create_claim(session, employee_id=employee.id, home_currency="USD")

        item_a = ExpenseItem(
            claim_id=claim_a.id,
            vendor="Uber",
            vendor_reference="TRIP-123",
            receipt_type="trip_summary",
            category=None,
            description=None,
            transaction_date=None,
            transaction_at=None,
            amount_original_amount=Decimal("10.00"),
            amount_original_currency="USD",
            amount_home_amount=Decimal("10.00"),
            amount_home_currency=claim_a.home_currency,
            fx_rate_to_home=Decimal("1.0"),
            metadata_json={"employee_reviewed": True},
            dedupe_key="Uber:TRIP-123",
        )
        session.add(item_a)
        session.commit()

        item_b = ExpenseItem(
            claim_id=claim_b.id,
            vendor="Uber",
            vendor_reference="TRIP-123",
            receipt_type="trip_summary",
            category=None,
            description=None,
            transaction_date=None,
            transaction_at=None,
            amount_original_amount=Decimal("12.00"),
            amount_original_currency="USD",
            amount_home_amount=Decimal("12.00"),
            amount_home_currency=claim_b.home_currency,
            fx_rate_to_home=Decimal("1.0"),
            metadata_json={"employee_reviewed": True},
            dedupe_key="Uber:TRIP-123",
        )
        session.add(item_b)
        session.commit()

        assert (
            session.scalar(
                select(ExpenseItem.id).where(
                    ExpenseItem.claim_id == claim_a.id,
                    ExpenseItem.vendor == "Uber",
                    ExpenseItem.vendor_reference == "TRIP-123",
                )
            )
            is not None
        )
        assert (
            session.scalar(
                select(ExpenseItem.id).where(
                    ExpenseItem.claim_id == claim_b.id,
                    ExpenseItem.vendor == "Uber",
                    ExpenseItem.vendor_reference == "TRIP-123",
                )
            )
            is not None
        )

