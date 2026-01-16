from __future__ import annotations

from datetime import date
from decimal import Decimal

from sqlalchemy import select

from serendipity_spend.core.db import SessionLocal
from serendipity_spend.modules.claims.service import create_claim, update_claim
from serendipity_spend.modules.expenses.service import create_manual_item
from serendipity_spend.modules.identity.models import UserRole
from serendipity_spend.modules.identity.service import create_user
from serendipity_spend.modules.policy.models import PolicySeverity, PolicyViolation
from serendipity_spend.modules.policy.service import evaluate_claim


def test_parse_generic_receipt_extracts_total_and_date():
    from serendipity_spend.modules.extraction.service import _parse_generic_receipt

    parsed = _parse_generic_receipt(
        "Example Hotel\nDate: 2026-01-05\nGrand Total USD 650.00\nThank you"
    )
    assert parsed is not None
    assert parsed.vendor == "Example Hotel"
    assert parsed.currency == "USD"
    assert parsed.amount == Decimal("650.00")
    assert parsed.transaction_date == date(2026, 1, 5)


def test_policy_hotel_cap_fails_over_300_per_night():
    with SessionLocal() as session:
        employee = create_user(
            session, email="employee@example.com", password="pw", role=UserRole.EMPLOYEE
        )
        claim = create_claim(session, employee_id=employee.id, home_currency="USD")
        update_claim(
            session,
            claim=claim,
            user=employee,
            travel_start_date=date(2026, 1, 1),
            travel_end_date=date(2026, 1, 3),
            purpose="Work trip",
        )

        create_manual_item(
            session,
            claim=claim,
            user=employee,
            vendor="Example Hotel",
            category="lodging",
            description="Hotel stay",
            transaction_date=date(2026, 1, 2),
            amount_original_amount=Decimal("650.00"),
            amount_original_currency="USD",
            metadata_json={"hotel_nights": 2, "employee_reviewed": True},
        )

        evaluate_claim(session, claim_id=claim.id)
        violations = list(
            session.scalars(select(PolicyViolation).where(PolicyViolation.claim_id == claim.id))
        )
        assert any(v.rule_id == "R103" and v.severity == PolicySeverity.FAIL for v in violations)


def test_policy_meal_attendees_required_over_usd_100():
    with SessionLocal() as session:
        employee = create_user(
            session, email="employee@example.com", password="pw", role=UserRole.EMPLOYEE
        )
        claim = create_claim(session, employee_id=employee.id, home_currency="USD")
        update_claim(
            session,
            claim=claim,
            user=employee,
            travel_start_date=date(2026, 1, 1),
            travel_end_date=date(2026, 1, 2),
            purpose="Work trip",
        )

        create_manual_item(
            session,
            claim=claim,
            user=employee,
            vendor="Restaurant",
            category="meals",
            description="Client dinner",
            transaction_date=date(2026, 1, 1),
            amount_original_amount=Decimal("150.00"),
            amount_original_currency="USD",
            metadata_json={"employee_reviewed": True},
        )

        evaluate_claim(session, claim_id=claim.id)
        violations = list(
            session.scalars(select(PolicyViolation).where(PolicyViolation.claim_id == claim.id))
        )
        assert any(v.rule_id == "R112" for v in violations)


def test_policy_short_flight_must_be_economy():
    with SessionLocal() as session:
        employee = create_user(
            session, email="employee@example.com", password="pw", role=UserRole.EMPLOYEE
        )
        claim = create_claim(session, employee_id=employee.id, home_currency="USD")
        update_claim(
            session,
            claim=claim,
            user=employee,
            travel_start_date=date(2026, 1, 1),
            travel_end_date=date(2026, 1, 2),
            purpose="Work trip",
        )

        create_manual_item(
            session,
            claim=claim,
            user=employee,
            vendor="Airline",
            category="airfare",
            description="Flight ticket",
            transaction_date=date(2026, 1, 1),
            amount_original_amount=Decimal("200.00"),
            amount_original_currency="USD",
            metadata_json={
                "flight_duration_hours": 5,
                "flight_cabin_class": "business",
                "employee_reviewed": True,
            },
        )

        evaluate_claim(session, claim_id=claim.id)
        violations = list(
            session.scalars(select(PolicyViolation).where(PolicyViolation.claim_id == claim.id))
        )
        assert any(v.rule_id == "R123" and v.severity == PolicySeverity.FAIL for v in violations)

