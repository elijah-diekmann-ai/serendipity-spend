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


def test_extract_total_amount_rejects_non_iso_currency_codes():
    from serendipity_spend.modules.extraction.service import _extract_total_amount

    assert _extract_total_amount("Example\nGrand Total GMT 650.00\n") is None


def test_extract_total_amount_parses_locale_amount_formats():
    from serendipity_spend.modules.extraction.service import _extract_total_amount

    assert _extract_total_amount("Example\nTotal EUR 1.234,56\n") == ("EUR", Decimal("1234.56"))
    assert _extract_total_amount("Example\nTotal EUR 1\u202f234,56\n") == (
        "EUR",
        Decimal("1234.56"),
    )
    assert _extract_total_amount("Example\nTotal EUR 1 234,56\n") == ("EUR", Decimal("1234.56"))
    assert _extract_total_amount("Example\nTotal EUR 1'234.56\n") == ("EUR", Decimal("1234.56"))


def test_extract_total_amount_treats_dollar_symbol_as_ambiguous():
    from serendipity_spend.modules.extraction.service import _extract_total_amount

    assert _extract_total_amount("Example\nTotal $ 10.00\n") == ("XXX", Decimal("10.00"))


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
    assert parsed.metadata.get("extraction_family") == "generic"
    assert parsed.metadata.get("extraction_method") == "generic"

    parsed_variant = _parse_generic_receipt(
        "Example Hotel\nDate: 2026-01-05\nGrand Total USD 650.00\nThank you",
        extraction_method="generic_page",
    )
    assert parsed_variant is not None
    assert parsed_variant.metadata.get("extraction_family") == "generic"
    assert parsed_variant.metadata.get("extraction_method") == "generic_page"


def test_parse_generic_receipt_extracts_hotel_nights_from_check_in_out():
    from serendipity_spend.modules.extraction.service import _parse_generic_receipt

    parsed = _parse_generic_receipt(
        "Example Hotel\nCheck-in: 2026-01-05\nCheck-out: 2026-01-08\nTotal USD 900.00\n"
    )
    assert parsed is not None
    assert parsed.category == "lodging"
    assert parsed.metadata.get("hotel_nights") == 3


def test_parse_generic_receipt_extracts_flight_duration_and_cabin():
    from serendipity_spend.modules.extraction.service import _parse_generic_receipt

    parsed = _parse_generic_receipt(
        "Airline Receipt\nItinerary\nDuration: 5h 30m\nCabin: Business\nTotal USD 200.00\n"
    )
    assert parsed is not None
    assert parsed.category == "airfare"
    assert parsed.metadata.get("flight_duration_hours") == 5.5
    assert parsed.metadata.get("flight_cabin_class") == "business"


def test_parse_generic_receipt_extracts_meal_attendees_count():
    from serendipity_spend.modules.extraction.service import _parse_generic_receipt

    parsed = _parse_generic_receipt(
        "Restaurant\nGuests: 3\nSubtotal $120.00\nTip $24.00\nTotal USD 144.00\n"
    )
    assert parsed is not None
    assert parsed.category == "meals"
    assert parsed.metadata.get("attendees") == 3


def test_parse_generic_receipt_ai_enrichment_fills_missing_policy_fields(monkeypatch):
    from serendipity_spend.modules.extraction import service as extraction_service

    monkeypatch.setattr(
        extraction_service,
        "extract_policy_fields",
        lambda _text: {
            "category": "airfare",
            "flight_duration_hours": 2.25,
            "flight_cabin_class": "economy",
            "confidence": 0.9,
        },
    )

    parsed = extraction_service._parse_generic_receipt("Some receipt\nTotal USD 100.00\n")
    assert parsed is not None
    assert parsed.category == "airfare"
    assert parsed.metadata.get("flight_duration_hours") == 2.25
    assert parsed.metadata.get("flight_cabin_class") == "economy"


def test_policy_generic_extraction_variants_require_employee_review():
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
            vendor="Example Hotel",
            category="lodging",
            description="Hotel stay",
            transaction_date=date(2026, 1, 1),
            amount_original_amount=Decimal("650.00"),
            amount_original_currency="USD",
            metadata_json={"extraction_method": "generic_page", "employee_reviewed": False},
        )

        evaluate_claim(session, claim_id=claim.id)
        violations = list(
            session.scalars(select(PolicyViolation).where(PolicyViolation.claim_id == claim.id))
        )
        assert any(v.rule_id == "R040" and v.data_json.get("submit_blocking") for v in violations)


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


def test_policy_invalid_currency_emits_r031_not_r030():
    from serendipity_spend.modules.expenses.models import ExpenseItem

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

        session.add(
            ExpenseItem(
                claim_id=claim.id,
                vendor="Bad Currency Vendor",
                vendor_reference=None,
                receipt_type="manual",
                category="other",
                description="Invalid currency",
                transaction_date=date(2026, 1, 1),
                transaction_at=None,
                amount_original_amount=Decimal("10.00"),
                amount_original_currency="GMT",
                amount_home_amount=None,
                amount_home_currency=claim.home_currency,
                fx_rate_to_home=None,
                metadata_json={"employee_reviewed": True},
                dedupe_key="manual:bad-currency",
            )
        )
        session.commit()

        evaluate_claim(session, claim_id=claim.id)
        violations = list(
            session.scalars(select(PolicyViolation).where(PolicyViolation.claim_id == claim.id))
        )
        assert any(v.rule_id == "R031" and v.data_json.get("submit_blocking") for v in violations)
        assert not any(v.rule_id == "R030" for v in violations)
