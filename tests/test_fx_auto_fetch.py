from __future__ import annotations

from datetime import date
from decimal import Decimal

from sqlalchemy import select

from serendipity_spend.core.db import SessionLocal
from serendipity_spend.modules.claims.service import create_claim
from serendipity_spend.modules.expenses.service import create_manual_item
from serendipity_spend.modules.fx.models import FxRate
from serendipity_spend.modules.identity.models import UserRole
from serendipity_spend.modules.identity.service import create_user


def test_auto_upsert_fx_rates_applies_to_items(monkeypatch):
    from serendipity_spend.modules.fx import service as fx_service

    monkeypatch.setattr(
        fx_service,
        "_fetch_frankfurter_rate",
        lambda *, from_currency, to_currency: (Decimal("1.25"), date(2026, 1, 1)),
    )

    with SessionLocal() as session:
        employee = create_user(
            session,
            email="employee@example.com",
            password="pw",
            role=UserRole.EMPLOYEE,
        )
        claim = create_claim(session, employee_id=employee.id, home_currency="SGD")

        item = create_manual_item(
            session,
            claim=claim,
            user=employee,
            vendor="Test",
            category="other",
            description="USD item",
            transaction_date=None,
            amount_original_amount=Decimal("10.00"),
            amount_original_currency="USD",
            metadata_json={"employee_reviewed": True},
        )
        assert item.amount_home_amount is None

        fx_service.auto_upsert_fx_rates(
            session,
            claim_id=claim.id,
            to_currency="SGD",
            from_currencies=["USD"],
        )

        fx = session.scalar(
            select(FxRate).where(
                FxRate.claim_id == claim.id,
                FxRate.from_currency == "USD",
                FxRate.to_currency == "SGD",
            )
        )
        assert fx is not None
        assert fx.rate == Decimal("1.25")
        assert fx.as_of_date == date(2026, 1, 1)
        assert fx.source == "frankfurter.app"

        session.refresh(item)
        assert item.amount_home_amount == Decimal("12.50")
        assert item.fx_rate_to_home == Decimal("1.25")

