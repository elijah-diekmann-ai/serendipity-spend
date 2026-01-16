from __future__ import annotations

import uuid
from decimal import Decimal

from sqlalchemy import select
from sqlalchemy.orm import Session

from serendipity_spend.modules.expenses.models import ExpenseItem
from serendipity_spend.modules.fx.models import FxRate


def upsert_fx_rate(
    session: Session,
    *,
    claim_id: uuid.UUID,
    from_currency: str,
    to_currency: str,
    rate: Decimal,
    as_of_date=None,
    source: str | None = None,
) -> FxRate:
    fx = session.scalar(
        select(FxRate).where(
            FxRate.claim_id == claim_id,
            FxRate.from_currency == from_currency.upper(),
            FxRate.to_currency == to_currency.upper(),
        )
    )
    if not fx:
        fx = FxRate(
            claim_id=claim_id,
            from_currency=from_currency.upper(),
            to_currency=to_currency.upper(),
            rate=rate,
            as_of_date=as_of_date,
            source=source,
        )
        session.add(fx)
    else:
        fx.rate = rate
        fx.as_of_date = as_of_date
        fx.source = source
        session.add(fx)
    session.commit()
    session.refresh(fx)
    return fx


def apply_fx_to_claim_items(session: Session, *, claim_id: uuid.UUID) -> None:
    fx_rates = list(session.scalars(select(FxRate).where(FxRate.claim_id == claim_id)))
    by_pair = {(fx.from_currency, fx.to_currency): fx for fx in fx_rates}

    items = list(session.scalars(select(ExpenseItem).where(ExpenseItem.claim_id == claim_id)))
    for item in items:
        pair = (item.amount_original_currency.upper(), item.amount_home_currency.upper())
        if pair[0] == pair[1]:
            item.amount_home_amount = item.amount_original_amount
            item.fx_rate_to_home = Decimal("1")
            session.add(item)
            continue
        fx = by_pair.get(pair)
        if not fx:
            continue
        item.amount_home_amount = (item.amount_original_amount * fx.rate).quantize(Decimal("0.01"))
        item.fx_rate_to_home = fx.rate
        session.add(item)

    session.commit()
