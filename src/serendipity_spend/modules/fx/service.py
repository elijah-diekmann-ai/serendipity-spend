from __future__ import annotations

import uuid
from collections.abc import Iterable
from datetime import date
from decimal import Decimal

import httpx
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


def auto_upsert_fx_rates(
    session: Session,
    *,
    claim_id: uuid.UUID,
    to_currency: str,
    from_currencies: Iterable[str],
) -> list[FxRate]:
    to_currency = to_currency.strip().upper()
    if not to_currency or len(to_currency) != 3:
        raise ValueError("Invalid to_currency")

    out: list[FxRate] = []
    for raw in sorted({c.strip().upper() for c in from_currencies if c}):
        if raw == to_currency:
            continue
        rate, as_of_date = _fetch_frankfurter_rate(from_currency=raw, to_currency=to_currency)
        fx = upsert_fx_rate(
            session,
            claim_id=claim_id,
            from_currency=raw,
            to_currency=to_currency,
            rate=rate,
            as_of_date=as_of_date,
            source="frankfurter.app",
        )
        out.append(fx)

    apply_fx_to_claim_items(session, claim_id=claim_id)
    return out


def _fetch_frankfurter_rate(*, from_currency: str, to_currency: str) -> tuple[Decimal, date]:
    from_currency = from_currency.strip().upper()
    to_currency = to_currency.strip().upper()
    if not from_currency or len(from_currency) != 3:
        raise ValueError("Invalid from_currency")
    if not to_currency or len(to_currency) != 3:
        raise ValueError("Invalid to_currency")
    if from_currency == to_currency:
        return Decimal("1"), date.today()

    url = "https://api.frankfurter.app/latest"
    resp = httpx.get(
        url,
        params={"from": from_currency, "to": to_currency},
        timeout=10,
        follow_redirects=True,
    )
    resp.raise_for_status()
    data = resp.json()

    raw_rate = (data.get("rates") or {}).get(to_currency)
    raw_date = data.get("date")
    if raw_rate is None or not raw_date:
        raise ValueError("Unexpected FX response shape")

    return Decimal(str(raw_rate)), date.fromisoformat(str(raw_date))
