from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal


@dataclass(frozen=True)
class ParsedExpense:
    vendor: str
    vendor_reference: str | None
    receipt_type: str
    category: str | None
    description: str | None
    transaction_date: date | None
    amount: Decimal
    currency: str
    metadata: dict


def parse_united_wifi_receipt(text: str) -> ParsedExpense | None:
    if "Thanks for your purchase with United" not in text:
        return None

    flight = _find(r"Flight 1 of 1\s*([A-Z]{2}[0-9]+)", text)
    route = _find(r"\([0-9]{13}\)\s*([A-Z]{3}-[A-Z]{3})", text)
    ref = _find(r"Reference Number:\s*\n?\s*([0-9]{13})", text)
    item = _find(r"(Inflight Wi-Fi[^\n]+)\s*\(", text)
    purchase_date_str = _find(r"Date of purchase:\s*([^\n]+)", text)
    purchase_date = _parse_united_date(purchase_date_str)
    last4 = _find(r"ending in\s*\n\s*([0-9]{4})", text)
    m = re.search(r"Total:\s*([0-9]+\.[0-9]{2})\s*([A-Z]{3})", text)
    if not m:
        return None
    amount_str, currency = m.groups()

    desc = "United inflight Wi‑Fi"
    if route and flight:
        desc = f"United Wi‑Fi ({flight} {route})"

    return ParsedExpense(
        vendor="United Airlines",
        vendor_reference=ref,
        receipt_type="email_receipt",
        category="travel_ancillary",
        description=desc,
        transaction_date=purchase_date,
        amount=Decimal(amount_str),
        currency=currency,
        metadata={
            "flight_number": flight,
            "route": route,
            "reference_number": ref,
            "item_description": item,
            "purchase_date_raw": purchase_date_str,
            "payment_last4": last4,
        },
    )


def _find(pattern: str, text: str) -> str | None:
    m = re.search(pattern, text, re.I)
    return m.group(1).strip() if m else None


def _parse_united_date(s: str | None) -> date | None:
    if not s:
        return None
    try:
        return datetime.strptime(s.strip(), "%a, %b %d, %Y").date()
    except ValueError:
        return None
