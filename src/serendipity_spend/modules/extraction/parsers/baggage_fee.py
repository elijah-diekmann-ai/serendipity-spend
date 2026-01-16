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


def parse_baggage_fee_payment_receipt(text: str) -> ParsedExpense | None:
    if "PAYMENT RECEIPT" not in text or "BAG FEE" not in text:
        return None

    # Example: "CATLIN/RICHARD JUSTIN JEJUUB 31AUG25 9:34 AM"
    pnr = None
    tx_date = None
    tx_time = None
    m = re.search(
        r"\b([A-Z0-9]{5,6})\s+([0-9]{2}[A-Z]{3}[0-9]{2})\s+([0-9]{1,2}:[0-9]{2}\s*[AP]M)\b", text
    )
    if m:
        pnr, date_str, time_str = m.groups()
        try:
            tx_date = datetime.strptime(date_str.title(), "%d%b%y").date()
        except ValueError:
            tx_date = None
        tx_time = time_str

    last4 = None
    total_amount = None
    m = re.search(r"AMEX\s+X+([0-9]{4}).*?CAD\s*\$([0-9]+\.[0-9]{2})", text, re.I)
    if m:
        last4 = m.group(1)
        total_amount = Decimal(m.group(2))

    ref = None
    m = re.search(r"\bBAG\s+FEE\s+([0-9]{10,})\b", text, re.I)
    if m:
        ref = m.group(1)

    if total_amount is None:
        return None

    return ParsedExpense(
        vendor="Airline",
        vendor_reference=ref,
        receipt_type="payment_receipt",
        category="airline_fee",
        description="Airline baggage fee",
        transaction_date=tx_date,
        amount=total_amount,
        currency="CAD",
        metadata={
            "pnr": pnr,
            "time": tx_time,
            "payment_last4": last4,
            "fee_reference": ref,
        },
    )
