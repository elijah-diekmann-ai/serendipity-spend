from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal

from serendipity_spend.core.currencies import normalize_currency


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


def parse_wifionboard_receipt(text: str) -> ParsedExpense | None:
    if not re.search(r"(?i)\bwif[\u2011-]?fi\s+onboard\b|\bwifionboard\b", text):
        return None
    if not re.search(r"(?i)\btotal\s+paid\b", text):
        return None

    vendor_reference = None
    m = re.search(r"(?i)\border\s*[:#]?\s*([A-Z0-9-]{6,})\b", text)
    if m:
        vendor_reference = m.group(1).strip()[:200] or None

    m = re.search(
        r"(?is)\btotal\s+paid\b.*?(?:CA\$|US\$|\$|£|€)?\s*"
        r"([0-9][0-9,.'\u202f\xa0 ]*[0-9])\s*([A-Z]{3})\b",
        text,
    )
    if not m:
        return None
    amount_str, cur = m.groups()
    currency = normalize_currency(cur)
    if not currency or currency == "XXX":
        return None
    amount = _parse_amount_decimal(amount_str)
    if amount is None:
        return None

    tx_date = _extract_any_date(text)

    desc = "In-flight Wi-Fi"
    if vendor_reference:
        desc = f"{desc} (Order {vendor_reference})"

    return ParsedExpense(
        vendor="Wi-Fi Onboard",
        vendor_reference=vendor_reference,
        receipt_type="wifi_receipt",
        category="travel_ancillary",
        description=desc,
        transaction_date=tx_date,
        amount=amount,
        currency=currency,
        metadata={
            "extraction_family": "vendor",
            "extraction_method": "vendor",
            "extraction_confidence": 0.9,
            "employee_reviewed": False,
            "order": vendor_reference,
        },
    )


def _parse_amount_decimal(s: str) -> Decimal | None:
    raw = str(s or "").strip()
    if not raw:
        return None
    raw = raw.replace("\u202f", " ").replace("\xa0", " ").replace(" ", "").replace("'", "")
    raw = re.sub(r"[^0-9,\\.]", "", raw)
    if not raw or not any(ch.isdigit() for ch in raw):
        return None

    if "," in raw and "." in raw:
        decimal_sep = "," if raw.rfind(",") > raw.rfind(".") else "."
        thousands_sep = "." if decimal_sep == "," else ","
        normalized = raw.replace(thousands_sep, "").replace(decimal_sep, ".")
    elif "," in raw:
        if raw.count(",") > 1:
            normalized = raw.replace(",", "")
        else:
            idx = raw.rfind(",")
            digits_after = len(raw) - idx - 1
            if digits_after == 2:
                normalized = raw.replace(",", ".")
            else:
                normalized = raw.replace(",", "")
    else:
        normalized = raw.replace(",", "")

    try:
        return Decimal(normalized).quantize(Decimal("0.01"))
    except Exception:
        return None


def _extract_any_date(text: str) -> date | None:
    # Prefer dates in the receipt itself over EmailDate metadata lines.
    lines = [
        ln
        for ln in (text or "").splitlines()
        if not ln.strip().lower().startswith("emaildate:")
    ]
    t = "\n".join(lines)

    m = re.search(r"(?i)\bdate:\s*([0-9]{1,2}\s+[A-Za-z]{3,9}\s+[0-9]{4})\b", t)
    if m:
        s = m.group(1)
        for fmt in ("%d %b %Y", "%d %B %Y"):
            try:
                return datetime.strptime(s, fmt).date()
            except ValueError:
                continue

    m = re.search(r"\b([0-9]{1,2}/[0-9]{1,2}/[0-9]{2,4})\b", t)
    if m:
        s = m.group(1)
        for fmt in ("%m/%d/%y", "%d/%m/%y", "%m/%d/%Y", "%d/%m/%Y"):
            try:
                return datetime.strptime(s, fmt).date()
            except ValueError:
                continue

    return None
