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


def parse_uber_trip_summary(summary_page: str, detail_page: str) -> ParsedExpense | None:
    if not re.search(r"(?i)\btrip\s+with\s+u\s*b\s*e\s*r\b", summary_page) or not re.search(
        r"(?i)\btota[li]\b", summary_page
    ):
        return None

    m = re.search(
        r"(?i)\btotal\b\s*[:\-]?\s*(CA\$|US\$|\$)\s*([0-9][0-9,.'\u202f\xa0 ]*[0-9])",
        summary_page,
    )
    if not m:
        return None

    sym, amount_str = m.groups()
    currency = "CAD" if sym == "CA$" else "USD"
    amount = _parse_amount_decimal(amount_str)
    if amount is None:
        return None

    trip_date_str = _find(r"\n([A-Za-z]+\s+[0-9]{1,2},\s+[0-9]{4})\n", summary_page)
    trip_date = _parse_month_d_y(trip_date_str)

    breakdown: list[dict] = []
    for ln in summary_page.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        m2 = re.match(
            r"(.+?)\s*(CA\$|US\$|\$)\s*([0-9][0-9,.'\u202f\xa0 ]*[0-9])\s*$", ln
        )
        if not m2:
            continue
        label, sym2, val = m2.groups()
        val_dec = _parse_amount_decimal(val)
        if val_dec is None:
            continue
        breakdown.append(
            {
                "label": label.strip(),
                "currency": "CAD" if sym2 == "CA$" else "USD",
                "amount": str(val_dec),
            }
        )

    ride_type = _find(r"\n(Black|Comfort|UberX|UberXL|Premier|Premium)\s", "\n" + detail_page)
    dist = _find(r"\b([0-9]+\.?[0-9]*)\s*(miles|kilometers)\s*\|", detail_page)
    dist_unit = _find(r"\b[0-9]+\.?[0-9]*\s*(miles|kilometers)\s*\|", detail_page)
    duration = _find(r"\|\s*([0-9]+)\s*minutes\b", detail_page)

    pickup_time, pickup_location, dropoff_time, dropoff_location = _parse_locations(detail_page)

    desc = "Uber trip"
    if ride_type:
        desc = f"Uber {ride_type}"
    if pickup_location and dropoff_location:
        desc = f"{desc}: {pickup_location} → {dropoff_location}"

    return ParsedExpense(
        vendor="Uber",
        vendor_reference=None,
        receipt_type="trip_summary",
        category="transport",
        description=desc,
        transaction_date=trip_date,
        amount=amount,
        currency=currency,
        metadata={
            "ride_type": ride_type,
            "distance": dist,
            "distance_unit": dist_unit,
            "duration_mins": duration,
            "pickup_time": pickup_time,
            "pickup_location": pickup_location,
            "dropoff_time": dropoff_time,
            "dropoff_location": dropoff_location,
            "breakdown": breakdown,
            "is_payment_receipt": "not a payment receipt" not in summary_page.lower(),
        },
    )


def parse_uber_email_receipt(text: str) -> ParsedExpense | None:
    if not re.search(r"(?i)\btrip\s+with\s+u\s*b\s*e\s*r\b", text) or not re.search(
        r"(?i)\btota[li]\b", text
    ):
        return None

    m = re.search(
        r"(?i)\btotal\b\s*[:\-]?\s*(CA\$|US\$|\$)\s*"
        r"([0-9][0-9,.'\u202f\xa0 ]*[0-9])(?=[^0-9]|$)",
        text,
    )
    if not m:
        return None

    sym, amount_str = m.groups()
    if sym == "CA$":
        currency = "CAD"
    elif sym == "US$":
        currency = "USD"
    else:
        # '$' is ambiguous; infer from other currency hints when possible.
        has_cad = "CA$" in text
        has_usd = "US$" in text
        if has_cad and not has_usd:
            currency = "CAD"
        elif has_usd and not has_cad:
            currency = "USD"
        else:
            return None

    amount = _parse_amount_decimal(amount_str)
    if amount is None:
        return None

    # Uber receipt emails include a well-formed "Date: 12 January 2026 ..." header.
    trip_date = None
    m = re.search(r"(?i)\bdate:\s*([0-9]{1,2}\s+[A-Za-z]{3,9}\s+[0-9]{4})\b", text)
    if m:
        s = m.group(1)
        for fmt in ("%d %b %Y", "%d %B %Y"):
            try:
                trip_date = datetime.strptime(s, fmt).date()
                break
            except ValueError:
                continue

    is_payment_receipt = "not a payment receipt" not in text.lower()

    return ParsedExpense(
        vendor="Uber",
        vendor_reference=None,
        receipt_type="trip_summary",
        category="transport",
        description="Uber trip",
        transaction_date=trip_date,
        amount=amount,
        currency=currency,
        metadata={
            "extraction_family": "vendor",
            "extraction_method": "vendor",
            "extraction_confidence": 0.9,
            "employee_reviewed": False,
            "is_payment_receipt": is_payment_receipt,
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


def _find(pattern: str, text: str) -> str | None:
    m = re.search(pattern, text, re.I)
    return m.group(1).strip() if m else None


def _parse_month_d_y(s: str | None) -> date | None:
    if not s:
        return None
    try:
        return datetime.strptime(s.strip(), "%B %d, %Y").date()
    except ValueError:
        return None


def _parse_locations(detail_page: str) -> tuple[str | None, str | None, str | None, str | None]:
    time_re = re.compile(r"\b([0-9]{1,2}:[0-9]{2}\s*(AM|PM))\b")
    lines = [ln.strip() for ln in detail_page.splitlines() if ln.strip()]
    time_idxs = [i for i, ln in enumerate(lines) if time_re.search(ln)]
    if len(time_idxs) < 2:
        return None, None, None, None
    i1, i2 = time_idxs[0], time_idxs[1]
    pickup_time = time_re.search(lines[i1]).group(0)
    dropoff_time = time_re.search(lines[i2]).group(0)
    pickup_location = " ".join(lines[i1 + 1 : i2]).strip() or None
    dropoff_location = " ".join(lines[i2 + 1 :]).strip() or None
    return pickup_time, pickup_location, dropoff_time, dropoff_location
