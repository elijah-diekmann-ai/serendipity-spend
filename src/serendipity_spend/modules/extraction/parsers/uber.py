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
    if "trip with Uber" not in summary_page or "Total" not in summary_page:
        return None

    m = re.search(r"Total\s*(CA\$|\$)\s*([0-9]+\.[0-9]{2})", summary_page)
    if not m:
        return None

    sym, amount_str = m.groups()
    currency = "CAD" if sym == "CA$" else "USD"

    trip_date_str = _find(r"\n([A-Za-z]+\s+[0-9]{1,2},\s+[0-9]{4})\n", summary_page)
    trip_date = _parse_month_d_y(trip_date_str)

    breakdown: list[dict] = []
    for ln in summary_page.splitlines():
        ln = ln.strip()
        if not ln:
            continue
        m2 = re.match(r"(.+)\s*(CA\$|\$)([0-9]+\.[0-9]{2})$", ln)
        if not m2:
            continue
        label, sym2, val = m2.groups()
        breakdown.append(
            {"label": label.strip(), "currency": "CAD" if sym2 == "CA$" else "USD", "amount": val}
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
        amount=Decimal(amount_str),
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
