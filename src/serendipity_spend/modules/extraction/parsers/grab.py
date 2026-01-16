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


def parse_grab_ride_receipt(page_1: str, page_2: str) -> ParsedExpense | None:
    if "Your Grab E-Receipt" not in page_1 or "Booking ID:" not in page_1:
        return None

    booking_id = _find(r"Booking ID:\s*([A-Z0-9-]+)", page_1)
    if not booking_id:
        return None

    ride_type = _find(r"\n\s*([^\n]+)\nHope you enjoyed your ride!", page_1)
    pickup_date_str = _find(r"Picked up on\s*([^\n]+)", page_1)
    pickup_date = _parse_date_dmy_month_year(pickup_date_str)

    currency = _find(r"Total Paid\s*([A-Z]{3})\s*[0-9]+\.[0-9]{2}", page_1) or "SGD"
    amount_str = _find(r"Total Paid\s*[A-Z]{3}\s*([0-9]+\.[0-9]{2})", page_1)
    if not amount_str:
        return None

    passenger = _find(r"Passenger\s*\n([^\n]+)", page_1)
    profile = _find(r"Profile\s*\n([^\n]+)", page_1)

    paid_by_last4 = None
    m = re.search(r"Paid by\s*\n(\d{4})", page_1)
    if m:
        paid_by_last4 = m.group(1)

    breakdown = {
        "fare": _find_decimal(r"Fare\s*([0-9]+\.[0-9]{2})", page_1),
        "platform_fee": _find_decimal(r"Platform & partner fee\s*([0-9]+\.[0-9]{2})", page_1),
        "driver_fee": _find_decimal(r"Driver Fee\s*([0-9]+\.[0-9]{2})", page_1),
    }

    trip_distance = None
    trip_unit = None
    trip_duration_mins = None
    m = re.search(
        r"\b([0-9]+\.?[0-9]*)\s*(km|miles|kilometers)\s*•\s*([0-9]+)\s*mins\b", page_2, re.I
    )
    if m:
        trip_distance, trip_unit, trip_duration_mins = m.groups()

    pickup_location = pickup_time = dropoff_location = dropoff_time = None
    if "Your Trip" in page_2:
        lines = [ln.strip() for ln in page_2.splitlines() if ln.strip()]
        try:
            idx = lines.index("⋮")
        except ValueError:
            idx = None
        if idx is not None and idx + 4 < len(lines):
            pickup_location, pickup_time, dropoff_location, dropoff_time = lines[idx + 1 : idx + 5]

    desc_from_to = None
    if pickup_location and dropoff_location:
        desc_from_to = f"{pickup_location} → {dropoff_location}"

    return ParsedExpense(
        vendor="Grab",
        vendor_reference=booking_id,
        receipt_type="ride_receipt",
        category="transport",
        description=f"Grab ride ({ride_type})" + (f": {desc_from_to}" if desc_from_to else ""),
        transaction_date=pickup_date,
        amount=Decimal(amount_str),
        currency=currency,
        metadata={
            "booking_id": booking_id,
            "ride_type": ride_type,
            "passenger": passenger,
            "profile": profile,
            "paid_by_last4": paid_by_last4,
            "breakdown": breakdown,
            "trip_distance": trip_distance,
            "trip_unit": trip_unit,
            "trip_duration_mins": trip_duration_mins,
            "pickup_location": pickup_location,
            "pickup_time": pickup_time,
            "dropoff_location": dropoff_location,
            "dropoff_time": dropoff_time,
        },
    )


def _find(pattern: str, text: str) -> str | None:
    m = re.search(pattern, text, re.I)
    return m.group(1).strip() if m else None


def _find_decimal(pattern: str, text: str) -> float | None:
    s = _find(pattern, text)
    if s is None:
        return None
    try:
        return float(s)
    except ValueError:
        return None


def _parse_date_dmy_month_year(s: str | None) -> date | None:
    if not s:
        return None
    try:
        return datetime.strptime(s.strip(), "%d %B %Y").date()
    except ValueError:
        return None
