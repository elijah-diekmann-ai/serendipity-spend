from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, date, datetime, time, timedelta, timezone
from decimal import Decimal


@dataclass(frozen=True)
class ParsedExpense:
    vendor: str
    vendor_reference: str | None
    receipt_type: str
    category: str | None
    description: str | None
    transaction_date: date | None
    transaction_at: datetime | None
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
        transaction_at=None,
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
    tzinfo = _extract_gmt_offset_tzinfo(text)
    trip_date, trip_time = _extract_trip_date_time(text)

    transaction_at = None
    if trip_date and trip_time:
        try:
            dt_local = datetime.combine(trip_date, trip_time, tzinfo=tzinfo or UTC)
            transaction_at = dt_local.astimezone(UTC)
        except Exception:
            transaction_at = None

    if not trip_date:
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

    breakdown = _extract_breakdown(text)
    trip_details = _extract_trip_details(text)

    desc = "Uber trip"
    ride_type = trip_details.get("ride_type")
    pickup_location = trip_details.get("pickup_location")
    dropoff_location = trip_details.get("dropoff_location")
    if ride_type:
        desc = f"Uber {ride_type}"
    if pickup_location and dropoff_location:
        desc = f"{desc}: {pickup_location} → {dropoff_location}"

    metadata: dict = {
        "extraction_family": "vendor",
        "extraction_method": "vendor",
        "extraction_confidence": 0.9,
        "employee_reviewed": False,
        "is_payment_receipt": is_payment_receipt,
    }
    if breakdown:
        metadata["breakdown"] = breakdown
    if trip_details:
        metadata.update(trip_details)
    if tzinfo:
        metadata["receipt_tz_offset_minutes"] = int(tzinfo.utcoffset(None).total_seconds() // 60)

    return ParsedExpense(
        vendor="Uber",
        vendor_reference=None,
        receipt_type="trip_summary",
        category="transport",
        description=desc,
        transaction_date=trip_date,
        transaction_at=transaction_at,
        amount=amount,
        currency=currency,
        metadata=metadata,
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


_URL_RE = re.compile(r"<https?://[^>]+>|https?://\S+", re.I)


def _clean_text_keep_lines(text: str) -> list[str]:
    raw = (text or "").replace("\u202f", " ").replace("\xa0", " ").replace("\t", " ")
    out: list[str] = []
    for ln in raw.splitlines():
        ln = _URL_RE.sub(" ", ln)
        ln = re.sub(r"\s+", " ", ln).strip()
        if ln:
            out.append(ln)
    return out


def _extract_gmt_offset_tzinfo(text: str) -> timezone | None:
    # Look for a forwarded email header line like:
    #   Date: 13 January 2026 at 13:12:18 GMT-5
    # or:
    #   Date: ... GMT-06:00
    for ln in _clean_text_keep_lines(text):
        if not ln.lower().startswith("date:"):
            continue
        m = re.search(r"(?i)\bGMT\s*([+-])\s*([0-9]{1,2})(?::?([0-9]{2}))?\b", ln)
        if not m:
            continue
        sign, hh, mm = m.groups()
        hours = int(hh)
        minutes = int(mm) if mm else 0
        total = hours * 60 + minutes
        if sign == "-":
            total = -total
        return timezone(timedelta(minutes=total))
    return None


def _parse_trip_date(s: str | None) -> date | None:
    if not s:
        return None
    raw = str(s).strip()
    for fmt in ("%d %b %Y", "%d %B %Y", "%b %d, %Y", "%B %d, %Y"):
        try:
            return datetime.strptime(raw, fmt).date()
        except ValueError:
            continue
    return None


def _parse_hhmm(s: str | None) -> time | None:
    if not s:
        return None
    raw = str(s).strip()
    m = re.fullmatch(r"([0-9]{1,2}):([0-9]{2})", raw)
    if not m:
        return None
    hh, mm = int(m.group(1)), int(m.group(2))
    if hh > 23 or mm > 59:
        return None
    return time(hour=hh, minute=mm)


def _extract_trip_date_time(text: str) -> tuple[date | None, time | None]:
    # Prefer the receipt's displayed trip date/time (e.g., "13 Jan 2026" then "12:38"),
    # not the email header Date: line.
    lines = _clean_text_keep_lines(text)

    # 1) Combined line: "13 Jan 2026 , 12:38"
    for ln in lines:
        m = re.search(
            r"\b([0-9]{1,2}\s+[A-Za-z]{3,9}\s+[0-9]{4})\b\s*[,–—-]?\s*"
            r"\b([0-9]{1,2}:[0-9]{2})\b",
            ln,
        )
        if not m:
            continue
        d = _parse_trip_date(m.group(1))
        t = _parse_hhmm(m.group(2))
        if d and t:
            return d, t

    # 2) Date line then time line.
    for i, ln in enumerate(lines):
        if ln.lower().startswith("date:"):
            # Skip the email header date.
            continue
        m = re.search(r"\b([0-9]{1,2}\s+[A-Za-z]{3,9}\s+[0-9]{4})\b", ln)
        if not m:
            continue
        d = _parse_trip_date(m.group(1))
        if not d:
            continue
        for j in range(i + 1, min(i + 4, len(lines))):
            t_match = re.search(r"\b([0-9]{1,2}:[0-9]{2})\b", lines[j])
            if not t_match:
                continue
            t = _parse_hhmm(t_match.group(1))
            if t:
                return d, t

    return None, None


def _clean_for_regex(text: str) -> str:
    t = (text or "").replace("\u202f", " ").replace("\xa0", " ").replace("\t", " ")
    t = _URL_RE.sub(" ", t)
    # Help with artifacts like "Comfort6.98" and "12:439 Oxford" (time followed by a digit).
    t = re.sub(r"([A-Za-z])([0-9])", r"\1 \2", t)
    t = re.sub(r"(\b[0-2]?[0-9]:[0-5][0-9])(?=[0-9])", r"\1 ", t)
    t = re.sub(r"\s+", " ", t).strip()
    return t


def _extract_breakdown(text: str) -> list[dict]:
    t = _clean_for_regex(text)
    if not t:
        return []
    m = re.search(r"(?i)\btotal\b", t)
    if not m:
        return []
    tail = t[m.start() :]
    tail = re.split(r"(?i)\b(trip details|need help|payments)\b", tail, maxsplit=1)[0]

    entries: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for m2 in re.finditer(
        r"(?i)\b([A-Za-z][A-Za-z0-9 .,&/\-]{1,60}?)\b\s*(CA\$|US\$|\$)\s*"
        r"([0-9][0-9,.' ]*[0-9])\b",
        tail,
    ):
        label, sym, amt = m2.groups()
        label = label.strip()
        if not label or label.lower() in {"total", "payments"}:
            continue
        amount = _parse_amount_decimal(amt)
        if amount is None:
            continue
        if sym == "CA$":
            currency = "CAD"
        elif sym == "US$":
            currency = "USD"
        else:
            # Ambiguous '$' - ignore breakdown line items rather than guessing.
            continue
        key = (label.lower(), currency, str(amount))
        if key in seen:
            continue
        seen.add(key)
        entries.append({"label": label, "currency": currency, "amount": str(amount)})
    return entries


def _extract_trip_details(text: str) -> dict:
    t = _clean_for_regex(text)
    if not t:
        return {}
    if "trip details" not in t.lower():
        return {}
    details = t.split("Trip details", 1)[1]

    out: dict = {}

    m = re.search(
        r"\b(Black|Comfort|UberX|UberXL|Premier|Premium)\b\s*"
        r"([0-9]+\.?[0-9]*)\s*(miles|kilometers)\s*,\s*([0-9]{1,3})\s*minutes\b",
        details,
        re.I,
    )
    if m:
        ride_type, dist, unit, mins = m.groups()
        out["ride_type"] = ride_type
        out["distance"] = dist
        out["distance_unit"] = unit.lower()
        out["duration_mins"] = mins

    # Pickup/dropoff: "12:43 9 Oxford St ... 13:01 600 Atlantic Ave ...".
    m = re.search(
        r"\b([0-2]?[0-9]:[0-5][0-9])\b\s+(.+?)\s+\b([0-2]?[0-9]:[0-5][0-9])\b\s+(.+?)"
        r"(?=\bYou rode with\b|\bNeed help\b|\bWhen you ride\b|\bUber\b|$)",
        details,
        re.I,
    )
    if m:
        pickup_time, pickup_location, dropoff_time, dropoff_location = m.groups()
        pickup_location = pickup_location.strip(" -\u2013\u2014")
        dropoff_location = dropoff_location.strip(" -\u2013\u2014")
        out["pickup_time"] = pickup_time
        out["pickup_location"] = pickup_location[:300] if pickup_location else None
        out["dropoff_time"] = dropoff_time
        out["dropoff_location"] = dropoff_location[:300] if dropoff_location else None

    m = re.search(
        r"\bYou rode with\s+([A-Za-z][A-Za-z .'-]{0,40})\s*([0-9]\.[0-9]{1,2})?",
        details,
    )
    if m:
        name = (m.group(1) or "").strip()
        rating = (m.group(2) or "").strip()
        if name:
            out["driver_name"] = name
        if rating:
            out["driver_rating"] = rating

    return {k: v for k, v in out.items() if v is not None and v != ""}
