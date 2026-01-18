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
    transaction_at: datetime | None
    amount: Decimal
    currency: str
    metadata: dict


def parse_agoda_receipt(text: str) -> ParsedExpense | None:
    t = (text or "").replace("\u202f", " ").replace("\xa0", " ")
    if not re.search(r"(?i)\bagoda\b", t):
        return None
    if not re.search(r"(?i)\bbooking\s+no\b", t):
        return None

    lines = [ln.strip() for ln in t.splitlines() if ln.strip()]

    issuer = _extract_issuer(lines)
    booking_no = _extract_booking_no(t)
    payment_date = _extract_payment_date(lines)
    hotel_name = _extract_value_after_label(lines, label="Hotel Name")
    check_in, check_out = _extract_stay_period(lines)
    nights = None
    if check_in and check_out and check_out > check_in:
        computed = (check_out - check_in).days
        if 1 <= computed <= 60:
            nights = computed

    usd_total = _extract_money_after_label(lines, label="GRAND TOTAL")
    sgd_charge = _extract_money_after_label(lines, label="Total Charge")

    totals: dict[str, str] = {}
    if usd_total:
        totals[usd_total[0]] = str(usd_total[1])
    if sgd_charge:
        totals[sgd_charge[0]] = str(sgd_charge[1])

    # Prefer the charged currency from "Total Charge" as the original amount,
    # but keep all detected totals in metadata for policy/FX accuracy.
    chosen_currency = None
    chosen_amount = None
    if sgd_charge and sgd_charge[0]:
        chosen_currency, chosen_amount = sgd_charge
    elif usd_total and usd_total[0]:
        chosen_currency, chosen_amount = usd_total
    else:
        return None

    vendor = hotel_name or issuer or "Agoda"
    description = f"Hotel: {hotel_name}" if hotel_name else f"Receipt: {vendor}"

    metadata: dict = {
        "extraction_family": "vendor",
        "extraction_method": "vendor",
        "extraction_confidence": 0.95,
        "employee_reviewed": False,
    }
    if issuer:
        metadata["issuer_name"] = issuer
    if hotel_name:
        metadata["hotel_name"] = hotel_name
    if booking_no:
        metadata["booking_no"] = booking_no
    if check_in:
        metadata["hotel_check_in"] = check_in.isoformat()
    if check_out:
        metadata["hotel_check_out"] = check_out.isoformat()
    if nights is not None:
        metadata["hotel_nights"] = nights
    if totals:
        metadata["amounts_by_currency"] = totals

    return ParsedExpense(
        vendor=vendor,
        vendor_reference=booking_no,
        receipt_type="hotel_receipt",
        category="lodging",
        description=description,
        transaction_date=payment_date or check_in,
        transaction_at=None,
        amount=chosen_amount,
        currency=chosen_currency,
        metadata=metadata,
    )


def _extract_issuer(lines: list[str]) -> str | None:
    # Common PDF layout:
    #   Address:
    #   Agoda Company Pte, Ltd.
    for i, ln in enumerate(lines):
        if ln.lower().startswith("address") and i + 1 < len(lines):
            candidate = lines[i + 1].strip()
            if candidate:
                return candidate[:100]
    # Fallback: first line containing Agoda
    for ln in lines:
        if "agoda" in ln.lower():
            return ln.strip()[:100]
    return None


def _extract_booking_no(text: str) -> str | None:
    m = re.search(r"(?is)\bbooking\s+no\.?\s*([0-9]{6,})\b", text)
    return (m.group(1).strip() if m else None) or None


def _extract_payment_date(lines: list[str]) -> date | None:
    raw = _extract_value_after_label(lines, label="Payment Date")
    if not raw:
        return None
    for fmt in ("%B %d, %Y", "%b %d, %Y"):
        try:
            return datetime.strptime(raw, fmt).date()
        except ValueError:
            continue
    return None


def _extract_value_after_label(lines: list[str], *, label: str) -> str | None:
    label_l = label.strip().lower()
    for i, ln in enumerate(lines):
        if ln.strip().lower() == label_l and i + 1 < len(lines):
            candidate = lines[i + 1].strip()
            return candidate[:200] if candidate else None
    return None


def _extract_stay_period(lines: list[str]) -> tuple[date | None, date | None]:
    # Example:
    #   Period
    #   January 11, 2026 - January 12, 2026 (1 night(s))
    period = _extract_value_after_label(lines, label="Period")
    if not period:
        # Sometimes "Stay Period" is used.
        period = _extract_value_after_label(lines, label="Stay Period")
    if not period:
        return None, None

    m = re.search(
        r"(?i)\b([A-Za-z]{3,9}\s+[0-9]{1,2},\s*[0-9]{4})\s*(?:-|–|—|to)\s*"
        r"([A-Za-z]{3,9}\s+[0-9]{1,2},\s*[0-9]{4})\b",
        period,
    )
    if not m:
        return None, None

    def parse(d: str) -> date | None:
        for fmt in ("%B %d, %Y", "%b %d, %Y"):
            try:
                return datetime.strptime(d, fmt).date()
            except ValueError:
                continue
        return None

    return parse(m.group(1)), parse(m.group(2))


def _extract_money_after_label(lines: list[str], *, label: str) -> tuple[str, Decimal] | None:
    label_l = label.strip().lower()
    for i, ln in enumerate(lines):
        if ln.strip().lower() != label_l:
            continue
        if i + 1 >= len(lines):
            return None
        raw = lines[i + 1].strip()
        m = re.search(
            r"\b([A-Z]{3})\s*([0-9][0-9,.'\u202f\xa0 ]*[0-9])\b",
            raw,
        )
        if not m:
            return None
        cur = normalize_currency(m.group(1))
        if not cur:
            return None
        amount = _parse_amount_decimal(m.group(2))
        if amount is None:
            return None
        return cur, amount
    return None


def _parse_amount_decimal(raw: str) -> Decimal | None:
    s = str(raw or "").strip()
    if not s:
        return None
    s = s.replace("\u202f", " ").replace("\xa0", " ")
    s = re.sub(r"[^0-9,.' ]", "", s)
    s = s.replace(" ", "").replace("'", "")
    if not s or not any(ch.isdigit() for ch in s):
        return None

    if "," in s and "." in s:
        decimal_sep = "," if s.rfind(",") > s.rfind(".") else "."
        thousands_sep = "." if decimal_sep == "," else ","
        normalized = s.replace(thousands_sep, "").replace(decimal_sep, ".")
    elif "," in s:
        if s.count(",") > 1:
            normalized = s.replace(",", "")
        else:
            idx = s.rfind(",")
            digits_after = len(s) - idx - 1
            normalized = s.replace(",", ".") if digits_after == 2 else s.replace(",", "")
    else:
        normalized = s.replace(",", "")

    try:
        return Decimal(normalized).quantize(Decimal("0.01"))
    except Exception:
        return None
