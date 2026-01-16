from __future__ import annotations

import json
import re
from typing import Any

import httpx

from serendipity_spend.core.config import settings

_ALLOWED_CATEGORIES: set[str] = {
    "lodging",
    "airfare",
    "meals",
    "transport",
    "travel_ancillary",
    "airline_fee",
    "other",
}

_ALLOWED_CABIN_CLASSES: set[str] = {"economy", "premium_economy", "business", "first"}


def extract_policy_fields(text: str) -> dict[str, Any] | None:
    """
    Best-effort AI extraction of policy-relevant fields.

    Returns a dict with optional keys: category, hotel_nights, flight_duration_hours,
    flight_cabin_class, attendees, confidence.
    """
    if not settings.receipt_ai_enabled:
        return None
    if not settings.openai_api_key:
        return None

    cleaned = _truncate_text(text, max_chars=int(settings.receipt_ai_max_chars or 0) or 12000)
    if not cleaned:
        return None

    payload = {
        "model": settings.openai_model,
        "temperature": 0,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You extract policy-relevant fields from travel receipts/invoices.\n"
                    "Only use information explicitly present in the text. Never guess.\n"
                    "If a field is not clearly present, return null for it.\n"
                    "Return JSON only."
                ),
            },
            {
                "role": "user",
                "content": (
                    "Extract these fields from the receipt text.\n"
                    "- category: one of "
                    + ", ".join(sorted(_ALLOWED_CATEGORIES))
                    + " or null\n"
                    "- hotel_nights: integer or null\n"
                    "- flight_duration_hours: number (hours, e.g. 5.5) or null\n"
                    "- flight_cabin_class: one of "
                    + ", ".join(sorted(_ALLOWED_CABIN_CLASSES))
                    + " or null\n"
                    "- attendees: attendee names as a string, or a count, or null\n"
                    "- confidence: number between 0 and 1\n\n"
                    "Rules:\n"
                    "- Do not infer flight duration from departure/arrival times unless a duration "
                    "is explicitly stated.\n"
                    "- For hotel nights, if check-in and check-out dates are explicitly stated, you"
                    " may compute nights as (check_out - check_in) in days.\n"
                    "- For attendees, if the receipt shows Guests/Covers/PAX/etc, return the "
                    "count.\n\n"
                    "Receipt text:\n"
                    + cleaned
                ),
            },
        ],
    }

    headers = {
        "Authorization": f"Bearer {settings.openai_api_key}",
        "Content-Type": "application/json",
    }

    url = settings.openai_base_url.rstrip("/") + "/chat/completions"
    try:
        resp = httpx.post(
            url,
            headers=headers,
            json=payload,
            timeout=float(settings.receipt_ai_timeout_seconds or 20.0),
            follow_redirects=True,
        )
        resp.raise_for_status()
    except Exception:
        return None

    try:
        raw = resp.json()
        content = str(raw["choices"][0]["message"]["content"])
    except Exception:
        return None

    obj = _parse_json_object(content)
    if not isinstance(obj, dict):
        return None

    return _sanitize_policy_fields(obj)


def _truncate_text(text: str, *, max_chars: int) -> str:
    t = (text or "").replace("\u202f", " ").replace("\xa0", " ").strip()
    if not t:
        return ""
    if max_chars <= 0:
        return t
    if len(t) <= max_chars:
        return t
    return t[: max_chars - 20].rstrip() + "\n\n[TRUNCATED]"


def _parse_json_object(content: str) -> Any:
    c = (content or "").strip()
    if not c:
        return None
    try:
        return json.loads(c)
    except Exception:
        pass

    # Fallback: extract the first {...} block.
    m = re.search(r"\{.*\}", c, re.S)
    if not m:
        return None
    try:
        return json.loads(m.group(0))
    except Exception:
        return None


def _sanitize_policy_fields(obj: dict[str, Any]) -> dict[str, Any] | None:
    out: dict[str, Any] = {}

    category = obj.get("category")
    if isinstance(category, str):
        cat = category.strip().lower()
        if cat in _ALLOWED_CATEGORIES:
            out["category"] = cat

    hotel_nights = obj.get("hotel_nights")
    if isinstance(hotel_nights, (int, float, str)):
        try:
            nights = int(str(hotel_nights).strip())
            if 1 <= nights <= 60:
                out["hotel_nights"] = nights
        except Exception:
            pass

    duration = obj.get("flight_duration_hours")
    if isinstance(duration, (int, float, str)):
        try:
            hours = float(str(duration).strip())
            if 0.1 <= hours <= 30:
                out["flight_duration_hours"] = round(hours, 2)
        except Exception:
            pass

    cabin = obj.get("flight_cabin_class")
    if isinstance(cabin, str):
        cabin_norm = cabin.strip().lower()
        if cabin_norm in _ALLOWED_CABIN_CLASSES:
            out["flight_cabin_class"] = cabin_norm

    attendees = obj.get("attendees")
    if isinstance(attendees, int):
        if 1 <= attendees <= 50:
            out["attendees"] = attendees
    elif isinstance(attendees, str):
        att = attendees.strip()
        if att:
            out["attendees"] = att[:200]

    confidence = obj.get("confidence")
    if isinstance(confidence, (int, float, str)):
        try:
            conf = float(str(confidence).strip())
            if 0.0 <= conf <= 1.0:
                out["confidence"] = conf
        except Exception:
            pass

    return out or None
