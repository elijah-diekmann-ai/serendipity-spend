from __future__ import annotations

import json
import re
from datetime import date
from decimal import Decimal, InvalidOperation
from typing import Any

import httpx

from serendipity_spend.core.config import settings
from serendipity_spend.core.currencies import normalize_currency

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

_POLICY_FIELDS_RESPONSE_FORMAT: dict[str, Any] = {
    "type": "json_schema",
    "json_schema": {
        "name": "policy_fields_extraction",
        "strict": True,
        "schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "category": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "value": {
                            "anyOf": [
                                {"type": "string", "enum": sorted(_ALLOWED_CATEGORIES)},
                                {"type": "null"},
                            ]
                        },
                        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                        "evidence_lines": {
                            "type": "array",
                            "items": {"type": "integer", "minimum": 1},
                            "maxItems": 20,
                        },
                        "evidence_snippets": {
                            "type": "array",
                            "items": {"type": "string"},
                            "maxItems": 5,
                        },
                    },
                    "required": ["value", "confidence", "evidence_lines"],
                },
                "hotel_nights": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "value": {
                            "anyOf": [
                                {"type": "integer", "minimum": 1, "maximum": 60},
                                {"type": "null"},
                            ]
                        },
                        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                        "evidence_lines": {
                            "type": "array",
                            "items": {"type": "integer", "minimum": 1},
                            "maxItems": 20,
                        },
                        "evidence_snippets": {
                            "type": "array",
                            "items": {"type": "string"},
                            "maxItems": 5,
                        },
                    },
                    "required": ["value", "confidence", "evidence_lines"],
                },
                "flight_duration_hours": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "value": {
                            "anyOf": [
                                {"type": "number", "minimum": 0.1, "maximum": 30},
                                {"type": "null"},
                            ]
                        },
                        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                        "evidence_lines": {
                            "type": "array",
                            "items": {"type": "integer", "minimum": 1},
                            "maxItems": 20,
                        },
                        "evidence_snippets": {
                            "type": "array",
                            "items": {"type": "string"},
                            "maxItems": 5,
                        },
                    },
                    "required": ["value", "confidence", "evidence_lines"],
                },
                "flight_cabin_class": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "value": {
                            "anyOf": [
                                {"type": "string", "enum": sorted(_ALLOWED_CABIN_CLASSES)},
                                {"type": "null"},
                            ]
                        },
                        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                        "evidence_lines": {
                            "type": "array",
                            "items": {"type": "integer", "minimum": 1},
                            "maxItems": 20,
                        },
                        "evidence_snippets": {
                            "type": "array",
                            "items": {"type": "string"},
                            "maxItems": 5,
                        },
                    },
                    "required": ["value", "confidence", "evidence_lines"],
                },
                "attendees": {
                    "type": "object",
                    "additionalProperties": False,
                    "properties": {
                        "value": {
                            "anyOf": [
                                {"type": "integer", "minimum": 1, "maximum": 50},
                                {"type": "string", "minLength": 1, "maxLength": 200},
                                {"type": "null"},
                            ]
                        },
                        "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                        "evidence_lines": {
                            "type": "array",
                            "items": {"type": "integer", "minimum": 1},
                            "maxItems": 20,
                        },
                        "evidence_snippets": {
                            "type": "array",
                            "items": {"type": "string"},
                            "maxItems": 5,
                        },
                    },
                    "required": ["value", "confidence", "evidence_lines"],
                },
                "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            },
            "required": [
                "category",
                "hotel_nights",
                "flight_duration_hours",
                "flight_cabin_class",
                "attendees",
                "confidence",
            ],
        },
    },
}


def receipt_ai_available() -> bool:
    return bool(settings.receipt_ai_enabled and settings.openai_api_key)


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
    numbered = _number_lines(cleaned, max_lines=260)
    if not numbered:
        return None

    payload = {
        "model": settings.openai_model,
        "temperature": 0,
        "response_format": _POLICY_FIELDS_RESPONSE_FORMAT,
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
                    "Extract these policy fields from the numbered receipt text.\n"
                    "Return JSON with this exact shape:\n"
                    "{\n"
                    '  "category": {"value": one_of['
                    + ", ".join(sorted(_ALLOWED_CATEGORIES))
                    + "]|null, \"confidence\": number, \"evidence_lines\": number[]},\n"
                    '  "hotel_nights": {"value": integer|null, "confidence": number, '
                    '"evidence_lines": number[]},\n'
                    '  "flight_duration_hours": {"value": number|null, "confidence": number, '
                    '"evidence_lines": number[]},\n'
                    '  "flight_cabin_class": {"value": one_of['
                    + ", ".join(sorted(_ALLOWED_CABIN_CLASSES))
                    + "]|null, \"confidence\": number, \"evidence_lines\": number[]},\n"
                    '  "attendees": {"value": string|integer|null, "confidence": number, '
                    '"evidence_lines": number[]},\n'
                    '  "confidence": number\n'
                    "}\n\n"
                    "Rules:\n"
                    "- Only use information explicitly present in the text.\n"
                    "- Do not infer flight duration from departure/arrival times unless a duration "
                    "is explicitly stated.\n"
                    "- For hotel nights, if check-in and check-out dates are explicitly stated, "
                    "you may compute nights as (check_out - check_in) in days.\n"
                    "- evidence_lines MUST reference the line numbers you used.\n"
                    "- If value is null, set confidence to 0 and evidence_lines to [].\n"
                    "- evidence_snippets are optional; if provided, keep them short "
                    "and verbatim.\n\n"
                    "Numbered receipt text:\n"
                    + numbered
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
    except httpx.HTTPStatusError as e:
        # Some models/endpoints don't support Structured Outputs; fall back to JSON mode.
        if e.response is None or e.response.status_code not in {400, 422}:
            return None
        payload["response_format"] = {"type": "json_object"}
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
    except Exception:
        return None

    try:
        raw = resp.json()
        msg = raw["choices"][0]["message"]
        if isinstance(msg, dict) and msg.get("refusal"):
            return None
        content = msg.get("content") if isinstance(msg, dict) else None
    except Exception:
        return None

    if not isinstance(content, str) or not content.strip():
        return None

    obj = _parse_json_object(content)
    if not isinstance(obj, dict):
        return None

    return _sanitize_policy_fields(obj)


def extract_receipt_fields(text: str) -> dict[str, Any] | None:
    """
    Best-effort AI extraction of core receipt fields (with provenance).

    Returns a dict with keys: vendor, transaction_date, total, category.
    Each value is an object containing `value` (or amount/currency), `confidence`,
    and `evidence_lines` (line numbers from the provided numbered text).
    """
    if not settings.receipt_ai_enabled:
        return None
    if not settings.openai_api_key:
        return None

    cleaned = _truncate_text(text, max_chars=int(settings.receipt_ai_max_chars or 0) or 12000)
    numbered = _number_lines(cleaned, max_lines=260)
    if not numbered:
        return None

    payload = {
        "model": settings.openai_model,
        "temperature": 0,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You extract fields from travel receipts/invoices.\n"
                    "Only use information explicitly present in the text. Never guess.\n"
                    "If a field is not clearly present, return null for it.\n"
                    "Return JSON only."
                ),
            },
            {
                "role": "user",
                "content": (
                    "Extract these fields from the numbered receipt text.\n"
                    "Return JSON with this exact shape:\n"
                    "{\n"
                    '  "vendor": {"value": string|null, "confidence": number, '
                    '"evidence_lines": number[]},\n'
                    '  "transaction_date": {"value": "YYYY-MM-DD"|null, "confidence": number, '
                    '"evidence_lines": number[]},\n'
                    '  "total": {"amount": string|null, "currency": string|null, "confidence": '
                    'number, "evidence_lines": number[]},\n'
                    '  "category": {"value": one_of['
                    + ", ".join(sorted(_ALLOWED_CATEGORIES))
                    + "]|null, \"confidence\": number, \"evidence_lines\": number[]}\n"
                    "}\n\n"
                    "Rules:\n"
                    "- Currency MUST be an ISO-4217 code.\n"
                    "- Amount MUST be the receipt total/grand total/amount charged "
                    "(not a tax/subtotal).\n"
                    "- evidence_lines MUST reference the line numbers you used.\n"
                    "- If value is null, set confidence to 0 and evidence_lines to [].\n\n"
                    "Numbered receipt text:\n"
                    + numbered
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

    return _sanitize_receipt_fields(obj)


def _number_lines(text: str, *, max_lines: int) -> str:
    if not text:
        return ""
    out_lines: list[str] = []
    for idx, ln in enumerate(text.splitlines()):
        if len(out_lines) >= max_lines:
            break
        s = ln.strip("\r")
        if not s.strip():
            continue
        out_lines.append(f"{idx + 1}|{s[:300]}")
    return "\n".join(out_lines).strip()


def _sanitize_receipt_fields(obj: dict[str, Any]) -> dict[str, Any] | None:
    def _get_field(name: str) -> dict[str, Any]:
        val = obj.get(name)
        return val if isinstance(val, dict) else {}

    def _confidence(field: dict[str, Any]) -> float:
        raw = field.get("confidence")
        try:
            conf = float(raw)
        except Exception:
            return 0.0
        if conf < 0.0:
            return 0.0
        if conf > 1.0:
            return 1.0
        return conf

    def _evidence_lines(field: dict[str, Any]) -> list[int]:
        raw = field.get("evidence_lines")
        if not isinstance(raw, list):
            return []
        out: list[int] = []
        for x in raw[:20]:
            try:
                n = int(x)
            except Exception:
                continue
            if n > 0:
                out.append(n)
        # keep stable order
        seen: set[int] = set()
        deduped: list[int] = []
        for n in out:
            if n in seen:
                continue
            seen.add(n)
            deduped.append(n)
        return deduped

    out: dict[str, Any] = {}

    vendor_f = _get_field("vendor")
    vendor_val = vendor_f.get("value")
    if isinstance(vendor_val, str):
        v = vendor_val.strip()
        if v:
            out["vendor"] = {
                "value": v[:100],
                "confidence": _confidence(vendor_f),
                "evidence_lines": _evidence_lines(vendor_f),
            }

    date_f = _get_field("transaction_date")
    date_val = date_f.get("value")
    if isinstance(date_val, str):
        s = date_val.strip()
        try:
            d = date.fromisoformat(s)
        except Exception:
            d = None
        if d:
            out["transaction_date"] = {
                "value": d.isoformat(),
                "confidence": _confidence(date_f),
                "evidence_lines": _evidence_lines(date_f),
            }

    total_f = _get_field("total")
    amount_val = total_f.get("amount")
    currency_val = total_f.get("currency")
    amount_s: str | None = None
    if isinstance(amount_val, (int, float, str)):
        try:
            amt = Decimal(str(amount_val).strip().replace(",", ""))
            if amt > Decimal("0"):
                amount_s = str(amt.quantize(Decimal("0.01")))
        except (InvalidOperation, ValueError):
            amount_s = None
    cur_norm = normalize_currency(currency_val) if isinstance(currency_val, str) else None
    if amount_s and cur_norm:
        out["total"] = {
            "amount": amount_s,
            "currency": cur_norm,
            "confidence": _confidence(total_f),
            "evidence_lines": _evidence_lines(total_f),
        }

    category_f = _get_field("category")
    category_val = category_f.get("value")
    if isinstance(category_val, str):
        cat = category_val.strip().lower()
        if cat in _ALLOWED_CATEGORIES:
            out["category"] = {
                "value": cat,
                "confidence": _confidence(category_f),
                "evidence_lines": _evidence_lines(category_f),
            }

    return out or None


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
    provenance: dict[str, Any] = {}

    def _field(name: str) -> dict[str, Any] | None:
        val = obj.get(name)
        return val if isinstance(val, dict) else None

    def _confidence(field: dict[str, Any] | None) -> float:
        if not field:
            return 0.0
        raw = field.get("confidence")
        try:
            conf = float(raw)
        except Exception:
            return 0.0
        if conf < 0.0:
            return 0.0
        if conf > 1.0:
            return 1.0
        return conf

    def _evidence_lines(field: dict[str, Any] | None) -> list[int]:
        if not field:
            return []
        raw = field.get("evidence_lines")
        if not isinstance(raw, list):
            return []
        out_lines: list[int] = []
        for x in raw[:20]:
            try:
                n = int(x)
            except Exception:
                continue
            if n > 0:
                out_lines.append(n)
        seen: set[int] = set()
        deduped: list[int] = []
        for n in out_lines:
            if n in seen:
                continue
            seen.add(n)
            deduped.append(n)
        return deduped

    def _evidence_snippets(field: dict[str, Any] | None) -> list[str]:
        if not field:
            return []
        raw = field.get("evidence_snippets")
        if not isinstance(raw, list):
            return []
        out_snips: list[str] = []
        for x in raw[:5]:
            if not isinstance(x, str):
                continue
            s = x.strip()
            if not s:
                continue
            out_snips.append(s[:300])
        return out_snips

    category_f = _field("category")
    category_v = category_f.get("value") if category_f else obj.get("category")
    if isinstance(category_v, str):
        cat = category_v.strip().lower()
        if cat in _ALLOWED_CATEGORIES:
            out["category"] = cat
            if category_f:
                prov: dict[str, Any] = {
                    "confidence": _confidence(category_f),
                    "evidence_lines": _evidence_lines(category_f),
                }
                snippets = _evidence_snippets(category_f)
                if snippets:
                    prov["evidence_snippets"] = snippets
                provenance["category"] = prov

    hotel_f = _field("hotel_nights")
    hotel_v = hotel_f.get("value") if hotel_f else obj.get("hotel_nights")
    if isinstance(hotel_v, (int, float, str)):
        try:
            nights = int(str(hotel_v).strip())
            if 1 <= nights <= 60:
                out["hotel_nights"] = nights
                if hotel_f:
                    prov = {
                        "confidence": _confidence(hotel_f),
                        "evidence_lines": _evidence_lines(hotel_f),
                    }
                    snippets = _evidence_snippets(hotel_f)
                    if snippets:
                        prov["evidence_snippets"] = snippets
                    provenance["hotel_nights"] = prov
        except Exception:
            pass

    duration_f = _field("flight_duration_hours")
    duration_v = duration_f.get("value") if duration_f else obj.get("flight_duration_hours")
    if isinstance(duration_v, (int, float, str)):
        try:
            hours = float(str(duration_v).strip())
            if 0.1 <= hours <= 30:
                out["flight_duration_hours"] = round(hours, 2)
                if duration_f:
                    prov = {
                        "confidence": _confidence(duration_f),
                        "evidence_lines": _evidence_lines(duration_f),
                    }
                    snippets = _evidence_snippets(duration_f)
                    if snippets:
                        prov["evidence_snippets"] = snippets
                    provenance["flight_duration_hours"] = prov
        except Exception:
            pass

    cabin_f = _field("flight_cabin_class")
    cabin_v = cabin_f.get("value") if cabin_f else obj.get("flight_cabin_class")
    if isinstance(cabin_v, str):
        cabin_norm = cabin_v.strip().lower()
        if cabin_norm in _ALLOWED_CABIN_CLASSES:
            out["flight_cabin_class"] = cabin_norm
            if cabin_f:
                prov = {
                    "confidence": _confidence(cabin_f),
                    "evidence_lines": _evidence_lines(cabin_f),
                }
                snippets = _evidence_snippets(cabin_f)
                if snippets:
                    prov["evidence_snippets"] = snippets
                provenance["flight_cabin_class"] = prov

    attendees_f = _field("attendees")
    attendees_v = attendees_f.get("value") if attendees_f else obj.get("attendees")
    if isinstance(attendees_v, int):
        if 1 <= attendees_v <= 50:
            out["attendees"] = attendees_v
            if attendees_f:
                prov = {
                    "confidence": _confidence(attendees_f),
                    "evidence_lines": _evidence_lines(attendees_f),
                }
                snippets = _evidence_snippets(attendees_f)
                if snippets:
                    prov["evidence_snippets"] = snippets
                provenance["attendees"] = prov
    elif isinstance(attendees_v, str):
        att = attendees_v.strip()
        if att:
            out["attendees"] = att[:200]
            if attendees_f:
                prov = {
                    "confidence": _confidence(attendees_f),
                    "evidence_lines": _evidence_lines(attendees_f),
                }
                snippets = _evidence_snippets(attendees_f)
                if snippets:
                    prov["evidence_snippets"] = snippets
                provenance["attendees"] = prov

    confidence = obj.get("confidence")
    if isinstance(confidence, (int, float, str)):
        try:
            conf = float(str(confidence).strip())
            if 0.0 <= conf <= 1.0:
                out["confidence"] = conf
        except Exception:
            pass

    if provenance:
        out["_provenance"] = provenance

    return out or None
