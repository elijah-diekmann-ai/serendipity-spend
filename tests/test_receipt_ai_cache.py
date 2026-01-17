from __future__ import annotations

import hashlib
from decimal import Decimal

from serendipity_spend.core.db import SessionLocal


def test_parse_receipt_with_ai_uses_cache(monkeypatch):
    from serendipity_spend.modules.extraction import service as extraction_service

    monkeypatch.setattr(extraction_service, "receipt_ai_available", lambda: True)

    calls: list[str] = []

    def _stub(_text: str):
        calls.append("call")
        return {
            "vendor": {"value": "Test Hotel", "confidence": 0.9, "evidence_lines": [1]},
            "total": {
                "amount": "10.00",
                "currency": "USD",
                "confidence": 0.9,
                "evidence_lines": [2],
            },
            "transaction_date": {
                "value": "2026-01-05",
                "confidence": 0.9,
                "evidence_lines": [3],
            },
        }

    monkeypatch.setattr(extraction_service, "extract_receipt_fields", _stub)

    text = "Test Hotel\nTotal USD 10.00\nDate: 2026-01-05\n"
    text_hash = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()

    with SessionLocal() as session:
        parsed1 = extraction_service._parse_receipt_with_ai(
            session=session,
            text=text,
            text_hash=text_hash,
            extraction_method="ai_test",
        )
        parsed2 = extraction_service._parse_receipt_with_ai(
            session=session,
            text=text,
            text_hash=text_hash,
            extraction_method="ai_test",
        )

        assert parsed1 is not None
        assert parsed2 is not None
        assert parsed1.currency == "USD"
        assert parsed1.amount == Decimal("10.00")
        assert len(calls) == 1


def test_parse_receipt_with_ai_requires_total_provenance(monkeypatch):
    from serendipity_spend.modules.extraction import service as extraction_service

    monkeypatch.setattr(extraction_service, "receipt_ai_available", lambda: True)
    monkeypatch.setattr(
        extraction_service,
        "extract_receipt_fields",
        lambda _text: {
            "total": {
                "amount": "10.00",
                "currency": "USD",
                "confidence": 0.9,
                "evidence_lines": [],
            }
        },
    )

    text = "Test Hotel\nTotal USD 10.00\n"
    text_hash = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()

    with SessionLocal() as session:
        parsed = extraction_service._parse_receipt_with_ai(
            session=session,
            text=text,
            text_hash=text_hash,
            extraction_method="ai_test",
        )
        assert parsed is None


def test_parse_receipt_with_ai_supports_comma_decimal_totals(monkeypatch):
    from serendipity_spend.modules.extraction import service as extraction_service

    monkeypatch.setattr(extraction_service, "receipt_ai_available", lambda: True)
    monkeypatch.setattr(
        extraction_service,
        "extract_receipt_fields",
        lambda _text: {
            "total": {
                "amount": "10,00",
                "currency": "EUR",
                "confidence": 0.9,
                "evidence_lines": [2],
            }
        },
    )

    text = "Test Hotel\nTotal EUR 10,00\n"
    text_hash = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()

    with SessionLocal() as session:
        parsed = extraction_service._parse_receipt_with_ai(
            session=session,
            text=text,
            text_hash=text_hash,
            extraction_method="ai_test",
        )
        assert parsed is not None
        assert parsed.currency == "EUR"
        assert parsed.amount == Decimal("10.00")
