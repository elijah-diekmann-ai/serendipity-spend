from __future__ import annotations

import hashlib
import os
import uuid
from dataclasses import dataclass
from decimal import Decimal
from io import BytesIO

from pypdf import PdfReader
from sqlalchemy import select

from serendipity_spend.core.db import SessionLocal
from serendipity_spend.core.storage import get_storage
from serendipity_spend.modules.claims.models import Claim, ClaimStatus
from serendipity_spend.modules.documents.models import (
    EvidenceDocument,
    SourceFile,
    SourceFileStatus,
)
from serendipity_spend.modules.expenses.models import ExpenseItem, ExpenseItemEvidence
from serendipity_spend.modules.extraction.parsers.baggage_fee import (
    parse_baggage_fee_payment_receipt,
)
from serendipity_spend.modules.extraction.parsers.grab import parse_grab_ride_receipt
from serendipity_spend.modules.extraction.parsers.uber import parse_uber_trip_summary
from serendipity_spend.modules.extraction.parsers.united_wifi import parse_united_wifi_receipt
from serendipity_spend.modules.fx.models import FxRate


@dataclass(frozen=True)
class Segment:
    start_page_idx: int
    end_page_idx: int
    vendor: str
    receipt_type: str


def extract_source_file(*, source_file_id: str) -> None:
    with SessionLocal() as session:
        source = session.scalar(
            select(SourceFile).where(SourceFile.id == uuid.UUID(source_file_id))
        )
        if not source:
            return

        claim = session.scalar(select(Claim).where(Claim.id == source.claim_id))
        if not claim:
            return

        source.status = SourceFileStatus.PROCESSING
        source.error_message = None
        session.add(source)
        session.commit()

        try:
            body = get_storage().get(key=source.storage_key)
            if source.filename.lower().endswith(".pdf") or (source.content_type or "").endswith(
                "/pdf"
            ):
                _process_pdf_bundle(session=session, claim=claim, source=source, body=body)
            else:
                raise ValueError("Unsupported file type (v1 supports PDF receipts only)")

            from serendipity_spend.modules.policy.service import evaluate_claim

            evaluate_claim(session, claim_id=claim.id)

            source.status = SourceFileStatus.PROCESSED
            session.add(source)

            if claim.status in {ClaimStatus.DRAFT, ClaimStatus.PROCESSING}:
                claim.status = ClaimStatus.NEEDS_EMPLOYEE_REVIEW
                session.add(claim)

            session.commit()
        except Exception as e:  # noqa: BLE001
            source.status = SourceFileStatus.FAILED
            source.error_message = str(e)
            session.add(source)
            session.commit()


def _process_pdf_bundle(*, session, claim: Claim, source: SourceFile, body: bytes) -> None:
    pages = _extract_pdf_pages(body)
    segments = _segment_pdf_pages(pages)
    for seg in segments:
        seg_text = "\n\n".join(pages[seg.start_page_idx : seg.end_page_idx + 1])
        text_hash = hashlib.sha256(seg_text.encode("utf-8", errors="ignore")).hexdigest()

        evidence = EvidenceDocument(
            source_file_id=source.id,
            page_start=seg.start_page_idx + 1,
            page_end=seg.end_page_idx + 1,
            vendor=seg.vendor,
            receipt_type=seg.receipt_type,
            extracted_text=seg_text,
            text_hash=text_hash,
            classification_confidence=1.0,
        )
        session.add(evidence)
        session.flush()

        parsed = _parse_segment(seg=seg, pages=pages)
        if not parsed:
            continue

        amount_home, fx_rate_to_home = _convert_to_home(
            session=session,
            claim_id=claim.id,
            from_currency=parsed.currency,
            to_currency=claim.home_currency,
            amount=parsed.amount,
        )

        dedupe_key = _dedupe_key(parsed.vendor, parsed.vendor_reference, text_hash)

        item = session.scalar(
            select(ExpenseItem).where(
                ExpenseItem.claim_id == claim.id, ExpenseItem.dedupe_key == dedupe_key
            )
        )
        if not item:
            item = ExpenseItem(
                claim_id=claim.id,
                vendor=parsed.vendor,
                vendor_reference=parsed.vendor_reference,
                receipt_type=parsed.receipt_type,
                category=parsed.category,
                description=parsed.description,
                transaction_date=parsed.transaction_date,
                transaction_at=None,
                amount_original_amount=parsed.amount,
                amount_original_currency=parsed.currency,
                amount_home_amount=amount_home,
                amount_home_currency=claim.home_currency,
                fx_rate_to_home=fx_rate_to_home,
                metadata_json=parsed.metadata,
                dedupe_key=dedupe_key,
            )
            session.add(item)
            session.flush()

        # link evidence
        existing_link = session.scalar(
            select(ExpenseItemEvidence).where(
                ExpenseItemEvidence.expense_item_id == item.id,
                ExpenseItemEvidence.evidence_document_id == evidence.id,
            )
        )
        if not existing_link:
            session.add(
                ExpenseItemEvidence(expense_item_id=item.id, evidence_document_id=evidence.id)
            )

    session.commit()


def _extract_pdf_pages(body: bytes) -> list[str]:
    reader = PdfReader(BytesIO(body))
    pages: list[str] = []
    for page in reader.pages:
        text = (page.extract_text() or "").replace("\u202f", " ").replace("\xa0", " ")
        if not text.strip():
            text = _ocr_pdf_page(page).replace("\u202f", " ").replace("\xa0", " ") or text
        pages.append(text)
    return pages


def _ocr_pdf_page(page) -> str:
    try:
        import pytesseract
    except Exception:
        return ""

    try:
        page_images = list(page.images)
    except Exception:
        return ""

    best_image = None
    best_area = 0
    for image_file in page_images:
        try:
            image = image_file.image
            width = image.width
            height = image.height
        except Exception:
            continue
        area = width * height
        if area > best_area:
            best_area = area
            best_image = image

    if best_image is None:
        return ""

    tesseract_lang = os.getenv("TESSERACT_LANG", "eng")
    try:
        if best_image.mode not in {"RGB", "L"}:
            best_image = best_image.convert("RGB")
        return pytesseract.image_to_string(best_image, lang=tesseract_lang) or ""
    except Exception:
        return ""


def _segment_pdf_pages(pages: list[str]) -> list[Segment]:
    segments: list[Segment] = []
    i = 0
    while i < len(pages):
        t = pages[i]
        if _is_grab_start(t) and i + 1 < len(pages):
            segments.append(Segment(i, i + 1, "Grab", "ride_receipt"))
            i += 2
            continue
        if _is_united_start(t) and i + 1 < len(pages):
            segments.append(Segment(i, i + 1, "United Airlines", "email_receipt"))
            i += 2
            continue
        if _is_uber_start(t) and i + 2 < len(pages):
            segments.append(Segment(i, i + 2, "Uber", "trip_summary"))
            i += 3
            continue
        if _is_baggage_fee(t):
            segments.append(Segment(i, i, "Airline", "payment_receipt"))
            i += 1
            continue
        i += 1
    return segments


def _is_grab_start(text: str) -> bool:
    return "Your Grab E-Receipt" in text and "Booking ID:" in text


def _is_united_start(text: str) -> bool:
    return "Thanks for your purchase with United" in text


def _is_uber_start(text: str) -> bool:
    return "trip with Uber" in text and "Total" in text


def _is_baggage_fee(text: str) -> bool:
    return "PAYMENT RECEIPT" in text and "BAG FEE" in text


def _parse_segment(*, seg: Segment, pages: list[str]):
    if seg.vendor == "Grab":
        return parse_grab_ride_receipt(pages[seg.start_page_idx], pages[seg.start_page_idx + 1])
    if seg.vendor == "United Airlines":
        return parse_united_wifi_receipt(
            "\n\n".join(pages[seg.start_page_idx : seg.end_page_idx + 1])
        )
    if seg.vendor == "Uber":
        return parse_uber_trip_summary(pages[seg.start_page_idx], pages[seg.start_page_idx + 1])
    if seg.vendor == "Airline":
        return parse_baggage_fee_payment_receipt(pages[seg.start_page_idx])
    return None


def _dedupe_key(vendor: str, vendor_reference: str | None, text_hash: str) -> str:
    if vendor_reference:
        raw = f"{vendor}:{vendor_reference}"
    else:
        raw = f"{vendor}:text:{text_hash[:32]}"
    return raw[:80]


def _convert_to_home(
    *,
    session,
    claim_id: uuid.UUID,
    from_currency: str,
    to_currency: str,
    amount,
):
    if from_currency.upper() == to_currency.upper():
        return amount, Decimal("1")

    fx = session.scalar(
        select(FxRate).where(
            FxRate.claim_id == claim_id,
            FxRate.from_currency == from_currency.upper(),
            FxRate.to_currency == to_currency.upper(),
        )
    )
    if not fx:
        return None, None
    return (amount * fx.rate).quantize(Decimal("0.01")), fx.rate
