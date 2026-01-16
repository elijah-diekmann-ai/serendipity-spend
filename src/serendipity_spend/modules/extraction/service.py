from __future__ import annotations

import hashlib
import os
import re
import uuid
from dataclasses import dataclass
from datetime import UTC, date, datetime
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
from serendipity_spend.modules.workflow.models import Task, TaskStatus


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
            elif _is_supported_image(source.filename, source.content_type):
                _process_image(session=session, claim=claim, source=source, body=body)
            else:
                raise ValueError("Unsupported file type (v1 supports PDF and image receipts)")

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
    if not pages:
        _sync_extraction_task(
            session=session,
            claim=claim,
            source=source,
            status=TaskStatus.OPEN,
            title=f"Manual review needed: {source.filename}",
            description=(
                "No text could be extracted from this PDF (it may be a scanned image or photo). "
                "Try uploading a clearer PDF or image."
            ),
        )
        session.commit()
        return

    segments = _segment_pdf_pages(pages)
    if not segments and pages:
        _process_unknown_pdf(session=session, claim=claim, source=source, pages=pages)
        return

    parsed_count = 0
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
        parsed_count += 1

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

    uncovered = _uncovered_page_idxs(page_count=len(pages), segments=segments)
    if uncovered:
        for idx in uncovered:
            page_text = pages[idx]
            page_text_hash = hashlib.sha256(page_text.encode("utf-8", errors="ignore")).hexdigest()
            session.add(
                EvidenceDocument(
                    source_file_id=source.id,
                    page_start=idx + 1,
                    page_end=idx + 1,
                    vendor="Unknown",
                    receipt_type="unknown",
                    extracted_text=page_text,
                    text_hash=page_text_hash,
                    classification_confidence=0.0,
                )
            )
        _sync_extraction_task(
            session=session,
            claim=claim,
            source=source,
            status=TaskStatus.OPEN,
            title=f"Manual review needed: {source.filename}",
            description=(
                f"{len(uncovered)} page(s) in this PDF were not recognized. "
                "Add missing line items manually or upload clearer documents."
            ),
        )
    elif parsed_count > 0:
        _sync_extraction_task(
            session=session,
            claim=claim,
            source=source,
            status=TaskStatus.RESOLVED,
            title=f"Manual review needed: {source.filename}",
            description=None,
        )
    elif parsed_count == 0:
        _sync_extraction_task(
            session=session,
            claim=claim,
            source=source,
            status=TaskStatus.OPEN,
            title=f"Manual review needed: {source.filename}",
            description=(
                "Receipts were detected but no expense items could be extracted. "
                "Add items manually or upload clearer documents."
            ),
        )

    session.commit()


def _process_image(*, session, claim: Claim, source: SourceFile, body: bytes) -> None:
    text = _ocr_image_bytes(body)
    vendor, receipt_type, confidence = _classify_text(text)
    text_hash = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()

    evidence = EvidenceDocument(
        source_file_id=source.id,
        page_start=None,
        page_end=None,
        vendor=vendor,
        receipt_type=receipt_type,
        extracted_text=text,
        text_hash=text_hash,
        classification_confidence=confidence,
    )
    session.add(evidence)
    session.flush()

    parsed = _parse_single_text(vendor=vendor, receipt_type=receipt_type, text=text)
    if not parsed:
        parsed = _parse_generic_receipt(text)
    if not parsed:
        _sync_extraction_task(
            session=session,
            claim=claim,
            source=source,
            status=TaskStatus.OPEN,
            title=f"Manual review needed: {source.filename}",
            description=(
                "No expense item could be extracted from this image. "
                "Add a line item manually or upload a clearer image/PDF."
            ),
        )
        session.commit()
        return

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
            ExpenseItem.claim_id == claim.id,
            ExpenseItem.dedupe_key == dedupe_key,
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

    existing_link = session.scalar(
        select(ExpenseItemEvidence).where(
            ExpenseItemEvidence.expense_item_id == item.id,
            ExpenseItemEvidence.evidence_document_id == evidence.id,
        )
    )
    if not existing_link:
        session.add(ExpenseItemEvidence(expense_item_id=item.id, evidence_document_id=evidence.id))

    _sync_extraction_task(
        session=session,
        claim=claim,
        source=source,
        status=TaskStatus.RESOLVED,
        title=f"Manual review needed: {source.filename}",
        description=None,
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


def _ocr_image_bytes(body: bytes) -> str:
    try:
        import pytesseract
    except Exception:
        return ""

    try:
        from PIL import Image
    except Exception:
        return ""

    try:
        image = Image.open(BytesIO(body))
    except Exception:
        return ""

    tesseract_lang = os.getenv("TESSERACT_LANG", "eng")
    try:
        if image.mode not in {"RGB", "L"}:
            image = image.convert("RGB")
        return pytesseract.image_to_string(image, lang=tesseract_lang) or ""
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


def _classify_text(text: str) -> tuple[str, str, float]:
    if _is_baggage_fee(text):
        return "Airline", "payment_receipt", 0.9
    if _is_united_start(text):
        return "United Airlines", "email_receipt", 0.9
    if _is_grab_start(text):
        return "Grab", "ride_receipt", 0.6
    if _is_uber_start(text):
        return "Uber", "trip_summary", 0.6
    return "Unknown", "unknown", 0.1


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


def _parse_single_text(*, vendor: str, receipt_type: str, text: str):
    if vendor == "United Airlines":
        return parse_united_wifi_receipt(text)
    if vendor == "Airline" and receipt_type == "payment_receipt":
        return parse_baggage_fee_payment_receipt(text)
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


def _process_unknown_pdf(*, session, claim: Claim, source: SourceFile, pages: list[str]) -> None:
    seg_text = "\n\n".join(pages)
    text_hash = hashlib.sha256(seg_text.encode("utf-8", errors="ignore")).hexdigest()
    evidence = EvidenceDocument(
        source_file_id=source.id,
        page_start=1 if pages else None,
        page_end=len(pages) if pages else None,
        vendor="Unknown",
        receipt_type="unknown",
        extracted_text=seg_text,
        text_hash=text_hash,
        classification_confidence=0.0,
    )
    session.add(evidence)
    session.flush()

    parsed = _parse_generic_receipt(seg_text)
    if not parsed:
        _sync_extraction_task(
            session=session,
            claim=claim,
            source=source,
            status=TaskStatus.OPEN,
            title=f"Manual review needed: {source.filename}",
            description=(
                "This PDF format was not recognized. "
                "Add a line item manually or upload a more standard receipt/invoice."
            ),
        )
        session.commit()
        return

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
            ExpenseItem.claim_id == claim.id,
            ExpenseItem.dedupe_key == dedupe_key,
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

    _sync_extraction_task(
        session=session,
        claim=claim,
        source=source,
        status=TaskStatus.RESOLVED,
        title=f"Manual review needed: {source.filename}",
        description=None,
    )
    session.commit()


def _uncovered_page_idxs(*, page_count: int, segments: list[Segment]) -> list[int]:
    covered: set[int] = set()
    for seg in segments:
        covered.update(range(seg.start_page_idx, seg.end_page_idx + 1))
    return [i for i in range(page_count) if i not in covered]


def _parse_generic_receipt(text: str):
    total = _extract_total_amount(text)
    if not total:
        return None
    currency, amount = total
    tx_date = _extract_any_date(text)
    vendor = _extract_vendor_name(text) or "Unknown"
    return _GenericParsedExpense(
        vendor=vendor,
        vendor_reference=None,
        receipt_type="generic_receipt",
        category=None,
        description=f"Receipt: {vendor}" if vendor else "Receipt",
        transaction_date=tx_date,
        amount=amount,
        currency=currency,
        metadata={
            "extraction_method": "generic",
            "extraction_confidence": 0.3,
            "employee_reviewed": False,
        },
    )


@dataclass(frozen=True)
class _GenericParsedExpense:
    vendor: str
    vendor_reference: str | None
    receipt_type: str
    category: str | None
    description: str | None
    transaction_date: date | None
    amount: Decimal
    currency: str
    metadata: dict


def _extract_total_amount(text: str) -> tuple[str, Decimal] | None:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    keyword_re = re.compile(r"\b(total|total paid|grand total|amount due|balance due)\b", re.I)
    candidates: list[tuple[str, Decimal]] = []

    for ln in lines:
        if not keyword_re.search(ln):
            continue

        # Prefer explicit currency codes (optionally with a currency symbol).
        for m in re.finditer(
            r"\b([A-Z]{3})\s*(?:CA\$|US\$|\$|£|€)?\s*([0-9][0-9,]*\.[0-9]{2})\b",
            ln,
        ):
            cur, amt = m.groups()
            candidates.append((cur.upper(), Decimal(amt.replace(",", ""))))

        # Symbol-prefixed amounts.
        for m in re.finditer(r"(CA\$|US\$|\$|£|€)\s*([0-9][0-9,]*\.[0-9]{2})\b", ln):
            sym, amt = m.groups()
            cur = {"$": "USD", "US$": "USD", "CA$": "CAD", "£": "GBP", "€": "EUR"}.get(sym, "USD")
            candidates.append((cur, Decimal(amt.replace(",", ""))))

        # Amount followed by currency code.
        for m in re.finditer(r"\b([0-9][0-9,]*\.[0-9]{2})\s*([A-Z]{3})\b", ln):
            amt, cur = m.groups()
            candidates.append((cur.upper(), Decimal(amt.replace(",", ""))))

    if not candidates:
        return None
    # Use the largest amount found on "total" lines.
    return max(candidates, key=lambda x: x[1])


def _extract_any_date(text: str):
    # ISO date: 2025-09-05
    m = re.search(r"\b([0-9]{4}-[0-9]{2}-[0-9]{2})\b", text)
    if m:
        try:
            return datetime.strptime(m.group(1), "%Y-%m-%d").date()
        except ValueError:
            pass

    # 05 Sep 2025 / 05 September 2025
    m = re.search(r"\b([0-9]{1,2}\s+[A-Za-z]{3,9}\s+[0-9]{4})\b", text)
    if m:
        s = m.group(1)
        for fmt in ("%d %b %Y", "%d %B %Y"):
            try:
                return datetime.strptime(s, fmt).date()
            except ValueError:
                continue

    # Sep 05, 2025 / September 5, 2025
    m = re.search(r"\b([A-Za-z]{3,9}\s+[0-9]{1,2},\s+[0-9]{4})\b", text)
    if m:
        s = m.group(1)
        for fmt in ("%b %d, %Y", "%B %d, %Y"):
            try:
                return datetime.strptime(s, fmt).date()
            except ValueError:
                continue

    return None


def _extract_vendor_name(text: str) -> str | None:
    skip_prefixes = (
        "from:",
        "to:",
        "subject:",
        "date:",
        "begin forwarded message",
    )
    for ln in (ln.strip() for ln in text.splitlines()):
        if not ln:
            continue
        lnl = ln.lower()
        if any(lnl.startswith(p) for p in skip_prefixes):
            continue
        if "@" in ln or "http" in lnl:
            continue
        if len(ln) < 2 or len(ln) > 80:
            continue
        return ln[:100]
    return None


def _sync_extraction_task(
    *,
    session,
    claim: Claim,
    source: SourceFile,
    status: TaskStatus,
    title: str,
    description: str | None,
) -> None:
    task_type = f"EXTRACT_{source.id.hex[:12]}"
    task = session.scalar(
        select(Task)
        .where(Task.claim_id == claim.id, Task.expense_item_id.is_(None), Task.type == task_type)
        .order_by(Task.created_at.desc())
    )
    if not task and status == TaskStatus.RESOLVED:
        return
    if not task:
        task = Task(
            claim_id=claim.id,
            expense_item_id=None,
            created_by_user_id=None,
            assigned_to_user_id=claim.employee_id,
            type=task_type,
            title=title,
            description=description,
            status=status,
            resolved_at=None,
        )
        session.add(task)
        return

    task.title = title
    task.description = description
    if status == TaskStatus.RESOLVED and task.status != TaskStatus.RESOLVED:
        task.status = TaskStatus.RESOLVED
        task.resolved_at = datetime.now(UTC)
    if status == TaskStatus.OPEN and task.status != TaskStatus.OPEN:
        task.status = TaskStatus.OPEN
        task.resolved_at = None
    session.add(task)


def _is_supported_image(filename: str, content_type: str | None) -> bool:
    if (content_type or "").lower().startswith("image/"):
        return True
    return filename.lower().endswith((".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp"))
