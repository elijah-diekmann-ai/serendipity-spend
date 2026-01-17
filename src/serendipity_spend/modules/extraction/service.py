from __future__ import annotations

import hashlib
import os
import re
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal
from io import BytesIO

from pypdf import PdfReader
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from serendipity_spend.core.config import settings
from serendipity_spend.core.currencies import normalize_currency
from serendipity_spend.core.db import SessionLocal
from serendipity_spend.core.logging import get_logger, log_event, log_exception, monotonic_ms
from serendipity_spend.core.storage import get_storage
from serendipity_spend.modules.claims.models import Claim, ClaimStatus
from serendipity_spend.modules.documents.models import (
    EvidenceDocument,
    SourceFile,
    SourceFileStatus,
)
from serendipity_spend.modules.expenses.models import ExpenseItem, ExpenseItemEvidence
from serendipity_spend.modules.extraction.ai import (
    extract_policy_fields,
    extract_receipt_fields,
    receipt_ai_available,
)
from serendipity_spend.modules.extraction.models import ExtractionAICache
from serendipity_spend.modules.extraction.parsers.baggage_fee import (
    parse_baggage_fee_payment_receipt,
)
from serendipity_spend.modules.extraction.parsers.grab import parse_grab_ride_receipt
from serendipity_spend.modules.extraction.parsers.uber import parse_uber_trip_summary
from serendipity_spend.modules.extraction.parsers.united_wifi import parse_united_wifi_receipt
from serendipity_spend.modules.fx.models import FxRate
from serendipity_spend.modules.workflow.models import Task, TaskStatus

logger = get_logger(__name__)


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

        start = time.monotonic()
        log_event(
            logger,
            "extraction.start",
            source_file_id=str(source.id),
            claim_id=str(claim.id),
            filename=source.filename,
            content_type=source.content_type,
            byte_size=source.byte_size,
            sha256=source.sha256,
            storage_key=source.storage_key,
            source_status=source.status.value,
        )

        if source.status == SourceFileStatus.PROCESSED:
            return

        if not _try_start_source_processing(session=session, source=source):
            return

        _cleanup_source_file_evidence(session=session, source_id=source.id)

        try:
            body = get_storage().get(key=source.storage_key)
            kind = _detect_file_kind(
                filename=source.filename,
                content_type=source.content_type,
                body=body,
            )
            log_event(
                logger,
                "extraction.file_kind",
                source_file_id=str(source.id),
                claim_id=str(claim.id),
                filename=source.filename,
                content_type=source.content_type,
                kind=kind,
            )
            if kind == "bad_pdf_upload":
                _sync_extraction_task(
                    session=session,
                    claim=claim,
                    source=source,
                    status=TaskStatus.OPEN,
                    title=f"Bad upload: {source.filename}",
                    description=(
                        "This file looks like a PDF but does not start with the %PDF header. "
                        "Re-upload a valid PDF, or upload the original email/HTML/text file "
                        "with the correct extension."
                    ),
                )
                source.status = SourceFileStatus.FAILED
                source.error_message = "Bad upload: expected PDF header (%PDF)"
                session.add(source)
                if claim.status in {ClaimStatus.DRAFT, ClaimStatus.PROCESSING}:
                    prev_status = claim.status
                    claim.status = ClaimStatus.NEEDS_EMPLOYEE_REVIEW
                    session.add(claim)
                    log_event(
                        logger,
                        "claim.status.changed",
                        claim_id=str(claim.id),
                        from_status=prev_status.value,
                        to_status=claim.status.value,
                        reason="extraction_bad_pdf_upload",
                    )
                session.commit()
                log_event(
                    logger,
                    "extraction.finish",
                    source_file_id=str(source.id),
                    claim_id=str(claim.id),
                    status="failed",
                    reason="bad_pdf_upload",
                    duration_ms=monotonic_ms(start),
                )
                return

            if kind == "pdf":
                _process_pdf_bundle(session=session, claim=claim, source=source, body=body)
            elif kind == "image":
                _process_image(session=session, claim=claim, source=source, body=body)
            elif kind == "text":
                _process_text(session=session, claim=claim, source=source, body=body)
            else:
                _sync_extraction_task(
                    session=session,
                    claim=claim,
                    source=source,
                    status=TaskStatus.OPEN,
                    title=f"Unsupported upload: {source.filename}",
                    description=(
                        "This file type isn't supported yet. Upload PDF, images, or text files, "
                        "or upload emails as .eml/.msg (or bundle multiple files in a .zip)."
                    ),
                )
                source.status = SourceFileStatus.FAILED
                source.error_message = "Unsupported file type"
                session.add(source)
                if claim.status in {ClaimStatus.DRAFT, ClaimStatus.PROCESSING}:
                    prev_status = claim.status
                    claim.status = ClaimStatus.NEEDS_EMPLOYEE_REVIEW
                    session.add(claim)
                    log_event(
                        logger,
                        "claim.status.changed",
                        claim_id=str(claim.id),
                        from_status=prev_status.value,
                        to_status=claim.status.value,
                        reason="extraction_unsupported_upload",
                    )
                session.commit()
                log_event(
                    logger,
                    "extraction.finish",
                    source_file_id=str(source.id),
                    claim_id=str(claim.id),
                    status="failed",
                    reason="unsupported_upload",
                    duration_ms=monotonic_ms(start),
                )
                return

            from serendipity_spend.modules.policy.service import evaluate_claim

            evaluate_claim(session, claim_id=claim.id)

            source.status = SourceFileStatus.PROCESSED
            session.add(source)

            if claim.status in {ClaimStatus.DRAFT, ClaimStatus.PROCESSING}:
                prev_status = claim.status
                claim.status = ClaimStatus.NEEDS_EMPLOYEE_REVIEW
                session.add(claim)
                log_event(
                    logger,
                    "claim.status.changed",
                    claim_id=str(claim.id),
                    from_status=prev_status.value,
                    to_status=claim.status.value,
                    reason="extraction_complete",
                )

            session.commit()
            log_event(
                logger,
                "extraction.finish",
                source_file_id=str(source.id),
                claim_id=str(claim.id),
                status="success",
                duration_ms=monotonic_ms(start),
            )
        except Exception as e:  # noqa: BLE001
            _sync_extraction_task(
                session=session,
                claim=claim,
                source=source,
                status=TaskStatus.OPEN,
                title=f"Extraction failed: {source.filename}",
                description=(
                    "We couldn't process this file. Try re-uploading it as a PDF/image/text file "
                    "(or upload the original email as .eml/.msg). Error: " + str(e)
                ),
            )
            source.status = SourceFileStatus.FAILED
            source.error_message = str(e)
            session.add(source)
            if claim.status in {ClaimStatus.DRAFT, ClaimStatus.PROCESSING}:
                prev_status = claim.status
                claim.status = ClaimStatus.NEEDS_EMPLOYEE_REVIEW
                session.add(claim)
                log_event(
                    logger,
                    "claim.status.changed",
                    claim_id=str(claim.id),
                    from_status=prev_status.value,
                    to_status=claim.status.value,
                    reason="extraction_error",
                )
            session.commit()
            log_exception(
                logger,
                "extraction.error",
                source_file_id=str(source.id),
                claim_id=str(claim.id),
                duration_ms=monotonic_ms(start),
            )


def _try_start_source_processing(*, session, source: SourceFile) -> bool:
    stale_before = datetime.now(UTC) - timedelta(minutes=30)
    result = session.execute(
        update(SourceFile)
        .where(
            SourceFile.id == source.id,
            (
                SourceFile.status.in_((SourceFileStatus.UPLOADED, SourceFileStatus.FAILED))
                | (
                    (SourceFile.status == SourceFileStatus.PROCESSING)
                    & (SourceFile.updated_at < stale_before)
                )
            ),
        )
        .values(status=SourceFileStatus.PROCESSING, error_message=None)
    )
    if not result.rowcount:
        return False
    session.commit()
    session.refresh(source)
    return True


def _cleanup_source_file_evidence(*, session, source_id: uuid.UUID) -> None:
    evidence_ids = select(EvidenceDocument.id).where(EvidenceDocument.source_file_id == source_id)
    session.execute(
        ExpenseItemEvidence.__table__.delete().where(
            ExpenseItemEvidence.evidence_document_id.in_(evidence_ids)
        )
    )
    session.execute(
        EvidenceDocument.__table__.delete().where(EvidenceDocument.source_file_id == source_id)
    )
    session.commit()


def _process_pdf_bundle(*, session, claim: Claim, source: SourceFile, body: bytes) -> None:
    pages, ocr_pages = _extract_pdf_pages(body)
    log_event(
        logger,
        "extraction.pdf.pages",
        source_file_id=str(source.id),
        claim_id=str(claim.id),
        page_count=len(pages),
        ocr_pages=ocr_pages,
    )
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
    segments_by_type: dict[str, int] = {}
    for seg in segments:
        key = f"{seg.vendor}:{seg.receipt_type}"
        segments_by_type[key] = segments_by_type.get(key, 0) + 1
    log_event(
        logger,
        "extraction.pdf.segments",
        source_file_id=str(source.id),
        claim_id=str(claim.id),
        segments_total=len(segments),
        segments_by_type=segments_by_type,
    )
    if not segments and pages:
        _process_unknown_pdf(session=session, claim=claim, source=source, pages=pages)
        return

    parsed_count = 0
    failed_segments: list[Segment] = []
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

        parser_used = None
        parse_failures: list[str] = []
        parsed, reason = _parse_segment(seg=seg, pages=pages)
        if parsed:
            parser_used = f"vendor:{seg.vendor}"
        else:
            _append_parse_failure(parse_failures, f"vendor:{seg.vendor}", reason)
            parsed, reason = _parse_receipt_with_ai(
                session=session,
                text=seg_text,
                text_hash=text_hash,
                extraction_method="ai_fallback",
            )
            if parsed:
                parser_used = "ai_fallback"
            else:
                _append_parse_failure(parse_failures, "ai_fallback", reason)
        if not parsed:
            parsed, reason = _parse_generic_receipt(seg_text, extraction_method="generic_fallback")
            if parsed:
                parser_used = "generic_fallback"
            else:
                _append_parse_failure(parse_failures, "generic_fallback", reason)
        if not parsed:
            failed_segments.append(seg)
            log_event(
                logger,
                "extraction.segment.unparsed",
                source_file_id=str(source.id),
                claim_id=str(claim.id),
                evidence_document_id=str(evidence.id),
                vendor=seg.vendor,
                receipt_type=seg.receipt_type,
                page_start=seg.start_page_idx + 1,
                page_end=seg.end_page_idx + 1,
                text_hash=text_hash,
                evidence_snippet=_evidence_snippet(seg_text),
                parse_failures=parse_failures,
            )
            continue

        log_event(
            logger,
            "extraction.segment.parsed",
            source_file_id=str(source.id),
            claim_id=str(claim.id),
            evidence_document_id=str(evidence.id),
            vendor=parsed.vendor,
            receipt_type=parsed.receipt_type,
            parser_used=parser_used,
            page_start=seg.start_page_idx + 1,
            page_end=seg.end_page_idx + 1,
            text_hash=text_hash,
            evidence_snippet=_evidence_snippet(seg_text),
            parse_failures=parse_failures,
        )

        _upsert_item_and_link_evidence(
            session=session,
            claim=claim,
            evidence=evidence,
            parsed=parsed,
            text_hash=text_hash,
        )
        parsed_count += 1

    uncovered = _uncovered_page_idxs(page_count=len(pages), segments=segments)
    parsed_uncovered = 0
    unhandled_uncovered: list[int] = []
    if uncovered:
        parsed_uncovered, unhandled_uncovered = _process_page_ranges(
            session=session,
            claim=claim,
            source=source,
            pages=pages,
            page_idxs=uncovered,
        )

    total_parsed = parsed_count + parsed_uncovered
    if unhandled_uncovered or failed_segments:
        parts: list[str] = []
        if unhandled_uncovered:
            parts.append(f"{len(unhandled_uncovered)} page(s) could not be parsed")
        if failed_segments:
            parts.append(f"{len(failed_segments)} recognized segment(s) could not be parsed")
        _sync_extraction_task(
            session=session,
            claim=claim,
            source=source,
            status=TaskStatus.OPEN,
            title=f"Manual review needed: {source.filename}",
            description="; ".join(parts)
            + ". Add missing line items manually or upload clearer documents.",
        )
    elif total_parsed > 0:
        _sync_extraction_task(
            session=session,
            claim=claim,
            source=source,
            status=TaskStatus.RESOLVED,
            title=f"Manual review needed: {source.filename}",
            description=None,
        )
    else:
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

    log_event(
        logger,
        "extraction.pdf.summary",
        source_file_id=str(source.id),
        claim_id=str(claim.id),
        parsed_segments=parsed_count,
        parsed_uncovered=parsed_uncovered,
        failed_segments=len(failed_segments),
        unhandled_pages=len(unhandled_uncovered),
        total_parsed=total_parsed,
    )
    session.commit()


def _process_image(*, session, claim: Claim, source: SourceFile, body: bytes) -> None:
    text = _ocr_image_bytes(body)
    vendor, receipt_type, confidence = _classify_text(text)
    text_hash = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()
    log_event(
        logger,
        "extraction.image.classified",
        source_file_id=str(source.id),
        claim_id=str(claim.id),
        vendor=vendor,
        receipt_type=receipt_type,
        confidence=confidence,
        text_length=len(text),
        text_hash=text_hash,
    )

    parser_used = None
    parse_failures: list[str] = []
    parsed, reason = _parse_single_text(vendor=vendor, receipt_type=receipt_type, text=text)
    if not parsed and _should_try_receipt_ai(vendor=vendor, confidence=confidence):
        _append_parse_failure(parse_failures, "vendor", reason)
        parsed, reason = _parse_receipt_with_ai(
            session=session,
            text=text,
            text_hash=text_hash,
            extraction_method="ai_image",
        )
        if parsed:
            parser_used = "ai_image"
        else:
            _append_parse_failure(parse_failures, "ai_image", reason)
    if not parsed:
        parsed, reason = _parse_generic_receipt(text)
        if parsed:
            parser_used = "generic"
        else:
            _append_parse_failure(parse_failures, "generic", reason)
    if parsed:
        if not parser_used:
            parser_used = "vendor"
        if vendor == "Unknown":
            vendor = parsed.vendor
        if receipt_type == "unknown":
            receipt_type = parsed.receipt_type
        confidence = max(confidence, float(parsed.metadata.get("extraction_confidence") or 0.0))

    evidence = EvidenceDocument(
        source_file_id=source.id,
        page_start=None,
        page_end=None,
        vendor=vendor if parsed else "Unknown",
        receipt_type=receipt_type if parsed else "unknown",
        extracted_text=text,
        text_hash=text_hash,
        classification_confidence=confidence if parsed else 0.0,
    )
    session.add(evidence)
    session.flush()
    if not parsed:
        log_event(
            logger,
            "extraction.image.unparsed",
            source_file_id=str(source.id),
            claim_id=str(claim.id),
            evidence_document_id=str(evidence.id),
            vendor=vendor,
            receipt_type=receipt_type,
            text_hash=text_hash,
            evidence_snippet=_evidence_snippet(text),
            parse_failures=parse_failures,
        )
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

    log_event(
        logger,
        "extraction.image.parsed",
        source_file_id=str(source.id),
        claim_id=str(claim.id),
        evidence_document_id=str(evidence.id),
        vendor=parsed.vendor,
        receipt_type=parsed.receipt_type,
        parser_used=parser_used,
        text_hash=text_hash,
        evidence_snippet=_evidence_snippet(text),
        parse_failures=parse_failures,
    )
    _upsert_item_and_link_evidence(
        session=session,
        claim=claim,
        evidence=evidence,
        parsed=parsed,
        text_hash=text_hash,
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


def _process_text(*, session, claim: Claim, source: SourceFile, body: bytes) -> None:
    text = _decode_text_bytes(body=body, filename=source.filename, content_type=source.content_type)
    if not text.strip():
        _sync_extraction_task(
            session=session,
            claim=claim,
            source=source,
            status=TaskStatus.OPEN,
            title=f"Manual review needed: {source.filename}",
            description="No text could be extracted from this file.",
        )
        session.commit()
        return

    vendor, receipt_type, confidence = _classify_text(text)
    text_hash = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()
    log_event(
        logger,
        "extraction.text.classified",
        source_file_id=str(source.id),
        claim_id=str(claim.id),
        vendor=vendor,
        receipt_type=receipt_type,
        confidence=confidence,
        text_length=len(text),
        text_hash=text_hash,
    )

    parser_used = None
    parse_failures: list[str] = []
    parsed, reason = _parse_single_text(vendor=vendor, receipt_type=receipt_type, text=text)
    if not parsed and _should_try_receipt_ai(vendor=vendor, confidence=confidence):
        _append_parse_failure(parse_failures, "vendor", reason)
        parsed, reason = _parse_receipt_with_ai(
            session=session,
            text=text,
            text_hash=text_hash,
            extraction_method="ai_text",
        )
        if parsed:
            parser_used = "ai_text"
        else:
            _append_parse_failure(parse_failures, "ai_text", reason)
    if not parsed:
        parsed, reason = _parse_generic_receipt(text, extraction_method="generic")
        if parsed:
            parser_used = "generic"
        else:
            _append_parse_failure(parse_failures, "generic", reason)

    if parsed and vendor == "Unknown":
        vendor = parsed.vendor
        receipt_type = parsed.receipt_type
        confidence = max(confidence, float(parsed.metadata.get("extraction_confidence") or 0.0))
    if parsed and not parser_used:
        parser_used = "vendor"

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

    if not parsed:
        log_event(
            logger,
            "extraction.text.unparsed",
            source_file_id=str(source.id),
            claim_id=str(claim.id),
            evidence_document_id=str(evidence.id),
            vendor=vendor,
            receipt_type=receipt_type,
            text_hash=text_hash,
            evidence_snippet=_evidence_snippet(text),
            parse_failures=parse_failures,
        )
        _sync_extraction_task(
            session=session,
            claim=claim,
            source=source,
            status=TaskStatus.OPEN,
            title=f"Manual review needed: {source.filename}",
            description="No expense item could be extracted from this text file.",
        )
        session.commit()
        return

    log_event(
        logger,
        "extraction.text.parsed",
        source_file_id=str(source.id),
        claim_id=str(claim.id),
        evidence_document_id=str(evidence.id),
        vendor=parsed.vendor,
        receipt_type=parsed.receipt_type,
        parser_used=parser_used,
        text_hash=text_hash,
        evidence_snippet=_evidence_snippet(text),
        parse_failures=parse_failures,
    )
    _upsert_item_and_link_evidence(
        session=session,
        claim=claim,
        evidence=evidence,
        parsed=parsed,
        text_hash=text_hash,
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


def _decode_text_bytes(*, body: bytes, filename: str, content_type: str | None) -> str:
    ctype = (content_type or "").lower()
    is_html = ctype.startswith("text/html") or filename.lower().endswith((".html", ".htm"))
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        text = body.decode("latin-1", errors="replace")
    if is_html or _looks_like_html(text):
        text = _html_to_text(text)
    return text


def _looks_like_html(text: str) -> bool:
    t = (text or "").lstrip().lower()
    if not t:
        return False
    if t.startswith("<!doctype html") or t.startswith("<html"):
        return True
    head = t[:2000]
    return bool(re.search(r"<(html|body|div|p|br|table|tr|td|span)(\s|>)", head, re.I))


def _detect_file_kind(*, filename: str, content_type: str | None, body: bytes) -> str:
    if _looks_like_pdf_bytes(body):
        return "pdf"
    if _looks_like_image_bytes(body):
        return "image"
    if _looks_like_text_bytes(body):
        return "text"

    # Fallback to filename/content-type hints.
    if _is_supported_image(filename, content_type):
        return "image"
    if _is_supported_text(filename, content_type):
        return "text"

    # Layer 0 PDF guardrail: never attempt PdfReader if bytes are not a PDF.
    if filename.lower().endswith(".pdf") or (content_type or "").lower().endswith("/pdf"):
        return "bad_pdf_upload"

    return "unknown"


def _looks_like_pdf_bytes(body: bytes) -> bool:
    if not body:
        return False
    b = body.lstrip()
    if b.startswith(b"\xef\xbb\xbf"):
        b = b[3:].lstrip()
    return b.startswith(b"%PDF")


def _looks_like_image_bytes(body: bytes) -> bool:
    if not body:
        return False
    b = body.lstrip()
    return (
        b.startswith(b"\x89PNG\r\n\x1a\n")
        or b.startswith(b"\xff\xd8\xff")
        or b.startswith(b"II*\x00")
        or b.startswith(b"MM\x00*")
        or b.startswith(b"BM")
        or b.startswith((b"GIF87a", b"GIF89a"))
        or (len(b) >= 12 and b.startswith(b"RIFF") and b[8:12] == b"WEBP")
    )


def _looks_like_text_bytes(body: bytes) -> bool:
    if not body:
        return False
    sample = body[:4096]
    if b"\x00" in sample:
        return False
    stripped = sample.lstrip()
    if stripped.startswith(b"\xef\xbb\xbf"):
        stripped = stripped[3:]
    lower = stripped.lower()
    if b"<!doctype html" in lower or b"<html" in lower or b"<body" in lower:
        return True
    if b"subject:" in lower and b"from:" in lower:
        return True
    try:
        stripped.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False

    nontext = 0
    for ch in stripped:
        if ch in {9, 10, 13}:
            continue
        if 32 <= ch <= 126:
            continue
        # valid UTF-8 non-ASCII bytes will pass the strict decode above
        if 128 <= ch <= 255:
            continue
        nontext += 1
    return (nontext / max(1, len(stripped))) <= 0.02


def _html_to_text(html: str) -> str:
    from html import unescape

    html = re.sub(r"(?is)<(script|style).*?>.*?</\1>", "", html)
    html = re.sub(r"(?i)<br\s*/?>", "\n", html)
    html = re.sub(r"(?i)</p\s*>", "\n\n", html)
    html = re.sub(r"(?i)</div\s*>", "\n", html)
    html = re.sub(r"(?s)<[^>]+>", "", html)
    html = unescape(html)
    lines = [re.sub(r"\s+", " ", ln).strip() for ln in html.splitlines()]
    return "\n".join([ln for ln in lines if ln])


def _extract_pdf_pages(body: bytes) -> tuple[list[str], int]:
    reader = PdfReader(BytesIO(body))
    pages: list[str] = []
    ocr_pages = 0
    for page in reader.pages:
        text = (page.extract_text() or "").replace("\u202f", " ").replace("\xa0", " ")
        if not text.strip():
            ocr_pages += 1
            text = _ocr_pdf_page(page).replace("\u202f", " ").replace("\xa0", " ") or text
        pages.append(text)
    return pages, ocr_pages


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
    t = text.replace("\u202f", " ").replace("\xa0", " ")
    return bool(
        re.search(r"(?i)\byour\s+grab\s+e\s*[-]?\s*receipt\b", t)
        and re.search(r"(?i)\bbooking\s*id\b", t)
    )


def _is_united_start(text: str) -> bool:
    t = text.replace("\u202f", " ").replace("\xa0", " ")
    return bool(
        re.search(r"(?i)\bthanks\s+for\s+your\s+purchase\b", t)
        and re.search(r"(?i)\bunited\b", t)
    )


def _is_uber_start(text: str) -> bool:
    t = text.replace("\u202f", " ").replace("\xa0", " ")
    return bool(
        re.search(r"(?i)\btrip\s+with\s+u\s*b\s*e\s*r\b", t)
        and re.search(r"(?i)\btota[li]\b", t)
    )


def _is_baggage_fee(text: str) -> bool:
    t = text.replace("\u202f", " ").replace("\xa0", " ")
    return bool(re.search(r"(?i)\bpayment\s+receipt\b", t) and re.search(r"(?i)\bbag\s*fee\b", t))


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


def _append_parse_failure(failures: list[str], parser_name: str, reason: str | None) -> None:
    if reason:
        failures.append(f"{parser_name}:{reason}")
    else:
        failures.append(f"{parser_name}:unknown")


def _evidence_snippet(text: str, max_len: int = 200) -> str | None:
    snippet = re.sub(r"\s+", " ", text).strip()
    if not snippet:
        return None
    if len(snippet) > max_len:
        return snippet[:max_len] + "..."
    return snippet


def _metadata_subset(metadata: dict) -> dict:
    keys = (
        "hotel_nights",
        "flight_duration_hours",
        "flight_cabin_class",
        "attendees",
        "extraction_family",
        "extraction_method",
    )
    return {key: metadata.get(key) for key in keys if key in metadata}


def _parse_grab_with_reason(page_1: str, page_2: str):
    parsed = parse_grab_ride_receipt(page_1, page_2)
    if parsed:
        return parsed, None
    if "Your Grab E-Receipt" not in page_1 or "Booking ID:" not in page_1:
        return None, "missing_header"
    if not re.search(r"Booking ID:\s*([A-Z0-9-]+)", page_1, re.I):
        return None, "missing_booking_id"
    if not re.search(r"Total Paid\s*[A-Z]{3}\s*[0-9]+\.[0-9]{2}", page_1, re.I):
        return None, "missing_total"
    return None, "grab_parse_failed"


def _parse_united_with_reason(text: str):
    parsed = parse_united_wifi_receipt(text)
    if parsed:
        return parsed, None
    if "Thanks for your purchase with United" not in text:
        return None, "missing_header"
    if not re.search(r"Total:\s*([0-9]+\.[0-9]{2})\s*([A-Z]{3})", text, re.I):
        return None, "missing_total"
    return None, "united_parse_failed"


def _parse_uber_with_reason(summary_page: str, detail_page: str):
    parsed = parse_uber_trip_summary(summary_page, detail_page)
    if parsed:
        return parsed, None
    if not re.search(r"(?i)\btrip\s+with\s+u\s*b\s*e\s*r\b", summary_page):
        return None, "missing_trip_header"
    if not re.search(r"(?i)\btota[li]\b", summary_page):
        return None, "missing_total_label"
    m = re.search(
        r"(?i)\btotal\b\s*[:\-]?\s*(CA\$|US\$|\$)\s*([0-9][0-9,.'\u202f\xa0 ]*[0-9])",
        summary_page,
    )
    if not m:
        return None, "missing_total_amount"
    if _parse_decimal_amount(m.group(2)) is None:
        return None, "amount_parse_failed"
    return None, "uber_parse_failed"


def _parse_baggage_fee_with_reason(text: str):
    parsed = parse_baggage_fee_payment_receipt(text)
    if parsed:
        return parsed, None
    if "PAYMENT RECEIPT" not in text or "BAG FEE" not in text:
        return None, "missing_header"
    if not re.search(r"AMEX\s+X+[0-9]{4}.*?CAD\s*\$[0-9]+\.[0-9]{2}", text, re.I):
        return None, "missing_total"
    return None, "baggage_fee_parse_failed"


def _parse_segment(*, seg: Segment, pages: list[str]) -> tuple[object | None, str | None]:
    if seg.vendor == "Grab":
        return _parse_grab_with_reason(
            pages[seg.start_page_idx],
            pages[seg.start_page_idx + 1],
        )
    if seg.vendor == "United Airlines":
        return _parse_united_with_reason(
            "\n\n".join(pages[seg.start_page_idx : seg.end_page_idx + 1])
        )
    if seg.vendor == "Uber":
        return _parse_uber_with_reason(
            pages[seg.start_page_idx],
            pages[seg.start_page_idx + 1],
        )
    if seg.vendor == "Airline":
        return _parse_baggage_fee_with_reason(pages[seg.start_page_idx])
    return None, "unsupported_segment"


def _parse_single_text(*, vendor: str, receipt_type: str, text: str) -> tuple[object | None, str | None]:
    if vendor == "United Airlines":
        return _parse_united_with_reason(text)
    if vendor == "Airline" and receipt_type == "payment_receipt":
        return _parse_baggage_fee_with_reason(text)
    return None, "unsupported_vendor"


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


def _upsert_item_and_link_evidence(
    *,
    session,
    claim: Claim,
    evidence: EvidenceDocument,
    parsed,
    text_hash: str,
) -> ExpenseItem:
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
    action = "existing"
    if not item:
        action = "created"
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
        try:
            with session.begin_nested():
                session.add(item)
                session.flush()
        except IntegrityError:
            action = "dedupe_conflict"
            item = session.scalar(
                select(ExpenseItem).where(
                    ExpenseItem.claim_id == claim.id,
                    ExpenseItem.dedupe_key == dedupe_key,
                )
            )
            if not item:
                raise

    existing_link = session.scalar(
        select(ExpenseItemEvidence).where(
            ExpenseItemEvidence.expense_item_id == item.id,
            ExpenseItemEvidence.evidence_document_id == evidence.id,
        )
    )
    if not existing_link:
        session.add(ExpenseItemEvidence(expense_item_id=item.id, evidence_document_id=evidence.id))

    log_event(
        logger,
        "expense_item.upsert",
        claim_id=str(claim.id),
        expense_item_id=str(item.id),
        evidence_document_id=str(evidence.id),
        source_file_id=str(evidence.source_file_id),
        dedupe_key=dedupe_key,
        vendor=parsed.vendor,
        vendor_reference=parsed.vendor_reference,
        receipt_type=item.receipt_type,
        category=item.category,
        description=item.description,
        transaction_date=item.transaction_date,
        amount_original_amount=item.amount_original_amount,
        amount_original_currency=item.amount_original_currency,
        amount_home_amount=item.amount_home_amount,
        amount_home_currency=item.amount_home_currency,
        fx_rate_to_home=item.fx_rate_to_home,
        metadata_subset=_metadata_subset(item.metadata_json or parsed.metadata or {}),
        action=action,
    )
    return item


def _process_unknown_pdf(*, session, claim: Claim, source: SourceFile, pages: list[str]) -> None:
    parsed_items, unhandled = _process_page_ranges(
        session=session,
        claim=claim,
        source=source,
        pages=pages,
        page_idxs=list(range(len(pages))),
    )

    if unhandled:
        _sync_extraction_task(
            session=session,
            claim=claim,
            source=source,
            status=TaskStatus.OPEN,
            title=f"Manual review needed: {source.filename}",
            description=(
                f"{len(unhandled)} page(s) could not be parsed. "
                "Add missing line items manually or upload clearer documents."
            ),
        )
    elif parsed_items > 0:
        _sync_extraction_task(
            session=session,
            claim=claim,
            source=source,
            status=TaskStatus.RESOLVED,
            title=f"Manual review needed: {source.filename}",
            description=None,
        )
    else:
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
    log_event(
        logger,
        "extraction.pdf.unknown.summary",
        source_file_id=str(source.id),
        claim_id=str(claim.id),
        parsed_items=parsed_items,
        unhandled_pages=len(unhandled),
    )
    session.commit()


def _uncovered_page_idxs(*, page_count: int, segments: list[Segment]) -> list[int]:
    covered: set[int] = set()
    for seg in segments:
        covered.update(range(seg.start_page_idx, seg.end_page_idx + 1))
    return [i for i in range(page_count) if i not in covered]


def _group_consecutive_page_idxs(page_idxs: list[int]) -> list[tuple[int, int]]:
    if not page_idxs:
        return []
    sorted_idxs = sorted(set(page_idxs))
    ranges: list[tuple[int, int]] = []
    start = prev = sorted_idxs[0]
    for idx in sorted_idxs[1:]:
        if idx == prev + 1:
            prev = idx
            continue
        ranges.append((start, prev))
        start = prev = idx
    ranges.append((start, prev))
    return ranges


def _add_evidence_document(
    *,
    session,
    source: SourceFile,
    page_start: int | None,
    page_end: int | None,
    vendor: str,
    receipt_type: str,
    extracted_text: str,
    confidence: float,
) -> tuple[EvidenceDocument, str]:
    text_hash = hashlib.sha256(extracted_text.encode("utf-8", errors="ignore")).hexdigest()
    evidence = EvidenceDocument(
        source_file_id=source.id,
        page_start=page_start,
        page_end=page_end,
        vendor=vendor,
        receipt_type=receipt_type,
        extracted_text=extracted_text,
        text_hash=text_hash,
        classification_confidence=confidence,
    )
    session.add(evidence)
    session.flush()
    return evidence, text_hash


def _process_page_ranges(
    *,
    session,
    claim: Claim,
    source: SourceFile,
    pages: list[str],
    page_idxs: list[int],
) -> tuple[int, list[int]]:
    parsed_items = 0
    unhandled_page_idxs: list[int] = []
    page_attempts: dict[int, dict[str, object]] = {}

    for start, end in _group_consecutive_page_idxs(page_idxs):
        if start == end:
            page_text = pages[start]
            vendor, receipt_type, confidence = _classify_text(page_text)
            page_text_hash = hashlib.sha256(
                page_text.encode("utf-8", errors="ignore")
            ).hexdigest()
            parser_used = None
            parse_failures: list[str] = []
            parsed, reason = _parse_single_text(
                vendor=vendor,
                receipt_type=receipt_type,
                text=page_text,
            )
            if not parsed and _should_try_receipt_ai(vendor=vendor, confidence=confidence):
                _append_parse_failure(parse_failures, "vendor", reason)
                parsed, reason = _parse_receipt_with_ai(
                    session=session,
                    text=page_text,
                    text_hash=page_text_hash,
                    extraction_method="ai_page",
                )
                if parsed:
                    parser_used = "ai_page"
                else:
                    _append_parse_failure(parse_failures, "ai_page", reason)
            if not parsed:
                parsed, reason = _parse_generic_receipt(
                    page_text,
                    extraction_method="generic_page",
                )
                if parsed:
                    parser_used = "generic_page"
                else:
                    _append_parse_failure(parse_failures, "generic_page", reason)

            if parsed:
                if not parser_used:
                    parser_used = "vendor"
                if vendor == "Unknown":
                    vendor = parsed.vendor
                if receipt_type == "unknown":
                    receipt_type = parsed.receipt_type
                confidence = max(
                    confidence, float(parsed.metadata.get("extraction_confidence") or 0.0)
                )

            evidence, text_hash = _add_evidence_document(
                session=session,
                source=source,
                page_start=start + 1,
                page_end=start + 1,
                vendor=vendor if parsed else "Unknown",
                receipt_type=receipt_type if parsed else "unknown",
                extracted_text=page_text,
                confidence=confidence if parsed else 0.0,
            )
            if parsed:
                log_event(
                    logger,
                    "extraction.page.parsed",
                    source_file_id=str(source.id),
                    claim_id=str(claim.id),
                    evidence_document_id=str(evidence.id),
                    page_start=start + 1,
                    page_end=start + 1,
                    vendor=parsed.vendor,
                    receipt_type=parsed.receipt_type,
                    parser_used=parser_used,
                    text_hash=text_hash,
                    evidence_snippet=_evidence_snippet(page_text),
                    parse_failures=parse_failures,
                )
                _upsert_item_and_link_evidence(
                    session=session,
                    claim=claim,
                    evidence=evidence,
                    parsed=parsed,
                    text_hash=text_hash,
                )
                parsed_items += 1
            else:
                log_event(
                    logger,
                    "extraction.page.unparsed",
                    source_file_id=str(source.id),
                    claim_id=str(claim.id),
                    evidence_document_id=str(evidence.id),
                    page_start=start + 1,
                    page_end=start + 1,
                    text_hash=text_hash,
                    evidence_snippet=_evidence_snippet(page_text),
                    parse_failures=parse_failures,
                )
                unhandled_page_idxs.append(start)
            continue

        per_page_parsed: list[
            tuple[int, object, str, str, float, str, list[str], str | None]
        ] = []
        for idx in range(start, end + 1):
            page_text = pages[idx]
            vendor, receipt_type, confidence = _classify_text(page_text)
            page_text_hash = hashlib.sha256(
                page_text.encode("utf-8", errors="ignore")
            ).hexdigest()
            parser_used = None
            parse_failures: list[str] = []
            parsed, reason = _parse_single_text(
                vendor=vendor,
                receipt_type=receipt_type,
                text=page_text,
            )
            if not parsed and _should_try_receipt_ai(vendor=vendor, confidence=confidence):
                _append_parse_failure(parse_failures, "vendor", reason)
                parsed, reason = _parse_receipt_with_ai(
                    session=session,
                    text=page_text,
                    text_hash=page_text_hash,
                    extraction_method="ai_page",
                )
                if parsed:
                    parser_used = "ai_page"
                else:
                    _append_parse_failure(parse_failures, "ai_page", reason)
            if not parsed:
                parsed, reason = _parse_generic_receipt(
                    page_text,
                    extraction_method="generic_page",
                )
                if parsed:
                    parser_used = "generic_page"
                else:
                    _append_parse_failure(parse_failures, "generic_page", reason)
            page_attempts[idx] = {
                "text_hash": page_text_hash,
                "snippet": _evidence_snippet(page_text),
                "parse_failures": parse_failures,
            }
            if not parsed:
                continue
            if vendor == "Unknown":
                vendor = parsed.vendor
            if receipt_type == "unknown":
                receipt_type = parsed.receipt_type
            confidence = max(confidence, float(parsed.metadata.get("extraction_confidence") or 0.0))
            if not parser_used:
                parser_used = "vendor"
            per_page_parsed.append(
                (
                    idx,
                    parsed,
                    vendor,
                    receipt_type,
                    confidence,
                    parser_used,
                    parse_failures,
                    _evidence_snippet(page_text),
                )
            )

        if len(per_page_parsed) >= 2:
            parsed_by_idx = {idx for idx, *_ in per_page_parsed}
            for (
                idx,
                parsed,
                vendor,
                receipt_type,
                confidence,
                parser_used,
                parse_failures,
                page_snippet,
            ) in per_page_parsed:
                page_text = pages[idx]
                evidence, text_hash = _add_evidence_document(
                    session=session,
                    source=source,
                    page_start=idx + 1,
                    page_end=idx + 1,
                    vendor=vendor,
                    receipt_type=receipt_type,
                    extracted_text=page_text,
                    confidence=confidence,
                )
                log_event(
                    logger,
                    "extraction.page.parsed",
                    source_file_id=str(source.id),
                    claim_id=str(claim.id),
                    evidence_document_id=str(evidence.id),
                    page_start=idx + 1,
                    page_end=idx + 1,
                    vendor=parsed.vendor,
                    receipt_type=parsed.receipt_type,
                    parser_used=parser_used,
                    text_hash=text_hash,
                    evidence_snippet=page_snippet,
                    parse_failures=parse_failures,
                )
                _upsert_item_and_link_evidence(
                    session=session,
                    claim=claim,
                    evidence=evidence,
                    parsed=parsed,
                    text_hash=text_hash,
                )
                parsed_items += 1

            for idx in range(start, end + 1):
                if idx in parsed_by_idx:
                    continue
                page_text = pages[idx]
                _add_evidence_document(
                    session=session,
                    source=source,
                    page_start=idx + 1,
                    page_end=idx + 1,
                    vendor="Unknown",
                    receipt_type="unknown",
                    extracted_text=page_text,
                    confidence=0.0,
                )
                attempt = page_attempts.get(idx, {})
                log_event(
                    logger,
                    "extraction.page.unparsed",
                    source_file_id=str(source.id),
                    claim_id=str(claim.id),
                    page_start=idx + 1,
                    page_end=idx + 1,
                    text_hash=attempt.get("text_hash"),
                    evidence_snippet=attempt.get("snippet"),
                    parse_failures=attempt.get("parse_failures"),
                )
                unhandled_page_idxs.append(idx)
            continue

        combined_text = "\n\n".join(pages[start : end + 1])
        vendor, receipt_type, confidence = _classify_text(combined_text)
        combined_text_hash = hashlib.sha256(
            combined_text.encode("utf-8", errors="ignore")
        ).hexdigest()
        parser_used = None
        parse_failures: list[str] = []
        parsed, reason = _parse_single_text(
            vendor=vendor,
            receipt_type=receipt_type,
            text=combined_text,
        )
        if not parsed and _should_try_receipt_ai(vendor=vendor, confidence=confidence):
            _append_parse_failure(parse_failures, "vendor", reason)
            parsed, reason = _parse_receipt_with_ai(
                session=session,
                text=combined_text,
                text_hash=combined_text_hash,
                extraction_method="ai_multi_page",
            )
            if parsed:
                parser_used = "ai_multi_page"
            else:
                _append_parse_failure(parse_failures, "ai_multi_page", reason)
        if not parsed:
            parsed, reason = _parse_generic_receipt(
                combined_text,
                extraction_method="generic_multi_page",
            )
            if parsed:
                parser_used = "generic_multi_page"
            else:
                _append_parse_failure(parse_failures, "generic_multi_page", reason)

        if parsed:
            if not parser_used:
                parser_used = "vendor"
            if vendor == "Unknown":
                vendor = parsed.vendor
            if receipt_type == "unknown":
                receipt_type = parsed.receipt_type
            confidence = max(confidence, float(parsed.metadata.get("extraction_confidence") or 0.0))
            evidence, text_hash = _add_evidence_document(
                session=session,
                source=source,
                page_start=start + 1,
                page_end=end + 1,
                vendor=vendor,
                receipt_type=receipt_type,
                extracted_text=combined_text,
                confidence=confidence,
            )
            log_event(
                logger,
                "extraction.page.parsed",
                source_file_id=str(source.id),
                claim_id=str(claim.id),
                evidence_document_id=str(evidence.id),
                page_start=start + 1,
                page_end=end + 1,
                vendor=parsed.vendor,
                receipt_type=parsed.receipt_type,
                parser_used=parser_used,
                text_hash=text_hash,
                evidence_snippet=_evidence_snippet(combined_text),
                parse_failures=parse_failures,
            )
            _upsert_item_and_link_evidence(
                session=session,
                claim=claim,
                evidence=evidence,
                parsed=parsed,
                text_hash=text_hash,
            )
            parsed_items += 1
            continue

        if per_page_parsed:
            (
                idx,
                parsed,
                vendor,
                receipt_type,
                confidence,
                parser_used,
                parse_failures,
                page_snippet,
            ) = per_page_parsed[0]
            page_text = pages[idx]
            evidence, text_hash = _add_evidence_document(
                session=session,
                source=source,
                page_start=idx + 1,
                page_end=idx + 1,
                vendor=vendor,
                receipt_type=receipt_type,
                extracted_text=page_text,
                confidence=confidence,
            )
            log_event(
                logger,
                "extraction.page.parsed",
                source_file_id=str(source.id),
                claim_id=str(claim.id),
                evidence_document_id=str(evidence.id),
                page_start=idx + 1,
                page_end=idx + 1,
                vendor=parsed.vendor,
                receipt_type=parsed.receipt_type,
                parser_used=parser_used,
                text_hash=text_hash,
                evidence_snippet=page_snippet,
                parse_failures=parse_failures,
            )
            _upsert_item_and_link_evidence(
                session=session,
                claim=claim,
                evidence=evidence,
                parsed=parsed,
                text_hash=text_hash,
            )
            parsed_items += 1
            for other_idx in range(start, end + 1):
                if other_idx == idx:
                    continue
                other_text = pages[other_idx]
                _add_evidence_document(
                    session=session,
                    source=source,
                    page_start=other_idx + 1,
                    page_end=other_idx + 1,
                    vendor="Unknown",
                    receipt_type="unknown",
                    extracted_text=other_text,
                    confidence=0.0,
                )
                attempt = page_attempts.get(other_idx, {})
                log_event(
                    logger,
                    "extraction.page.unparsed",
                    source_file_id=str(source.id),
                    claim_id=str(claim.id),
                    page_start=other_idx + 1,
                    page_end=other_idx + 1,
                    text_hash=attempt.get("text_hash"),
                    evidence_snippet=attempt.get("snippet"),
                    parse_failures=attempt.get("parse_failures"),
                )
                unhandled_page_idxs.append(other_idx)
            continue

        for idx in range(start, end + 1):
            page_text = pages[idx]
            _add_evidence_document(
                session=session,
                source=source,
                page_start=idx + 1,
                page_end=idx + 1,
                vendor="Unknown",
                receipt_type="unknown",
                extracted_text=page_text,
                confidence=0.0,
            )
            attempt = page_attempts.get(idx, {})
            log_event(
                logger,
                "extraction.page.unparsed",
                source_file_id=str(source.id),
                claim_id=str(claim.id),
                page_start=idx + 1,
                page_end=idx + 1,
                text_hash=attempt.get("text_hash"),
                evidence_snippet=attempt.get("snippet"),
                parse_failures=attempt.get("parse_failures"),
            )
            unhandled_page_idxs.append(idx)

    return parsed_items, unhandled_page_idxs


def _should_try_receipt_ai(*, vendor: str, confidence: float) -> bool:
    # Deterministic vendor-specific parsing can fail even when the classifier is confident.
    # When we have no parsed item, AI is a fallback regardless of vendor/confidence.
    return True


def _get_cached_receipt_ai(session, *, text_hash: str) -> dict | None:
    cached = session.scalar(
        select(ExtractionAICache).where(ExtractionAICache.text_hash == text_hash)
    )
    if not cached:
        return None
    if cached.schema_version != 1:
        return None
    if not isinstance(cached.response_json, dict):
        return None
    return cached.response_json


def _upsert_receipt_ai_cache(session, *, text_hash: str, response_json: dict) -> None:
    cached = session.scalar(
        select(ExtractionAICache).where(ExtractionAICache.text_hash == text_hash)
    )
    if not cached:
        candidate = ExtractionAICache(
            text_hash=text_hash,
            provider="openai",
            model=str(settings.openai_model or ""),
            schema_version=1,
            response_json=response_json,
        )
        try:
            with session.begin_nested():
                session.add(candidate)
                session.flush()
            return
        except IntegrityError:
            cached = session.scalar(
                select(ExtractionAICache).where(ExtractionAICache.text_hash == text_hash)
            )
            if not cached:
                return
    cached.provider = "openai"
    cached.model = str(settings.openai_model or "")
    cached.schema_version = 1
    cached.response_json = response_json
    session.add(cached)
    session.flush()


def _parse_receipt_with_ai(
    *,
    session,
    text: str,
    text_hash: str,
    extraction_method: str,
):
    if not receipt_ai_available():
        return None, "ai_unavailable"
    ai = _get_cached_receipt_ai(session, text_hash=text_hash)
    if ai is None:
        ai = extract_receipt_fields(text)
        if ai and isinstance(ai, dict):
            _upsert_receipt_ai_cache(session, text_hash=text_hash, response_json=ai)

    if not ai:
        return None, "ai_no_response"

    total = ai.get("total") if isinstance(ai, dict) else None
    if not isinstance(total, dict):
        return None, "ai_missing_total"

    cur = total.get("currency")
    amt = total.get("amount")
    evidence_lines = total.get("evidence_lines")
    if not isinstance(evidence_lines, list) or not evidence_lines:
        return None, "ai_missing_total_evidence"

    if not isinstance(cur, str) or not isinstance(amt, str):
        return None, "ai_invalid_currency_or_amount"
    cur_norm = normalize_currency(cur)
    if not cur_norm:
        return None, "ai_invalid_currency"
    try:
        amount = _parse_decimal_amount(str(amt))
    except Exception:
        return None, "ai_invalid_amount"
    if amount is None:
        return None, "ai_invalid_amount"

    evidence_snippet = _snippet_from_line_refs(text, evidence_lines=evidence_lines)
    corroborated = _extract_total_amount(evidence_snippet)
    if not corroborated or corroborated[0] != cur_norm or corroborated[1] != amount:
        return None, "ai_total_not_correlated"

    tx_date = None
    tx_date_from_ai = False
    dt = ai.get("transaction_date")
    if isinstance(dt, dict) and isinstance(dt.get("value"), str):
        raw_date = dt["value"]
        try:
            candidate = date.fromisoformat(raw_date)
        except Exception:
            candidate = None
        ev = dt.get("evidence_lines")
        if candidate and isinstance(ev, list) and ev:
            snippet = _snippet_from_line_refs(text, evidence_lines=ev)
            corroborated_date = _extract_any_date(snippet)
            if corroborated_date == candidate:
                tx_date = candidate
                tx_date_from_ai = True

    vendor = None
    vendor_from_ai = False
    v = ai.get("vendor")
    if isinstance(v, dict) and isinstance(v.get("value"), str):
        vv = v["value"].strip()[:100] or None
        ev = v.get("evidence_lines")
        if vv and isinstance(ev, list) and ev:
            snippet = _snippet_from_line_refs(text, evidence_lines=ev)
            if vv.lower() in snippet.lower():
                vendor = vv
                vendor_from_ai = True
    vendor = vendor or _extract_vendor_name(text) or "Unknown"

    category = None
    cat = ai.get("category")
    if isinstance(cat, dict) and isinstance(cat.get("value"), str):
        category = cat["value"].strip().lower() or None
    category = category or _guess_category(text)

    confidence = 0.0
    try:
        confidence = float(total.get("confidence") or 0.0)
    except Exception:
        confidence = 0.0
    confidence = max(0.0, min(1.0, confidence))

    metadata: dict = {
        "extraction_family": "generic",
        "extraction_method": extraction_method,
        "extraction_confidence": max(0.3, confidence),
        "employee_reviewed": False,
        "ai_receipt_fields": ai,
        "ai_receipt_fields_validated": {
            "total": True,
            "vendor": vendor_from_ai,
            "transaction_date": tx_date_from_ai,
        },
    }

    inferred_category, policy_metadata = _infer_policy_fields(text=text, category_hint=category)
    if not category and inferred_category:
        category = inferred_category
    metadata.update(policy_metadata)

    return (
        _GenericParsedExpense(
            vendor=vendor,
            vendor_reference=None,
            receipt_type="generic_receipt",
            category=category,
            description=f"Receipt: {vendor}" if vendor else "Receipt",
            transaction_date=tx_date,
            amount=amount,
            currency=cur_norm,
            metadata=metadata,
        ),
        None,
    )


def _parse_generic_receipt(text: str, *, extraction_method: str = "generic"):
    total = _extract_total_amount(text)
    if not total:
        return None, "generic_missing_total"
    currency, amount = total
    tx_date = _extract_any_date(text)
    vendor = _extract_vendor_name(text) or "Unknown"
    category = _guess_category(text)

    metadata: dict = {
        "extraction_family": "generic",
        "extraction_method": extraction_method,
        "extraction_confidence": 0.3,
        "employee_reviewed": False,
    }

    inferred_category, policy_metadata = _infer_policy_fields(text=text, category_hint=category)
    if not category and inferred_category:
        category = inferred_category
    metadata.update(policy_metadata)

    return (
        _GenericParsedExpense(
            vendor=vendor,
            vendor_reference=None,
            receipt_type="generic_receipt",
            category=category,
            description=f"Receipt: {vendor}" if vendor else "Receipt",
            transaction_date=tx_date,
            amount=amount,
            currency=currency,
            metadata=metadata,
        ),
        None,
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


def _guess_category(text: str) -> str | None:
    t = text.lower()

    lodging_strong = ("check-in", "check in", "check-out", "check out", "folio", "room rate")
    airfare_strong = (
        "boarding pass",
        "e-ticket",
        "eticket",
        "ticket number",
        "pnr",
        "itinerary",
        "flight number",
        "gate",
        "terminal",
        "seat",
    )
    meals_strong = ("gratuity", "tip", "server", "table", "covers", "pax", "guests")

    scores = {"lodging": 0, "airfare": 0, "meals": 0}

    if any(k in t for k in lodging_strong) or "hotel" in t:
        scores["lodging"] += 2
    if any(k in t for k in airfare_strong) or "flight" in t:
        scores["airfare"] += 2
    if any(k in t for k in meals_strong) or any(k in t for k in ("restaurant", "cafe", "bar")):
        scores["meals"] += 2

    # Softer signals
    for k in ("reservation", "stay", "room", "nights"):
        if k in t:
            scores["lodging"] += 1
    for k in ("depart", "departure", "arrive", "arrival", "airline", "fare"):
        if k in t:
            scores["airfare"] += 1
    for k in ("subtotal", "tax", "dine", "dining", "beverage"):
        if k in t:
            scores["meals"] += 1

    best = max(scores, key=scores.get)
    if scores[best] < 2:
        return None

    # Avoid ambiguous ties (e.g., itinerary emails can mention "arrival"/"departure" for hotels).
    top = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    if len(top) >= 2 and top[0][1] == top[1][1]:
        return None
    return best


def _infer_policy_fields(*, text: str, category_hint: str | None) -> tuple[str | None, dict]:
    inferred_category = category_hint
    metadata: dict = {}

    if inferred_category in {None, "lodging"}:
        check_in, check_out = _extract_hotel_stay_dates(text)
        nights = _extract_hotel_nights(text)
        if nights is None and check_in and check_out and check_out > check_in:
            computed = (check_out - check_in).days
            if 1 <= computed <= 60:
                nights = computed
        if nights:
            metadata["hotel_nights"] = nights
            inferred_category = inferred_category or "lodging"
        if check_in:
            metadata["hotel_check_in"] = check_in.isoformat()
        if check_out:
            metadata["hotel_check_out"] = check_out.isoformat()

    if inferred_category in {None, "airfare"}:
        duration = _extract_flight_duration_hours(text)
        cabin = _extract_flight_cabin_class(text)
        if duration is not None:
            metadata["flight_duration_hours"] = duration
            inferred_category = inferred_category or "airfare"
        if cabin:
            metadata["flight_cabin_class"] = cabin
            inferred_category = inferred_category or "airfare"

    if inferred_category in {None, "meals"}:
        attendees = _extract_meal_attendees(text)
        if attendees is not None:
            metadata["attendees"] = attendees
            inferred_category = inferred_category or "meals"

    # Optional AI enrichment (fills missing policy fields + category)
    ai = extract_policy_fields(text)
    if ai:
        provenance = ai.get("_provenance") if isinstance(ai.get("_provenance"), dict) else {}

        def corroborated_snippet(field: str) -> str | None:
            prov = provenance.get(field)
            if not isinstance(prov, dict):
                return None
            lines = prov.get("evidence_lines")
            if not isinstance(lines, list) or not lines:
                return None
            return _snippet_from_line_refs(text, evidence_lines=lines)

        ai_cat = ai.get("category")
        if isinstance(ai_cat, str) and not inferred_category:
            snippet = corroborated_snippet("category") if provenance else None
            if snippet and _guess_category(snippet) == ai_cat:
                inferred_category = ai_cat
            elif not provenance:
                inferred_category = ai_cat

        if inferred_category == "lodging" and not metadata.get("hotel_nights"):
            nights = ai.get("hotel_nights")
            if isinstance(nights, int) and 1 <= nights <= 60:
                snippet = corroborated_snippet("hotel_nights") if provenance else None
                if snippet:
                    det = _extract_hotel_nights(snippet)
                    if det == nights:
                        metadata["hotel_nights"] = nights
                    else:
                        ci, co = _extract_hotel_stay_dates(snippet)
                        if ci and co and co > ci and (co - ci).days == nights:
                            metadata["hotel_nights"] = nights
                elif not provenance:
                    metadata["hotel_nights"] = nights

        if inferred_category == "airfare":
            if metadata.get("flight_duration_hours") is None:
                duration = ai.get("flight_duration_hours")
                if isinstance(duration, (int, float)) and 0.1 <= float(duration) <= 30:
                    snippet = corroborated_snippet("flight_duration_hours") if provenance else None
                    if snippet:
                        det = _extract_flight_duration_hours(snippet)
                        if det is not None and abs(float(det) - float(duration)) <= 0.05:
                            metadata["flight_duration_hours"] = round(float(duration), 2)
                    elif not provenance:
                        metadata["flight_duration_hours"] = round(float(duration), 2)
            if not metadata.get("flight_cabin_class"):
                cabin = ai.get("flight_cabin_class")
                if isinstance(cabin, str) and cabin.strip():
                    cabin_norm = cabin.strip().lower()
                    snippet = corroborated_snippet("flight_cabin_class") if provenance else None
                    if snippet:
                        det = _extract_flight_cabin_class(snippet)
                        if det and det == cabin_norm:
                            metadata["flight_cabin_class"] = cabin_norm
                    elif not provenance:
                        metadata["flight_cabin_class"] = cabin_norm

        if inferred_category == "meals" and metadata.get("attendees") in {None, ""}:
            attendees = ai.get("attendees")
            if isinstance(attendees, int) and 1 <= attendees <= 50:
                snippet = corroborated_snippet("attendees") if provenance else None
                if snippet:
                    det = _extract_meal_attendees(snippet)
                    if det == attendees:
                        metadata["attendees"] = attendees
                elif not provenance:
                    metadata["attendees"] = attendees
            elif isinstance(attendees, str) and attendees.strip():
                att = attendees.strip()[:200]
                snippet = corroborated_snippet("attendees") if provenance else None
                if snippet:
                    if att.lower() in snippet.lower():
                        metadata["attendees"] = att
                elif not provenance:
                    metadata["attendees"] = att

        if "confidence" in ai:
            metadata["policy_fields_confidence"] = ai.get("confidence")

    return inferred_category, metadata


_DATE_PATTERNS = (
    r"[0-9]{4}-[0-9]{2}-[0-9]{2}",  # 2026-01-16
    r"[0-9]{1,2}\s+[A-Za-z]{3,9}\s+[0-9]{4}",  # 16 Jan 2026
    r"[A-Za-z]{3,9}\s+[0-9]{1,2},\s*[0-9]{4}",  # Jan 16, 2026
    r"[0-9]{2}[A-Za-z]{3}[0-9]{2}",  # 31AUG25
    r"[0-9]{1,2}/[0-9]{1,2}/[0-9]{4}",  # 1/16/2026
)
_DATE_RE = re.compile(r"\b(" + "|".join(_DATE_PATTERNS) + r")\b")


def _extract_hotel_stay_dates(text: str) -> tuple[date | None, date | None]:
    t = text.replace("\u202f", " ").replace("\xa0", " ")
    check_in = _extract_date_near_keywords(
        t,
        keywords=(
            "check-in",
            "check in",
            "arrival",
            "arrival date",
        ),
    )
    check_out = _extract_date_near_keywords(
        t,
        keywords=(
            "check-out",
            "check out",
            "departure",
            "departure date",
        ),
    )

    if check_in and check_out:
        return check_in, check_out

    # "Stay: 2026-01-15 - 2026-01-17"
    m = re.search(
        r"(?i)\b(stay|dates)\b[^\n]{0,80}?\b(" + _DATE_RE.pattern + r")\b[^\n]{0,10}?"
        r"(?:-|–|—|to|until|through)\s*\b(" + _DATE_RE.pattern + r")\b",
        t,
    )
    if m:
        d1 = _parse_date_any(m.group(2))
        d2 = _parse_date_any(m.group(4))
        if d1 and d2:
            return d1, d2

    return check_in, check_out


def _extract_date_near_keywords(text: str, *, keywords: tuple[str, ...]) -> date | None:
    for kw in keywords:
        m = re.search(rf"(?i)\b{re.escape(kw)}\b[^\n]{{0,40}}{_DATE_RE.pattern}", text)
        if not m:
            continue
        candidate = m.group(1)
        parsed = _parse_date_any(candidate)
        if parsed:
            return parsed
    return None


def _parse_date_any(s: str | None) -> date | None:
    if not s:
        return None
    raw = str(s).strip()
    # ISO
    try:
        d = datetime.strptime(raw, "%Y-%m-%d").date()
        return d if _is_plausible_receipt_date(d) else None
    except ValueError:
        pass
    # 05 Sep 2025 / 05 September 2025
    for fmt in ("%d %b %Y", "%d %B %Y"):
        try:
            d = datetime.strptime(raw, fmt).date()
            return d if _is_plausible_receipt_date(d) else None
        except ValueError:
            continue
    # Sep 05, 2025 / September 5, 2025
    for fmt in ("%b %d, %Y", "%B %d, %Y"):
        try:
            d = datetime.strptime(raw, fmt).date()
            return d if _is_plausible_receipt_date(d) else None
        except ValueError:
            continue
    # 31AUG25
    try:
        d = datetime.strptime(raw.title(), "%d%b%y").date()
        return d if _is_plausible_receipt_date(d) else None
    except ValueError:
        pass
    # 12/31/2025 or 31/12/2025 (prefer unambiguous)
    m = re.fullmatch(r"([0-9]{1,2})/([0-9]{1,2})/([0-9]{4})", raw)
    if m:
        a, b = (int(m.group(1)), int(m.group(2)))
        for fmt, ok in (
            ("%m/%d/%Y", a <= 12 and b <= 31),
            ("%d/%m/%Y", b <= 12 and a <= 31),
        ):
            if not ok:
                continue
            try:
                d = datetime.strptime(raw, fmt).date()
                return d if _is_plausible_receipt_date(d) else None
            except ValueError:
                continue
    return None


def _extract_flight_duration_hours(text: str) -> float | None:
    keywords = ("duration", "flight time", "journey time", "total time", "elapsed time")
    exclude = ("layover", "connection", "stopover")
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]

    candidates: list[float] = []
    for ln in lines:
        lnl = ln.lower()
        if not any(k in lnl for k in keywords):
            continue
        if any(b in lnl for b in exclude):
            continue

        # 5h 30m / 5 hr 30 min
        m = re.search(
            r"\b([0-9]{1,2})\s*(?:h|hr|hrs|hour|hours)\s*([0-9]{1,2})\s*(?:m|min|mins|minute|minutes)\b",
            lnl,
        )
        if m:
            h, mins = int(m.group(1)), int(m.group(2))
            candidates.append(round(h + mins / 60.0, 2))
            continue

        # 05:30
        m = re.search(r"\b([0-9]{1,2}):([0-9]{2})\b", lnl)
        if m:
            h, mins = int(m.group(1)), int(m.group(2))
            if 0 <= mins < 60:
                candidates.append(round(h + mins / 60.0, 2))
            continue

        # 5.5 hours / 5 hours
        m = re.search(r"\b([0-9]{1,2}(?:\.[0-9]+)?)\s*(?:h|hr|hrs|hour|hours)\b", lnl)
        if m:
            try:
                candidates.append(round(float(m.group(1)), 2))
            except Exception:
                pass

    if not candidates:
        return None

    best = max(candidates)
    if not (0.1 <= best <= 30):
        return None
    return best


def _extract_flight_cabin_class(text: str) -> str | None:
    t = text.lower()

    # Look for explicit cabin names first.
    cabin_keywords: list[tuple[str, tuple[str, ...]]] = [
        ("premium_economy", ("premium economy", "economy plus", "comfort+", "extra legroom")),
        ("business", ("business class", "business", "club world", "club", "executive")),
        ("first", ("first class", "first")),
        ("economy", ("economy class", "economy", "coach", "main cabin")),
    ]
    for cabin, kws in cabin_keywords:
        if any(kw in t for kw in kws):
            return cabin

    # Cabin/Class: Y/J/F mapping (only when explicitly labeled).
    m = re.search(r"(?i)\b(cabin|class|booking class|fare class)\b\s*[:#]?\s*([A-Z])\b", text)
    if m:
        code = m.group(2).upper()
        if code in {"F", "A", "P"}:
            return "first"
        if code in {"J", "C", "D", "I", "Z", "R"}:
            return "business"
        if code in {"W"}:
            return "premium_economy"
        if code in {"Y", "B", "M", "H", "K", "L", "Q", "V", "S", "T", "U", "X"}:
            return "economy"

    return None


def _extract_meal_attendees(text: str) -> int | None:
    t = text.lower()
    if not any(k in t for k in ("guests", "guest", "covers", "pax", "party of", "people")):
        return None

    patterns = (
        r"\b(?:guests?|covers|pax|people|persons?)\s*[:#]?\s*([0-9]{1,2})\b",
        r"\b([0-9]{1,2})\s*(?:guests?|covers|pax|people|persons?)\b",
        r"\bparty\s+of\s+([0-9]{1,2})\b",
    )
    for pat in patterns:
        m = re.search(pat, t, re.I)
        if not m:
            continue
        try:
            n = int(m.group(1))
        except Exception:
            continue
        if 1 <= n <= 50:
            return n
    return None


def _extract_hotel_nights(text: str) -> int | None:
    t = text.lower()
    if "night" not in t and "nights" not in t:
        return None
    m = re.search(r"\b([0-9]{1,2})\s+nights?\b", t)
    if m:
        try:
            nights = int(m.group(1))
            return nights if nights > 0 else None
        except ValueError:
            return None
    m = re.search(r"\bnights?\s*[:#]?\s*([0-9]{1,2})\b", t)
    if m:
        try:
            nights = int(m.group(1))
            return nights if nights > 0 else None
        except ValueError:
            return None
    return None


def _extract_total_amount(text: str) -> tuple[str, Decimal] | None:
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    keyword_re = re.compile(
        r"\b("
        r"total|total paid|grand total|amount due|balance due|amount paid|amount charged|"
        r"total amount|total price|total fare|total charge|total charges"
        r")\b",
        re.I,
    )
    candidates: list[tuple[str, Decimal]] = []

    def add_candidates_from_line(ln: str) -> None:
        # Prefer explicit currency codes (optionally with a currency symbol).
        for m in re.finditer(
            r"\b([A-Z]{3})\s*(?:CA\$|US\$|\$|£|€)?\s*([0-9][0-9,.'\u202f\xa0 ]*[0-9])\b",
            ln,
        ):
            cur, amt = m.groups()
            cur_norm = normalize_currency(cur)
            if not cur_norm:
                continue
            amount = _parse_decimal_amount(amt)
            if amount is not None:
                candidates.append((cur_norm, amount))

        # Symbol-prefixed amounts.
        for m in re.finditer(
            r"(CA\$|US\$|\$|£|€)\s*([0-9][0-9,.'\u202f\xa0 ]*[0-9])\b", ln
        ):
            sym, amt = m.groups()
            cur = {"$": "XXX", "US$": "USD", "CA$": "CAD", "£": "GBP", "€": "EUR"}.get(sym)
            cur_norm = normalize_currency(cur)
            if not cur_norm:
                continue
            amount = _parse_decimal_amount(amt)
            if amount is not None:
                candidates.append((cur_norm, amount))

        # Amount followed by currency code.
        for m in re.finditer(
            r"\b([0-9][0-9,.'\u202f\xa0 ]*[0-9])\s*([A-Z]{3})\b",
            ln,
        ):
            amt, cur = m.groups()
            cur_norm = normalize_currency(cur)
            if not cur_norm:
                continue
            amount = _parse_decimal_amount(amt)
            if amount is not None:
                candidates.append((cur_norm, amount))

    for i, ln in enumerate(lines):
        if not keyword_re.search(ln):
            continue

        add_candidates_from_line(ln)
        if i + 1 < len(lines):
            add_candidates_from_line(lines[i + 1])

    if not candidates:
        # Fallback: largest amount that looks currency-denominated anywhere in the document.
        for ln in lines:
            add_candidates_from_line(ln)
        if not candidates:
            return None
    # Use the largest amount found on "total" lines.
    return max(candidates, key=lambda x: x[1])


def _parse_decimal_amount(raw: str) -> Decimal | None:
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
            if digits_after == 2:
                normalized = s.replace(",", ".")
            elif digits_after == 3 and len(s[:idx]) <= 3:
                normalized = s.replace(",", "")
            elif digits_after in {0, 1}:
                normalized = s.replace(",", ".")
            else:
                normalized = s.replace(",", "")
    elif "." in s:
        if s.count(".") > 1:
            normalized = s.replace(".", "")
        else:
            idx = s.rfind(".")
            digits_after = len(s) - idx - 1
            if digits_after == 2:
                normalized = s
            elif digits_after == 3 and len(s[:idx]) <= 3:
                normalized = s.replace(".", "")
            elif digits_after in {0, 1}:
                normalized = s
            else:
                normalized = s.replace(".", "")
    else:
        normalized = s

    try:
        return Decimal(normalized).quantize(Decimal("0.01"))
    except Exception:
        return None


def _snippet_from_line_refs(text: str, *, evidence_lines: list[object]) -> str:
    lines = text.splitlines()
    if not lines:
        return ""
    nums: set[int] = set()
    for raw in evidence_lines[:30]:
        try:
            n = int(raw)
        except Exception:
            continue
        for nn in (n, n + 1):
            if 1 <= nn <= len(lines):
                nums.add(nn)
    snippet_lines = [lines[n - 1].strip() for n in sorted(nums) if lines[n - 1].strip()]
    return "\n".join(snippet_lines)


def _is_plausible_receipt_date(d: date) -> bool:
    today = date.today()
    if d < (today - timedelta(days=365 * 15)):
        return False
    if d > (today + timedelta(days=365 * 2)):
        return False
    return True


def _extract_any_date(text: str):
    # ISO date: 2025-09-05
    m = re.search(r"\b([0-9]{4}-[0-9]{2}-[0-9]{2})\b", text)
    if m:
        try:
            d = datetime.strptime(m.group(1), "%Y-%m-%d").date()
            if _is_plausible_receipt_date(d):
                return d
        except ValueError:
            pass

    # 05 Sep 2025 / 05 September 2025
    m = re.search(r"\b([0-9]{1,2}\s+[A-Za-z]{3,9}\s+[0-9]{4})\b", text)
    if m:
        s = m.group(1)
        for fmt in ("%d %b %Y", "%d %B %Y"):
            try:
                d = datetime.strptime(s, fmt).date()
                if _is_plausible_receipt_date(d):
                    return d
            except ValueError:
                continue

    # Sep 05, 2025 / September 5, 2025
    m = re.search(r"\b([A-Za-z]{3,9}\s+[0-9]{1,2},\s+[0-9]{4})\b", text)
    if m:
        s = m.group(1)
        for fmt in ("%b %d, %Y", "%B %d, %Y"):
            try:
                d = datetime.strptime(s, fmt).date()
                if _is_plausible_receipt_date(d):
                    return d
            except ValueError:
                continue

    # 31AUG25
    m = re.search(r"\b([0-9]{2}[A-Za-z]{3}[0-9]{2})\b", text)
    if m:
        try:
            d = datetime.strptime(m.group(1).title(), "%d%b%y").date()
            if _is_plausible_receipt_date(d):
                return d
        except ValueError:
            pass

    # 12/31/2025 or 31/12/2025
    m = re.search(r"\b([0-9]{1,2}/[0-9]{1,2}/[0-9]{4})\b", text)
    if m:
        s = m.group(1)
        a, b, c = s.split("/")
        try:
            aa, bb, _ = int(a), int(b), int(c)
        except ValueError:
            aa = bb = 0
        # Prefer month/day when unambiguous, otherwise try day/month.
        for fmt in (("%m/%d/%Y", aa <= 12 and bb <= 31), ("%d/%m/%Y", bb <= 12 and aa <= 31)):
            f, ok = fmt
            if not ok:
                continue
            try:
                d = datetime.strptime(s, f).date()
                if _is_plausible_receipt_date(d):
                    return d
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
        session.flush()
        log_event(
            logger,
            "extraction.task.upsert",
            claim_id=str(claim.id),
            task_id=str(task.id),
            task_type=task.type,
            task_status=task.status.value,
            source_file_id=str(source.id),
            action="created",
        )
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
    session.flush()
    log_event(
        logger,
        "extraction.task.upsert",
        claim_id=str(claim.id),
        task_id=str(task.id),
        task_type=task.type,
        task_status=task.status.value,
        source_file_id=str(source.id),
        action="updated",
    )


def _is_supported_image(filename: str, content_type: str | None) -> bool:
    if (content_type or "").lower().startswith("image/"):
        return True
    return filename.lower().endswith(
        (".png", ".jpg", ".jpeg", ".tif", ".tiff", ".bmp", ".gif", ".webp")
    )


def _is_supported_text(filename: str, content_type: str | None) -> bool:
    ctype = (content_type or "").lower()
    if ctype.startswith("text/plain") or ctype.startswith("text/html"):
        return True
    return filename.lower().endswith((".txt", ".md", ".html", ".htm", ".csv"))
