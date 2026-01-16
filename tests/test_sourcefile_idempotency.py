from __future__ import annotations

import hashlib

from sqlalchemy import func, select

from serendipity_spend.core.db import SessionLocal
from serendipity_spend.modules.claims.service import create_claim
from serendipity_spend.modules.documents.models import (
    EvidenceDocument,
    SourceFile,
    SourceFileStatus,
)
from serendipity_spend.modules.documents.service import create_source_file
from serendipity_spend.modules.expenses.models import ExpenseItem
from serendipity_spend.modules.extraction.service import extract_source_file
from serendipity_spend.modules.identity.models import UserRole
from serendipity_spend.modules.identity.service import create_user


def test_extract_source_file_is_idempotent_when_already_processed():
    with SessionLocal() as session:
        employee = create_user(
            session,
            email="employee@example.com",
            password="pw",
            role=UserRole.EMPLOYEE,
            full_name="Employee",
        )
        claim = create_claim(session, employee_id=employee.id, home_currency="USD")

        source = create_source_file(
            session,
            claim=claim,
            user=employee,
            filename="receipt.txt",
            content_type="text/plain",
            body=b"Total: USD 10.00\nDate: 2026-01-15\nVendor: Example\n",
        )

        extract_source_file(source_file_id=str(source.id))
        session.expire_all()

        evidence_count_1 = session.scalar(
            select(func.count())
            .select_from(EvidenceDocument)
            .where(EvidenceDocument.source_file_id == source.id)
        )
        item_count_1 = session.scalar(
            select(func.count()).select_from(ExpenseItem).where(ExpenseItem.claim_id == claim.id)
        )

        extract_source_file(source_file_id=str(source.id))
        session.expire_all()

        evidence_count_2 = session.scalar(
            select(func.count())
            .select_from(EvidenceDocument)
            .where(EvidenceDocument.source_file_id == source.id)
        )
        item_count_2 = session.scalar(
            select(func.count()).select_from(ExpenseItem).where(ExpenseItem.claim_id == claim.id)
        )

        assert evidence_count_2 == evidence_count_1
        assert item_count_2 == item_count_1


def test_reprocess_cleans_up_existing_evidence_documents():
    with SessionLocal() as session:
        employee = create_user(
            session,
            email="employee@example.com",
            password="pw",
            role=UserRole.EMPLOYEE,
            full_name="Employee",
        )
        claim = create_claim(session, employee_id=employee.id, home_currency="USD")

        source = create_source_file(
            session,
            claim=claim,
            user=employee,
            filename="receipt.txt",
            content_type="text/plain",
            body=b"Total: USD 10.00\nDate: 2026-01-15\nVendor: Example\n",
        )

        extract_source_file(source_file_id=str(source.id))
        session.expire_all()

        extra_text = "stale evidence"
        session.add(
            EvidenceDocument(
                source_file_id=source.id,
                page_start=None,
                page_end=None,
                vendor="Stale",
                receipt_type="unknown",
                extracted_text=extra_text,
                text_hash=hashlib.sha256(extra_text.encode("utf-8")).hexdigest(),
                classification_confidence=0.0,
            )
        )
        session.commit()

        src_row = session.scalar(select(SourceFile).where(SourceFile.id == source.id))
        assert src_row
        src_row.status = SourceFileStatus.FAILED
        session.add(src_row)
        session.commit()

        extract_source_file(source_file_id=str(source.id))
        session.expire_all()

        evidences = list(
            session.scalars(
                select(EvidenceDocument).where(EvidenceDocument.source_file_id == source.id)
            )
        )
        assert len(evidences) == 1
