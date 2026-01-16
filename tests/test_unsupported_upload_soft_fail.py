from __future__ import annotations

from sqlalchemy import select

from serendipity_spend.core.db import SessionLocal
from serendipity_spend.modules.claims.models import Claim, ClaimStatus
from serendipity_spend.modules.claims.service import create_claim
from serendipity_spend.modules.documents.models import SourceFile, SourceFileStatus
from serendipity_spend.modules.documents.service import create_source_file
from serendipity_spend.modules.extraction.service import extract_source_file
from serendipity_spend.modules.identity.models import UserRole
from serendipity_spend.modules.identity.service import create_user
from serendipity_spend.modules.workflow.models import Task, TaskStatus


def test_unsupported_upload_creates_extract_task_and_recovers_claim_status():
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
            filename="receipt.docx",
            content_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            body=b"\x00\x01\x02not-a-supported-file",
        )

        extract_source_file(source_file_id=str(source.id))
        session.expire_all()

        refreshed_claim = session.scalar(select(Claim).where(Claim.id == claim.id))
        assert refreshed_claim
        assert refreshed_claim.status == ClaimStatus.NEEDS_EMPLOYEE_REVIEW

        refreshed_source = session.scalar(select(SourceFile).where(SourceFile.id == source.id))
        assert refreshed_source
        assert refreshed_source.status == SourceFileStatus.FAILED

        task = session.scalar(
            select(Task)
            .where(Task.claim_id == claim.id, Task.type.like("EXTRACT_%"))
            .order_by(Task.created_at.desc())
        )
        assert task
        assert task.status == TaskStatus.OPEN
        assert task.title.startswith("Unsupported upload:")
