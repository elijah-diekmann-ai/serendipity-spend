from __future__ import annotations

import pytest
from sqlalchemy import select

from serendipity_spend.core.db import SessionLocal
from serendipity_spend.core.storage import StorageError, get_storage
from serendipity_spend.modules.claims.models import Claim
from serendipity_spend.modules.claims.service import create_claim, delete_claim
from serendipity_spend.modules.documents.service import create_source_file
from serendipity_spend.modules.exports.models import ExportRun
from serendipity_spend.modules.exports.service import create_export_run, generate_export
from serendipity_spend.modules.identity.models import User, UserRole
from serendipity_spend.modules.identity.service import create_user


def test_delete_claim_deletes_storage_objects():
    with SessionLocal() as session:
        employee = create_user(
            session,
            email="employee@example.com",
            password="pw",
            role=UserRole.EMPLOYEE,
            full_name="Employee",
        )
        claim = create_claim(session, employee_id=employee.id, home_currency="USD")
        claim_id = claim.id
        employee_id = employee.id

        source = create_source_file(
            session,
            claim=claim,
            user=employee,
            filename="receipt.txt",
            content_type="text/plain",
            body=b"hello",
        )
        source_key = source.storage_key

    run = create_export_run(claim_id=claim_id, requested_by_user_id=employee_id)
    generate_export(export_run_id=str(run.id))

    with SessionLocal() as session:
        run_row = session.scalar(select(ExportRun).where(ExportRun.id == run.id))
        assert run_row
        assert run_row.summary_xlsx_key
        assert run_row.supporting_pdf_key
        summary_key = run_row.summary_xlsx_key
        supporting_key = run_row.supporting_pdf_key

        claim_row = session.scalar(select(Claim).where(Claim.id == claim_id))
        user_row = session.scalar(select(User).where(User.id == employee_id))
        assert claim_row
        assert user_row
        delete_claim(session, claim=claim_row, user=user_row)

    storage = get_storage()
    with pytest.raises(StorageError):
        storage.get(key=source_key)
    with pytest.raises(StorageError):
        storage.get(key=summary_key)
    with pytest.raises(StorageError):
        storage.get(key=supporting_key)

