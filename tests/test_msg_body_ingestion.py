from __future__ import annotations

import sys
import types
from datetime import UTC, date, datetime
from decimal import Decimal

from sqlalchemy import select

from serendipity_spend.core.db import SessionLocal
from serendipity_spend.modules.claims.service import create_claim
from serendipity_spend.modules.documents.service import create_source_files_from_upload
from serendipity_spend.modules.expenses.models import ExpenseItem
from serendipity_spend.modules.extraction.service import extract_source_file
from serendipity_spend.modules.identity.models import UserRole
from serendipity_spend.modules.identity.service import create_user


def test_msg_upload_ingests_body_and_extracts_item(monkeypatch):
    class FakeMessage:
        def __init__(self, path, **kwargs):  # noqa: ARG002
            pass

        subject = "Hotel confirmation"
        sender = "Marriott <noreply@marriott.com>"
        to = "employee@example.com"
        body = "Total: USD 123.45\nDate: 2026-01-15\n"
        htmlBody = ""
        parsedDate = datetime(2026, 1, 16, 10, 0, 0, tzinfo=UTC)
        attachments = []

        def close(self) -> None:
            return

    fake_module = types.SimpleNamespace(Message=FakeMessage)
    monkeypatch.setitem(sys.modules, "extract_msg", fake_module)

    with SessionLocal() as session:
        employee = create_user(
            session,
            email="employee@example.com",
            password="pw",
            role=UserRole.EMPLOYEE,
            full_name="Employee",
        )
        claim = create_claim(session, employee_id=employee.id, home_currency="USD")

        sources = create_source_files_from_upload(
            session,
            claim=claim,
            user=employee,
            filename="hotel.msg",
            content_type="application/vnd.ms-outlook",
            body=b"fake msg bytes",
        )
        assert any(s.content_type == "text/plain" for s in sources)

        body_source = next(s for s in sources if s.content_type == "text/plain")
        extract_source_file(source_file_id=str(body_source.id))

        items = list(session.scalars(select(ExpenseItem).where(ExpenseItem.claim_id == claim.id)))
        assert len(items) == 1
        assert items[0].vendor == "Marriott"
        assert items[0].amount_original_currency == "USD"
        assert items[0].amount_original_amount == Decimal("123.45")
        assert items[0].transaction_date == date(2026, 1, 15)

