from __future__ import annotations

from datetime import date
from decimal import Decimal
from email.message import EmailMessage

from sqlalchemy import select

from serendipity_spend.core.db import SessionLocal
from serendipity_spend.modules.claims.service import create_claim
from serendipity_spend.modules.documents.service import create_source_files_from_upload
from serendipity_spend.modules.expenses.models import ExpenseItem
from serendipity_spend.modules.extraction.service import extract_source_file
from serendipity_spend.modules.identity.models import UserRole
from serendipity_spend.modules.identity.service import create_user


def test_eml_upload_ingests_body_and_extracts_item():
    with SessionLocal() as session:
        employee = create_user(
            session,
            email="employee@example.com",
            password="pw",
            role=UserRole.EMPLOYEE,
            full_name="Employee",
        )
        claim = create_claim(session, employee_id=employee.id, home_currency="USD")

        msg = EmailMessage()
        msg["From"] = "Marriott <noreply@marriott.com>"
        msg["To"] = "employee@example.com"
        msg["Subject"] = "Hotel confirmation"
        msg["Date"] = "Thu, 16 Jan 2026 10:00:00 +0000"
        msg.set_content("Total: USD 123.45\nDate: 2026-01-15\n")

        sources = create_source_files_from_upload(
            session,
            claim=claim,
            user=employee,
            filename="hotel.eml",
            content_type="message/rfc822",
            body=msg.as_bytes(),
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
