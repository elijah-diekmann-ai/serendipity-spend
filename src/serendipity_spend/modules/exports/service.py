from __future__ import annotations

import io
import uuid
import zipfile
from datetime import UTC, date, datetime

from openpyxl import Workbook
from sqlalchemy import select

from serendipity_spend.core.db import SessionLocal
from serendipity_spend.core.storage import get_storage
from serendipity_spend.modules.claims.models import Claim
from serendipity_spend.modules.documents.models import SourceFile
from serendipity_spend.modules.expenses.models import ExpenseItem
from serendipity_spend.modules.exports.models import ExportRun, ExportStatus
from serendipity_spend.modules.identity.models import User


def create_export_run(*, claim_id: uuid.UUID, requested_by_user_id: uuid.UUID) -> ExportRun:
    with SessionLocal() as session:
        run = ExportRun(
            claim_id=claim_id,
            requested_by_user_id=requested_by_user_id,
            status=ExportStatus.QUEUED,
            error_message=None,
            summary_xlsx_key=None,
            supporting_zip_key=None,
            completed_at=None,
        )
        session.add(run)
        session.commit()
        session.refresh(run)
        return run


def generate_export(*, export_run_id: str) -> None:
    with SessionLocal() as session:
        run = session.scalar(select(ExportRun).where(ExportRun.id == uuid.UUID(export_run_id)))
        if not run:
            return

        run.status = ExportStatus.RUNNING
        run.error_message = None
        session.add(run)
        session.commit()

        try:
            claim = session.scalar(select(Claim).where(Claim.id == run.claim_id))
            if not claim:
                raise ValueError("Claim not found")

            employee = session.scalar(select(User).where(User.id == claim.employee_id))
            items = list(
                session.scalars(select(ExpenseItem).where(ExpenseItem.claim_id == claim.id))
            )
            sources = list(
                session.scalars(select(SourceFile).where(SourceFile.claim_id == claim.id))
            )

            xlsx_bytes = _build_reimbursement_xlsx(claim=claim, employee=employee, items=items)
            zip_bytes = _build_supporting_zip(sources=sources)

            summary_key = f"claims/{claim.id}/exports/{run.id}/summary.xlsx"
            supporting_key = f"claims/{claim.id}/exports/{run.id}/supporting.zip"

            get_storage().put(key=summary_key, body=xlsx_bytes)
            get_storage().put(key=supporting_key, body=zip_bytes)

            run.status = ExportStatus.COMPLETED
            run.summary_xlsx_key = summary_key
            run.supporting_zip_key = supporting_key
            run.completed_at = datetime.now(UTC)
            session.add(run)
            session.commit()
        except Exception as e:  # noqa: BLE001
            run.status = ExportStatus.FAILED
            run.error_message = str(e)
            session.add(run)
            session.commit()


def _build_reimbursement_xlsx(
    *, claim: Claim, employee: User | None, items: list[ExpenseItem]
) -> bytes:
    wb = Workbook()
    ws = wb.active
    ws.title = "Reimbursement"

    employee_label = (
        (employee.full_name if employee and employee.full_name else None)
        or (employee.email if employee else None)
        or str(claim.employee_id)
    )
    ws["A1"] = "Employee"
    ws["B1"] = employee_label
    ws["A2"] = "Travel period"
    if claim.travel_start_date and claim.travel_end_date:
        ws["B2"] = f"{claim.travel_start_date} to {claim.travel_end_date}"
    ws["A3"] = "Purpose of the trip"
    ws["B3"] = claim.purpose or ""

    ws["C5"] = "Source Currency"
    ws["H5"] = "Reimbursement"

    headers = ["Date", "Description", "USD", "SGD", "CAD", "GBP", "EX rate", claim.home_currency]
    for col, value in enumerate(headers, start=1):
        ws.cell(row=6, column=col, value=value)

    currency_col = {"USD": 3, "SGD": 4, "CAD": 5, "GBP": 6}

    row = 8
    for item in sorted(items, key=lambda i: (i.transaction_date or date.min, i.created_at)):
        ws.cell(
            row=row,
            column=1,
            value=item.transaction_date.isoformat() if item.transaction_date else "",
        )
        ws.cell(row=row, column=2, value=item.description or item.vendor)

        col = currency_col.get(item.amount_original_currency.upper())
        if col:
            ws.cell(row=row, column=col, value=float(item.amount_original_amount))

        if item.fx_rate_to_home is not None:
            ws.cell(row=row, column=7, value=float(item.fx_rate_to_home))

        if item.amount_home_amount is not None:
            ws.cell(row=row, column=8, value=float(item.amount_home_amount))

        row += 1

    total_row = row
    ws.cell(row=total_row, column=2, value="Total")
    for col in [3, 4, 5, 6, 8]:
        start = 8
        end = total_row - 1
        start_coord = ws.cell(row=start, column=col).coordinate
        end_coord = ws.cell(row=end, column=col).coordinate
        ws.cell(row=total_row, column=col, value=f"=SUM({start_coord}:{end_coord})")

    out = io.BytesIO()
    wb.save(out)
    return out.getvalue()


def _build_supporting_zip(*, sources: list[SourceFile]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for s in sources:
            body = get_storage().get(key=s.storage_key)
            filename = s.filename or f"{s.id}.bin"
            zf.writestr(filename, body)
    return buf.getvalue()
