# Serendipity Spend

Expense reimbursement intake and review for travel and related expenses.

## Goals
- Replace manual email + spreadsheet workflows with a structured portal.
- Auto-generate a claim summary and check against Travel Policy rules.
- Route claims for employee confirmation and approver review before payment.
- Maintain a clean audit trail with supporting documents.

## Proposed stack
- API: Python + FastAPI
- Database: PostgreSQL
- Background jobs: Celery + Redis
- Object storage: S3-compatible (Railway-friendly)
- Deployment: Railway.com

## Data
Drop the sample files here so we can inspect formats and fields:
- `Data/Travel Reimbursement_DC_Jan 2026.xlsx`
- `Data/DC_OOP_05 Sep 2025.pdf`
- `Data/Expenses.eml` (optional email example)
- `Data/sample-data-notes.md` (analysis notes from the PDF text)

## Next steps
- Review sample files in `Data/` and extract required fields.
- Define policy rules and validation checks.
- Draft data model and API endpoints.
- Design the portal flow (employee intake -> validation -> approval).

---

## Run locally (MVP)

This repo now contains a working MVP (API + minimal portal UI) that can:

- Create claims
- Upload a PDF bundle and extract line items (Grab / Uber / United Wi‑Fi / baggage fee from the sample)
- Evaluate basic policy rules and create tasks
- Submit and approve claims
- Generate an Excel reimbursement summary + a supporting-documents zip

### 1) Install

```bash
python -m pip install -e '.[dev]'
```

### 2) Configure

Copy env example and set an admin user:

```bash
cp .env.example .env
```

Defaults:

- DB: SQLite (`sqlite:///./serendipity.db`) in `dev`
- Storage: local folder (`.local_storage/`)
- Celery: runs **eagerly** in `dev` (no Redis required)

### 3) Run the app

```bash
uvicorn serendipity_spend.main:app --reload
```

Open the portal UI:

- `http://localhost:8000/app`

Or use the API docs:

- `http://localhost:8000/docs`

### 4) Quick demo flow (using the included sample PDF)

1. Log in (credentials from `.env`).
2. Create a new claim.
3. Upload `Data/DC__OOP__05 Sep 2025.pdf` and wait for extraction.
4. Review tasks/policy flags; fill purpose + travel period.
5. (Optional) set FX rates for USD/CAD → SGD.
6. Submit claim; approve as approver/admin.
7. Generate export and download `summary.xlsx` + `supporting.zip`.

---

Issue Statement:

Currently, employees who wish to claim travel expenses send invoices and receipts directly to me (for example, hotel confirmation emails, Uber receipts, etc.; see the attached email titled “Expenses” as an example). I then manually review these items and prepare a summary table in Excel (see “Travel Reimbursement_DC_Jan 2026”). As part of this process, I check each item for compliance with the Travel Policy, such as ensuring hotel rates do not exceed USD 300 per night and that flights under six hours are booked in economy class.

 

This process is entirely manual, time-consuming, and prone to errors, including incorrect amounts and potential duplication. The attachment “DC_OOP_05 Sep 2025” reflects the current output used to support reimbursement claims, where the Excel file is the summary and the PDF contains the supporting documents.

 

Ideally, the process would be streamlined as follows:

 
Employees upload all relevant supporting documents to a portal, which automatically generates a claim summary.

Automated checks are performed against the Travel Policy, with any inconsistencies clearly flagged at the summary level.

Employees review the generated summary to confirm accuracy and completeness, fill in any missing information (for example, trip purpose, or names of attendees for food and beverage expenses over USD 100), and address any flagged items.

The summary and supporting documents are then routed to me for review and approval prior to payment.
