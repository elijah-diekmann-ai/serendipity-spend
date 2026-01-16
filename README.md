# Serendipity Reimbursement Portal

## What it does

1. **Employees upload receipts** (PDFs, Uber/Grab receipts, hotel invoices, etc.)
2. **Auto-extracts line items** from the documents
3. **Checks against travel policy** (e.g., hotel < $300/night, economy class for short flights)
4. **Flags issues** for review
5. **Routes to approver** for sign-off
6. **Generates Excel summary + zip of supporting docs** for payment processing

## The problem it solves

Automates the intake-to-approval workflow.

---

## Stack

- **API**: Python + FastAPI
- **Database**: PostgreSQL
- **Background jobs**: Celery + Redis
- **Storage**: S3-compatible (Railway Bucket)
- **Deployment**: Railway

---

## Uploads & extraction (v1)

- **Upload types**: PDF, images (PNG/JPG), ZIP bundles, and `.eml` email files (attachments are ingested).
- **Batch uploads**: multi-file selection + drag-and-drop in the UI.
- **Unrecognized receipts**: the system creates a task and employees can add/edit expense items manually.

## Policy checks (v1)

- Claim purpose required (`R001`, FAIL)
- Travel dates required (`R002`, FAIL)
- Uber trip summary may be insufficient (`R010`, NEEDS_INFO)
- Grab receipt indicates PERSONAL profile (`R020`, WARN)
- Missing FX rate to home currency (`R030`, NEEDS_INFO)
- Generic “total” extraction requires employee review (`R040`, NEEDS_INFO)
- Hotel nightly cap (USD 300/night) using `hotel_nights` (`R101`–`R103`)
- Meals over USD 100 require attendees (`R111`–`R112`)
- Flights under 6 hours must be economy (`R121`–`R123`)

## Run locally

### 1. Install

```bash
python -m pip install -e '.[dev]'
```

### 2. Configure

```bash
cp .env.example .env
```

### 3. Run

```bash
uvicorn serendipity_spend.main:app --reload
```

Open: [http://localhost:8000/app](http://localhost:8000/app)

---

## Deploy to Railway

See [railway.MD](railway.MD) for step-by-step deployment instructions.
