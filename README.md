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
