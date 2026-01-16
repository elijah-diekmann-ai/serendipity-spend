# Serendipity Spend — Modular Monolith Architecture & Implementation Plan

Expense reimbursement intake and review for travel and related expenses.

This document is a **design spec** for building the first production version as a **modular monolith** (one deployable, clear internal module boundaries) using the proposed stack:

- API: Python + FastAPI
- Database: PostgreSQL
- Background jobs: Celery + Redis
- Object storage: S3-compatible
- Deployment: Railway

---

## 1) Context (what exists today)

Current workflow (from `README.md`):

1. Employee emails receipts/invoices (hotel confirmations, Uber receipts, etc.).
2. Reviewer manually checks policy compliance (e.g., hotel < USD 300/night; flights < 6h economy).
3. Reviewer manually creates an Excel reimbursement summary.
4. Supporting documents are compiled into a PDF.

Target workflow:

1. Employee uploads supporting documents to a portal.
2. System extracts and generates a claim summary.
3. System runs travel-policy checks; flags issues at the summary level.
4. Employee confirms summary, fills missing fields (purpose, attendees > USD 100, etc.), and resolves flags.
5. Approver reviews and approves prior to payment.

---

## 2) Sample data extracted from `Data/`

### 2.1 Excel template (`Data/Travel Reimbursement_DC_Jan 2026.xlsx`)

Workbook has one sheet: `DC__Personal__05 Sep`.

Header fields (present, but “Travel period” and “Purpose of the trip” are blank in the sample):

- `Employee`: **Dick Catlin**
- `Travel period`: (blank)
- `Purpose of the trip`: (blank)

Line-item table shape:

- Columns: `Date`, `Description`, `USD`, `SGD`, `CAD`, `GBP`, `EX rate`, `SGD (Reimbursement)`
- Totals row sums `C8:C26`, `D8:D26`, `E8:E26`, `H8:H26`

Implications:

- The portal should produce a reimbursement summary compatible with this structure.
- The system must support **multi-currency** (USD/SGD/CAD/GBP at minimum) and store **FX rates used** for reimbursement currency conversion.

### 2.2 PDF bundle (`Data/DC__OOP__05 Sep 2025.pdf`)

The PDF is a concatenated bundle of emailed receipts and summaries (43 pages). It contains multiple receipt types and currencies. Extracted structured items:

#### Grab rides (SGD)

| Vendor | Type | Date | Booking ID | Amount | Currency | Distance | Duration | From → To |
|---|---|---:|---|---:|---|---:|---:|---|
| Grab | Ride receipt | 26 Aug 2025 | A-89O5QPCGWCW4AV | 10.60 | SGD | 2.9 km | 10 min | Lobby, The Fullerton Hotel → Guoco Midtown Office |
| Grab | Ride receipt | 26 Aug 2025 | A-89NU3JOWXB2NAV | 8.60 | SGD | 3.01 km | 10 min | Guoco Midtown Office → Lobby, The Fullerton Hotel |
| Grab | Ride receipt | 27 Aug 2025 | A-89R7C9MGW6M2AV | 37.50 | SGD | 26.58 km | 22 min | 25 Linden Dr → Terminal 2 Departure - Changi Airport |
| Grab | Ride receipt | 04 Sep 2025 | A-8AS7WD6WWKSNAV | 45.20 | SGD | 26.27 km | 25 min | Door 5, L1 Pick-up, T2 Arrivals, Changi Airport → 25 Linden Dr |

Notes:

- Each Grab receipt includes a breakdown (fare, platform fee, driver fee), passenger name, and a “Paid by” last-4-like token (sample shows `5255`).
- The PDF bundling implies ingestion must **segment** a single PDF into many receipts.

#### United Airlines Wi‑Fi purchases (USD)

| Vendor | Type | Flight | Route | Purchase date | Reference # | Amount | Currency |
|---|---|---|---|---|---|---:|---|
| United | Email receipt | UA2 | SIN→SFO | Tue, Aug 26, 2025 | 0164325442037 | 19.99 | USD |
| United | Email receipt | UA2356 | SFO→BOS | Wed, Aug 27, 2025 | 0164325602737 | 8.00 | USD |
| United | Email receipt | UA1 | SFO→SIN | Wed, Sep 03, 2025 | 0164327234604 | 19.99 | USD |

Notes:

- Receipts include payment method last-4 (sample shows AmEx ending `2008`).
- These map cleanly to a “Travel / Airline ancillary / Wi‑Fi” category.

#### Uber trip summaries (USD + CAD)

All Uber documents explicitly state: **“This is not a payment receipt. It is a trip summary…”** (policy may require a payment receipt for reimbursement).

| Vendor | Type | Trip date | Total | Currency | Ride type | Distance | Duration | From → To |
|---|---|---:|---:|---|---|---:|---:|---|
| Uber | Trip summary | 27 Aug 2025 | 40.53 | USD | Black | 1.78 miles | 6 min | BOS airport → 101 Harborside Dr, Boston |
| Uber | Trip summary | 28 Aug 2025 | 42.98 | USD | Comfort | 8.38 miles | 30 min | 101 Harborside Dr, Boston → 1350 Massachusetts Ave, Cambridge |
| Uber | Trip summary | 29 Aug 2025 | 42.71 | CAD | Comfort | 18.90 km | 22 min | Calgary airport → 700 Centre St SE, Calgary |
| Uber | Trip summary | 29 Aug 2025 | 25.19 | USD | Comfort | 2.30 miles | 8 min | 101 Harborside Dr, Boston → BOS airport |
| Uber | Trip summary | 31 Aug 2025 | 36.94 | USD | Comfort | 13.75 miles | 21 min | SAN airport → 3299 Holiday Ct, La Jolla |
| Uber | Trip summary | 31 Aug 2025 | 42.12 | CAD | Comfort | 20.89 km | 23 min | 1036 9 Ave SW, Calgary → Calgary airport |
| Uber | Trip summary | 01 Sep 2025 | 70.18 | USD | Comfort | 20.84 miles | 25 min | 17550 Bernardo Oaks Dr → 3299 Holiday Ct, La Jolla |
| Uber | Trip summary | 02 Sep 2025 | 52.09 | USD | Comfort | 19.67 miles | 28 min | 3299 Holiday Ct → 16465 via esprillo |
| Uber | Trip summary | 02 Sep 2025 | 85.97 | USD | Comfort | 25.79 miles | 29 min | 16465 via esprillo → SAN airport |

Notes:

- Trip summaries include many region-specific surcharges (airport pickup, tolls, state fees, etc.). Data extraction must be **vendor + locale aware**.
- Distances use **miles** (US) and **kilometers** (Canada), and timezones vary (e.g., GMT-7, GMT-6, GMT-4).

#### Airline baggage fee payment receipt (CAD)

Single-page structured receipt:

- Type: **Payment receipt**
- Description: **BAG FEE**
- Date/time: **31AUG25 9:34 AM**
- Amount: **CAD 47.25** (fee CAD 45.00 + GST CAD 2.25)
- Form of payment: AmEx ending **2008**
- Additional tax identifiers present (GST/TPS, QST/TVQ numbers)

Implications:

- Some documents are true payment receipts; others are “trip summaries” that may not satisfy audit requirements.
- Duplicate detection should use stable identifiers when present (Grab booking ID, United reference #, airline PNR/receipt #, etc.).

---

## 3) Product requirements

### 3.1 Functional requirements

**Claim intake**

- Employee creates a claim, enters trip metadata (travel period, purpose, cost center/project if needed).
- Employee uploads one or many files (PDF, images; optionally `.eml` in the future).
- System stores originals and starts extraction asynchronously.

**Auto-extraction & normalization**

- Extract text (PDF text extraction; OCR fallback for image-based PDFs).
- Segment multi-receipt bundles into individual receipt “evidence documents”.
- Classify vendor + receipt type (Grab ride receipt, Uber trip summary, United ancillary receipt, etc.).
- Parse into structured “expense items” with amounts, currencies, dates, merchant, locations (where available), and references.

**Employee confirmation**

- Show generated summary and flagged issues.
- Allow edits (category, business purpose, attendees, notes, manual amount overrides with justification).
- Allow attachment-to-item linking and merging/splitting extracted items.

**Policy checks**

- Run deterministic rule checks with clear pass/fail + explanation + suggested remediation.
- Support “missing info” checks that create tasks (e.g., attendees required for meals > threshold).

**Approvals**

- Route to approver(s) based on org rules (manager, finance).
- Approver can approve, reject, or request changes; comments required on reject.
- Capture approval audit trail (who/when/what changed).

**Export / payout handoff**

- Generate a reimbursement summary (Excel-like) and a supporting-documents package for payment.
- Provide a “ready for payment” status and export history.

### 3.2 Non-functional requirements

- **Auditability:** immutable event log for submissions, edits, approvals; provenance of extracted fields (source file + page + confidence).
- **Idempotency:** re-processing the same file should not create duplicate expenses.
- **Security:** role-based access, least privilege; PII handling; signed URLs for downloads.
- **Reliability:** background retries with DLQ; safe re-runs; resilient to partial extraction failures.
- **Extensibility:** add new vendor parsers and new policy rules without rewriting core flows.

---

## 4) Modular monolith: module boundaries

The system ships as one deployable (API + worker), but code is organized as bounded modules with explicit dependencies.

### 4.1 Proposed modules

1. **Identity & Access**
   - Users, roles (Employee/Approver/Admin), org units, authentication integration.
2. **Claims**
   - Claim aggregate and lifecycle; claim totals; assignment to approvers.
3. **Documents**
   - Source files, versions, storage abstraction (S3); signed download URLs.
4. **Extraction**
   - Text extraction (PDF/OCR), segmentation, classification, vendor parsers; provenance and confidence scoring.
5. **Expenses**
   - Canonical expense item model (merchant, category, money, date/time, metadata); linking to evidence documents.
6. **FX & Money**
   - Currency types, rounding rules, exchange rates, conversion snapshots.
7. **Policy**
   - Travel policy rules, rule evaluation, violations, remediation tasks.
8. **Workflow**
   - Review tasks, comments, approvals, state machine and transitions.
9. **Audit**
   - Append-only event log; “who did what when”; field-level change tracking.
10. **Notifications**
   - Email notifications for tasks/approvals; digest/reminders.
11. **Exports**
   - Generate Excel/PDF packages; export status tracking.

### 4.2 Dependency rules (enforced by code structure)

- Modules may depend on **Shared Kernel** (common primitives: `Money`, `DateRange`, error types, event bus).
- Cross-module calls happen through **application interfaces** (ports), not through direct DB access.
- Domain models remain internal; other modules interact via:
  - Commands/queries exposed by the module’s application layer
  - Domain events published to the in-process event bus

---

## 5) Runtime architecture (one deployable, separated responsibilities)

**Services (processes)**

- **API process** (FastAPI): synchronous HTTP; authorization; orchestration; reads/writes Postgres.
- **Worker process** (Celery): extraction, OCR, classification, export generation, notification sends.
- **Redis**: Celery broker/backing store; optional caching.
- **Postgres**: source of truth for claims, items, policy results, audit, references.
- **S3-compatible storage**: original documents + derived artifacts (segmented PDFs, exports).

**Data flow (happy path)**

1. Upload → store object → create `documents.source_file` record.
2. Enqueue `extraction.extract_source_file(source_file_id)`.
3. Worker extracts text → segments → classifies → parses → upserts `expenses.expense_item` records.
4. Run policy evaluation → create `policy.violation` and `workflow.task` records.
5. Employee reviews → submits → approver reviews → export → mark paid.

---

## 6) Core domain model (high-level)

### 6.1 Key aggregates

**Claim (aggregate root)**

- `claim_id`
- `employee_id`
- `travel_period: DateRange`
- `purpose: str`
- `home_currency` (e.g., SGD)
- `status` (draft → in_review → approved → paid)
- `submitted_at`, `approved_at`, `paid_at`

**ExpenseItem (aggregate root)**

- `expense_item_id`
- `claim_id`
- `vendor` (Grab, Uber, United, Airline, …)
- `category` (transport, airfare, lodging, meals, ancillary, …)
- `receipt_type` (payment_receipt, trip_summary, email_receipt, invoice, …)
- `transaction_at` (datetime with timezone, if available)
- `amount_original: Money`
- `amount_home: Money` (computed via FX snapshot)
- `fx_rate_snapshot_id` (nullable if already home currency)
- `metadata` (locations, flight info, booking ID, reference numbers)

**EvidenceDocument**

- Represents one logical receipt/invoice extracted from a source file (or uploaded individually).
- Links: `source_file_id`, page range, extracted text, hash, and the structured parse output.

### 6.2 Invariants

- A claim cannot be submitted unless required fields are present (purpose, travel period, required attestations).
- An expense item must have at least one evidence document link (unless explicitly allowed as manual entry).
- If an item is in non-home currency, the FX conversion must be reproducible via stored rate snapshot.

---

## 7) Database design (Postgres)

Recommend a single Postgres database with either:

- **Option A (simpler):** one schema, table prefixes per module (`claims_*`, `documents_*`, …)
- **Option B (stronger boundaries):** separate schemas per module (`claims`, `documents`, `extraction`, …)

Either way, enforce boundaries in code and keep foreign keys explicit.

Minimum tables (illustrative, not exhaustive):

- `identity.user`, `identity.role`, `identity.user_role`
- `claims.claim`
- `documents.source_file`, `documents.stored_object`, `documents.evidence_document`
- `extraction.extraction_run`, `extraction.extracted_field` (provenance)
- `expenses.expense_item`, `expenses.expense_item_evidence`
- `fx.rate_snapshot`, `fx.rate_source`
- `policy.rule`, `policy.violation`, `policy.check_result`
- `workflow.task`, `workflow.comment`, `workflow.approval`
- `audit.event_log` (append-only)
- `exports.export_run`, `exports.export_artifact`

Indexes to include early:

- Unique keys for duplicate detection: `(vendor, vendor_reference)` where possible (Grab booking ID, United reference number)
- `raw_text_hash` on evidence documents
- `(claim_id, status)` on claims and tasks

---

## 8) Extraction pipeline (PDF/images/xlsx)

### 8.1 Principles

- **Asynchronous by default** (Celery): extraction can be slow and should not block uploads.
- **Provenance-first:** every extracted value stores `(source_file_id, evidence_document_id, page, extractor_version, confidence)`.
- **Idempotent:** re-processing uses content hashes and vendor reference keys to avoid duplicates.
- **Pluggable parsers:** add new vendor types without changing the ingestion workflow.

### 8.2 Steps

1. **Text extraction**
   - PDF with embedded text: extract via a PDF text extractor.
   - Image-based PDF: OCR fallback (choose one):
     - Open source: Tesseract-based OCR (container dependency)
     - Cloud: Textract/Document AI (later; costs but high accuracy)
2. **Segmentation**
   - For a PDF bundle, split into `EvidenceDocument`s.
   - Heuristics for the sample bundle:
     - Start boundaries at lines like `Subject:` or headers like `PAYMENT RECEIPT / RECU DE PAIEMENT`
     - Group multi-page receipts (e.g., Grab receipts are 2 pages; Uber summaries are 3 pages)
3. **Classification**
   - Identify `(vendor, receipt_type)` using keywords and structural markers:
     - Grab: `Your Grab E-Receipt`, `Booking ID`
     - Uber: `Your ... trip with Uber`, `This is not a payment receipt`
     - United: `Thanks for your purchase with United`, `Inflight Wi‑Fi`
     - Airline payment receipt: `PAYMENT RECEIPT`, `BAG FEE`
4. **Parsing**
   - Vendor-specific parsers output normalized `ExpenseItemCandidate` objects.
   - Merge candidates into canonical `ExpenseItem` records linked to evidence docs.
5. **Validation + policy**
   - Structural validation: required fields per type (date, total, currency).
   - Policy checks: trip summary vs payment receipt, required metadata, thresholds.

### 8.3 Vendor parser outputs (initial)

- **Grab ride receipt**
  - booking_id, ride_type, pickup_date, pickup/dropoff locations + times, distance + unit, duration, total, breakdown components, paid_by_last4
- **Uber trip summary**
  - trip_date, pickup/dropoff locations + times, distance + unit, duration, total, breakdown line items, “not a payment receipt” flag
- **United ancillary receipt**
  - flight_number, route, travel date/time (if needed), purchase_date, item_description, reference_number, total, payment_last4
- **Airline bag fee payment receipt**
  - pnr/receipt reference (if present), fee description, taxes, total, payment_last4

### 8.4 XLSX handling

- Phase 1: treat XLSX as an **export format** (generate an equivalent summary).
- Optional migration feature: ingest existing XLSX summaries to bootstrap claims, but keep it separate from receipt extraction.

---

## 9) Policy & validation engine

### 9.1 Policy rule model

Each policy rule:

- Has an identifier and version (for audit and reproducibility).
- Runs against a scope:
  - `ExpenseItem` (e.g., “Uber receipt must be a payment receipt”)
  - `Claim` (e.g., “Claim purpose required”)
- Outputs one of: `PASS`, `WARN`, `FAIL`, `NEEDS_INFO`
- Creates structured evidence:
  - human explanation
  - impacted fields/items
  - suggested remediation steps

### 9.2 Initial rules (based on README + sample receipts)

- **R001 — Claim purpose required**: claim cannot be submitted without `purpose`.
- **R002 — Travel period required**: require start/end date.
- **R010 — Uber trip summary not acceptable**: if `vendor=Uber` and `receipt_type=trip_summary`, flag `NEEDS_INFO`/`FAIL` depending on policy; request payment receipt.
- **R020 — Missing business/personal signal**: if receipt indicates `Profile=PERSONAL` (Grab), require employee attestation or additional context.
- **R100 — Meal > threshold requires attendees**: if category is meals and amount > 100 (configurable), require attendee list.
- **R200 — Hotel nightly cap**: hotel nightly rate must be <= 300 USD (configurable; requires lodging line item + nights).
- **R210 — Flight class rule**: flights < 6 hours must be economy (requires flight metadata; likely a later enhancement).

### 9.3 Remediation tasks

Policy engine creates tasks in `workflow.task` such as:

- “Upload payment receipt for Uber trip on Sep 2”
- “Add business purpose”
- “Add attendees for meal expense”

---

## 10) Workflow and states

### 10.1 Claim status state machine

- `DRAFT` → `PROCESSING` (after upload)
- `PROCESSING` → `NEEDS_EMPLOYEE_REVIEW` (extraction complete; tasks exist)
- `NEEDS_EMPLOYEE_REVIEW` → `SUBMITTED` (employee attests, resolves tasks)
- `SUBMITTED` → `NEEDS_APPROVER_REVIEW` (routing decision)
- `NEEDS_APPROVER_REVIEW` → `APPROVED` | `CHANGES_REQUESTED` | `REJECTED`
- `APPROVED` → `READY_FOR_PAYMENT` → `PAID`

All transitions emit audit events.

### 10.2 Roles and permissions (minimum)

- **Employee:** create/edit own drafts; submit; view decision.
- **Approver:** view assigned claims; comment; approve/request changes/reject.
- **Admin/Finance:** manage policies; manage users; mark paid; run exports.

---

## 11) API surface (FastAPI)

This is a suggested v1 (REST). Exact shapes can evolve.

**Claims**

- `POST /claims` create claim
- `GET /claims/{id}` claim details + items + status + tasks
- `PATCH /claims/{id}` update metadata (purpose, travel period)
- `POST /claims/{id}/submit`
- `POST /claims/{id}/route` (admin/system) assign approver(s)

**Documents & uploads**

- `POST /claims/{id}/documents` upload (multipart)
- `GET /documents/{id}` metadata
- `POST /documents/{id}/reprocess` rerun extraction
- `GET /documents/{id}/download` signed URL

**Expenses**

- `GET /claims/{id}/items`
- `PATCH /items/{id}` edit category/fields with audit reason
- `POST /claims/{id}/items/manual` manual line item entry
- `POST /items/{id}/link-evidence` attach/detach evidence documents

**Policy + tasks**

- `GET /claims/{id}/policy` all policy results
- `POST /tasks/{id}/resolve` resolve with data (attendees, explanations, uploads)

**Approvals**

- `GET /approvals/inbox`
- `POST /claims/{id}/approve`
- `POST /claims/{id}/request-changes`
- `POST /claims/{id}/reject`

**Exports**

- `POST /claims/{id}/exports` generate export package
- `GET /exports/{id}` status + artifacts

---

## 12) Observability & audit

- Structured JSON logging with request IDs and claim IDs.
- Background jobs log extraction stages with timings + failure reasons.
- `audit.event_log` records:
  - actor (user/system)
  - event type (CLAIM_SUBMITTED, ITEM_EDITED, POLICY_FAILED, APPROVAL_GRANTED, …)
  - payload (diffs and references)

---

## 13) Deployment (Railway)

Deploy two services from the same repo:

- `web`: FastAPI (uvicorn/gunicorn)
- `worker`: Celery worker

Provisioned add-ons:

- Postgres
- Redis
- S3-compatible object storage (or Railway volume + later migrate)

Migrations:

- Run Alembic migrations automatically on deploy (or via a release phase).

---

## 14) Implementation plan (phased)

### Phase 0 — Foundations (1–2 weeks)

- Repo structure for modular monolith (module boundaries + shared kernel).
- FastAPI skeleton, config management, DB connection, migrations.
- Identity (basic auth) + role model.
- S3 integration and document upload endpoint.

### Phase 1 — Claim + upload flow (1–2 weeks)

- Claim CRUD + state machine scaffolding.
- Upload multiple documents per claim.
- Background extraction job pipeline stub (store extracted text + “needs parsing” state).
- Basic UI/API responses for “processing” and “results pending”.

### Phase 2 — Extraction MVP for sample vendors (2–3 weeks)

- Implement PDF text extraction + segmentation for multi-receipt bundles.
- Implement vendor classifiers + parsers:
  - Grab ride receipt
  - Uber trip summary
  - United Wi‑Fi receipt
  - Airline baggage fee payment receipt
- Persist normalized `ExpenseItem`s with evidence + provenance.
- Duplicate detection using vendor reference IDs and text hashes.

### Phase 3 — Employee review experience (1–2 weeks)

- “Generated summary” view: list items, totals, currencies, evidence links.
- Edit flow with audit reason.
- Manual item add + merge/split item tools (minimal version).

### Phase 4 — Policy engine MVP (1–2 weeks)

- Rule framework + versioning.
- Implement initial rules (purpose/travel period required; trip-summary warning; threshold tasks).
- Task creation and resolution endpoints.

### Phase 5 — Approvals + export (2–3 weeks)

- Approver inbox + decision endpoints + comments.
- Export generator producing:
  - Excel summary matching the template columns
  - “supporting documents” bundle (PDF merge or zip)
- Status transitions: APPROVED → READY_FOR_PAYMENT.

### Phase 6 — Hardening & scale (ongoing)

- OCR integration for scans.
- Better segmentation (ML-assisted) and receipt classification.
- Additional policy rules (hotel caps, flight class based on duration).
- Observability dashboards, rate source management for FX.
- Optional: multi-entity (multiple companies) support.

---

## 15) Appendix: design choices to keep it a “modular monolith”

To avoid an unstructured “big ball of mud”:

- Enforce module imports (only through module public APIs).
- Keep DB access within a module’s infrastructure layer; expose repositories/services via interfaces.
- Prefer domain events + application services over cross-module table joins.
- Treat “Extraction” as a subsystem with clear contracts (input: evidence docs; output: candidates + provenance).