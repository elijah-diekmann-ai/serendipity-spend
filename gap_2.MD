# Gap: Merged PDF Export

## Problem

Export produces `supporting.zip` (archive of files) instead of a single merged PDF.
Finance workflow requires one combined PDF like `DC_OOP_05 Sep 2025.pdf`.

## Current behavior

- `Summary.xlsx` — generated
- `supporting.zip` — all receipts as separate files in archive

The system is functional but two gaps remain:
1. **Merged PDF export** — implement single PDF instead of ZIP
2. **Output verification** — compare generated Excel/PDF against reference files in `Data/` to ensure column headers, formatting, and structure match the expected output.

## Required behavior

- `Summary.xlsx` — generated
- `Supporting_Documents.pdf` — all receipts merged into one PDF

## Implementation

1. Convert uploaded images (JPEG, PNG) to PDF pages
2. Merge all PDFs into single document
3. Order pages chronologically or by expense item

## Reference (critical)

See `Data/` directory for expected output format:
- `Data/DC__OOP__05 Sep 2025.pdf` — example merged PDF
- `Data/Travel Reimbursement_DC_Jan 2026.xlsx` — example Excel format

---

## Context: The Problem We're Solving

**Current state (manual):**
Employees send receipts (hotel emails, Uber receipts, etc.) directly to finance. Finance manually reviews each item, compiles an Excel summary, checks policy compliance (hotel rates < $300/night, economy class for <6hr flights), and bundles supporting documents into a PDF.

**Pain points:** Time-consuming, error-prone, potential duplicates, no audit trail.

**Ideal state (automated):**
1. Employees upload supporting documents to a portal
2. System auto-generates claim summary with policy checks flagged
3. Employees review, fill missing info (trip purpose, meal attendees), resolve flags
4. Claim routes to approver for review/approval prior to payment

**Expected output:** Excel summary + merged PDF of supporting documents.