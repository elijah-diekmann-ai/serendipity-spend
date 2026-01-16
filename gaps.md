# Serendipity Spend — Gaps

## Problem Statement

Currently, employees who wish to claim travel expenses send invoices and receipts directly to me (for example, hotel confirmation emails, Uber receipts, etc.). I then manually review these items and prepare a summary table in Excel. As part of this process, I check each item for compliance with the Travel Policy, such as ensuring hotel rates do not exceed USD 300 per night and that flights under six hours are booked in economy class.

This process is entirely manual, time-consuming, and prone to errors, including incorrect amounts and potential duplication.

Ideally, the process would be streamlined as follows:

1. Employees upload all relevant supporting documents to a portal, which automatically generates a claim summary.
2. Automated checks are performed against the Travel Policy, with any inconsistencies clearly flagged at the summary level.
3. Employees review the generated summary to confirm accuracy and completeness, fill in any missing information (for example, trip purpose, or names of attendees for food and beverage expenses over USD 100), and address any flagged items.
4. The summary and supporting documents are then routed to me for review and approval prior to payment.

---

## Areas to Investigate

### Receipt Extraction

Current parsers handle Grab, Uber, United Wi-Fi, and baggage fees only.

Evaluate coverage for: hotels, flights, restaurants, and general receipts. Determine how unrecognized formats should be handled.

### Policy Rules

Current checks: missing purpose, travel dates, FX rates, and vendor-specific warnings.

Review the full Travel Policy and identify which rules are not enforced.

### OCR Pipeline

Text extraction uses pypdf with Tesseract fallback.

Test against representative documents including scanned receipts and photos. Assess whether accuracy meets requirements.

### Input Channels

Documents are uploaded manually via the web portal.

The original workflow involves emailed receipts. Determine if email ingestion is needed.

### Batch Uploads

The current upload flow accepts one file at a time I believe.

Employees often have many receipts per trip (10-20+ images or PDFs). Uploading individually would be tedious. Investigate support for:

- Multi-file selection in a single upload
- Drag-and-drop of multiple files
- ZIP file upload containing multiple receipts
- Processing multiple images/PDFs as separate line items from one upload

---

## Next Steps

Identify specific deficiencies in each area and implement solutions. Keep the solutions minimal and simple but ensure the system fully solves the core problem statement above and addresses remaining gaps.