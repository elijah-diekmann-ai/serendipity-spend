# Serendipity Spend — Known Gaps

This document outlines areas where the current implementation does not fully address the stated requirements. Each gap requires investigation to determine the appropriate solution.

---

## 1. Receipt Coverage

The extraction layer only handles four receipt types: Grab, Uber, United Wi-Fi, and airline baggage fees.

Common expense categories remain unhandled:
- Hotel invoices and confirmation emails
- Flight itineraries and boarding passes
- Restaurant and food/beverage receipts
- Generic expense receipts (taxis, office supplies, etc.)

Unknown receipt formats are currently skipped without extraction.

---

## 2. Policy Rule Coverage

The policy engine checks for missing claim metadata (purpose, travel dates, FX rates) and flags specific vendor issues (Uber trip summaries, Grab personal profiles).

The following rules from the Travel Policy are not implemented:
- Hotel nightly rate limits
- Flight class restrictions based on duration
- Attendee documentation requirements for meal expenses above thresholds

The policy rule set should be reviewed against the full Travel Policy document.

---

## 3. OCR Accuracy

Text extraction relies on pypdf with Tesseract OCR as a fallback for image-based pages.

This approach may produce unreliable results for:
- Scanned paper receipts
- Photographed documents
- Receipts with non-Latin scripts
- Low-resolution images

The OCR pipeline should be evaluated against representative sample documents.

---

## 4. Input Channels

The system accepts documents via manual file upload only.

The original workflow describes employees forwarding receipts via email. There is no mechanism to ingest emailed documents or attachments.

---

## Next Steps

Review each gap area, identify specific deficiencies in the codebase, and implement solutions that handle real-world document variability.

