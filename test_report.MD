# E2E Extraction Test Report

**Claim**: `f655c165-986e-4ff0-abc0-8a1a985d15ea`  
**Request**: `64f9ab64-dd71-44f9-b6b1-17f383dd587d`

---

## Coverage

- 10 uploads → 11 SourceFiles (Agoda .eml unpacked into email-body + Receipt.pdf) → 11 Celery tasks
- All SourceFile.status=PROCESSED
- 9 unique ExpenseItems; Receipt.pdf uploaded twice was deduped (action=existing on expense_item_id ff65259a-04ce-41e1-b7ab-e3f3642dbb1c)
- 1 unparsed (Agoda email-body — no receipt content)
- 17 policy violations

---

## Mismatches (vs receipts.md)

### Critical (2 items)

**Uber Tue 13 Jan 12:38** (`Fwd_ Your Tuesday afternoon trip with Uber.eml`)
- Expected: USD 40.26, 2026-01-13, transport
- Actual: USD 40.00, 2026-01-14, meals, vendor "Richard Catlin"
- expense_item_id: `3d4f4c0d-2d95-4758-9a5f-2adb6ea3f59a`
- parser: generic, parse_failures: `vendor:unsupported_vendor;ai_text:ai_total_not_correlated`
- text_hash: `37f8dbc0653ce24b5a84e4d88231f4c3e0d25ff37cc23536f7811e3a9e07dcc1`
- **Root Cause**: AI fallback failed, generic parser extracted $40.00 from line items (missed $5 tip). Vendor from email header.

**Air Canada WiFi** (`Fwd_ Heres_Your_Air_Canada_Receipt...eml`)
- Expected: CAD 8.40, 2026-01-11
- Actual: XXX 8.40, 2026-01-12, vendor "Richard Catlin"
- expense_item_id: `64b1c322-4914-48f7-8acb-81aec1ca5a46`
- parser: generic, parse_failures: `vendor:unsupported_vendor;ai_text:ai_total_not_correlated`
- text_hash: `eda2c1a42780ed239d8efd4c0cb1cfaf9c3aa3ecd36b1ba2bb6eded4e174a43b`
- **Root Cause**: Generic parser matched `$8.40` but missed trailing `CAD` in `$8.40 CAD` format.
- Policy: R030 (missing FX), R031 (invalid currency XXX), R121/R122 (airfare fields missing)

---

### Minor (2 items)

**Lenox hotel** (`The Lenox - Boston - 12-13th Jan.jpg`)
- Amount correct: USD 296.95, hotel_nights=1
- Issue: transaction_date is NULL
- expense_item_id: `01c8bcb8-16b1-4631-978c-fa59a633483f`
- parser: ai_image, text_hash: `5b55f8c3091695029957e85781e05f9690ecadf898351e3bc6ef8190d60c35d8`
- **Root Cause**: AI didn't extract date from booking screenshot.

**Uber Mon morning Toronto** (CAD receipt)
- Amount correct: CAD 16.15, 2026-01-12
- Issue: amount_home_amount is NULL (no CAD→SGD FX rate)
- expense_item_id: `c8372498-6049-46a9-a3f2-5e0e976d0707`
- Policy: R030 OPEN

---

### Unparsed

**Agoda email-body** (source_file_id `d2ce66af-9961-4989-bbc6-bbce8a63251f`)
- extraction.text.unparsed — email body only contains forwarding text, no receipt data
- parse_failures: `vendor:unsupported_vendor;ai_text:ai_missing_total;generic:generic_missing_total`
- Task opened: `EXTRACT_d2ce66af9961`
- Note: Attached Receipt.pdf parsed correctly → lodging SGD 247.08 (1 night)

---

## Correct Items (6)

| Receipt | Amount | Date |
|---------|--------|------|
| Uber Tue afternoon #1 | US$26.62 | Jan 13 |
| Uber Tue morning | US$33.58 | Jan 13 |
| Uber Mon afternoon | US$35.53 | Jan 12 |
| Uber Mon morning (Boston) | US$33.56 | Jan 12 |
| Uber Mon morning (Toronto) | CA$16.15 | Jan 12 |
| Agoda hotel (PDF) | SGD 247.08 | Jan 12 |

---

## Parser Outcomes

| Parser | Success | Failures | Notes |
|--------|---------|----------|-------|
| `vendor:Uber` | 0 | 6 | All Uber emails failed (email format, not PDF bundle) |
| `ai_text` | 5 | 2 | 2 failed with `ai_total_not_correlated` |
| `ai_image` | 1 | 0 | The Lenox hotel |
| `ai_page` | 1 | 0 | Agoda Receipt.pdf |
| `generic` | 2 | 0 | Air Canada & Uber #2 (both with issues) |

---

## Policy Violations (17)

| Rule | Severity | Count | Description |
|------|----------|-------|-------------|
| R030 | NEEDS_INFO | 2 OPEN | Missing FX rate (CAD, XXX) |
| R040 | NEEDS_INFO | 9 OPEN | Generic extraction, needs review |
| R121 | NEEDS_INFO | 1 OPEN | Airfare missing flight duration |
| R122 | NEEDS_INFO | 1 OPEN | Airfare missing cabin class |
| R001 | FAIL | RESOLVED | Purpose filled |
| R002 | FAIL | RESOLVED | Travel dates filled |