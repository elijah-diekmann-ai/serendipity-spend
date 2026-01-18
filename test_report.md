# E2E Receipt Extraction Test Report (Railway)

Claim ID: `e1ab2b64-60e2-4bb1-a9df-04b5e2540877`

## Run Context

- Environment: Railway `production` (`web` + `worker`)
- Upload request_id: `c74a4da6-e695-41fa-a62a-221eb5571481`
- Upload window (web `upload.received`): `2026-01-18T10:25:13.228446Z` → `2026-01-18T10:25:20.052476Z`
- Extraction window (worker `extraction.finish`): `2026-01-18T10:25:17.493971Z` → `2026-01-18T10:25:26.210774Z`

## Coverage Summary

- Receipts uploaded (original attachments): **10**
- Unique `SourceFile` rows created/deduped: **9**
  - `Receipt.pdf` was uploaded directly and also attached inside `Fwd_ Agoda - Customer Receipt...eml`; it deduped by `(sha256, byte_size)` so only 1 `SourceFile` exists.
- `EvidenceDocument` rows: **9**
- `ExpenseItem` rows: **9**
- Unparsed segments/pages: **0**
- Extraction errors: **none observed** (`extraction.error` not present in the time window)

## Parsed Items (DB Snapshot)

| Vendor | Receipt Type | Category | Date | Amount (Orig) | Amount (Home) | Vendor Ref | Evidence Document | Text Hash |
|---|---|---|---|---:|---:|---|---|---|
| DoubleTree by Hilton Toronto Airport | hotel_receipt | lodging | 2026-01-12 | SGD 247.08 | SGD 247.08 | 1687271287 | 0e135897-76c3-4cd3-85ed-96bc8f971a03 | 3d6eabf74e653e4850a06d04484b429a3714b8b509ab56bd9970d5b46fdb8a53 |
| Wi-Fi Onboard | wifi_receipt | travel_ancillary | 2026-01-11 | CAD 8.40 | SGD 7.79 | 422793475SUAC | 983dbd49-6856-440e-a0ce-4d491b458ddd | eda2c1a42780ed239d8efd4c0cb1cfaf9c3aa3ecd36b1ba2bb6eded4e174a43b |
| Uber | trip_summary | transport | 2026-01-12 | CAD 16.15 | SGD 14.98 |  | 7f674bdf-3d6e-445c-b972-cf51163e0e7a | e48442584c76a283cffe1c1462106b3d83b0bcb3e469a410bfbff4c52199c468 |
| Uber | trip_summary | transport | 2026-01-12 | USD 33.56 | SGD 43.22 |  | 6acc2666-825b-4560-92fd-493729d5cc7b | 2c9a25294b45d5f8576f94d63ba94035cd21ca71cd26eed004f426bc45d9a8fb |
| Uber | trip_summary | transport | 2026-01-12 | USD 35.53 | SGD 45.76 |  | 261a0707-5cf0-4e81-afa7-e0deb712921b | ccde980df4dc4287ad66e65164e096aaf369114e4484300d9e41897d0cc89f5f |
| The Lenox | generic_receipt | lodging | 2026-01-12 | USD 296.95 | SGD 382.44 |  | 44bf1212-0d63-409b-b4c1-101188bbc87a | 5b55f8c3091695029957e85781e05f9690ecadf898351e3bc6ef8190d60c35d8 |
| Uber | trip_summary | transport | 2026-01-13 | USD 33.58 | SGD 43.25 |  | 8e8f808a-acc2-417c-bdbd-4b9fab92f75a | d112af99ea8d65f624c7e811f6b11e04a9e2df9c8dfc3f33aa9a1c16d364a811 |
| Uber | trip_summary | transport | 2026-01-13 | USD 40.26 | SGD 51.85 |  | 7490b6f8-bab2-4759-8234-5e7226ca6737 | 37f8dbc0653ce24b5a84e4d88231f4c3e0d25ff37cc23536f7811e3a9e07dcc1 |
| Uber | trip_summary | transport | 2026-01-13 | USD 26.62 | SGD 34.28 |  | 872eb0e2-a913-4569-b976-064720b45cba | 9846f1e6e2cb3b35eeed3ab368032a55ffc7aa3dd0c0f6dcad811e1b3f1dd6a8 |

## Parser Outcome (Logs)

All receipts were parsed successfully. Only the hotel image required AI fallback because the initial vendor classification was `Unknown`.

| Source File ID | Filename | Kind | Parsed Event | Vendor | Receipt Type | Parser Used | Parse Failures | Evidence Document | Text Hash |
|---|---|---|---|---|---|---|---|---|---|
| 0b463808-fe04-42f1-8921-abb1dfea0f5f | email-body-Fwd_Your_Monday_morning_trip_with_Uber.txt | text | extraction.text.parsed | Uber | trip_summary | vendor |  | 7f674bdf-3d6e-445c-b972-cf51163e0e7a | e48442584c76a283cffe1c1462106b3d83b0bcb3e469a410bfbff4c52199c468 |
| 3d832db2-d5a9-4ef8-acca-17b39660d8a3 | email-body-Fwd_Your_Monday_afternoon_trip_with_Uber.txt | text | extraction.text.parsed | Uber | trip_summary | vendor |  | 261a0707-5cf0-4e81-afa7-e0deb712921b | ccde980df4dc4287ad66e65164e096aaf369114e4484300d9e41897d0cc89f5f |
| 402e55a1-5c01-447c-86e6-2b461567848a | email-body-Fwd_Heres_Your_Air_Canada_Receipt_-_Order_422793475SUAC.txt | text | extraction.text.parsed | Wi-Fi Onboard | wifi_receipt | vendor |  | 983dbd49-6856-440e-a0ce-4d491b458ddd | eda2c1a42780ed239d8efd4c0cb1cfaf9c3aa3ecd36b1ba2bb6eded4e174a43b |
| 5c95ad2e-f6d6-4765-8d86-5a4affdb618e | email-body-Fwd_Your_Tuesday_afternoon_trip_with_Uber.txt | text | extraction.text.parsed | Uber | trip_summary | vendor |  | 872eb0e2-a913-4569-b976-064720b45cba | 9846f1e6e2cb3b35eeed3ab368032a55ffc7aa3dd0c0f6dcad811e1b3f1dd6a8 |
| 606581c0-2a29-4563-ad56-91ff63225d7c | email-body-Fwd_Your_Tuesday_morning_trip_with_Uber.txt | text | extraction.text.parsed | Uber | trip_summary | vendor |  | 8e8f808a-acc2-417c-bdbd-4b9fab92f75a | d112af99ea8d65f624c7e811f6b11e04a9e2df9c8dfc3f33aa9a1c16d364a811 |
| 9d060510-7c7a-43d8-bc9f-541b8ca23425 | Receipt.pdf | pdf | extraction.page.parsed | DoubleTree by Hilton Toronto Airport | hotel_receipt | vendor |  | 0e135897-76c3-4cd3-85ed-96bc8f971a03 | 3d6eabf74e653e4850a06d04484b429a3714b8b509ab56bd9970d5b46fdb8a53 |
| 9d69bb03-4a07-4a70-8941-f3e789ee966e | email-body-Fwd_Your_Tuesday_afternoon_trip_with_Uber.txt | text | extraction.text.parsed | Uber | trip_summary | vendor |  | 7490b6f8-bab2-4759-8234-5e7226ca6737 | 37f8dbc0653ce24b5a84e4d88231f4c3e0d25ff37cc23536f7811e3a9e07dcc1 |
| 9ea2a09a-ab51-47e4-b324-fc200fe85575 | email-body-Fwd_Your_Monday_morning_trip_with_Uber.txt | text | extraction.text.parsed | Uber | trip_summary | vendor |  | 6acc2666-825b-4560-92fd-493729d5cc7b | 2c9a25294b45d5f8576f94d63ba94035cd21ca71cd26eed004f426bc45d9a8fb |
| a3c252ca-38de-4842-8cbd-397fef5dcca1 | The Lenox - Boston - 12-13th Jan.jpg | image | extraction.image.parsed | The Lenox | generic_receipt | ai_image | vendor:unsupported_vendor | 44bf1212-0d63-409b-b4c1-101188bbc87a | 5b55f8c3091695029957e85781e05f9690ecadf898351e3bc6ef8190d60c35d8 |

## Validation vs `receipts.md`

### Non-Uber receipts

- `Receipt.pdf` (Agoda): **PASS**
  - Booking `1687271287`, Payment Date `2026-01-12`, Stay `2026-01-11 → 2026-01-12 (1 night)`, Total Charge `SGD 247.08` (also captured USD total in `metadata_json.amounts_by_currency`).
  - Evidence: `0e135897-76c3-4cd3-85ed-96bc8f971a03` / `3d6eabf74e653e4850a06d04484b429a3714b8b509ab56bd9970d5b46fdb8a53`.

- `The Lenox - Boston - 12-13th Jan.jpg`: **PASS**
  - Total Charge `USD 296.95`; `hotel_nights=1`; dates inferred from filename into `hotel_check_in=2026-01-12`, `hotel_check_out=2026-01-13`.
  - Evidence: `44bf1212-0d63-409b-b4c1-101188bbc87a` / `5b55f8c3091695029957e85781e05f9690ecadf898351e3bc6ef8190d60c35d8`.

- `Fwd_ Here's Your Air Canada Receipt - Order #422793475SUAC.eml`: **PASS**
  - Order `422793475SUAC`; Total paid `CAD 8.40`; Date `2026-01-11`.
  - Evidence: `983dbd49-6856-440e-a0ce-4d491b458ddd` / `eda2c1a42780ed239d8efd4c0cb1cfaf9c3aa3ecd36b1ba2bb6eded4e174a43b`.

### Uber receipts (key field extraction)

Amounts/currencies/dates/categories for all Uber receipts match `receipts.md` (**PASS** on core fields).

**Mismatch: Uber `metadata_json.breakdown` is incorrect/incomplete in the DB rows created by this run.**

| Receipt (by amount) | Expected breakdown (from `receipts.md`) | Actual breakdown (from DB `metadata_json.breakdown`) | Evidence |
|---|---|---|---|
| CA$16.15 (Mon 12 Jan 06:02) | 6 line items (Trip fare 7.97, insurance 0.84, HST 1.86, accessibility 0.10, fee 0.35, airport surcharge 5.03) | `null` | `7f674bdf-3d6e-445c-b972-cf51163e0e7a` / `e48442584c76a283cffe1c1462106b3d83b0bcb3e469a410bfbff4c52199c468` |
| US$33.56 (Mon 12 Jan 10:25) | 6 line items (Trip fare 21.86, AFC 5.50, Booking 1.74, MA surcharge 0.60, Toll 2.65, Wait 1.21) | `[{"label":"the payment is processed with payment information. Trip fare","currency":"USD","amount":"21.00"}]` | `6acc2666-825b-4560-92fd-493729d5cc7b` / `2c9a25294b45d5f8576f94d63ba94035cd21ca71cd26eed004f426bc45d9a8fb` |
| US$35.53 (Mon 12 Jan 12:59) | 3 line items (Trip fare 33.38, Booking 1.55, MA surcharge 0.60) | `[{"label":"the payment is processed with payment information. Trip fare","currency":"USD","amount":"33.00"}]` | `261a0707-5cf0-4e81-afa7-e0deb712921b` / `ccde980df4dc4287ad66e65164e096aaf369114e4484300d9e41897d0cc89f5f` |
| US$33.58 (Tue 13 Jan 10:40) | 3 line items (Trip fare 31.55, Booking 1.43, MA surcharge 0.60) | `[{"label":"the payment is processed with payment information. Trip fare","currency":"USD","amount":"31.00"}]` | `8e8f808a-acc2-417c-bdbd-4b9fab92f75a` / `d112af99ea8d65f624c7e811f6b11e04a9e2df9c8dfc3f33aa9a1c16d364a811` |
| US$40.26 (Tue 13 Jan 12:38) | 5 line items (Trip fare 32.41, Booking 1.55, Toll 0.70, MA surcharge 0.60, Tip 5.00) | `[{"label":"fare","currency":"USD","amount":"32.41"}]` | `7490b6f8-bab2-4759-8234-5e7226ca6737` / `37f8dbc0653ce24b5a84e4d88231f4c3e0d25ff37cc23536f7811e3a9e07dcc1` |
| US$26.62 (Tue 13 Jan 14:02) | 3 line items (Trip fare 24.53, Booking 1.49, MA surcharge 0.60) | `[{"label":"the payment is processed with payment information. Trip fare","currency":"USD","amount":"24.00"}]` | `872eb0e2-a913-4569-b976-064720b45cba` / `9846f1e6e2cb3b35eeed3ab368032a55ffc7aa3dd0c0f6dcad811e1b3f1dd6a8` |

**Mismatch: Uber trip details fields for the US$40.26 receipt**

- Expected: `ride_type=Comfort`, `pickup=12:43 — 9 Oxford St...`, `dropoff=13:01 — 600 Atlantic Ave...`, `driver=Emilio (4.98)`.
- Actual (DB `metadata_json`):
  - `ride_type=Comfort` and pickup fields were captured.
  - `dropoff_location` contains duplicated pickup/dropoff text and the driver string appended.
  - `driver_name` / `driver_rating` were not populated.

## Root Cause Analysis

### Uber breakdown extraction

The Uber email HTML-to-text output sometimes concatenates tokens without whitespace, e.g.:

- `US$21.86Airport Facility Charge ...`
- `CA$0.84HST ...`

The breakdown regex requires a word boundary after the amount. When a decimal amount is immediately followed by a letter (`...21.86Airport...`), `\b` does **not** match (both `6` and `A` are “word chars”), so the regex fails to capture the decimal amount and/or subsequent items. Additionally, the original “tail cutoff” used `payments` as a stop word, which truncated the breakdown at the valid line item label `Estimated insurance and payments costs`.

### Uber trip details for US$40.26

The trip details block contained concatenations like `USYou rode with ...` and duplicated pickup/dropoff segments. This caused:

- the pickup/dropoff parser to include extra text in `dropoff_location`
- the driver regex not to match `You rode with ...`

### Extraction log completeness

Because `SourceFile` dedupe can enqueue multiple Celery tasks for the same `source_file_id`, the worker can log `extraction.start` and then immediately return when the source is already `PROCESSED`, leading to `extraction.start` without a corresponding `extraction.finish`.

## Proposed Fixes (Implemented Locally)

1) Fix Uber metadata extraction (`breakdown`, `dropoff_location`, driver fields)

- File: `src/serendipity_spend/modules/extraction/parsers/uber.py`
- Changes:
  - Make `_clean_for_regex` insert missing spaces between digits/letters and some concatenated “CamelCase” tokens.
  - Stop truncating breakdown on `payments` (valid Uber line item label contains this word).
  - Tighten breakdown label matching to avoid pulling in preceding sentence fragments.
  - Trim duplicate time blocks out of `dropoff_location`.
  - Make “You rode with …” extraction case-insensitive.

Validation (local): re-running `parse_uber_email_receipt()` on the stored `EvidenceDocument.extracted_text` for the six Uber evidence docs yields the expected line items and correct trip details (including driver name/rating for US$40.26).

2) Make extraction logs consistent for skipped work

- File: `src/serendipity_spend/modules/extraction/service.py`
- Change: emit an `extraction.finish` log with `status=\"skipped\"` when a source file is already processed or already being processed.

3) Remove non-core policy noise for Uber trip summaries (R010)

- Root cause: `R010` is emitted unconditionally for every `Uber` `trip_summary`, including cases that are actual payment receipts, creating distracting false positives.
- Fix: remove `R010` from `evaluate_claim` so it no longer produces `PolicyViolation` / `POLICY_R010` tasks.
- File: `src/serendipity_spend/modules/policy/service.py`
- Note: existing `R010` violations/tasks on this claim will auto-resolve on the next policy evaluation after deploy.

## Notes / Next Steps

- The fixes above will affect **future extractions** after deploy. This claim’s current `ExpenseItem.metadata_json` will not update unless extraction is re-run.
- Re-validation recommendation: create a new claim and upload the same receipts (same-claim `SourceFile` dedupe prevents reprocessing identical uploads).
