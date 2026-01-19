# E2E Receipt Extraction Test Report (Railway / production)

## Run Metadata

- `claim_id`: `56d0536b-fa94-49a6-9bbc-43ddfa8040a1`
- Upload batch correlation: `request_id=28122c9b-885f-45b1-b8a1-343e5d6d5f52`
- Time window (from logs): `2026-01-19T02:35:19Z` → `2026-01-19T02:35:44Z`
- Services observed: `web` (`upload.received`, `upload.unpack.*`, `celery.task.enqueued`), `worker` (`celery.task.*`, `extraction.*`, `expense_item.upsert`)

## Inputs (Uploads)

10 uploads were received by `web` (`upload.received`). `.eml` uploads were unpacked into child SourceFiles (`upload.unpack.finish`).

| Uploaded file | Ingested SourceFile(s) | Notes |
|---|---|---|
| `Receipt.pdf` | `Receipt.pdf` (`source_file_id=98fc366a-2218-4437-8b10-a20a90313fa7`) | Direct PDF ingest + extraction task enqueued |
| `Fwd_ Agoda - Customer Receipt from Booking ID_ 1687271287.eml` | `Receipt.pdf` (`source_file_id=98fc366a-2218-4437-8b10-a20a90313fa7`) | `upload.unpack.finish` shows `deduped_count=1` (attachment PDF deduped to the already-uploaded `Receipt.pdf`); no additional extraction task enqueued |
| `Fwd_ Here's Your Air Canada Receipt - Order #422793475SUAC.eml` | `email-body-…422793475SUAC-eda2c1a4.txt` (`source_file_id=152b4dac-f4d8-421c-b833-c5e6cd813d43`) | `.eml` body ingested as text child + extraction task enqueued |
| `Fwd_ Your Monday morning trip with Uber.eml` | `email-body-…Uber-e4844258.txt` (`source_file_id=7be9dad9-0d29-482c-af28-9cde3fb58908`) | `.eml` body ingested as text child + extraction task enqueued |
| `Fwd_ Your Monday morning trip with Uber_1.eml` | `email-body-…Uber_1-2c9a2529.txt` (`source_file_id=c57ffd54-b3a7-4e52-96bd-b354869cf6bb`) | `.eml` body ingested as text child + extraction task enqueued |
| `Fwd_ Your Monday afternoon trip with Uber.eml` | `email-body-…Uber-ccde980d.txt` (`source_file_id=15981080-18a2-4056-b877-fecdd3578d50`) | `.eml` body ingested as text child + extraction task enqueued |
| `The Lenox - Boston - 12-13th Jan.jpg` | `The Lenox - Boston - 12-13th Jan.jpg` (`source_file_id=011c1b89-878c-4b7c-b2bb-52de644b21a1`) | Direct image ingest + extraction task enqueued |
| `Fwd_ Your Tuesday morning trip with Uber.eml` | `email-body-…Uber-d112af99.txt` (`source_file_id=04ec9566-a55b-46b2-98fd-ea05cb7ff177`) | `.eml` body ingested as text child + extraction task enqueued |
| `Fwd_ Your Tuesday afternoon trip with Uber.eml` | `email-body-…Uber-37f8dbc0.txt` (`source_file_id=e3d8da24-8964-4c72-89b7-f2ed59bc3f55`) | `.eml` body ingested as text child + extraction task enqueued |
| `Fwd_ Your Tuesday afternoon trip with Uber_1.eml` | `email-body-…Uber_1-9846f1e6.txt` (`source_file_id=e7d78bf2-8617-4ee5-96c5-df6f3c165895`) | `.eml` body ingested as text child + extraction task enqueued |

## Coverage Summary

- Uploads received: `10`
- `.eml` containers unpacked: `8` (each produced `child_count=1`)
- SourceFiles created for this claim (`documents_source_file`): `9` (all `status=PROCESSED`)
- Extraction tasks enqueued (`celery.task.enqueued`): `9`
- Extraction outcomes (`worker`): `9` `extraction.start` → `9` `extraction.finish` (`status=success`)
- Parsed coverage: `9`/`9` SourceFiles produced an `expense_item.upsert`; `0` unparsed segments/pages
- Policy state (post-extraction): 3 OPEN violations in `policy_violation` (`R001`, `R002`, `R040`)

## Parsed Results (Actual)

All extracted items below were observed in `worker` logs (`expense_item.upsert`) and confirmed via DB queries (`expenses_expense_item` + evidence join).

| Upload | Vendor / receipt_type | Amount (orig) | Date | Category | Parser outcome | Evidence (`text_hash`) | Notes |
|---|---|---:|---|---|---|---|---|
| `Receipt.pdf` | `DoubleTree by Hilton Toronto Airport` / `hotel_receipt` | `247.08 SGD` | `2026-01-12` | `lodging` | `extraction.page.parsed` (`parser_used=vendor`, `parse_failures=[]`) | `3d6eabf74e653e4850a06d04484b429a3714b8b509ab56bd9970d5b46fdb8a53` | `vendor_reference=1687271287`; metadata includes `hotel_nights=1`, `amounts_by_currency={USD:191.91, SGD:247.08}` |
| `Fwd_ Agoda - …1687271287.eml` | *(deduped to `Receipt.pdf`)* | *(same as above)* | *(same)* | *(same)* | `upload.unpack.finish` showed `deduped_count=1` | *(same as above)* | No new SourceFile/extraction run created for the `.eml` attachment |
| `Fwd_ Here's Your Air Canada Receipt - Order #422793475SUAC.eml` | `Wi-Fi Onboard` / `wifi_receipt` | `8.40 CAD` | `2026-01-11` | `travel_ancillary` | `extraction.text.parsed` (`parser_used=vendor`, `parse_failures=[]`) | `eda2c1a42780ed239d8efd4c0cb1cfaf9c3aa3ecd36b1ba2bb6eded4e174a43b` | `vendor_reference=422793475SUAC` |
| `Fwd_ Your Monday morning trip with Uber.eml` | `Uber` / `trip_summary` | `16.15 CAD` | `2026-01-12` | `transport` | `extraction.text.parsed` (`parser_used=vendor`, `parse_failures=[]`) | `e48442584c76a283cffe1c1462106b3d83b0bcb3e469a410bfbff4c52199c468` | `transaction_at=2026-01-12 11:02:00+00` (from receipt tz offset `-300`) |
| `Fwd_ Your Monday morning trip with Uber_1.eml` | `Uber` / `trip_summary` | `33.56 USD` | `2026-01-12` | `transport` | `extraction.text.parsed` (`parser_used=vendor`, `parse_failures=[]`) | `2c9a25294b45d5f8576f94d63ba94035cd21ca71cd26eed004f426bc45d9a8fb` | `transaction_at=2026-01-12 15:25:00+00` |
| `Fwd_ Your Monday afternoon trip with Uber.eml` | `Uber` / `trip_summary` | `35.53 USD` | `2026-01-12` | `transport` | `extraction.text.parsed` (`parser_used=vendor`, `parse_failures=[]`) | `ccde980df4dc4287ad66e65164e096aaf369114e4484300d9e41897d0cc89f5f` | `transaction_at=2026-01-12 17:59:00+00` |
| `The Lenox - Boston - 12-13th Jan.jpg` | `The Lenox` / `generic_receipt` | `296.95 USD` | `2026-01-12` | `lodging` | `extraction.image.classified` → `extraction.image.parsed` (`parser_used=ai_image`, `parse_failures=[\"vendor:unsupported_vendor\"]`) | `5b55f8c3091695029957e85781e05f9690ecadf898351e3bc6ef8190d60c35d8` | Classifier returned `vendor=Unknown`, `confidence=0.1`; AI extracted total + category, and dates were inferred from filename (`hotel_check_in=2026-01-12`, `hotel_check_out=2026-01-13`, `hotel_nights=1`) |
| `Fwd_ Your Tuesday morning trip with Uber.eml` | `Uber` / `trip_summary` | `33.58 USD` | `2026-01-13` | `transport` | `extraction.text.parsed` (`parser_used=vendor`, `parse_failures=[]`) | `d112af99ea8d65f624c7e811f6b11e04a9e2df9c8dfc3f33aa9a1c16d364a811` | `transaction_at=2026-01-13 15:40:00+00` |
| `Fwd_ Your Tuesday afternoon trip with Uber.eml` | `Uber` / `trip_summary` | `40.26 USD` | `2026-01-13` | `transport` | `extraction.text.parsed` (`parser_used=vendor`, `parse_failures=[]`) | `37f8dbc0653ce24b5a84e4d88231f4c3e0d25ff37cc23536f7811e3a9e07dcc1` | Extracted ride details (Comfort, pickup/dropoff, driver name/rating) in `metadata_json` |
| `Fwd_ Your Tuesday afternoon trip with Uber_1.eml` | `Uber` / `trip_summary` | `26.62 USD` | `2026-01-13` | `transport` | `extraction.text.parsed` (`parser_used=vendor`, `parse_failures=[]`) | `9846f1e6e2cb3b35eeed3ab368032a55ffc7aa3dd0c0f6dcad811e1b3f1dd6a8` | `transaction_at=2026-01-13 19:02:00+00` |

## Expected vs Actual (Key Fields)

### Matches (no discrepancies found)

- Amount + currency: all 9 extracted items match the totals in `receipts.md`.
- Dates: all items have the correct `transaction_date`; Uber items also have a consistent `transaction_at` derived from receipt timezone metadata.
- Lodging totals: Agoda receipt preserved both charged currency and USD total via `metadata_json.amounts_by_currency`.

### Mismatches / Gaps (expected data not captured or differently categorized)

- **Category label mismatch (minor):** `receipts.md` labels the Air Canada email as “Airfare”, but the extracted item is `category=travel_ancillary` because it is an in-flight Wi‑Fi purchase (`vendor=Wi‑Fi Onboard`, `Order 422793475SUAC`).
- **Payment method not extracted:** receipts mention `AMEX …3006` (Wi‑Fi Onboard + one Uber receipt), but no `payment_method`/`card_last4` is present in the corresponding `expenses_expense_item.metadata_json`.
- **Taxes/fees breakdown for hotel screenshot not extracted:** The Lenox screenshot includes a taxes/fees split and “Pay at check-in” semantics; extraction captured only the total and inferred stay dates (AI + filename inference).

## DB Sanity Checks (when logs were sufficient but verified)

- `documents_source_file`: 9 rows for this claim (all `PROCESSED`)
- `documents_evidence_document`: 9 rows (1 per SourceFile)
- `expenses_expense_item`: 9 rows; each linked to 1 evidence row via `expenses_expense_item_evidence`
- `policy_violation`: 3 OPEN rows
  - `R001` (purpose missing), `R002` (travel period missing): expected because the claim is still in a new/blank state
  - `R040` (confirm auto-extracted details): attached to the AI-extracted Lenox item (`expense_item_id=b26cca73-d0a9-4a19-9871-4fe782a16fca`)

## Recommendations (do not implement)

### Fixes (3)

1. **Make `.eml` dedupe behavior visible in the UI/doc list.** The Agoda `.eml` unpack deduped its `Receipt.pdf` attachment to an existing SourceFile (`upload.unpack.finish` shows `deduped_count=1`, `source_file_id=98fc366a-…`), which is correct but can look like an upload “did nothing” from the user’s perspective.
2. **Disambiguate Uber email receipts vs PDF “trip_summary” terminology.** Current extraction stores Uber email bodies as `receipt_type=trip_summary` (from `extraction.text.classified` + `expenses_expense_item.receipt_type`). If downstream workflows want to differentiate email vs PDF bundle receipts, introduce a distinct receipt_type (e.g., `email_receipt`) and map parsers accordingly.
3. **Add structured payment-method extraction where present.** Receipts include payment hints (e.g., `AMEX …3006` in `receipts.md`) but current vendor parsers don’t populate it in `metadata_json`. Add a small, vendor-agnostic “payment instrument” extractor (regex-based) and store `card_brand` + `card_last4` when confidently present.

### Robustness Improvements (3)

1. **Reduce reliance on AI for common “booking detail” screenshots.** The Lenox image was classified `vendor=Unknown` with `confidence=0.1` (`extraction.image.classified`) and required AI fallback (`parser_used=ai_image`). Add a format-agnostic lodging-screenshot heuristic/parser (look for “Booking Detail”, “Taxes And Fees”, “Total Charge”) to deterministically extract totals + stay dates even when AI is disabled.
2. **Improve date extraction for generic/AI receipts.** For the Lenox item, AI validation marked `transaction_date=false` and the system inferred dates from filename. Extend the AI schema/prompt (and validation) to explicitly extract check-in/check-out (when present in OCR text), and only fall back to filename inference when the model returns low confidence or missing fields.
3. **Strengthen stable dedupe keys for vendors lacking references.** Uber receipts currently dedupe via `vendor:text:<hashprefix>` because `vendor_reference` is missing. Consider extracting stable “trip/order” identifiers when available, and for unknown vendors use a composite heuristic (vendor + date + total + last-4 when present) to avoid accidental duplicates across format variations.

### Overall Verdict

Extraction for this upload set is strong for known vendor formats (Uber, Agoda PDF, Wi‑Fi Onboard): totals/currencies/dates matched `receipts.md`, and no documents were left unparsed. Robustness is acceptable for unknown formats due to AI fallback, but the Lenox case demonstrates dependency on OCR + AI (and filename inference) for booking screenshots; accuracy remains good here, but resilience would improve with a deterministic “booking screenshot” parser and richer generic field extraction.

