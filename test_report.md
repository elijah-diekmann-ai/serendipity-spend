# E2E Receipt Extraction Test Report (Railway)

Claim ID: `91ed3fd9-7df2-437f-8a09-46bbf2eee463`

## Run Context

- Environment: Railway `production`
- Correlation
  - `request_id`: `34442f5a-928a-4595-a039-3cd9fb58edce`
  - Upload window (`upload.received.ts`): `2026-01-18T12:39:04.485550Z` → `2026-01-18T12:39:10.126245Z`

## Summary

- Uploads received (web): `10`
- `SourceFile` rows created: `9` (1 upload produced a deduped child file)
- Extraction tasks enqueued (web): `10` (1 duplicate task against an already-processed `SourceFile`)
- Worker outcomes: `9` success + `1` skipped (`already_processed`)
- Parsed results
  - Evidence documents: `9`
  - Expense items: `9`
  - Unparsed segments/pages: `0`
- Open policy violations (DB):
  - `R001` (FAIL): claim purpose missing
  - `R002` (FAIL): travel dates missing
  - `R040` (NEEDS_INFO): employee review required for an auto-extracted (generic/AI) receipt (`The Lenox`)

## Upload → SourceFile → Extraction Task (Correlation)

All uploads were handled under the same `request_id` (`34442f5a-928a-4595-a039-3cd9fb58edce`).

| Upload (web `upload.received.filename`) | Created SourceFile? | Notes |
|---|---:|---|
| `Receipt.pdf` | ✅ `e0d61e63-4eb9-4132-8551-18af83b4377c` | Also enqueued a duplicate extraction task due to dedupe behavior (see below) |
| `Fwd_ Agoda - Customer Receipt from Booking ID_ 1687271287.eml` | ❌ | Produced a *deduped* child `Receipt.pdf` (same SHA-256 as the separately uploaded `Receipt.pdf`) |
| `Fwd_ Here's Your Air Canada Receipt - Order #422793475SUAC.eml` | ✅ `fe21269b-0b4b-4a5f-89ab-4bf282c321f9` | Stored as `email-body-*.txt` |
| `Fwd_ Your Monday morning trip with Uber.eml` | ✅ `b400f802-f1e8-4fab-95da-b90da3a4f435` | Stored as `email-body-*.txt` |
| `Fwd_ Your Monday morning trip with Uber_1.eml` | ✅ `56a1af31-e3b9-4209-88c5-fadd00831679` | Stored as `email-body-*.txt` (filename collision with the other “Monday morning” upload) |
| `Fwd_ Your Monday afternoon trip with Uber.eml` | ✅ `f08ad055-0e7f-469d-8a6d-27a9e41ab531` | Stored as `email-body-*.txt` |
| `The Lenox - Boston - 12-13th Jan.jpg` | ✅ `ef7a7438-d6a2-4820-8601-bd253b2baab1` | Image OCR + AI extraction |
| `Fwd_ Your Tuesday morning trip with Uber.eml` | ✅ `feab3688-fd79-4093-a591-c035f66401b9` | Stored as `email-body-*.txt` |
| `Fwd_ Your Tuesday afternoon trip with Uber.eml` | ✅ `947cb74c-ef9c-41ec-8ec0-4ed560cb58e2` | Stored as `email-body-*.txt` |
| `Fwd_ Your Tuesday afternoon trip with Uber_1.eml` | ✅ `a6b522a9-41ac-4365-97a6-8c1f0937209c` | Stored as `email-body-*.txt` (filename collision with the other “Tuesday afternoon” upload) |

### Extraction Task Timeline (worker)

| celery_task_id | source_file_id | filename | status | duration_ms |
|---|---|---|---|---:|
| `870b7906-1643-49fe-ad59-b712206e4837` | `e0d61e63-4eb9-4132-8551-18af83b4377c` | `Receipt.pdf` | success | 1884 |
| `dac91b48-0b89-4472-a5fd-4ec8c2f1b865` | `e0d61e63-4eb9-4132-8551-18af83b4377c` | `Receipt.pdf` | skipped (`already_processed`) | 8 |
| `325e71ec-c12f-48b6-812b-55e1169ffb14` | `fe21269b-0b4b-4a5f-89ab-4bf282c321f9` | `email-body-Fwd_Heres_Your_Air_Canada_Receipt_-_Order_422793475SUAC.txt` | success | 827 |
| `add3bf6e-80f5-44a3-a1ce-398c379a67b3` | `b400f802-f1e8-4fab-95da-b90da3a4f435` | `email-body-Fwd_Your_Monday_morning_trip_with_Uber.txt` | success | 153 |
| `5dd9a80a-df0c-4ef1-b899-05e895329b2f` | `56a1af31-e3b9-4209-88c5-fadd00831679` | `email-body-Fwd_Your_Monday_morning_trip_with_Uber.txt` | success | 240 |
| `e3ded462-465b-4165-852e-ee7d6f7520c6` | `f08ad055-0e7f-469d-8a6d-27a9e41ab531` | `email-body-Fwd_Your_Monday_afternoon_trip_with_Uber.txt` | success | 154 |
| `e098e1e9-947b-4fd4-b756-58fe953fa8f4` | `ef7a7438-d6a2-4820-8601-bd253b2baab1` | `The Lenox - Boston - 12-13th Jan.jpg` | success | 5980 |
| `f36b7508-ad5d-49ea-ab69-ba16ee7de42a` | `feab3688-fd79-4093-a591-c035f66401b9` | `email-body-Fwd_Your_Tuesday_morning_trip_with_Uber.txt` | success | 178 |
| `2a0db0c5-8539-4464-a99b-e6a110f583d4` | `947cb74c-ef9c-41ec-8ec0-4ed560cb58e2` | `email-body-Fwd_Your_Tuesday_afternoon_trip_with_Uber.txt` | success | 174 |
| `d12052dd-9104-4609-9a90-0e634c1aab54` | `a6b522a9-41ac-4365-97a6-8c1f0937209c` | `email-body-Fwd_Your_Tuesday_afternoon_trip_with_Uber.txt` | success | 164 |

## Parsed Items (DB) + Evidence References

All `9` created `SourceFile`s produced an `ExpenseItem` and a linked `EvidenceDocument`.

For evidence references, this report uses `documents_evidence_document.text_hash` plus the `evidence_snippet` from the corresponding `extraction.*.parsed` log line.

| ExpenseItem | SourceFile | Evidence | Vendor / receipt_type | Amount (original) | Date | Category | Extraction | Evidence reference |
|---|---|---|---|---:|---|---|---|---|
| `5b63cae7-9fa9-4a0d-93de-48b75bd78e4d` | `e0d61e63-4eb9-4132-8551-18af83b4377c` (`Receipt.pdf`) | `79c2601e-b843-465a-bc19-0d189050ba2b` | `DoubleTree by Hilton Toronto Airport` / `hotel_receipt` | 247.08 SGD | 2026-01-12 | lodging | `vendor` | `text_hash=3d6eabf74e653e4850a06d04484b429a3714b8b509ab56bd9970d5b46fdb8a53` |
| `9f3ef069-43b2-4b80-a0dd-23480ac5d62f` | `ef7a7438-d6a2-4820-8601-bd253b2baab1` (`The Lenox - Boston - 12-13th Jan.jpg`) | `7418c305-ff39-4813-9870-af98578bb42d` | `The Lenox` / `generic_receipt` | 296.95 USD | 2026-01-12 | lodging | `ai_image` (classifier: `Unknown/unknown`) | `text_hash=5b55f8c3091695029957e85781e05f9690ecadf898351e3bc6ef8190d60c35d8` |
| `ef280c95-a1db-4fe1-83da-4e46ca550387` | `fe21269b-0b4b-4a5f-89ab-4bf282c321f9` (`email-body-...422793475SUAC.txt`) | `00062e9a-b1ba-4e0d-8005-78c6781bff0e` | `Wi‑Fi Onboard` / `wifi_receipt` | 8.40 CAD | 2026-01-11 | travel_ancillary | `vendor` | `text_hash=eda2c1a42780ed239d8efd4c0cb1cfaf9c3aa3ecd36b1ba2bb6eded4e174a43b` |
| `0358d50e-4e3a-459f-a563-c1ba7bcf57b4` | `b400f802-f1e8-4fab-95da-b90da3a4f435` (`email-body-...Monday_morning...txt`) | `ff6dc492-6796-4fc3-b0dd-0b00fd95aefe` | `Uber` / `trip_summary` | 16.15 CAD | 2026-01-12 | transport | `vendor` | `text_hash=e48442584c76a283cffe1c1462106b3d83b0bcb3e469a410bfbff4c52199c468` |
| `3a4f830a-37ec-455b-a7d9-3b5a376a6807` | `56a1af31-e3b9-4209-88c5-fadd00831679` (`email-body-...Monday_morning...txt`) | `c00e1b94-f994-446c-8d82-aa7f9d461cad` | `Uber` / `trip_summary` | 33.56 USD | 2026-01-12 | transport | `vendor` | `text_hash=2c9a25294b45d5f8576f94d63ba94035cd21ca71cd26eed004f426bc45d9a8fb` |
| `ae57abc0-df1f-46d1-b4a7-4ed13df4c63f` | `f08ad055-0e7f-469d-8a6d-27a9e41ab531` (`email-body-...Monday_afternoon...txt`) | `847a40fc-1cc9-49be-8c5a-b94e00767d11` | `Uber` / `trip_summary` | 35.53 USD | 2026-01-12 | transport | `vendor` | `text_hash=ccde980df4dc4287ad66e65164e096aaf369114e4484300d9e41897d0cc89f5f` |
| `3e4092a7-c10a-420b-95b8-2164ba2ac180` | `feab3688-fd79-4093-a591-c035f66401b9` (`email-body-...Tuesday_morning...txt`) | `992bad2b-924e-4ce8-9f11-37981a446406` | `Uber` / `trip_summary` | 33.58 USD | 2026-01-13 | transport | `vendor` | `text_hash=d112af99ea8d65f624c7e811f6b11e04a9e2df9c8dfc3f33aa9a1c16d364a811` |
| `fe83833b-c308-45c8-99f4-04c569e2a90f` | `947cb74c-ef9c-41ec-8ec0-4ed560cb58e2` (`email-body-...Tuesday_afternoon...txt`) | `7ecc45fc-8bc2-48fd-8790-4a8c64ab86a4` | `Uber` / `trip_summary` | 40.26 USD | 2026-01-13 | transport | `vendor` | `text_hash=37f8dbc0653ce24b5a84e4d88231f4c3e0d25ff37cc23536f7811e3a9e07dcc1` |
| `144b0a5e-38c8-48e2-bc17-f95627aaac67` | `a6b522a9-41ac-4365-97a6-8c1f0937209c` (`email-body-...Tuesday_afternoon...txt`) | `1e3d4be5-e46f-4229-bd28-c8f7c96c524d` | `Uber` / `trip_summary` | 26.62 USD | 2026-01-13 | transport | `vendor` | `text_hash=9846f1e6e2cb3b35eeed3ab368032a55ffc7aa3dd0c0f6dcad811e1b3f1dd6a8` |

### Evidence Snippets (from logs)

- `3d6eabf74e653e4850a06d04484b429a3714b8b509ab56bd9970d5b46fdb8a53`: `Address: Agoda Company Pte, Ltd. 36 Robinson Road City House #20-01 Singapore 068877 Booking No. 1687271287 Payment Date January 12, 2026 ...`
- `5b55f8c3091695029957e85781e05f9690ecadf898351e3bc6ef8190d60c35d8`: `< Booking Detail Guest info Cancellation Policy Payment Info ... Total Charge: USD 296.95 ...`
- `eda2c1a42780ed239d8efd4c0cb1cfaf9c3aa3ecd36b1ba2bb6eded4e174a43b`: `Subject: Fwd: Here's Your Air Canada Receipt - Order #422793475SUAC ... Total paid: $8.40 CAD ...`
- Uber receipts: all `extraction.text.parsed` evidence snippets begin with the forwarded email headers (Subject/From/To) and include the Uber “Trip with Uber” receipt content.

## Parser Outcomes / Parse Failures

- `Receipt.pdf` (`e0d61e63-...`)
  - `kind=pdf`, `page_count=1`, `segments_total=0` → processed as “unknown PDF” page parsing
  - Parsed successfully via vendor parser (`parse_agoda_receipt`), no `parse_failures`
- All `Uber` and `Wi‑Fi Onboard` receipts (text)
  - Classified as `Uber/trip_summary` (confidence `0.6`) or `Wi‑Fi Onboard/wifi_receipt` (confidence `0.8`)
  - Parsed successfully via vendor parsers, no `parse_failures`
- `The Lenox - Boston - 12-13th Jan.jpg` (image)
  - Classifier output: `Unknown/unknown` (confidence `0.1`)
  - Vendor parsing failure: `vendor:unsupported_vendor`
  - AI fallback succeeded: `parser_used=ai_image` (receipt_type became `generic_receipt`)

## Expected vs Actual (receipts.md)

No mismatches found for **amount, currency, transaction_date, category** across all parsed items.

### Lodging

- `Receipt.pdf` (Agoda / DoubleTree by Hilton Toronto Airport)
  - Expected: booking `1687271287`, Payment Date `2026-01-12`, Stay `2026-01-11` → `2026-01-12` (1 night), Total Charge `247.08 SGD` (USD total `191.91`)
  - Actual (DB `expenses_expense_item`):
    - vendor=`DoubleTree by Hilton Toronto Airport`, vendor_reference=`1687271287`
    - amount=`247.08 SGD`, transaction_date=`2026-01-12`, category=`lodging`
    - metadata: `hotel_check_in=2026-01-11`, `hotel_check_out=2026-01-12`, `hotel_nights=1`, `amounts_by_currency={USD:191.91, SGD:247.08}`
- `The Lenox - Boston - 12-13th Jan.jpg`
  - Expected: Total Charge `296.95 USD`, stay implied by filename `12–13 Jan` (1 night)
  - Actual:
    - vendor=`The Lenox`
    - amount=`296.95 USD`, transaction_date=`2026-01-12`, category=`lodging`
    - metadata: `hotel_check_in=2026-01-12`, `hotel_check_out=2026-01-13`, `hotel_nights=1`, `transaction_date_inferred_from=filename`

### Airfare / Ancillary

- Wi‑Fi Onboard (Order `422793475SUAC`)
  - Expected: total `8.40 CAD`, date `2026-01-11`
  - Actual:
    - amount=`8.40 CAD`, transaction_date=`2026-01-11`, category=`travel_ancillary`, vendor_reference=`422793475SUAC`

### Uber Trips

All 6 Uber receipts matched expected totals and dates; breakdown line items also matched `receipts.md`.

| Receipt (from `receipts.md`) | Expected | Actual (DB) |
|---|---|---|
| Mon 12 Jan 2026 06:02 | 16.15 CAD | 16.15 CAD (transaction_date `2026-01-12`, transaction_at `2026-01-12 11:02Z`) |
| Mon 12 Jan 2026 10:25 | 33.56 USD | 33.56 USD (transaction_at `2026-01-12 15:25Z`) |
| Mon 12 Jan 2026 12:59 | 35.53 USD | 35.53 USD (transaction_at `2026-01-12 17:59Z`) |
| Tue 13 Jan 2026 10:40 | 33.58 USD | 33.58 USD (transaction_at `2026-01-13 15:40Z`) |
| Tue 13 Jan 2026 12:38 | 40.26 USD | 40.26 USD (includes ride_type/pickup/dropoff; transaction_at `2026-01-13 17:38Z`) |
| Tue 13 Jan 2026 14:02 | 26.62 USD | 26.62 USD (transaction_at `2026-01-13 19:02Z`) |

## Policy / Workflow Notes (DB)

Open `policy_violation` rows:

- `R001` (FAIL): claim purpose missing (blocks submit)
- `R002` (FAIL): travel period missing (blocks submit)
- `R040` (NEEDS_INFO): `expense_item_id=9f3ef069-43b2-4b80-a0dd-23480ac5d62f` (`The Lenox`) requires employee review due to `metadata_json.extraction_family="generic"` + `employee_reviewed=false` (blocks submit)

## Recommended Fixes

1. **Avoid redundant extraction tasks when a child upload is deduped**
   - Observation: `source_file.deduped` still led to `celery.task.enqueued` for the already-existing `source_file_id=e0d61e63-...`, producing a second worker run that was immediately skipped as `already_processed`.
   - Root cause: enqueue is happening even when no new `SourceFile` row was created (dedupe path).
   - Fix direction:
     - In the upload/unpack pipeline (likely `documents/service.py:create_source_file*` or caller), only enqueue extraction when a new `SourceFile` is created **or** when the target `SourceFile.status` is in a state that needs processing (`UPLOADED`/`FAILED`), not `PROCESSED`.

2. **Preserve uniqueness of derived filenames from `.eml` uploads**
   - Observation: distinct uploads like `...Uber.eml` and `...Uber_1.eml` produced `SourceFile.filename` collisions (same `email-body-Fwd_Your_Monday_morning_trip_with_Uber.txt`, same for “Tuesday afternoon”).
   - Root cause: derived filename appears to be based on subject/normalized name, dropping the original upload filename suffix.
   - Fix direction:
     - Include a stable differentiator in derived filenames (e.g., original uploaded `.eml` filename stem including `_1`, or append a short prefix of the parent upload SHA / UUID).
     - Alternatively, store the original upload filename in `SourceFile` metadata (or add a column) and display that in the UI/export instead of the derived name.

3. **Add explicit container-unpack logs for `.eml`**
   - Observation: from logs alone, mapping “uploaded `.eml`” → “created `email-body-*.txt` SourceFile(s) + any attachments” isn’t explicit (it’s inferable, but not directly logged as a relationship).
   - Fix direction:
     - Add structured events like `upload.unpack.start/finish` with fields:
       - `container_filename`, `container_content_type`, `container_sha256`
       - `child_source_file_ids` (and filenames)
       - `deduped_children` (child filename → existing source_file_id)

4. **Clarify `R040` wording for AI-extracted receipts**
   - Observation: `R040` message says “parsed using a generic heuristic” but this receipt used `extraction_method=ai_image` with high confidence.
   - Fix direction: adjust policy message to reflect “generic/AI extraction” and optionally include `extraction_method` in the task description to aid reviewer confidence.
