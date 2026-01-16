# Manual End-to-End Testing (User Perspective)

This guide is for manually validating that Serendipity Spend solves the end-user workflow described in `AGENTS.MD`:

1) Employee uploads supporting documents to a portal → claim summary is generated.  
2) Automated travel-policy checks run and are clearly flagged.  
3) Employee reviews the summary, fills missing info, and addresses flags.  
4) Summary + supporting docs route to an approver for review/approval and export for payment.

---

## 0) Prerequisites

- Python `>=3.12`
- Local run commands from `README.md`
- Optional for OCR tests: a working Tesseract install (the Python package `pytesseract` needs the `tesseract` binary)

---

## 1) Start the app locally

1. Install and configure:
   - `python -m pip install -e '.[dev]'`
   - `cp .env.example .env`
2. Ensure `.env` contains an admin bootstrap user:
   - `INIT_ADMIN_EMAIL=admin@example.com`
   - `INIT_ADMIN_PASSWORD=admin123`
3. Run:
   - `uvicorn serendipity_spend.main:app --reload`
4. Open:
   - UI: `http://localhost:8000/app`
   - API docs: `http://localhost:8000/docs`

Notes:
- In `ENVIRONMENT=dev`, background tasks (extraction/export) run inline (no separate worker needed).

---

## 2) Create test users (Employee + Approver)

The UI does not include “create user” screens. Create users via API.

### Option A (recommended): Use Swagger UI (`/docs`)

1. `POST /api/auth/token` as the bootstrap admin (form fields):
   - `username=admin@example.com`
   - `password=admin123`
2. Copy the returned `access_token`
3. In Swagger, click “Authorize” and paste `Bearer <token>`
4. `POST /api/users` twice to create:
   - Employee: `{"email":"employee@example.com","password":"pw","role":"EMPLOYEE","full_name":"Employee"}`
   - Approver: `{"email":"approver@example.com","password":"pw","role":"APPROVER","full_name":"Approver"}`

### Option B: Use curl

```bash
TOKEN=$(
  curl -s -X POST -F 'username=admin@example.com' -F 'password=admin123' \
    http://localhost:8000/api/auth/token | python -c "import sys,json; print(json.load(sys.stdin)['access_token'])"
)

curl -s -X POST http://localhost:8000/api/users \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"email":"employee@example.com","password":"pw","role":"EMPLOYEE","full_name":"Employee"}'

curl -s -X POST http://localhost:8000/api/users \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"email":"approver@example.com","password":"pw","role":"APPROVER","full_name":"Approver"}'
```

---

## 3) Test scenario: “Happy path” from employee to approval to export

### 3.1 Employee creates a claim

1. Log in at `http://localhost:8000/login` as:
   - `employee@example.com` / `pw`
2. Click **New claim**

Expected:
- Claim page loads and shows the new claim.
- You see policy/task prompts that purpose + travel dates are required.

### 3.2 Employee batch-uploads receipts

Run each upload variant at least once:

**A) Multi-file upload**
1. In “Receipts & Documents”, select multiple files at once (or drag/drop):
   - Recommended: start with `Data/DC__OOP__05 Sep 2025.pdf`
2. Click **Upload & Extract**

Expected:
- The document list shows files and transitions to “Processed” in dev.
- “Expense Items” populates (the sample PDF should produce 17 extracted items).
- Policy flags appear (e.g., Uber trip summary warning; missing FX rates for non-home currencies).

**B) ZIP upload**
1. Create a zip with multiple receipts (example):
   - `zip -j /tmp/receipts.zip Data/DC__OOP__05\ Sep\ 2025.pdf`
2. Upload `/tmp/receipts.zip`

Expected:
- Each file inside the zip becomes a separate document row.
- Extraction runs for each supported file type.

**C) Email `.eml` upload (optional)**
1. Export a real “receipts” email from your mail client as `.eml` (with attachments)
2. Upload the `.eml`

Expected:
- Each attachment is ingested as a document and processed.

### 3.3 Employee reviews + fixes policy issues

1. Fill in Trip Details:
   - Start Date, End Date, Purpose → click **Save**
2. Add FX rates in the sidebar (at minimum USD and CAD → home currency) → click **Save**
3. Verify currency conversion and that “Missing FX rate” policy issues disappear.

Expected:
- Claim-level “required” issues for purpose/dates clear after saving.
- FX-related flags clear after setting FX and saving.

### 3.4 Employee fills missing info / resolves “Needs Info”

Test at least these:

**A) Generic extraction review**
1. Upload a receipt format the system doesn’t recognize well (e.g., a hotel PDF invoice)
2. If it appears as a generic receipt item, click **Edit** on that item
3. Check **Mark reviewed** and save

Expected:
- The “Confirm auto-extracted receipt details” policy issue (`R040`) clears after saving.

**B) Meals over USD 100 need attendees**
1. Add a manual item with:
   - Category: `meals`
   - Amount: `>= 100` USD-equivalent
2. Confirm a policy flag appears requiring attendees
3. Edit the item and fill “Meal attendees” → save

Expected:
- Attendee-required policy issue clears after saving.

**C) Hotel cap (USD 300/night)**
1. Add a manual item with:
   - Category: `lodging`
   - Amount and “Hotel nights” that exceeds USD 300/night
2. Confirm a blocking “Required” issue appears
3. Edit the item (adjust nights/amount) to bring it below the cap → save

Expected:
- Over-cap hotel violation blocks submission until corrected.

**D) Short flight must be economy**
1. Add a manual item with:
   - Category: `airfare`
   - “Flight duration (hours)” < 6
   - “Flight cabin class” != economy
2. Confirm a blocking “Required” issue appears
3. Edit cabin class to `economy` (or change duration to >= 6) → save

Expected:
- The blocking short-flight violation clears after correction.

### 3.5 Route + submit for approval

Routing can happen before or after submission.

1. Log in as admin (`admin@example.com` / `admin123`)
2. Open the claim and click **Route to me** (or use the admin route API to assign to `approver@example.com`)
3. Log back in as employee and click **Submit for Review**

Expected:
- If an approver is set, claim enters approver review state.
- If any “Required” policy issues remain, the claim should not advance.

### 3.6 Approver reviews + approves / requests changes

1. Log in as approver (`approver@example.com` / `pw`)
2. Open the claim from the dashboard list
3. Click **Approve** (then repeat once with **Request changes** to test the loop)

Expected:
- Approve moves the claim to an approved state.
- Request changes moves the claim to changes-requested; employee can edit and resubmit.

### 3.7 Export (Excel + supporting docs)

1. On the claim page, click **Export**
2. Download:
   - `Summary.xlsx`
   - `Documents.zip`

Expected:
- The summary has a reimbursement sheet with line items and totals.
- The zip contains the original uploaded files (with unique filenames if needed).

---

## 4) Additional “real world” checks

### 4.1 Duplicate prevention

1. Upload the same receipt(s) again (same PDF or same zip)

Expected:
- No duplicate expense line items are created for the claim (counts should remain stable).

### 4.2 Unsupported / low-quality inputs

1. Upload an image receipt photo that is blurry or rotated

Expected:
- If extraction fails, the document should show “Failed” and/or a task should prompt manual entry.
- Employee can still complete the claim by adding manual items.

---

## 5) Definition of “done” (acceptance)

The system “fully solves the core problem” for manual testing if you can:

- Upload many receipts efficiently (multi-file + zip/eml) and get an itemized summary.
- See clear policy flags for missing purpose/dates, FX rates, hotel cap, meals attendees, and short-flight cabin class.
- Correct/complete the claim via the UI (including manual line items and edits).
- Submit the claim and complete an approval decision flow.
- Export a payment-ready Excel summary + a supporting-documents bundle.

