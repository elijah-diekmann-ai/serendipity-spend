# Testing Walkthrough

Test the expense reimbursement flow on your deployed app.

**Your app:** https://serendipity-spend.up.railway.app

---

## Step 1: Log in

1. Go to https://serendipity-spend.up.railway.app
2. Click **Continue with Google**
3. Sign in with your @serendipitycapital.com account

✅ You should see the **Claims** page with the sidebar navigation.

---

## Step 2: Create a new claim

1. Click **New claim** in the sidebar
2. Select your home currency (SGD is default)
3. Click **Create claim**

✅ You're now on the claim detail page. Notice the alerts:
- "Claim purpose required"
- "Travel period required"

---

## Step 3: Fill in trip details

1. Enter a **Start Date** (e.g., Jan 1, 2026)
2. Enter an **End Date** (e.g., Jan 5, 2026)
3. Enter a **Purpose** (e.g., "Client meetings in Singapore")
4. Click **Save**

✅ The purpose/dates alerts should disappear.

---

## Step 4: Upload receipts

**Option A: Use the sample PDF**
- Download: `Data/DC__OOP__05 Sep 2025.pdf` from the repo
- Drag it into the upload zone or click to browse

**Option B: Upload your own receipts**
- PDFs, images, or ZIP files work
- You can select multiple files at once

1. Click **Upload & Extract**
2. Wait a few seconds for processing

✅ You should see:
- Documents listed with "Processed" status
- Expense items extracted (the sample PDF has 17 items)
- Policy flags for items needing attention

---

## Step 5: Review policy flags

Look at the alerts and the **To Do** sidebar. Common issues:

| Flag | What to do |
|------|------------|
| Missing FX rate | Enter rates in the FX Rates sidebar |
| Confirm auto-extracted details | Edit the item and check "Mark reviewed" |
| Meal attendees required | Edit meal items over $100 and add attendee names |

**To fix FX rates:**
1. In the right sidebar under **FX Rates**
2. Enter rates like: USD → SGD = 1.35, CAD → SGD = 1.00
3. Click **Save**

✅ FX-related flags should clear and amounts convert.

---

## Step 6: Add a manual expense (optional)

If a receipt wasn't recognized, add it manually:

1. Scroll to **Expense Items** section
2. Fill in: Vendor, Date, Category, Amount, Currency
3. Click **Add item**

---

## Step 7: Submit for review

Once all blocking issues are resolved:

1. Click **Submit for Review**

✅ Claim status changes. If an approver is assigned, it goes to their inbox.

---

## Step 8: Test the approver flow

As an admin, you can approve your own claims:

1. Click **Route to me** (if not already routed)
2. The claim enters approver review
3. Click **Approve**, **Request changes**, or **Reject**

✅ Approved claims can be exported.

---

## Step 9: Export for payment

1. Click **Export**
2. Wait a moment for generation
3. Download:
   - **Summary.xlsx** - The reimbursement spreadsheet
   - **Documents.zip** - All uploaded receipts

✅ Open the Excel file to see the itemized summary with totals.

---

## Quick tests to try

| Test | How |
|------|-----|
| Delete a draft claim | Go to Claims list, click trash icon |
| View all tasks | Click "My tasks" in sidebar |
| Check approvals inbox | Click "Approvals inbox" (admin only) |
| Multi-file upload | Select 3+ files at once in the upload zone |
| Edit an expense item | Click "Edit" on any expense row |

---

## What success looks like

You've tested the full flow if you can:

- [x] Create a claim and set trip details
- [x] Upload receipts and see extracted expenses
- [x] Fix policy issues (FX rates, missing info)
- [x] Submit and approve the claim
- [x] Download the Excel summary + documents ZIP

🎉 That's the complete expense reimbursement workflow!
