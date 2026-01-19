# Export Supporting PDF Testing (Railway / production) — PDF-only

## Goal

Validate and diagnose the supporting documents PDF export for a claim. Focus on the known defect: raw HTML / tracking URLs rendered into the PDF instead of clean receipt content.

## Inputs

- claim_id: `6820130e-2352-4096-994c-ee48e8980e63`
- Output artifact (what system produced): `Data/Supporting_Documents_Test_Output.pdf`
- Ground truth (manually collated receipts rendered as their original screenshots/images): `Data/DC__OOP__05 Sep 2025.pdf`
- Local originals for offline inspection (optional): `Data/*.eml`, `Data/*.jpg`

## Pre-Read (do before running)

- `access.md` (Railway logs + DB access)
- `src/serendipity_spend/modules/exports/service.py` (PDF building path)
- `src/serendipity_spend/modules/documents/service.py` (EML unpacking + HTML→text)
- `src/serendipity_spend/modules/extraction/service.py` (`_detect_file_kind`, HTML sniffing patterns)

## Acceptance Criteria (PDF)

Pass if all are true:

1. Email receipts appear as original images (not reformatted text). Compare to ground truth PDF.
2. No raw HTML markup visible (e.g., `<html`, `<div`, `</a>`, `<!doctype`, `&nbsp;`).
3. No tracking URL spam blocks (e.g., `_ri_=`, long `https://…` chains).
4. PDF pages can be attributed to source documents deterministically (page ranges map cleanly to SourceFiles in the export order).

Key expectation: end user downloads the PDF and sees original receipt images as-is, matching the reference document — not text extracted and reformatted.

Known issue: user reports the PDF contains raw HTML/tracking URLs; this test should identify which source(s) and why.

---

## Step 1 — Confirm the export run + download the PDF

1. Trigger a new export for claim_id (UI or `POST /api/claims/{claim_id}/exports`) and capture:
   - export_run_id
   - request_id (web) and celery_task_id (web/worker)
2. Tail logs and correlate:
   - web: `celery.task.enqueued` where task_name=generate_export (has export_run_id)
   - worker: `celery.task.start/finish/error` where task_name=generate_export
   - worker: `export.generate.start/finish/error` (from exports service)
3. Download supporting PDF (`GET /api/exports/{export_run_id}/download/supporting`) and save as `Data/Supporting_Documents_Test_Output.pdf` (record SHA256).

---

## Step 2 — Inspect the exported PDF for "bad" content (page-level)

1. Use pypdf to extract text per page from `Data/Supporting_Documents_Test_Output.pdf`.
2. Flag pages containing any of these markers:
   - HTML: `<html`, `<!doctype`, `<div`, `<a `, `</`, `&nbsp;`, `href=`
   - Tracking: `https://`, `<https://`, `_ri_=`, `utm_`, `wifionboard.com`
   - Email headers: `From:`, `Reply-To:`, `Subject:`, `EmailDate:`
3. For each flagged page, capture:
   - page_number
   - matched marker(s)
   - a 200–400 char surrounding snippet

Report interim output: list of "bad pages".

---

## Step 3 — Map PDF pages back to specific SourceFiles (required)

You must be able to answer "which source file(s) broke?" deterministically.

1. Query DB for this claim's sources (`documents_source_file`):
   - id, filename, content_type, storage_key, sha256, byte_size, created_at
2. Reconstruct export ordering using logic in `exports/service.py:_sort_sources_for_supporting_pdf` (chronological by earliest linked ExpenseItem.transaction_date, else upload time).
3. For each SourceFile in that order:
   - Load bytes (prefer storage_key via storage backend; fallback: match to local Data/ by sha256).
   - Run the same conversion used by export: `exports/service.py:_source_file_to_pdf_reader(...)`
   - Record each source's page_count in the converted PDF
4. Build a cumulative page-range map (e.g., source_file_id X => pages 1–2, source_file_id Y => pages 3–4).
5. Use that to attribute each flagged "bad page" to a specific SourceFile row.

Report interim output: "bad page → source_file_id/filename/content_type".

---

## Step 4 — Root-cause analysis for each breaking source

For each breaking SourceFile:

1. Identify what it actually is vs what metadata says:
   - Check if decoded text begins with/contains HTML despite content_type not being text/html
2. Trace the exact export code path:
   - `exports/service.py:_build_supporting_pdf` → `_source_file_to_pdf_reader`
   - `_source_file_to_pdf_reader` calls `extraction.service:_detect_file_kind` (returns text for HTML too)
   - `exports/service.py:_text_bytes_to_pdf` only calls `_html_to_text` when: content_type starts with text/html, OR filename ends with .html/.htm
3. Determine which failure mode applies:
   - **Mode A** (most likely): body contains HTML but content_type=text/plain / filename .txt → export never runs `_html_to_text` → raw HTML printed into PDF.
   - **Mode B**: `_html_to_text` runs but plain text still contains tracking URLs (they were in text/plain or visible anchor text).
4. If the source originated from an .eml:
   - Parse the corresponding local `Data/*.eml` and list each part's declared Content-Type
   - Confirm whether email body was mislabeled (text/plain containing HTML) or had a noisy text/plain alternative part.

---

## Output (required)

Create `export_pdf_test_report.md` with:

### Findings

- Bad pages: page number + snippet + marker(s)
- Breaking sources: source_file_id, filename, stored content_type, and why it broke (Mode A vs Mode B)
- Code-path explanation referencing exact functions in `src/serendipity_spend/modules/exports/service.py`

### Root Cause

- A clear statement of the primary cause (e.g., "HTML content stored as text/plain so export skipped HTML→text conversion")

### Recommendations

- Fixes (3): targeted, root-cause, cite exact functions and evidence
- Robustness improvements (3): generalize across unknown formats; exclude test harnesses/provenance/audit/monitoring

### Verdict

- ready for production / needs fixes / blocked (and why)