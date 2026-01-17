spec_version: 1

repo:
  name: serendipity-spend
  kind: modular_monolith
  domain: travel_expense_reimbursement
  language: python
  python_requires: ">=3.12"

agent_instructions:
  - do not use `git revert`
  - do not modify external changes you did not make unless explicitly instructed

lookup_instructions:
  - find “DC_OOP_05 Sep 2025” in problem_statement_verbatim within this file
  - the PDF is in the Data/ directory: Data/DC__OOP__05 Sep 2025.pdf
  - extract text from the PDF if you need to view the contents

problem_statement_verbatim: |-
  Currently, employees who wish to claim travel expenses send invoices and receipts directly to me (for example, hotel confirmation emails, Uber receipts, etc.; see the attached email titled “Expenses” as an example). I then manually review these items and prepare a summary table in Excel (see “Travel Reimbursement_DC_Jan 2026”). As part of this process, I check each item for compliance with the Travel Policy, such as ensuring hotel rates do not exceed USD 300 per night and that flights under six hours are booked in economy class.

  This process is entirely manual, time-consuming, and prone to errors, including incorrect amounts and potential duplication. The attachment “DC_OOP_05 Sep 2025” reflects the current output used to support reimbursement claims, where the Excel file is the summary and the PDF contains the supporting documents.

  Ideally, the process would be streamlined as follows:

  1. Employees upload all relevant supporting documents to a portal, which automatically generates a claim summary.
  2. Automated checks are performed against the Travel Policy, with any inconsistencies clearly flagged at the summary level.
  3. Employees review the generated summary to confirm accuracy and completeness, fill in any missing information (for example, trip purpose, or names of attendees for food and beverage expenses over USD 100), and address any flagged items.
  4. The summary and supporting documents are then routed to me for review and approval prior to payment.

docs_and_files:
  product_docs:
    readme: README.md
    architecture_overview: README.md
    railway_deploy_guide: railway.MD
    sample_data_notes: Data/sample-data-notes.md
  env_example: .env.example
  docker:
    dockerfile: Dockerfile
    compose: docker-compose.yml
  sample_inputs_outputs:
    sample_pdf_bundle: Data/DC__OOP__05 Sep 2025.pdf
    sample_excel_template: Data/Travel Reimbursement_DC_Jan 2026.xlsx
  entrypoints:
    http_app: src/serendipity_spend/main.py
    api_router: src/serendipity_spend/api/router.py
    ui_router: src/serendipity_spend/web/ui.py
    worker_app: src/serendipity_spend/worker/celery_app.py
    worker_tasks: src/serendipity_spend/worker/tasks.py
  core_lib:
    settings: src/serendipity_spend/core/config.py
    db: src/serendipity_spend/core/db.py
    orm_base: src/serendipity_spend/core/models.py
    security_jwt_and_passwords: src/serendipity_spend/core/security.py
    object_storage: src/serendipity_spend/core/storage.py
    bootstrap: src/serendipity_spend/bootstrap.py
  database_schema:
    models_import_hook_for_alembic: src/serendipity_spend/models.py
    alembic_env: alembic/env.py
    migrations_dir: alembic/versions
    migrations:
      - alembic/versions/243ff3aab6e1_init.py
      - alembic/versions/f971b58591ce_add_supporting_pdf_export.py
  tests:
    conftest: tests/conftest.py
    e2e_sample_pdf: tests/test_e2e_sample_pdf.py
    eml_body_ingestion: tests/test_eml_body_ingestion.py
    exports_merged_pdf_and_xlsx_format: tests/test_exports_merged_pdf_and_xlsx_format.py
    extraction_ocr_fallback: tests/test_extraction_ocr_fallback.py
    fx_auto_fetch: tests/test_fx_auto_fetch.py
    google_oauth_domain_restriction: tests/test_google_oauth_domain_restriction.py
    policy_additional_rules: tests/test_policy_additional_rules.py

runtime_stack:
  http:
    framework: fastapi
    ui: server_rendered_jinja2
    static_assets: src/serendipity_spend/web/static
    docs_ui: /docs
    portal_ui: /app
  db:
    orm: sqlalchemy
    migrations: alembic
    dev_default: sqlite:///./serendipity.db
    prod_recommended: postgresql+psycopg://...
  background_jobs:
    queue: celery
    broker_and_backend: redis
    dev_mode: task_always_eager=true (runs inline in web process)
  storage:
    backends:
      - local_filesystem
      - s3_compatible (boto3; Railway Bucket or MinIO)
    shared_storage_required_when:
      - ENVIRONMENT != dev and worker is separate from web
  pdf_and_ocr:
    pdf_text: pypdf
    ocr_fallback: pytesseract (uses Tesseract binary; installed in Dockerfile)

domain_model:
  roles:
    EMPLOYEE: creates_claims_uploads_docs_edits_own_claims_submits
    APPROVER: reviews_assigned_claims_records_decisions
    ADMIN: full_access_user_admin_routing
  primary_entities:
    User:
      table: identity_user
      model: src/serendipity_spend/modules/identity/models.py
      key_fields: [id, email, full_name, role, is_active]
    Claim:
      table: claims_claim
      model: src/serendipity_spend/modules/claims/models.py
      key_fields:
        [id, employee_id, approver_id, home_currency, travel_start_date, travel_end_date, purpose, status, submitted_at, approved_at, paid_at]
    SourceFile:
      table: documents_source_file
      model: src/serendipity_spend/modules/documents/models.py
      key_fields:
        [id, claim_id, uploader_id, filename, content_type, byte_size, sha256, storage_key, status, error_message]
    EvidenceDocument:
      table: documents_evidence_document
      model: src/serendipity_spend/modules/documents/models.py
      key_fields:
        [id, source_file_id, page_start, page_end, vendor, receipt_type, text_hash, classification_confidence]
    ExpenseItem:
      table: expenses_expense_item
      model: src/serendipity_spend/modules/expenses/models.py
      key_fields:
        [id, claim_id, vendor, vendor_reference, receipt_type, category, description, transaction_date, amount_original_*, amount_home_*, fx_rate_to_home, metadata_json, dedupe_key]
    ExpenseItemEvidence:
      table: expenses_expense_item_evidence
      model: src/serendipity_spend/modules/expenses/models.py
      key_fields: [expense_item_id, evidence_document_id]
    FxRate:
      table: fx_rate
      model: src/serendipity_spend/modules/fx/models.py
      key_fields: [id, claim_id, from_currency, to_currency, rate, as_of_date, source]
    PolicyViolation:
      table: policy_violation
      model: src/serendipity_spend/modules/policy/models.py
      key_fields:
        [id, claim_id, expense_item_id, rule_id, rule_version, severity, status, title, message, data_json, dedupe_key, resolved_at]
    Task:
      table: workflow_task
      model: src/serendipity_spend/modules/workflow/models.py
      key_fields:
        [id, claim_id, expense_item_id, type, title, description, status, created_by_user_id, assigned_to_user_id, resolved_at]
    Approval:
      table: workflow_approval
      model: src/serendipity_spend/modules/workflow/models.py
      key_fields: [id, claim_id, approver_user_id, decision, comment, decided_at]
    ExportRun:
      table: exports_export_run
      model: src/serendipity_spend/modules/exports/models.py
      key_fields:
        [id, claim_id, requested_by_user_id, status, error_message, summary_xlsx_key, supporting_pdf_key, supporting_zip_key, completed_at]
    AuditEvent:
      table: audit_event
      model: src/serendipity_spend/modules/audit/models.py
      key_fields: [id, event_type, claim_id, actor_user_id, payload_json, occurred_at]

claim_state_machine:
  source: src/serendipity_spend/modules/claims/models.py
  statuses:
    - DRAFT
    - PROCESSING
    - NEEDS_EMPLOYEE_REVIEW
    - SUBMITTED
    - NEEDS_APPROVER_REVIEW
    - CHANGES_REQUESTED
    - APPROVED
    - READY_FOR_PAYMENT
    - PAID
    - REJECTED
  enforced_transitions_and_guards:
    create_claim: DRAFT (src/serendipity_spend/modules/claims/service.py:create_claim)
    upload_source_file: DRAFT -> PROCESSING (src/serendipity_spend/modules/documents/service.py:create_source_file)
    extraction_success: (DRAFT|PROCESSING) -> NEEDS_EMPLOYEE_REVIEW (src/serendipity_spend/modules/extraction/service.py:extract_source_file)
    employee_editable_statuses:
      allowed: [DRAFT, NEEDS_EMPLOYEE_REVIEW, CHANGES_REQUESTED]
      enforced_by: src/serendipity_spend/modules/claims/service.py:update_claim
    submit_claim:
      allowed_from: [DRAFT, NEEDS_EMPLOYEE_REVIEW, CHANGES_REQUESTED]
      blocks_on_open_policy_violations_where:
        - severity == FAIL
        - data_json.submit_blocking == true
      to: SUBMITTED or NEEDS_APPROVER_REVIEW if approver_id set
      enforced_by: src/serendipity_spend/modules/claims/service.py:submit_claim
    approve_claim:
      allowed_from: NEEDS_APPROVER_REVIEW
      decisions_to_status:
        APPROVED: APPROVED
        CHANGES_REQUESTED: CHANGES_REQUESTED
        REJECTED: REJECTED
      enforced_by: src/serendipity_spend/modules/workflow/service.py:approve_claim

core_contracts:
  - id: ids_are_uuid
    rule: all_primary_keys_are_uuid_v4
    source: src/serendipity_spend/core/models.py
  - id: storage_is_source_of_truth_for_file_bytes
    rule: SourceFile.storage_key is the only pointer to bytes; DB never stores raw bytes
    source:
      - src/serendipity_spend/core/storage.py
      - src/serendipity_spend/modules/documents/models.py
  - id: multi_service_requires_shared_storage
    rule: web and worker must use same storage backend/credentials in production
    source: railway.MD
  - id: extraction_idempotency_per_claim
    rule: ExpenseItem.dedupe_key unique per claim; vendor+vendor_reference unique when reference present
    source: src/serendipity_spend/modules/expenses/models.py
  - id: policy_sync_is_authoritative
    rule: evaluate_claim recomputes OPEN/RESOLVED PolicyViolation and POLICY_* Task rows from current claim+items (and auto-resolves stale POLICY_* tasks)
    source: src/serendipity_spend/modules/policy/service.py
  - id: submit_blocks_on_failures
    rule: open PolicyViolation blocks submit when severity == FAIL OR data_json.submit_blocking == true
    source: src/serendipity_spend/modules/claims/service.py
  - id: extraction_review_tasks
    rule: extraction creates/updates one EXTRACT_* Task per SourceFile when manual review is needed
    source: src/serendipity_spend/modules/extraction/service.py
  - id: google_oauth_domain_restriction
    rule: when Google OAuth is enabled, users outside allowed domain are rejected (API + UI)
    source:
      - src/serendipity_spend/api/deps.py
      - src/serendipity_spend/web/ui.py
      - src/serendipity_spend/modules/identity/google_oauth.py

api_contract:
  base_prefix: /api
  auth:
    bearer_jwt:
      header: "Authorization: Bearer <token>"
      jwt:
        alg: HS256
        subject: user.id (uuid string)
        mint: src/serendipity_spend/core/security.py:create_access_token
        verify: src/serendipity_spend/core/security.py:decode_access_token
    password_login_disabled_when_google_oauth_configured: true
  endpoints:
    - method: GET
      path: /healthz
      auth: none
      impl: src/serendipity_spend/api/router.py:healthz
    - method: POST
      path: /api/auth/token
      auth: none
      impl: src/serendipity_spend/modules/identity/api.py:login
    - method: POST
      path: /api/auth/google
      auth: none
      impl: src/serendipity_spend/modules/identity/api.py:login_google
    - method: GET
      path: /api/auth/me
      auth: bearer
      impl: src/serendipity_spend/modules/identity/api.py:me
    - method: POST
      path: /api/users
      auth: bearer (ADMIN)
      impl: src/serendipity_spend/modules/identity/api.py:create_user_endpoint
    - method: POST
      path: /api/claims
      auth: bearer
      impl: src/serendipity_spend/modules/claims/api.py:create_claim_endpoint
    - method: GET
      path: /api/claims
      auth: bearer
      impl: src/serendipity_spend/modules/claims/api.py:list_claims_endpoint
    - method: GET
      path: /api/claims/{claim_id}
      auth: bearer
      impl: src/serendipity_spend/modules/claims/api.py:get_claim_endpoint
    - method: PATCH
      path: /api/claims/{claim_id}
      auth: bearer
      impl: src/serendipity_spend/modules/claims/api.py:update_claim_endpoint
    - method: POST
      path: /api/claims/{claim_id}/submit
      auth: bearer
      impl: src/serendipity_spend/modules/claims/api.py:submit_claim_endpoint
    - method: POST
      path: /api/claims/{claim_id}/route?approver_id=<uuid>
      auth: bearer (ADMIN)
      impl: src/serendipity_spend/modules/claims/api.py:route_claim_endpoint
    - method: POST
      path: /api/claims/{claim_id}/documents (multipart/form-data)
      auth: bearer
      impl: src/serendipity_spend/modules/documents/api.py:upload_document
    - method: POST
      path: /api/claims/{claim_id}/documents/batch (multipart/form-data)
      auth: bearer
      impl: src/serendipity_spend/modules/documents/api.py:upload_documents_batch
    - method: GET
      path: /api/claims/{claim_id}/documents
      auth: bearer
      impl: src/serendipity_spend/modules/documents/api.py:list_documents
    - method: GET
      path: /api/documents/{source_file_id}/download
      auth: bearer
      impl: src/serendipity_spend/modules/documents/api.py:download_document
    - method: POST
      path: /api/claims/{claim_id}/items
      auth: bearer
      impl: src/serendipity_spend/modules/expenses/api.py:create_item_endpoint
    - method: PATCH
      path: /api/claims/{claim_id}/items/{item_id}
      auth: bearer
      impl: src/serendipity_spend/modules/expenses/api.py:update_item_endpoint
    - method: DELETE
      path: /api/claims/{claim_id}/items/{item_id}
      auth: bearer
      impl: src/serendipity_spend/modules/expenses/api.py:delete_item_endpoint
    - method: GET
      path: /api/claims/{claim_id}/items
      auth: bearer
      impl: src/serendipity_spend/modules/expenses/api.py:list_items_endpoint
    - method: POST
      path: /api/claims/{claim_id}/fx-rates
      auth: bearer
      impl: src/serendipity_spend/modules/fx/api.py:set_fx_rates
    - method: POST
      path: /api/claims/{claim_id}/policy/evaluate
      auth: bearer
      impl: src/serendipity_spend/modules/policy/api.py:evaluate_policy_endpoint
    - method: GET
      path: /api/claims/{claim_id}/policy
      auth: bearer
      impl: src/serendipity_spend/modules/policy/api.py:list_policy_endpoint
    - method: GET
      path: /api/claims/{claim_id}/tasks
      auth: bearer
      impl: src/serendipity_spend/modules/workflow/api.py:list_tasks_endpoint
    - method: POST
      path: /api/tasks/{task_id}/resolve
      auth: bearer
      impl: src/serendipity_spend/modules/workflow/api.py:resolve_task_endpoint
    - method: GET
      path: /api/approvals/inbox
      auth: bearer
      impl: src/serendipity_spend/modules/workflow/api.py:approver_inbox
    - method: POST
      path: /api/claims/{claim_id}/approve
      auth: bearer (APPROVER|ADMIN)
      impl: src/serendipity_spend/modules/workflow/api.py:approve_claim_endpoint
    - method: POST
      path: /api/claims/{claim_id}/request-changes
      auth: bearer (APPROVER|ADMIN)
      impl: src/serendipity_spend/modules/workflow/api.py:request_changes_endpoint
    - method: POST
      path: /api/claims/{claim_id}/reject
      auth: bearer (APPROVER|ADMIN)
      impl: src/serendipity_spend/modules/workflow/api.py:reject_endpoint
    - method: POST
      path: /api/claims/{claim_id}/exports
      auth: bearer
      impl: src/serendipity_spend/modules/exports/api.py:create_export
    - method: GET
      path: /api/claims/{claim_id}/exports
      auth: bearer
      impl: src/serendipity_spend/modules/exports/api.py:list_exports
    - method: GET
      path: /api/exports/{export_run_id}
      auth: bearer
      impl: src/serendipity_spend/modules/exports/api.py:get_export
    - method: GET
      path: /api/exports/{export_run_id}/download/summary
      auth: bearer
      impl: src/serendipity_spend/modules/exports/api.py:download_summary
    - method: GET
      path: /api/exports/{export_run_id}/download/supporting
      auth: bearer
      impl: src/serendipity_spend/modules/exports/api.py:download_supporting

ui_contract:
  base_prefix: /app
  auth:
    cookie: access_token (JWT)
    login_pages: [/login, /auth/google/login, /auth/google/callback]
  primary_pages:
    - /app (dashboard)
    - /app/claims/new (create claim)
    - /app/claims/{claim_id} (claim detail + upload + fx + policy + export + approvals)
    - /app/tasks (open tasks for current user)
    - /app/inbox (approver inbox)
  source: src/serendipity_spend/web/ui.py

background_job_contract:
  celery_app: src/serendipity_spend/worker/celery_app.py:celery_app
  tasks:
    - name: extract_source_file
      task: src/serendipity_spend/worker/tasks.py:extract_source_file_task
      worker_impl: src/serendipity_spend/modules/extraction/service.py:extract_source_file
      input: {source_file_id: "<uuid string>"}
      triggers:
        - src/serendipity_spend/modules/documents/api.py:upload_document
        - src/serendipity_spend/modules/documents/api.py:upload_documents_batch
        - src/serendipity_spend/web/ui.py:upload_document_ui
    - name: generate_export
      task: src/serendipity_spend/worker/tasks.py:generate_export_task
      worker_impl: src/serendipity_spend/modules/exports/service.py:generate_export
      input: {export_run_id: "<uuid string>"}
      triggers:
        - src/serendipity_spend/modules/exports/api.py:create_export
        - src/serendipity_spend/web/ui.py:create_export_ui

storage_contract:
  backend_selector:
    env: STORAGE_BACKEND
    values: {local: LocalObjectStorage, s3: S3ObjectStorage}
    source: src/serendipity_spend/core/storage.py:get_storage
  key_scheme:
    source_upload: "claims/{claim_id}/source/{uuid4}-{original_filename}"
    export_summary_xlsx: "claims/{claim_id}/exports/{export_run_id}/summary.xlsx"
    export_supporting_pdf: "claims/{claim_id}/exports/{export_run_id}/supporting.pdf"

extraction_contract:
  supported_inputs_v1:
    - pdf (filename endswith .pdf OR content_type endswith /pdf)
    - image (content_type startswith image/ OR filename endswith .png/.jpg/.jpeg/.tif/.tiff/.bmp)
    - text (content_type text/plain|text/html OR filename endswith .txt/.md/.html/.htm)
    - zip (unpacked into child SourceFile uploads; see src/serendipity_spend/modules/documents/service.py:create_source_files_from_upload)
    - eml (email body ingested as text + attachments ingested; see src/serendipity_spend/modules/documents/service.py:create_source_files_from_upload)
  pipeline:
    - read bytes from storage (SourceFile.storage_key)
    - choose processor by file type (PDF/image/text) and create EvidenceDocument rows
    - for PDFs: extract per-page text via pypdf; OCR fallback for empty pages (pytesseract over embedded images)
    - parse known vendors/receipts; fall back to generic receipt heuristics when possible
    - dedupe and upsert ExpenseItem + link evidence
    - create/update EXTRACT_* Task when manual review is needed for a SourceFile
    - evaluate policy and advance claim status
  segmentation_rules:
    - grab: page contains ["Your Grab E-Receipt", "Booking ID:"] => 2-page segment
    - united_wifi: page contains "Thanks for your purchase with United" => 2-page segment
    - uber_trip_summary: page contains ["trip with Uber", "Total"] => 3-page segment
    - baggage_fee_payment: page contains ["PAYMENT RECEIPT", "BAG FEE"] => 1-page segment
  parsers:
    - vendor: Grab
      receipt_type: ride_receipt
      impl: src/serendipity_spend/modules/extraction/parsers/grab.py:parse_grab_ride_receipt
    - vendor: Uber
      receipt_type: trip_summary
      impl: src/serendipity_spend/modules/extraction/parsers/uber.py:parse_uber_trip_summary
    - vendor: United Airlines
      receipt_type: email_receipt
      impl: src/serendipity_spend/modules/extraction/parsers/united_wifi.py:parse_united_wifi_receipt
    - vendor: Airline
      receipt_type: payment_receipt
      impl: src/serendipity_spend/modules/extraction/parsers/baggage_fee.py:parse_baggage_fee_payment_receipt
  fx_behavior:
    - if from_currency == claim.home_currency: amount_home_amount = amount; fx_rate_to_home = 1
    - else if FxRate missing: amount_home_amount stays null and policy emits R030

policy_contract:
  source: src/serendipity_spend/modules/policy/service.py
  rules_currently_implemented:
    - id: R001
      severity: FAIL
      when: claim.purpose missing/blank
      outcome: blocks submit
    - id: R002
      severity: FAIL
      when: claim.travel_start_date OR claim.travel_end_date missing
      outcome: blocks submit
    - id: R010
      severity: NEEDS_INFO
      when: ExpenseItem.vendor == Uber AND receipt_type == trip_summary
      outcome: creates task; does not block submit
    - id: R020
      severity: WARN
      when: ExpenseItem.vendor == Grab AND metadata.profile == PERSONAL
    - id: R030
      severity: NEEDS_INFO
      when: item.amount_home_amount is null AND item.amount_original_currency != claim.home_currency
      outcome: blocks submit (submit_blocking)
    - id: R040
      severity: NEEDS_INFO
      when: item.metadata.extraction_method == generic AND item.metadata.employee_reviewed == false
      outcome: blocks submit (submit_blocking)
    - id: R101
      severity: NEEDS_INFO
      when: item.category in [lodging, hotel] AND item.metadata.hotel_nights missing/<=0
      outcome: blocks submit (submit_blocking)
    - id: R102
      severity: NEEDS_INFO
      when: item.category in [lodging, hotel] AND USD conversion missing for nightly cap check
      outcome: blocks submit (submit_blocking)
    - id: R103
      severity: FAIL
      when: item.category in [lodging, hotel] AND (total_usd / hotel_nights) > 300
      outcome: blocks submit
    - id: R111
      severity: NEEDS_INFO
      when: item.category in [meals, food, food_and_beverage] AND USD conversion missing for USD 100 threshold
      outcome: blocks submit (submit_blocking)
    - id: R112
      severity: NEEDS_INFO
      when: item.category in [meals, food, food_and_beverage] AND amount_usd >= 100 AND metadata.attendees missing/blank
      outcome: blocks submit (submit_blocking)
    - id: R121
      severity: NEEDS_INFO
      when: item.category in [airfare, flight] AND metadata.flight_duration_hours missing/invalid
      outcome: blocks submit (submit_blocking)
    - id: R122
      severity: NEEDS_INFO
      when: item.category in [airfare, flight] AND metadata.flight_cabin_class missing/blank
      outcome: blocks submit (submit_blocking)
    - id: R123
      severity: FAIL
      when: item.category in [airfare, flight] AND flight_duration_hours < 6 AND flight_cabin_class != economy
      outcome: blocks submit
  task_mapping:
    task_type_prefix: POLICY_
    example: R001 => POLICY_R001 (assigned_to_user_id = claim.employee_id)

export_contract:
  source: src/serendipity_spend/modules/exports/service.py
  artifacts:
    reimbursement_summary_xlsx:
      sheet: Reimbursement
      headers_row: 6
      data_start_row: 8
      currencies_supported_in_columns: [USD, SGD, CAD, GBP]
      reimbursement_column_currency: claim.home_currency
    supporting_docs_pdf:
      contents: "merged PDF of all SourceFile uploads (PDFs + images + text files converted to PDF pages), ordered by earliest linked ExpenseItem.transaction_date (fallback: upload time)"
    supporting_docs_zip:
      notes: supporting_zip_key exists for future use but is not currently produced by src/serendipity_spend/modules/exports/service.py:generate_export

operations:
  env_vars:
    source: src/serendipity_spend/core/config.py (also documented in .env.example and railway.MD)
    required_in_production:
      - ENVIRONMENT
      - SECRET_KEY
      - DATABASE_URL
      - REDIS_URL (if ENVIRONMENT != dev)
      - STORAGE_BACKEND + storage credentials (or LOCAL_STORAGE_PATH when using local storage)
    optional:
      - BASE_URL
      - GOOGLE_OAUTH_CLIENT_ID
      - GOOGLE_OAUTH_CLIENT_SECRET
      - GOOGLE_OAUTH_ALLOWED_DOMAIN
      - INIT_ADMIN_EMAIL (comma-separated list supported)
      - INIT_ADMIN_PASSWORD
      - LOCAL_STORAGE_PATH
      - S3_ENDPOINT_URL
      - S3_REGION
      - S3_BUCKET
      - S3_ACCESS_KEY_ID
      - S3_SECRET_ACCESS_KEY
      - ACCESS_TOKEN_EXP_MINUTES
      - TESSERACT_LANG
  local_dev_commands:
    - python -m pip install -e '.[dev]'
    - cp .env.example .env
    - uvicorn serendipity_spend.main:app --reload
    - pytest
    - ruff check .

testing:
  runner: pytest
  db_and_storage_in_tests:
    db: sqlite:///./.serendipity_test.db
    storage: local (.tmp_storage_test)
    reset_fixture: tests/conftest.py:_reset_db_and_storage
  e2e_contract:
    sample_pdf_expected_counts:
      file: Data/DC__OOP__05 Sep 2025.pdf
      items_total: 17
      by_vendor: {Grab: 4, "United Airlines": 3, Uber: 9, Airline: 1}
