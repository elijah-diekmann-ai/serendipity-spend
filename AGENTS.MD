spec_version: 1

repo:
  name: serendipity-spend
  kind: modular_monolith
  domain: travel_expense_reimbursement
  language: python
  python_requires: ">=3.12"

agent_instructions:
  - do not use `git revert`
  - keep changes scoped to the request
  - repo intentionally has no `tests/` directory (deleted due to mock nature)

lookup_instructions:
  - sample PDF bundle: Data/DC__OOP__05 Sep 2025.pdf
  - sample XLSX template: Data/Travel Reimbursement_DC_Jan 2026.xlsx
  - keep the string “DC_OOP_05 Sep 2025” in `problem_statement_verbatim` below (used for searching)
  - if you need to inspect the PDF: extract text via `pypdf`; OCR fallback uses `pytesseract` and
    requires the `tesseract` binary (Dockerfile installs it)

problem_statement_verbatim: |-
  The attachment “DC_OOP_05 Sep 2025” reflects the current reimbursement pack: an Excel summary plus
  a PDF bundle of supporting documents. Today employees email receipts/invoices; an approver
  manually reviews for policy compliance (e.g., hotels ≤ USD 300/night; flights under 6 hours must
  be economy) and prepares the summary. Desired flow: upload portal → auto-generated summary →
  automated policy checks/flags → employee review/completion → routing to approver for approval and
  payment.

docs_and_files:
  product_docs: [README.md, railway.MD, .env.example, Data/sample-data-notes.md]
  sample_inputs_outputs:
    sample_pdf_bundle: Data/DC__OOP__05 Sep 2025.pdf
    sample_excel_template: Data/Travel Reimbursement_DC_Jan 2026.xlsx
  entrypoints:
    http_app: src/serendipity_spend/main.py
    api_router: src/serendipity_spend/api/router.py
    ui_router: src/serendipity_spend/web/ui.py
    worker_tasks: src/serendipity_spend/worker/tasks.py
  core:
    settings: src/serendipity_spend/core/config.py
    db: src/serendipity_spend/core/db.py
    orm_base: src/serendipity_spend/core/models.py
    security: src/serendipity_spend/core/security.py
    storage: src/serendipity_spend/core/storage.py
    logging: src/serendipity_spend/core/logging.py
    bootstrap: src/serendipity_spend/bootstrap.py
  schema_and_migrations:
    models_import_hook_for_alembic: src/serendipity_spend/models.py
    alembic_env: alembic/env.py
    migrations_dir: alembic/versions

runtime_stack:
  http:
    framework: fastapi
    docs_ui: /docs
    healthz: /healthz
    ui: jinja2_server_rendered
    ui_base: /app
  db:
    orm: sqlalchemy
    migrations: alembic
    dev_default: sqlite:///./serendipity.db
    prod: postgresql+psycopg://...
  background_jobs:
    queue: celery
    broker_backend: redis
    dev_mode: task_always_eager when ENVIRONMENT=dev
  storage:
    backends: [local_filesystem, s3_compatible]
    shared_storage_required_when: ENVIRONMENT != dev and worker is separate from web
  pdf_and_ocr:
    pdf_text: pypdf
    ocr_fallback: pytesseract (requires tesseract binary)

domain_model:
  roles: {EMPLOYEE: create/edit/submit, APPROVER: review/decide, ADMIN: full_access_and_routing}
  primary_entities:
    - {table: identity_user, model: src/serendipity_spend/modules/identity/models.py:User}
    - {table: claims_claim, model: src/serendipity_spend/modules/claims/models.py:Claim}
    - {table: documents_source_file, model: src/serendipity_spend/modules/documents/models.py:SourceFile}
    - {table: documents_evidence_document, model: src/serendipity_spend/modules/documents/models.py:EvidenceDocument}
    - {table: expenses_expense_item, model: src/serendipity_spend/modules/expenses/models.py:ExpenseItem}
    - {table: expenses_expense_item_evidence, model: src/serendipity_spend/modules/expenses/models.py:ExpenseItemEvidence}
    - {table: fx_rate, model: src/serendipity_spend/modules/fx/models.py:FxRate}
    - {table: policy_violation, model: src/serendipity_spend/modules/policy/models.py:PolicyViolation}
    - {table: policy_exception, model: src/serendipity_spend/modules/policy/models.py:PolicyException}
    - {table: workflow_task, model: src/serendipity_spend/modules/workflow/models.py:Task}
    - {table: workflow_approval, model: src/serendipity_spend/modules/workflow/models.py:Approval}
    - {table: exports_export_run, model: src/serendipity_spend/modules/exports/models.py:ExportRun}
    - {table: extraction_ai_cache, model: src/serendipity_spend/modules/extraction/models.py:ExtractionAICache}
    - {table: audit_event, model: src/serendipity_spend/modules/audit/models.py:AuditEvent (model exists; currently no writes)}

claim_state_machine:
  source: src/serendipity_spend/modules/claims/service.py
  statuses: [DRAFT, PROCESSING, NEEDS_EMPLOYEE_REVIEW, SUBMITTED, NEEDS_APPROVER_REVIEW, CHANGES_REQUESTED, APPROVED, READY_FOR_PAYMENT, PAID, REJECTED]
  transitions:
    - create_claim: DRAFT
    - upload_source_file: DRAFT -> PROCESSING (documents/service.py:create_source_file)
    - extraction_complete: (DRAFT|PROCESSING) -> NEEDS_EMPLOYEE_REVIEW (extraction/service.py:extract_source_file)
    - employee_editable_statuses: [DRAFT, NEEDS_EMPLOYEE_REVIEW, CHANGES_REQUESTED] (claims/service.py:update_claim)
    - submit_claim:
        allowed_from: [DRAFT, NEEDS_EMPLOYEE_REVIEW, CHANGES_REQUESTED]
        blocks_on_open_violations: is_violation_blocking(..., allow_pending_exceptions=true)
        auto_assign_approver_if_single_approver_or_admin: true
        to: NEEDS_APPROVER_REVIEW if approver_id else SUBMITTED
    - route_claim (ADMIN): sets approver_id; SUBMITTED -> NEEDS_APPROVER_REVIEW; then evaluate_claim
    - approve_claim (APPROVER|ADMIN):
        allowed_from: NEEDS_APPROVER_REVIEW
        decisions_to_status: {APPROVED: APPROVED, CHANGES_REQUESTED: CHANGES_REQUESTED, REJECTED: REJECTED}
        approval_blocks_on: is_violation_blocking(..., allow_pending_exceptions=false)
    - delete_claim: allowed_from [DRAFT, PROCESSING, NEEDS_EMPLOYEE_REVIEW] (claims/service.py:delete_claim)

core_contracts:
  - ids_are_uuid_v4: src/serendipity_spend/core/models.py
  - storage_is_source_of_truth_for_bytes: SourceFile.storage_key only (core/storage.py; documents/models.py)
  - multi_service_requires_shared_storage: web+worker must share storage in prod (railway.MD)
  - extraction_idempotency_per_claim:
      - ExpenseItem.dedupe_key unique per claim (expenses/models.py; extraction/service.py:_dedupe_key)
      - vendor+vendor_reference unique when vendor_reference present (expenses/models.py)
  - policy_sync_is_authoritative: evaluate_claim recomputes OPEN/RESOLVED PolicyViolation + POLICY_* tasks and auto-resolves stale policy tasks
  - exceptions:
      - eligible_rules: [R103, R123] (policy/blocking.py)
      - PolicyException.dedupe_key == PolicyViolation.dedupe_key; REQUESTED exceptions can unblock submit but NOT approval
  - google_oauth_domain_restriction: users outside allowed domain are rejected (api/deps.py; web/ui.py; identity/google_oauth.py)
  - logging_context: JSON logs include request_id/user_id/celery_task_id (core/logging.py)

api_contract:
  base_prefix: /api
  auth:
    bearer_jwt_header: "Authorization: Bearer <token>"
    jwt_impl: src/serendipity_spend/core/security.py
    password_login_disabled_when_google_oauth_enabled: true
  router: src/serendipity_spend/api/router.py
  key_routes:
    - /healthz
    - /api/auth/* (token, google, me) and /api/users (ADMIN)
    - /api/claims/* (create/list/get/update/submit/route)
    - /api/claims/*/documents* and /api/documents/*/download
    - /api/claims/*/items*
    - /api/claims/*/fx-rates
    - /api/claims/*/policy/* (evaluate, list, exception request/decision)
    - /api/claims/*/tasks, /api/tasks/*/resolve, /api/approvals/inbox, /api/claims/*/(approve|request-changes|reject)
    - /api/claims/*/exports and /api/exports/*/download/*

ui_contract:
  base_prefix: /app
  auth:
    cookie: access_token (JWT)
    login_pages: [/login, /auth/google/login, /auth/google/callback]
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
  intake:
    accepted_uploads: [pdf, image, text, zip, eml, msg]
    zip_eml_msg_unpacked_into_children: src/serendipity_spend/modules/documents/service.py:create_source_files_from_upload
  processing_pipeline:
    - read bytes from storage (SourceFile.storage_key)
    - detect kind: pdf|image|text|bad_pdf_upload|unknown (extraction/service.py:_detect_file_kind)
    - create EvidenceDocument rows (per segment or per page)
    - parse vendors (Grab/Uber/United/Airline) else AI fallback (optional) else generic heuristic
    - upsert ExpenseItem + link evidence; compute dedupe_key (vendor+reference else vendor+text_hash_prefix)
    - create/update EXTRACT_<source_id_prefix> Task when manual review is needed
    - evaluate policy + advance claim status
  segmentation_rules_pdf:
    - "Grab: 2 pages (your grab e-receipt + booking id) → ride_receipt"
    - "United Airlines: 2 pages (thanks for your purchase with United) → email_receipt"
    - "Uber: 3 pages (trip with Uber + total) → trip_summary"
    - "Airline: 1 page (PAYMENT RECEIPT + BAG FEE) → payment_receipt"
  parsers:
    - {vendor: Grab, receipt_type: ride_receipt, impl: src/serendipity_spend/modules/extraction/parsers/grab.py:parse_grab_ride_receipt}
    - {vendor: Uber, receipt_type: trip_summary, impl: src/serendipity_spend/modules/extraction/parsers/uber.py:parse_uber_trip_summary}
    - {vendor: United Airlines, receipt_type: email_receipt, impl: src/serendipity_spend/modules/extraction/parsers/united_wifi.py:parse_united_wifi_receipt}
    - {vendor: Airline, receipt_type: payment_receipt, impl: src/serendipity_spend/modules/extraction/parsers/baggage_fee.py:parse_baggage_fee_payment_receipt}
  ai_fallback:
    enabled_when: RECEIPT_AI_ENABLED=true AND OPENAI_API_KEY set
    receipt_ai_cache_table: extraction_ai_cache (schema_version=1)
    policy_field_ai: src/serendipity_spend/modules/extraction/ai.py:extract_policy_fields
  fx_behavior:
    - if from_currency == claim.home_currency: amount_home_amount = amount; fx_rate_to_home = 1
    - else if FxRate missing: amount_home_amount stays null; policy emits R030

policy_contract:
  source: src/serendipity_spend/modules/policy/service.py:evaluate_claim
  blocking_logic: src/serendipity_spend/modules/policy/blocking.py:is_violation_blocking
  rules_currently_implemented:
    - R001 FAIL: claim.purpose missing/blank (blocks submit)
    - R002 FAIL: travel dates missing (blocks submit)
    - R010 NEEDS_INFO: Uber trip_summary may be insufficient (not blocking)
    - R020 WARN: Grab metadata.profile == PERSONAL (not blocking)
    - R031 NEEDS_INFO: invalid currency code (submit_blocking)
    - R030 NEEDS_INFO: missing FX to home currency (submit_blocking)
    - R040 NEEDS_INFO: generic extraction and metadata.employee_reviewed == false (submit_blocking)
    - R101/R102 NEEDS_INFO: hotel nights missing / USD conversion missing (submit_blocking)
    - R103 FAIL: (total_usd / hotel_nights) > 300 (exception eligible)
    - R111/R112 NEEDS_INFO: meals USD conversion missing / USD>=100 attendees missing (submit_blocking)
    - R121/R122 NEEDS_INFO: flight duration/cabin missing (submit_blocking)
    - R123 FAIL: flight_duration_hours < 6 and cabin != economy (exception eligible)
  task_mapping:
    - POLICY_{rule_id} Task per violation; default assigned_to=employee
    - exception REQUESTED on R103/R123 assigns task to approver if claim.approver_id

export_contract:
  source: src/serendipity_spend/modules/exports/service.py
  artifacts:
    reimbursement_summary_xlsx:
      template: Data/Travel Reimbursement_DC_Jan 2026.xlsx
      fallback: generated workbook
      sheet: Reimbursement
      headers_row: 6
      data_start_row: 8
      currencies_supported_in_columns: [USD, SGD, CAD, GBP]
      reimbursement_column_currency: claim.home_currency
    supporting_docs_pdf: "merged PDF of all SourceFiles (PDF+images+text→PDF), ordered by earliest linked ExpenseItem.transaction_date (fallback upload time)"
    supporting_docs_zip: "supporting_zip_key exists but is not produced"

operations:
  env_vars_source: [src/serendipity_spend/core/config.py, .env.example, railway.MD]
  required_in_production: [ENVIRONMENT, SECRET_KEY, DATABASE_URL, STORAGE_BACKEND, storage credentials, REDIS_URL (if ENVIRONMENT != dev)]
  optional:
    - BASE_URL
    - GOOGLE_OAUTH_CLIENT_ID
    - GOOGLE_OAUTH_CLIENT_SECRET
    - GOOGLE_OAUTH_ALLOWED_DOMAIN
    - INIT_ADMIN_EMAIL (comma-separated supported)
    - INIT_ADMIN_PASSWORD
    - ACCESS_TOKEN_EXP_MINUTES
    - RECEIPT_AI_ENABLED / RECEIPT_AI_TIMEOUT_SECONDS / RECEIPT_AI_MAX_CHARS
    - OPENAI_API_KEY / OPENAI_MODEL / OPENAI_BASE_URL
    - TESSERACT_LANG
  local_dev_commands:
    - python -m pip install -e '.[dev]'
    - cp .env.example .env
    - uvicorn serendipity_spend.main:app --reload
    - ruff check .
  notes:
    - migrations must be applied in production (`alembic upgrade head`); dev sqlite auto-creates tables on startup
    - tests were deleted intentionally; use the sample PDF to manually validate extraction/policy
  sample_e2e_expectations:
    file: Data/DC__OOP__05 Sep 2025.pdf
    items_total: 17
    by_vendor: {Grab: 4, "United Airlines": 3, Uber: 9, Airline: 1}