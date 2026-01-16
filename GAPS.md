# Extraction & Validation Gaps

## 1. File Type Detection

Add Layer 0: File type detection + fallback (magic-bytes sniffing, and if a ".pdf" isn't %PDF, treat it as text/HTML or raise a clear "bad upload" task instead of trying PdfReader).

## 2. Semantic Validators

Make "Regex Validators" semantic validators, not just regex: currency must be ISO-4217 allowlisted (this directly prevents the GMT bug caused by accepting any [A-Z]{3} as a currency in `_extract_total_amount` at `src/serendipity_spend/modules/extraction/service.py:1273`), dates must parse + be plausible, amounts must match a money context (not a time/timezone context).

## 3. LLM Strategy

Don't make the LLM always mandatory; a more robust default is: vendor parser fast-path (high confidence) → LLM when unknown/low confidence → deterministic fallback when LLM unavailable, plus caching by `EvidenceDocument.text_hash`.

## 4. Provenance & Confidence

Require provenance + confidence from the LLM (e.g., per-field evidence snippets/line refs). If validators can't corroborate, route to "needs employee review" rather than generating misleading policy violations like R030.

## 5. FX Hardening

Harden FX around bad currencies: `auto_upsert_fx_rates` currently tries any 3-letter code (`src/serendipity_spend/modules/fx/service.py:75`), so one bad "currency" can blow up auto-fill; it should skip invalid codes and report what was skipped, and the UI shouldn't be limited to fixed USD/CAD/GBP/EUR inputs (`src/serendipity_spend/web/templates/claim_detail.html:546`).

## 6. Structured Outputs for LLM Fields

When the LLM is invoked (currently only for policy-field extraction in `_infer_policy_fields`), switch to Structured Outputs / JSON Schema so the model must return a typed object (category, hotel_nights, flight_duration_hours, flight_cabin_class, attendees, confidence, plus optional evidence snippets). This improves reliability of the LLM step (fewer malformed responses, safer refusals), and should be layered on top of the LLM strategy (#3) and provenance requirements (#4); it does not replace semantic validators (#2).