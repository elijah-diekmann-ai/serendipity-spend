# Remaining Gaps

- Receipt coverage is still narrow (hard-coded recognition for a few vendors; everything else relies on generic heuristics + manual cleanup): src/serendipity_spend/modules/extraction/service.py:401, src/serendipity_spend/modules/extraction/service.py:603

- "Hotel confirmation emails" are not truly ingested: .eml handling only extracts attachments; email bodies (often the "receipt") aren't parsed/converted: src/serendipity_spend/modules/documents/service.py:105, src/serendipity_spend/modules/documents/service.py:193

- Submission enforcement is partial: only FAIL policy violations block submit, so "missing info" (FX, attendees, flight details, generic-review) can still be submitted: src/serendipity_spend/modules/claims/service.py:152

- UI doesn't surface why submit failed (exceptions are swallowed): src/serendipity_spend/web/ui.py:681

- Production export likely won't match the finance Excel template: the template is loaded from Data/...xlsx but Data/ isn't copied into the Docker image, causing fallback to a barebones workbook: src/serendipity_spend/modules/exports/service.py:146, Dockerfile:12

---

Implement robust solutions to resolve the remaining gaps.