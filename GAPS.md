## 1. No Exception/Justification Workflow

FAIL rules (hotel cap, cabin class) say "provide justification" but there's no structured override/approval mechanism; they remain submit-blocking.

**References:**
- `src/serendipity_spend/modules/policy/service.py:220`
- `src/serendipity_spend/modules/claims/service.py:180`

## 2. Exported Excel Doesn't Include Policy Flags

Policy issues are visible in the UI, but the generated summary.xlsx is amounts-focused and doesn't annotate violations per line item.

**References:**
- `src/serendipity_spend/modules/exports/service.py:88`

Implement a robust solution for these two issues.