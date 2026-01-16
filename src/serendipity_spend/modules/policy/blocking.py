from __future__ import annotations

from typing import Any

from serendipity_spend.modules.policy.models import PolicySeverity, PolicyViolation

EXCEPTION_ELIGIBLE_RULE_IDS = frozenset({"R103", "R123"})


def _exception_status(data_json: dict[str, Any] | None) -> str | None:
    data = data_json or {}
    exc = data.get("exception") or {}
    status = exc.get("status")
    if not status:
        return None
    return str(status).upper()


def is_violation_blocking(
    v: PolicyViolation, *, allow_pending_exceptions: bool
) -> bool:
    if v.rule_id in EXCEPTION_ELIGIBLE_RULE_IDS:
        status = _exception_status(v.data_json)
        if status == "APPROVED":
            return False
        if allow_pending_exceptions and status == "REQUESTED":
            return False

    if v.severity == PolicySeverity.FAIL:
        return True
    return bool((v.data_json or {}).get("submit_blocking"))

