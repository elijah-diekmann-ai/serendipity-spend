from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from serendipity_spend.api.deps import get_current_user
from serendipity_spend.core.db import db_session
from serendipity_spend.modules.claims.service import get_claim_for_user
from serendipity_spend.modules.fx.schemas import FxRateOut, FxRateUpsert
from serendipity_spend.modules.fx.service import apply_fx_to_claim_items, upsert_fx_rate
from serendipity_spend.modules.identity.models import User
from serendipity_spend.modules.policy.service import evaluate_claim

router = APIRouter(tags=["fx"])


@router.post("/claims/{claim_id}/fx-rates", response_model=list[FxRateOut])
def set_fx_rates(
    claim_id: uuid.UUID,
    payload: list[FxRateUpsert],
    session: Session = Depends(db_session),
    user: User = Depends(get_current_user),
) -> list[FxRateOut]:
    claim = get_claim_for_user(session, claim_id=claim_id, user=user)
    out: list[FxRateOut] = []
    for r in payload:
        fx = upsert_fx_rate(
            session,
            claim_id=claim.id,
            from_currency=r.from_currency,
            to_currency=r.to_currency,
            rate=r.rate,
            as_of_date=r.as_of_date,
            source=r.source,
        )
        out.append(FxRateOut.model_validate(fx, from_attributes=True))

    apply_fx_to_claim_items(session, claim_id=claim.id)
    evaluate_claim(session, claim_id=claim.id)
    return out
