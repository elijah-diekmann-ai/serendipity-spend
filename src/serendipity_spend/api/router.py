from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from serendipity_spend.core.storage import diagnose_storage
from serendipity_spend.modules.claims.api import router as claims_router
from serendipity_spend.modules.documents.api import router as documents_router
from serendipity_spend.modules.expenses.api import router as expenses_router
from serendipity_spend.modules.exports.api import router as exports_router
from serendipity_spend.modules.fx.api import router as fx_router
from serendipity_spend.modules.identity.api import router as identity_router
from serendipity_spend.modules.policy.api import router as policy_router
from serendipity_spend.modules.workflow.api import router as workflow_router

router = APIRouter()

router.include_router(identity_router, prefix="/api")
router.include_router(claims_router, prefix="/api")
router.include_router(documents_router, prefix="/api")
router.include_router(expenses_router, prefix="/api")
router.include_router(fx_router, prefix="/api")
router.include_router(policy_router, prefix="/api")
router.include_router(workflow_router, prefix="/api")
router.include_router(exports_router, prefix="/api")


@router.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/healthz/storage")
def healthz_storage(*, write_test: bool = False) -> JSONResponse:
    result = diagnose_storage(write_test=write_test)
    status_code = 200 if result.get("ok") else 503
    return JSONResponse(status_code=status_code, content=result)
