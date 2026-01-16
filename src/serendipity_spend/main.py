from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from serendipity_spend.api.router import router as api_router
from serendipity_spend.bootstrap import bootstrap
from serendipity_spend.web.ui import router as ui_router


def create_app() -> FastAPI:
    @asynccontextmanager
    async def lifespan(_: FastAPI):
        bootstrap()
        yield

    app = FastAPI(title="Serendipity Spend", version="0.1.0", lifespan=lifespan)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(api_router)
    app.include_router(ui_router)
    return app


app = create_app()
