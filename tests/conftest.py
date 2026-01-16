from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

# Set env before any serendipity_spend imports (settings/engine are created at import time).
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("DATABASE_URL", "sqlite:///./.serendipity_test.db")
os.environ.setdefault("STORAGE_BACKEND", "local")
os.environ.setdefault("LOCAL_STORAGE_PATH", ".tmp_storage_test")


@pytest.fixture(autouse=True)
def _reset_db_and_storage() -> None:
    import serendipity_spend.models  # noqa: F401
    from serendipity_spend.core.db import engine
    from serendipity_spend.core.models import Base

    # Reset storage cache and directory
    try:
        import serendipity_spend.core.storage as storage_mod

        storage_mod._storage = None
    except Exception:
        pass

    storage_path = Path(os.environ["LOCAL_STORAGE_PATH"])
    if storage_path.exists():
        shutil.rmtree(storage_path)

    # Reset DB schema
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)

    yield
