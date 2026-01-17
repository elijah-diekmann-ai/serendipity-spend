from __future__ import annotations

# Ensure all models are registered before any task runs
# isort: off
import serendipity_spend.models  # noqa: F401
# isort: on

import time

from serendipity_spend.core.logging import (
    get_logger,
    log_event,
    log_exception,
    monotonic_ms,
    reset_task_context,
    set_task_context,
)
from serendipity_spend.worker.celery_app import celery_app

logger = get_logger(__name__)


@celery_app.task(name="extract_source_file", bind=True)
def extract_source_file_task(self, source_file_id: str) -> None:
    from serendipity_spend.modules.extraction.service import extract_source_file

    task_id = getattr(self.request, "id", None)
    token = set_task_context(task_id)
    start = time.monotonic()
    log_event(
        logger,
        "celery.task.start",
        task_name="extract_source_file",
        celery_task_id=task_id,
        source_file_id=source_file_id,
    )
    try:
        extract_source_file(source_file_id=source_file_id)
        log_event(
            logger,
            "celery.task.finish",
            task_name="extract_source_file",
            celery_task_id=task_id,
            source_file_id=source_file_id,
            duration_ms=monotonic_ms(start),
        )
    except Exception:
        log_exception(
            logger,
            "celery.task.error",
            task_name="extract_source_file",
            celery_task_id=task_id,
            source_file_id=source_file_id,
            duration_ms=monotonic_ms(start),
        )
        raise
    finally:
        reset_task_context(token)


@celery_app.task(name="generate_export", bind=True)
def generate_export_task(self, export_run_id: str) -> None:
    from serendipity_spend.modules.exports.service import generate_export

    task_id = getattr(self.request, "id", None)
    token = set_task_context(task_id)
    start = time.monotonic()
    log_event(
        logger,
        "celery.task.start",
        task_name="generate_export",
        celery_task_id=task_id,
        export_run_id=export_run_id,
    )
    try:
        generate_export(export_run_id=export_run_id)
        log_event(
            logger,
            "celery.task.finish",
            task_name="generate_export",
            celery_task_id=task_id,
            export_run_id=export_run_id,
            duration_ms=monotonic_ms(start),
        )
    except Exception:
        log_exception(
            logger,
            "celery.task.error",
            task_name="generate_export",
            celery_task_id=task_id,
            export_run_id=export_run_id,
            duration_ms=monotonic_ms(start),
        )
        raise
    finally:
        reset_task_context(token)
