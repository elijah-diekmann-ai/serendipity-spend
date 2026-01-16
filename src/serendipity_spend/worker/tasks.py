from __future__ import annotations

from serendipity_spend.worker.celery_app import celery_app

# Ensure all models are registered before any task runs
import serendipity_spend.models  # noqa: F401


@celery_app.task(name="extract_source_file")
def extract_source_file_task(source_file_id: str) -> None:
    from serendipity_spend.modules.extraction.service import extract_source_file

    extract_source_file(source_file_id=source_file_id)


@celery_app.task(name="generate_export")
def generate_export_task(export_run_id: str) -> None:
    from serendipity_spend.modules.exports.service import generate_export

    generate_export(export_run_id=export_run_id)
