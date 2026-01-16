from __future__ import annotations

from celery import Celery

from serendipity_spend.core.config import settings


def make_celery() -> Celery:
    app = Celery("serendipity_spend", broker=settings.redis_url, backend=settings.redis_url)
    app.conf.update(
        task_always_eager=settings.environment == "dev",
        task_eager_propagates=True,
        task_track_started=True,
    )
    app.autodiscover_tasks(["serendipity_spend.worker.tasks"])
    return app


celery_app = make_celery()
