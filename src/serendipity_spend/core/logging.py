from __future__ import annotations

import contextvars
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

_request_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "request_id", default=None
)
_user_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "user_id", default=None
)
_task_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "celery_task_id", default=None
)

_configured = False


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat()
        if ts.endswith("+00:00"):
            ts = ts[:-6] + "Z"
        payload: dict[str, Any] = {
            "ts": ts,
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        event = getattr(record, "event", None)
        if event:
            payload["event"] = event
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            for key, value in fields.items():
                if value is None:
                    continue
                payload[key] = value
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=True)


def configure_logging() -> None:
    global _configured  # noqa: PLW0603
    if _configured:
        return
    level_name = os.getenv("LOG_LEVEL", "INFO").upper()
    level = logging._nameToLevel.get(level_name, logging.INFO)
    handler = logging.StreamHandler()
    handler.setLevel(level)
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger("serendipity_spend")
    logger.setLevel(level)
    logger.handlers = [handler]
    logger.propagate = False
    _configured = True


def get_logger(name: str) -> logging.Logger:
    configure_logging()
    return logging.getLogger(name)


def set_request_context(*, request_id: str | None) -> tuple[contextvars.Token, contextvars.Token]:
    token_request = _request_id_var.set(request_id)
    token_user = _user_id_var.set(None)
    return token_request, token_user


def reset_request_context(tokens: tuple[contextvars.Token, contextvars.Token]) -> None:
    token_request, token_user = tokens
    _request_id_var.reset(token_request)
    _user_id_var.reset(token_user)


def set_user_context(user_id: str | None) -> None:
    _user_id_var.set(user_id)


def get_request_id() -> str | None:
    return _request_id_var.get()


def set_task_context(task_id: str | None) -> contextvars.Token:
    return _task_id_var.set(task_id)


def reset_task_context(token: contextvars.Token) -> None:
    _task_id_var.reset(token)


def _merge_fields(fields: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    request_id = _request_id_var.get()
    if request_id:
        payload["request_id"] = request_id
    user_id = _user_id_var.get()
    if user_id:
        payload["user_id"] = user_id
    task_id = _task_id_var.get()
    if task_id:
        payload["celery_task_id"] = task_id
    for key, value in fields.items():
        if value is None:
            continue
        payload[key] = value
    return payload


def log_event(
    logger: logging.Logger, event: str, *, level: int = logging.INFO, **fields: Any
) -> None:
    payload = _merge_fields(fields)
    logger.log(level, event, extra={"event": event, "fields": payload})


def log_exception(logger: logging.Logger, event: str, **fields: Any) -> None:
    payload = _merge_fields(fields)
    logger.exception(event, extra={"event": event, "fields": payload})


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
        tokens = set_request_context(request_id=request_id)
        try:
            response = await call_next(request)
            response.headers["x-request-id"] = request_id
            return response
        except Exception:
            logger = get_logger(__name__)
            log_exception(
                logger,
                "http.request.error",
                method=request.method,
                path=request.url.path,
                query=str(request.url.query) if request.url.query else None,
            )
            raise
        finally:
            reset_request_context(tokens)


def monotonic_ms(start: float) -> int:
    return int((time.monotonic() - start) * 1000)
