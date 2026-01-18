from __future__ import annotations

import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from serendipity_spend.core.config import settings
from serendipity_spend.core.logging import get_logger, log_event, log_exception, monotonic_ms

logger = get_logger(__name__)


class StorageError(RuntimeError):
    pass


@dataclass(frozen=True)
class StoredObject:
    key: str
    byte_size: int


class ObjectStorage:
    def put(self, *, key: str, body: bytes) -> StoredObject:  # pragma: no cover
        raise NotImplementedError

    def get(self, *, key: str) -> bytes:  # pragma: no cover
        raise NotImplementedError

    def delete(self, *, key: str) -> None:  # pragma: no cover
        raise NotImplementedError


class LocalObjectStorage(ObjectStorage):
    def __init__(self, root: Path):
        self._root = root
        self._root.mkdir(parents=True, exist_ok=True)

    def put(self, *, key: str, body: bytes) -> StoredObject:
        start = time.monotonic()
        path = self._root / key
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(body)
        except Exception:
            log_exception(
                logger,
                "storage.put.failure",
                backend="local",
                storage_key=key,
                byte_size=len(body),
            )
            raise
        log_event(
            logger,
            "storage.put.success",
            backend="local",
            storage_key=key,
            byte_size=len(body),
            duration_ms=monotonic_ms(start),
        )
        return StoredObject(key=key, byte_size=len(body))

    def get(self, *, key: str) -> bytes:
        start = time.monotonic()
        path = self._root / key
        if not path.exists():
            log_event(
                logger,
                "storage.get.failure",
                backend="local",
                storage_key=key,
                duration_ms=monotonic_ms(start),
            )
            raise StorageError(f"Object not found: {key}")
        try:
            data = path.read_bytes()
        except Exception:
            log_exception(
                logger,
                "storage.get.failure",
                backend="local",
                storage_key=key,
                duration_ms=monotonic_ms(start),
            )
            raise
        return data

    def delete(self, *, key: str) -> None:
        path = self._root / key
        if path.exists():
            try:
                path.unlink()
            except Exception:
                log_exception(
                    logger,
                    "storage.delete.failure",
                    backend="local",
                    storage_key=key,
                )
                raise


class S3ObjectStorage(ObjectStorage):
    def __init__(self) -> None:
        # Handle Railway's "auto" region - boto3 needs a real region or None
        region = settings.s3_region
        if not region or region.lower() == "auto":
            region = "us-east-1"  # Default region for S3-compatible services

        session = boto3.session.Session(
            aws_access_key_id=settings.s3_access_key_id,
            aws_secret_access_key=settings.s3_secret_access_key,
            region_name=region,
        )
        # Treat empty string as None (use default AWS endpoint)
        endpoint_url = settings.s3_endpoint_url or None

        # Railway Bucket requires virtual-hosted-style URLs
        # Configure boto3 to use virtual addressing style for S3-compatible endpoints
        from botocore.config import Config

        config = Config(
            s3={"addressing_style": "virtual"},
            retries={"max_attempts": 3, "mode": "adaptive"},
            connect_timeout=30,
            read_timeout=60,
        )
        self._client = session.client("s3", endpoint_url=endpoint_url, config=config)
        self._bucket = settings.s3_bucket
        self._ensure_bucket()

    def _retry_delay_s(self, attempt: int) -> float:
        # Keep this small to avoid user-facing request timeouts on uploads.
        # attempt=1 => 0.25s, attempt=2 => 0.5s, attempt=3 => 1.0s, ...
        return min(3.0, 0.25 * (2 ** (attempt - 1)))

    def _should_retry_error(self, error: Exception) -> bool:
        if isinstance(error, ClientError):
            code = (error.response.get("Error") or {}).get("Code")
            return code in {
                "RequestCanceled",
                "RequestTimeout",
                "Throttling",
                "ThrottlingException",
                "SlowDown",
                "InternalError",
                "ServiceUnavailable",
            }
        return isinstance(error, BotoCoreError)

    def _ensure_bucket(self) -> None:
        try:
            self._client.head_bucket(Bucket=self._bucket)
        except Exception:
            self._client.create_bucket(Bucket=self._bucket)

    def put(self, *, key: str, body: bytes) -> StoredObject:
        start = time.monotonic()
        max_attempts = 5
        for attempt in range(1, max_attempts + 1):
            try:
                self._client.put_object(Bucket=self._bucket, Key=key, Body=body)
                break
            except Exception as e:  # noqa: BLE001
                if attempt < max_attempts and self._should_retry_error(e):
                    delay_s = self._retry_delay_s(attempt)
                    error_code = None
                    if isinstance(e, ClientError):
                        error_code = (e.response.get("Error") or {}).get("Code")
                    log_event(
                        logger,
                        "storage.put.retry",
                        backend="s3",
                        storage_key=key,
                        byte_size=len(body),
                        attempt=attempt,
                        delay_s=delay_s,
                        error_code=error_code,
                        error_type=type(e).__name__,
                    )
                    time.sleep(delay_s)
                    continue
                log_exception(
                    logger,
                    "storage.put.failure",
                    backend="s3",
                    storage_key=key,
                    byte_size=len(body),
                    attempt=attempt,
                )
                raise
        log_event(
            logger,
            "storage.put.success",
            backend="s3",
            storage_key=key,
            byte_size=len(body),
            duration_ms=monotonic_ms(start),
        )
        return StoredObject(key=key, byte_size=len(body))

    def get(self, *, key: str) -> bytes:
        start = time.monotonic()
        try:
            resp = self._client.get_object(Bucket=self._bucket, Key=key)
        except Exception as e:  # noqa: BLE001
            log_exception(
                logger,
                "storage.get.failure",
                backend="s3",
                storage_key=key,
                duration_ms=monotonic_ms(start),
            )
            raise StorageError(f"Object not found: {key}") from e
        try:
            return resp["Body"].read()
        except Exception:
            log_exception(
                logger,
                "storage.get.failure",
                backend="s3",
                storage_key=key,
                duration_ms=monotonic_ms(start),
            )
            raise

    def delete(self, *, key: str) -> None:
        try:
            self._client.delete_object(Bucket=self._bucket, Key=key)
        except Exception:
            log_exception(
                logger,
                "storage.delete.failure",
                backend="s3",
                storage_key=key,
            )
            raise


_storage: ObjectStorage | None = None


def get_storage() -> ObjectStorage:
    global _storage  # noqa: PLW0603
    if _storage is not None:
        return _storage

    if settings.storage_backend == "s3":
        _storage = S3ObjectStorage()
    else:
        root = settings.local_storage_path
        if not root.is_absolute():
            root = Path(os.getcwd()) / root
        _storage = LocalObjectStorage(root)
    return _storage


def diagnose_storage(*, write_test: bool = False) -> dict[str, Any]:
    """
    Best-effort connectivity diagnostics for the configured storage backend.

    Safe for production: does not return credentials. When write_test=True, it will
    write a small temporary object and delete it.
    """
    if settings.storage_backend == "s3":
        return _diagnose_s3(write_test=write_test)
    return _diagnose_local(write_test=write_test)


def _diagnose_local(*, write_test: bool) -> dict[str, Any]:
    root = settings.local_storage_path
    if not root.is_absolute():
        root = Path(os.getcwd()) / root
    result: dict[str, Any] = {"ok": True, "backend": "local", "root": str(root)}
    if not write_test:
        return result

    key = f"diagnostics/healthz-{time.time_ns()}.txt"
    body = b"ok"
    storage = LocalObjectStorage(root)
    try:
        storage.put(key=key, body=body)
        out = storage.get(key=key)
        storage.delete(key=key)
    except Exception as e:  # noqa: BLE001
        result["ok"] = False
        result["error_type"] = type(e).__name__
        result["error"] = str(e)
        return result

    result["write_test"] = {"ok": out == body, "key": key, "byte_size": len(body)}
    if out != body:
        result["ok"] = False
    return result


def _dns_lookup(host: str | None) -> dict[str, Any]:
    if not host:
        return {"ok": False, "error": "missing_host"}
    try:
        import socket

        infos = socket.getaddrinfo(host, 443)
        addrs = sorted({info[4][0] for info in infos if info and info[4]})
        return {"ok": True, "addresses": addrs}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error_type": type(e).__name__, "error": str(e)}


def _client_error_info(error: Exception) -> dict[str, Any]:
    payload: dict[str, Any] = {"error_type": type(error).__name__}
    if isinstance(error, ClientError):
        err = error.response.get("Error") or {}
        payload["error_code"] = err.get("Code")
        payload["error_message"] = err.get("Message")
        payload["http_status"] = (error.response.get("ResponseMetadata") or {}).get(
            "HTTPStatusCode"
        )
        return payload
    payload["error"] = str(error)
    return payload


def _diagnose_s3(*, write_test: bool) -> dict[str, Any]:
    endpoint_url = settings.s3_endpoint_url or None
    endpoint_host = urlparse(endpoint_url).hostname if endpoint_url else None
    bucket = settings.s3_bucket
    region_raw = settings.s3_region
    region = region_raw
    if not region or region.lower() == "auto":
        region = "us-east-1"

    result: dict[str, Any] = {
        "ok": True,
        "backend": "s3",
        "s3": {
            "endpoint_url": endpoint_url,
            "endpoint_host": endpoint_host,
            "bucket": bucket,
            "region": region_raw,
        },
        "checks": {},
    }

    if not bucket:
        return {"ok": False, "backend": "s3", "error": "missing_s3_bucket"}
    if not settings.s3_access_key_id or not settings.s3_secret_access_key:
        return {"ok": False, "backend": "s3", "error": "missing_s3_credentials"}

    session = boto3.session.Session(
        aws_access_key_id=settings.s3_access_key_id,
        aws_secret_access_key=settings.s3_secret_access_key,
        region_name=region,
    )

    from botocore.config import Config

    def run_step(check: dict[str, Any], name: str, fn) -> bool:
        start = time.monotonic()
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            check[name] = {
                "ok": False,
                "duration_ms": monotonic_ms(start),
                **_client_error_info(e),
            }
            return False
        check[name] = {"ok": True, "duration_ms": monotonic_ms(start)}
        return True

    styles = ("virtual", "path")
    for style in styles:
        check: dict[str, Any] = {"addressing_style": style}
        bucket_host = f"{bucket}.{endpoint_host}" if endpoint_host else None
        check["dns"] = {
            "endpoint_host": _dns_lookup(endpoint_host),
            "bucket_host": _dns_lookup(bucket_host),
        }

        client = session.client(
            "s3",
            endpoint_url=endpoint_url,
            config=Config(
                s3={"addressing_style": style},
                retries={"max_attempts": 1, "mode": "standard"},
                connect_timeout=5,
                read_timeout=20,
            ),
        )

        ok_head = run_step(
            check,
            "head_bucket",
            lambda _client=client, _bucket=bucket: _client.head_bucket(Bucket=_bucket),
        )

        key = None
        body = b"ok"
        if write_test and ok_head:
            key = f"diagnostics/healthz/{uuid.uuid4()}.txt"

            ok_put = run_step(
                check,
                "put_object",
                lambda _client=client, _bucket=bucket, _key=key, _body=body: _client.put_object(
                    Bucket=_bucket, Key=_key, Body=_body
                ),
            )
            if ok_put:
                ok_get = run_step(
                    check,
                    "get_object",
                    lambda _client=client, _bucket=bucket, _key=key: _client.get_object(
                        Bucket=_bucket, Key=_key
                    )["Body"].read(),
                )
                if ok_get:
                    check["get_object"]["expected_byte_size"] = len(body)
                run_step(
                    check,
                    "delete_object",
                    lambda _client=client, _bucket=bucket, _key=key: _client.delete_object(
                        Bucket=_bucket, Key=_key
                    ),
                )

        if key:
            check["test_key"] = key

        result["checks"][style] = check
        if not (check.get("head_bucket") or {}).get("ok"):
            result["ok"] = False
        if write_test and not (check.get("put_object") or {}).get("ok", True):
            result["ok"] = False

    return result
