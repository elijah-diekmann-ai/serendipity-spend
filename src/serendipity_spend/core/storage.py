from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path

import boto3

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

    def _ensure_bucket(self) -> None:
        try:
            self._client.head_bucket(Bucket=self._bucket)
        except Exception:
            self._client.create_bucket(Bucket=self._bucket)

    def put(self, *, key: str, body: bytes) -> StoredObject:
        start = time.monotonic()
        try:
            self._client.put_object(Bucket=self._bucket, Key=key, Body=body)
        except Exception:
            log_exception(
                logger,
                "storage.put.failure",
                backend="s3",
                storage_key=key,
                byte_size=len(body),
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
