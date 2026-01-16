from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import boto3

from serendipity_spend.core.config import settings


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
        path = self._root / key
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        return StoredObject(key=key, byte_size=len(body))

    def get(self, *, key: str) -> bytes:
        path = self._root / key
        if not path.exists():
            raise StorageError(f"Object not found: {key}")
        return path.read_bytes()

    def delete(self, *, key: str) -> None:
        path = self._root / key
        if path.exists():
            path.unlink()


class S3ObjectStorage(ObjectStorage):
    def __init__(self) -> None:
        session = boto3.session.Session(
            aws_access_key_id=settings.s3_access_key_id,
            aws_secret_access_key=settings.s3_secret_access_key,
            region_name=settings.s3_region or None,
        )
        # Treat empty string as None (use default AWS endpoint)
        endpoint_url = settings.s3_endpoint_url or None
        self._client = session.client("s3", endpoint_url=endpoint_url)
        self._bucket = settings.s3_bucket
        self._ensure_bucket()

    def _ensure_bucket(self) -> None:
        try:
            self._client.head_bucket(Bucket=self._bucket)
        except Exception:
            self._client.create_bucket(Bucket=self._bucket)

    def put(self, *, key: str, body: bytes) -> StoredObject:
        self._client.put_object(Bucket=self._bucket, Key=key, Body=body)
        return StoredObject(key=key, byte_size=len(body))

    def get(self, *, key: str) -> bytes:
        try:
            resp = self._client.get_object(Bucket=self._bucket, Key=key)
        except Exception as e:  # noqa: BLE001
            raise StorageError(f"Object not found: {key}") from e
        return resp["Body"].read()

    def delete(self, *, key: str) -> None:
        self._client.delete_object(Bucket=self._bucket, Key=key)


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
