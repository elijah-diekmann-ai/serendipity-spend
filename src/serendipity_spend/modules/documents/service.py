from __future__ import annotations

import hashlib
import uuid

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from serendipity_spend.core.storage import get_storage
from serendipity_spend.modules.claims.models import Claim, ClaimStatus
from serendipity_spend.modules.documents.models import SourceFile, SourceFileStatus
from serendipity_spend.modules.identity.models import User, UserRole


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def assert_claim_access(*, claim: Claim, user: User) -> None:
    if user.role == UserRole.ADMIN:
        return
    if user.role == UserRole.EMPLOYEE and claim.employee_id == user.id:
        return
    if user.role == UserRole.APPROVER and claim.approver_id == user.id:
        return
    raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed")


def create_source_file(
    session: Session,
    *,
    claim: Claim,
    user: User,
    filename: str,
    content_type: str | None,
    body: bytes,
) -> SourceFile:
    assert_claim_access(claim=claim, user=user)

    sha256 = _sha256_hex(body)
    key = f"claims/{claim.id}/source/{uuid.uuid4()}-{filename}"
    stored = get_storage().put(key=key, body=body)

    if claim.status == ClaimStatus.DRAFT:
        claim.status = ClaimStatus.PROCESSING
        session.add(claim)

    source = SourceFile(
        claim_id=claim.id,
        uploader_id=user.id,
        filename=filename,
        content_type=content_type,
        byte_size=stored.byte_size,
        sha256=sha256,
        storage_key=stored.key,
        status=SourceFileStatus.UPLOADED,
    )
    session.add(source)
    session.commit()
    session.refresh(source)
    return source


def list_source_files(session: Session, *, claim: Claim, user: User) -> list[SourceFile]:
    assert_claim_access(claim=claim, user=user)
    return list(
        session.scalars(
            select(SourceFile)
            .where(SourceFile.claim_id == claim.id)
            .order_by(SourceFile.created_at.desc())
        )
    )


def get_source_file(session: Session, *, source_file_id: uuid.UUID) -> SourceFile | None:
    return session.scalar(select(SourceFile).where(SourceFile.id == source_file_id))


def create_source_files_from_upload(
    session: Session,
    *,
    claim: Claim,
    user: User,
    filename: str,
    content_type: str | None,
    body: bytes,
) -> list[SourceFile]:
    if _is_zip_upload(filename=filename, content_type=content_type):
        children = _unpack_zip_upload(body)
        sources: list[SourceFile] = []
        for child in children:
            sources.extend(
                create_source_files_from_upload(
                    session,
                    claim=claim,
                    user=user,
                    filename=child["filename"],
                    content_type=child.get("content_type"),
                    body=child["body"],
                )
            )
        return sources

    if _is_eml_upload(filename=filename, content_type=content_type):
        children = _unpack_eml_upload(body)
        if not children:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email has no attachments to ingest.",
            )
        sources: list[SourceFile] = []
        for child in children:
            sources.extend(
                create_source_files_from_upload(
                    session,
                    claim=claim,
                    user=user,
                    filename=child["filename"],
                    content_type=child.get("content_type"),
                    body=child["body"],
                )
            )
        return sources

    return [
        create_source_file(
            session,
            claim=claim,
            user=user,
            filename=_sanitize_filename(filename) or "upload.bin",
            content_type=content_type,
            body=body,
        )
    ]


def _is_zip_upload(*, filename: str, content_type: str | None) -> bool:
    if filename.lower().endswith(".zip"):
        return True
    return (content_type or "").lower() in {
        "application/zip",
        "application/x-zip-compressed",
    }


def _is_eml_upload(*, filename: str, content_type: str | None) -> bool:
    if filename.lower().endswith(".eml"):
        return True
    return (content_type or "").lower() in {"message/rfc822"}


def _sanitize_filename(name: str) -> str:
    # Strip any path components and normalize whitespace.
    name = name.replace("\\", "/").split("/")[-1].strip()
    return " ".join(name.split())


def _unpack_zip_upload(body: bytes) -> list[dict]:
    import zipfile
    from io import BytesIO

    max_files = 100
    max_total_uncompressed = 200 * 1024 * 1024  # 200MB

    out: list[dict] = []
    total = 0

    with zipfile.ZipFile(BytesIO(body)) as zf:
        infos = [i for i in zf.infolist() if not i.is_dir()]
        if len(infos) > max_files:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"ZIP contains too many files (max {max_files}).",
            )

        for info in infos:
            filename = _sanitize_filename(info.filename)
            if not filename or filename.startswith(".") or filename.startswith("__MACOSX"):
                continue
            total += int(info.file_size or 0)
            if total > max_total_uncompressed:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="ZIP is too large when uncompressed.",
                )
            child_body = zf.read(info)
            out.append({"filename": filename, "content_type": None, "body": child_body})

    return out


def _unpack_eml_upload(body: bytes) -> list[dict]:
    from email import policy
    from email.parser import BytesParser

    msg = BytesParser(policy=policy.default).parsebytes(body)

    out: list[dict] = []
    idx = 0
    for part in msg.iter_attachments():
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        filename = part.get_filename() or f"attachment-{idx}"
        idx += 1
        out.append(
            {
                "filename": _sanitize_filename(filename) or f"attachment-{idx}",
                "content_type": part.get_content_type(),
                "body": payload,
            }
        )
    return out
