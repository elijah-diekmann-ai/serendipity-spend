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
