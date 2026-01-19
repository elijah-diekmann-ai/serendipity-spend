from __future__ import annotations

import hashlib
import os
import re
import uuid
from base64 import b64encode
from dataclasses import dataclass

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from serendipity_spend.core.logging import get_logger, log_event
from serendipity_spend.core.storage import get_storage
from serendipity_spend.core.text import html_to_text, is_url_heavy_text
from serendipity_spend.modules.claims.models import Claim, ClaimStatus
from serendipity_spend.modules.documents.models import SourceFile, SourceFileStatus
from serendipity_spend.modules.identity.models import User, UserRole

logger = get_logger(__name__)

@dataclass(frozen=True)
class IngestedSourceFile:
    source: SourceFile
    created: bool


def should_enqueue_extraction(ingested: IngestedSourceFile) -> bool:
    if ingested.created:
        return True
    return ingested.source.status in {SourceFileStatus.UPLOADED, SourceFileStatus.FAILED}


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
) -> IngestedSourceFile:
    assert_claim_access(claim=claim, user=user)

    sha256 = _sha256_hex(body)
    byte_size = len(body)
    existing = session.scalar(
        select(SourceFile)
        .where(
            SourceFile.claim_id == claim.id,
            SourceFile.sha256 == sha256,
            SourceFile.byte_size == byte_size,
        )
        .order_by(SourceFile.created_at.desc())
    )
    if existing:
        log_event(
            logger,
            "source_file.deduped",
            claim_id=str(claim.id),
            source_file_id=str(existing.id),
            storage_key=existing.storage_key,
            filename=existing.filename,
            content_type=existing.content_type,
            byte_size=existing.byte_size,
            sha256=existing.sha256,
            duplicate_filename=filename,
            duplicate_content_type=content_type,
        )
        return IngestedSourceFile(source=existing, created=False)

    key = f"claims/{claim.id}/source/{uuid.uuid4()}-{filename}"
    stored = get_storage().put(key=key, body=body)

    if claim.status == ClaimStatus.DRAFT:
        prev_status = claim.status
        claim.status = ClaimStatus.PROCESSING
        session.add(claim)
        log_event(
            logger,
            "claim.status.changed",
            claim_id=str(claim.id),
            from_status=prev_status.value,
            to_status=claim.status.value,
            reason="source_file_upload",
        )

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
    log_event(
        logger,
        "source_file.created",
        claim_id=str(claim.id),
        source_file_id=str(source.id),
        storage_key=source.storage_key,
        filename=source.filename,
        content_type=source.content_type,
        byte_size=source.byte_size,
        sha256=source.sha256,
    )
    return IngestedSourceFile(source=source, created=True)


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
) -> list[IngestedSourceFile]:
    if _is_zip_upload(filename=filename, content_type=content_type):
        children = _unpack_zip_upload(body)
        sources: list[IngestedSourceFile] = []
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
        container_sha256 = _sha256_hex(body)
        log_event(
            logger,
            "upload.unpack.start",
            claim_id=str(claim.id),
            container_kind="eml",
            container_filename=filename,
            container_content_type=content_type,
            container_byte_size=len(body),
            container_sha256=container_sha256,
        )
        children: list[dict] = []
        sources: list[IngestedSourceFile] = []
        child_source_files: list[dict] = []
        deduped_children: list[dict] = []
        try:
            children = _unpack_eml_upload(body, upload_filename=filename)
            if not children:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Email has no attachments to ingest.",
                )

            for child in children:
                child_sources = create_source_files_from_upload(
                    session,
                    claim=claim,
                    user=user,
                    filename=child["filename"],
                    content_type=child.get("content_type"),
                    body=child["body"],
                )
                sources.extend(child_sources)
                for ingested in child_sources:
                    child_source_files.append(
                        {
                            "child_filename": child["filename"],
                            "source_file_id": str(ingested.source.id),
                            "source_filename": ingested.source.filename,
                            "created": ingested.created,
                            "status": ingested.source.status.value,
                        }
                    )
                    if not ingested.created:
                        deduped_children.append(
                            {
                                "child_filename": child["filename"],
                                "source_file_id": str(ingested.source.id),
                                "existing_filename": ingested.source.filename,
                                "existing_status": ingested.source.status.value,
                            }
                        )

            created_count = sum(1 for ingested in sources if ingested.created)
            deduped_count = len(sources) - created_count
            log_event(
                logger,
                "upload.unpack.finish",
                claim_id=str(claim.id),
                container_kind="eml",
                container_filename=filename,
                container_content_type=content_type,
                container_byte_size=len(body),
                container_sha256=container_sha256,
                status="success",
                child_count=len(children),
                ingested_count=len(sources),
                created_count=created_count,
                deduped_count=deduped_count,
                child_source_files=child_source_files,
                deduped_children=deduped_children,
            )
            return sources
        except HTTPException as exc:
            created_count = sum(1 for ingested in sources if ingested.created)
            deduped_count = len(sources) - created_count
            log_event(
                logger,
                "upload.unpack.finish",
                claim_id=str(claim.id),
                container_kind="eml",
                container_filename=filename,
                container_content_type=content_type,
                container_byte_size=len(body),
                container_sha256=container_sha256,
                status="failed",
                reason="http_error",
                error=str(exc.detail),
                child_count=len(children),
                ingested_count=len(sources),
                created_count=created_count,
                deduped_count=deduped_count,
                child_source_files=child_source_files or None,
                deduped_children=deduped_children or None,
            )
            raise
        except Exception as exc:  # noqa: BLE001
            created_count = sum(1 for ingested in sources if ingested.created)
            deduped_count = len(sources) - created_count
            log_event(
                logger,
                "upload.unpack.finish",
                claim_id=str(claim.id),
                container_kind="eml",
                container_filename=filename,
                container_content_type=content_type,
                container_byte_size=len(body),
                container_sha256=container_sha256,
                status="failed",
                reason="error",
                error=str(exc),
                child_count=len(children),
                ingested_count=len(sources),
                created_count=created_count,
                deduped_count=deduped_count,
                child_source_files=child_source_files or None,
                deduped_children=deduped_children or None,
            )
            raise

    if _is_msg_upload(filename=filename, content_type=content_type):
        children = _unpack_msg_upload(body, upload_filename=filename)
        if not children:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Outlook message has no body or attachments to ingest.",
            )
        sources: list[IngestedSourceFile] = []
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


def _is_msg_upload(*, filename: str, content_type: str | None) -> bool:
    if filename.lower().endswith(".msg"):
        return True
    return (content_type or "").lower() in {
        "application/vnd.ms-outlook",
        "application/x-msg",
    }


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


def _unpack_eml_upload(body: bytes, *, upload_filename: str | None = None) -> list[dict]:
    from email import policy
    from email.parser import BytesParser

    msg = BytesParser(policy=policy.default).parsebytes(body)

    out: list[dict] = []

    attachments: list[dict] = []
    idx = 0
    for part in msg.iter_attachments():
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        filename = part.get_filename() or f"attachment-{idx}"
        idx += 1
        attachments.append(
            {
                "filename": _sanitize_filename(filename) or f"attachment-{idx}",
                "content_type": part.get_content_type(),
                "body": payload,
            }
        )

    body_choice = _select_email_body(msg)
    if body_choice is not None:
        body_content_type, body_bytes, body_text_for_receipt_check = body_choice
        include_body = True
        if attachments and (not _email_body_looks_like_receipt(body_text_for_receipt_check)):
            include_body = False
        if include_body:
            subject = str(msg.get("subject") or "").strip()
            fallback_filename = (
                "email-body.html" if body_content_type == "text/html" else "email-body.txt"
            )
            out.append(
                {
                    "filename": _sanitize_filename(
                        _email_body_filename_for_upload(
                            upload_filename=upload_filename,
                            subject=subject,
                            body_sha256=_sha256_hex(body_bytes),
                            extension=("html" if body_content_type == "text/html" else "txt"),
                        )
                    )
                    or fallback_filename,
                    "content_type": body_content_type,
                    "body": body_bytes,
                }
            )

    out.extend(attachments)
    return out


def _unpack_msg_upload(body: bytes, *, upload_filename: str | None = None) -> list[dict]:
    from datetime import datetime
    from email.utils import parseaddr
    from tempfile import TemporaryDirectory

    try:
        import extract_msg
    except Exception as e:  # noqa: BLE001
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Outlook .msg ingestion is not available. Upload as .eml instead.",
        ) from e

    with TemporaryDirectory() as tmpdir:
        from pathlib import Path

        msg_path = Path(tmpdir) / "upload.msg"
        msg_path.write_bytes(body)
        try:
            msg = extract_msg.Message(str(msg_path))
        except Exception as e:  # noqa: BLE001
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Could not read Outlook .msg file.",
            ) from e

        out: list[dict] = []
        try:
            subject = str(getattr(msg, "subject", "") or "").strip()
            from_header = str(getattr(msg, "sender", "") or "").strip()
            to_header = str(getattr(msg, "to", "") or "").strip()

            sender_hint = ""
            from_name, from_addr = parseaddr(from_header)
            from_name = str(from_name or "").strip()
            sender_hint = from_name
            if not sender_hint and "@" in from_addr:
                sender_hint = from_addr.split("@", 1)[-1].strip()

            email_date_iso = None
            parsed = getattr(msg, "parsedDate", None)
            if parsed:
                try:
                    email_date_iso = parsed.date().isoformat()
                except Exception:
                    email_date_iso = None
            elif getattr(msg, "date", None):
                raw_date = str(getattr(msg, "date", "") or "").strip()
                if raw_date:
                    try:
                        email_date_iso = datetime.fromisoformat(raw_date).date().isoformat()
                    except Exception:
                        email_date_iso = None

            body_text = str(getattr(msg, "body", "") or "").strip()
            html_body = str(getattr(msg, "htmlBody", "") or "").strip()
            if (not body_text) and html_body:
                body_text = _html_to_text(html_body)

            if body_text and body_text.strip():
                header_lines: list[str] = []
                if sender_hint:
                    header_lines.append(sender_hint)
                if subject:
                    header_lines.append(f"Subject: {subject}")
                if from_header:
                    header_lines.append(f"From: {from_header}")
                if to_header:
                    header_lines.append(f"To: {to_header}")

                combined_text = "\n".join(header_lines) + "\n\n" + body_text.strip()
                if email_date_iso:
                    combined_text = combined_text + f"\n\nEmailDate: {email_date_iso}"
                combined = (combined_text + "\n").encode("utf-8", errors="replace")
                combined_sha256 = _sha256_hex(combined)
                out.append(
                    {
                        "filename": _sanitize_filename(
                            _email_body_filename_for_upload(
                                upload_filename=upload_filename,
                                subject=subject,
                                body_sha256=combined_sha256,
                            )
                        )
                        or "email-body.txt",
                        "content_type": "text/plain",
                        "body": combined,
                    }
                )

            idx = 0
            for att in getattr(msg, "attachments", []) or []:
                payload = getattr(att, "data", None)
                if callable(payload):
                    payload = payload()
                if not payload:
                    continue

                filename = (
                    str(getattr(att, "longFilename", "") or "").strip()
                    or str(getattr(att, "shortFilename", "") or "").strip()
                    or str(getattr(att, "name", "") or "").strip()
                    or f"attachment-{idx}"
                )
                idx += 1
                out.append(
                    {
                        "filename": _sanitize_filename(filename) or f"attachment-{idx}",
                        "content_type": getattr(att, "mimetype", None),
                        "body": payload,
                    }
                )
        finally:
            try:
                msg.close()
            except Exception:
                pass

        return out


def _email_body_filename_for_upload(
    *, upload_filename: str | None, subject: str, body_sha256: str, extension: str = "txt"
) -> str:
    def safe_stem(value: str) -> str:
        v = str(value or "").strip()
        if not v:
            return ""
        v = re.sub(r"[^A-Za-z0-9._ -]+", "", v).strip()
        v = re.sub(r"\s+", " ", v).strip()
        v = v.replace(" ", "_")
        v = re.sub(r"_+", "_", v).strip("_")
        return v

    upload_stem = ""
    if upload_filename:
        name = os.path.splitext(_sanitize_filename(upload_filename))[0]
        upload_stem = safe_stem(name)

    subject_stem = safe_stem(subject)
    stem = upload_stem or subject_stem or "email-body"
    stem = stem[:60]

    suffix = str(body_sha256 or "")[:8]
    if suffix:
        return f"email-body-{stem}-{suffix}.{extension}"
    return f"email-body-{stem}.{extension}"


def _select_email_body(msg) -> tuple[str, bytes, str] | None:
    plain_text, html_text = _extract_email_body_parts(msg)
    cid_map = _extract_cid_data_uris(msg) if html_text else {}

    if html_text:
        html_text = _inline_cid_images(html_text, cid_map)
        html_clean = html_to_text(html_text)
        if html_clean.strip():
            if (
                plain_text
                and (not is_url_heavy_text(plain_text))
                and _email_body_looks_like_receipt(plain_text)
                and (not _email_body_looks_like_receipt(html_clean))
            ):
                return "text/plain", plain_text.encode("utf-8", errors="replace"), plain_text
            return "text/html", html_text.encode("utf-8", errors="replace"), html_clean

    if plain_text:
        return "text/plain", plain_text.encode("utf-8", errors="replace"), plain_text
    return None


def _extract_email_body_parts(msg) -> tuple[str | None, str | None]:
    parts_plain: list[str] = []
    parts_html: list[str] = []

    def get_part_text(part) -> str | None:
        try:
            content = part.get_content()
            return str(content) if content is not None else None
        except Exception:
            payload = part.get_payload(decode=True) or b""
            charset = part.get_content_charset() or "utf-8"
            try:
                return payload.decode(charset, errors="replace")
            except Exception:
                return payload.decode("utf-8", errors="replace")

    if getattr(msg, "is_multipart", lambda: False)():
        for part in msg.walk():
            if part.is_multipart():
                continue
            disposition = str(part.get_content_disposition() or "").lower()
            if disposition == "attachment":
                continue
            ctype = str(part.get_content_type() or "").lower()
            text = get_part_text(part)
            if not text:
                continue
            if ctype == "text/plain":
                parts_plain.append(text)
            elif ctype == "text/html":
                parts_html.append(text)
    else:
        ctype = str(msg.get_content_type() or "").lower()
        text = get_part_text(msg)
        if text:
            if ctype == "text/plain":
                parts_plain.append(text)
            elif ctype == "text/html":
                parts_html.append(text)

    plain = "\n\n".join(parts_plain).strip() if parts_plain else ""
    html = "\n\n".join(parts_html).strip() if parts_html else ""
    return plain or None, html or None


def _extract_cid_data_uris(msg) -> dict[str, str]:
    out: dict[str, str] = {}
    if not getattr(msg, "is_multipart", lambda: False)():
        return out

    for part in msg.walk():
        if part.is_multipart():
            continue
        cid = str(part.get("Content-ID") or "").strip()
        if not cid:
            continue
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        ctype = str(part.get_content_type() or "").lower().strip()
        if not ctype.startswith("image/"):
            continue
        cid_key = cid.strip("<>").strip().lower()
        if not cid_key:
            continue
        b64 = b64encode(payload).decode("ascii")
        out[cid_key] = f"data:{ctype};base64,{b64}"
    return out


def _inline_cid_images(html: str, cid_map: dict[str, str]) -> str:
    if not html or not cid_map:
        return html

    def repl(match: re.Match[str]) -> str:
        cid = str(match.group(1) or "").strip().strip("<>").strip().lower()
        return cid_map.get(cid, match.group(0))

    return re.sub(r"(?i)cid:([^'\"\\s>]+)", repl, html)


def _email_body_looks_like_receipt(text: str) -> bool:
    t = str(text or "")
    if not t.strip():
        return False
    # Strong signals: currency-denominated totals or amounts (avoids saving forwarding-only bodies).
    if re.search(r"(?i)\b(total|total paid|grand total|amount due|amount paid)\b", t) and re.search(
        r"(?i)(US\\$|CA\\$|£|€|\\$)\\s*[0-9]", t
    ):
        return True
    if re.search(r"(?i)(US\\$|CA\\$|£|€)\\s*[0-9][0-9,.'\\u202f\\xa0 ]*[0-9]", t):
        return True
    if re.search(r"\\$\\s*[0-9]+\\.[0-9]{2}\\b", t):
        return True
    if re.search(r"(?i)\\b[A-Z]{3}\\b\\s*[0-9]+\\.[0-9]{2}\\b", t):
        return True
    return False


def _html_to_text(html: str) -> str:
    return html_to_text(html, preserve_blank_lines=True)
