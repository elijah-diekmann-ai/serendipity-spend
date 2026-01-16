from __future__ import annotations

import hashlib
import re
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

    if _is_msg_upload(filename=filename, content_type=content_type):
        children = _unpack_msg_upload(body)
        if not children:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Outlook message has no body or attachments to ingest.",
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


def _unpack_eml_upload(body: bytes) -> list[dict]:
    from email import policy
    from email.parser import BytesParser
    from email.utils import parseaddr, parsedate_to_datetime

    msg = BytesParser(policy=policy.default).parsebytes(body)

    out: list[dict] = []

    body_text = _extract_email_body_text(msg)
    if body_text and body_text.strip():
        subject = str(msg.get("subject") or "").strip()
        from_header = str(msg.get("from") or "").strip()
        from_name, from_addr = parseaddr(from_header)
        from_name = str(from_name or "").strip()
        sender_hint = from_name
        if not sender_hint and "@" in from_addr:
            sender_hint = from_addr.split("@", 1)[-1].strip()

        email_date_iso = None
        date_header = str(msg.get("date") or "").strip()
        if date_header:
            try:
                email_date_iso = parsedate_to_datetime(date_header).date().isoformat()
            except Exception:
                email_date_iso = None

        header_lines: list[str] = []
        if sender_hint:
            header_lines.append(sender_hint)
        if subject:
            header_lines.append(f"Subject: {subject}")
        if from_header:
            header_lines.append(f"From: {from_header}")
        to_header = str(msg.get("to") or "").strip()
        if to_header:
            header_lines.append(f"To: {to_header}")

        combined_text = "\n".join(header_lines) + "\n\n" + body_text.strip()
        if email_date_iso:
            combined_text = combined_text + f"\n\nEmailDate: {email_date_iso}"
        combined = (combined_text + "\n").encode("utf-8", errors="replace")
        out.append(
            {
                "filename": _sanitize_filename(_email_body_filename(subject)) or "email-body.txt",
                "content_type": "text/plain",
                "body": combined,
            }
        )

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


def _unpack_msg_upload(body: bytes) -> list[dict]:
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
                out.append(
                    {
                        "filename": _sanitize_filename(_email_body_filename(subject))
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


def _email_body_filename(subject: str) -> str:
    subject = subject.strip()
    if not subject:
        return "email-body.txt"
    safe = re.sub(r"[^A-Za-z0-9._ -]+", "", subject).strip()
    safe = re.sub(r"\s+", " ", safe).strip()
    safe = safe.replace(" ", "_")
    if not safe:
        return "email-body.txt"
    return f"email-body-{safe[:60]}.txt"


def _extract_email_body_text(msg) -> str:
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

    if parts_plain:
        return "\n\n".join(parts_plain).strip()
    if parts_html:
        return _html_to_text("\n\n".join(parts_html))
    return ""


def _html_to_text(html: str) -> str:
    from html import unescape

    # Remove script/style blocks.
    html = re.sub(r"(?is)<(script|style).*?>.*?</\1>", "", html)
    # Basic block-to-newline conversions.
    html = re.sub(r"(?i)<br\s*/?>", "\n", html)
    html = re.sub(r"(?i)</p\s*>", "\n\n", html)
    html = re.sub(r"(?i)</div\s*>", "\n", html)
    # Strip remaining tags.
    html = re.sub(r"(?s)<[^>]+>", "", html)
    html = unescape(html)

    lines = [re.sub(r"\s+", " ", ln).strip() for ln in html.splitlines()]
    out_lines: list[str] = []
    last_blank = False
    for ln in lines:
        if not ln:
            if not last_blank:
                out_lines.append("")
            last_blank = True
            continue
        out_lines.append(ln)
        last_blank = False
    return "\n".join(out_lines).strip()
