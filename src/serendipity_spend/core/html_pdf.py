from __future__ import annotations

import base64
import ipaddress
import socket
from functools import lru_cache
from urllib.parse import unquote_to_bytes, urlparse

import httpx

from serendipity_spend.core.logging import get_logger

logger = get_logger(__name__)

_MAX_FETCH_BYTES = 5 * 1024 * 1024
_FETCH_TIMEOUT = httpx.Timeout(10.0, connect=5.0)
_ALLOWED_SCHEMES = {"http", "https", "data"}

_WEASYPRINT_HTML = None
_WEASYPRINT_CSS = None
_WEASYPRINT_ERROR: str | None = None


class HtmlToPdfUnavailableError(RuntimeError):
    pass


def render_html_to_pdf(*, html: str, base_url: str | None = None) -> bytes:
    HTML, CSS = _get_weasyprint()

    stylesheet = CSS(
        string=(
            "@page { size: Letter; margin: 12mm; }\n"
            "img { max-width: 100%; height: auto; }\n"
            "table { max-width: 100%; }\n"
        )
    )
    doc = HTML(string=html, base_url=base_url, url_fetcher=_safe_url_fetcher)
    return doc.write_pdf(stylesheets=[stylesheet])


def _get_weasyprint():
    global _WEASYPRINT_CSS  # noqa: PLW0603
    global _WEASYPRINT_ERROR  # noqa: PLW0603
    global _WEASYPRINT_HTML  # noqa: PLW0603

    if _WEASYPRINT_ERROR:
        raise HtmlToPdfUnavailableError(_WEASYPRINT_ERROR)
    if _WEASYPRINT_HTML and _WEASYPRINT_CSS:
        return _WEASYPRINT_HTML, _WEASYPRINT_CSS

    try:
        from weasyprint import CSS, HTML  # type: ignore[import-not-found]
    except Exception as e:  # noqa: BLE001
        _WEASYPRINT_ERROR = (
            "HTML receipts require WeasyPrint. Install weasyprint and system dependencies."
        )
        raise HtmlToPdfUnavailableError(_WEASYPRINT_ERROR) from e

    _WEASYPRINT_HTML = HTML
    _WEASYPRINT_CSS = CSS
    return _WEASYPRINT_HTML, _WEASYPRINT_CSS


@lru_cache(maxsize=256)
def _safe_url_fetcher(url: str) -> dict:
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        logger.warning("weasyprint.fetch_blocked_scheme", extra={"url": url, "scheme": scheme})
        return {"string": b"", "mime_type": "application/octet-stream", "redirected_url": url}

    if scheme == "data":
        try:
            return _fetch_data_url(url)
        except Exception as e:  # noqa: BLE001
            logger.warning("weasyprint.fetch_failed", extra={"url": url, "error": str(e)})
            return {"string": b"", "mime_type": "application/octet-stream", "redirected_url": url}

    hostname = parsed.hostname
    if not hostname:
        logger.warning("weasyprint.fetch_blocked_host", extra={"url": url, "reason": "missing"})
        return {"string": b"", "mime_type": "application/octet-stream", "redirected_url": url}
    if not _hostname_is_public(hostname):
        logger.warning("weasyprint.fetch_blocked_host", extra={"url": url, "reason": "non_public"})
        return {"string": b"", "mime_type": "application/octet-stream", "redirected_url": url}

    headers = {"User-Agent": "serendipity-spend/exports"}
    try:
        with httpx.Client(
            follow_redirects=True,
            timeout=_FETCH_TIMEOUT,
            headers=headers,
        ) as client:
            with client.stream("GET", url) as resp:
                for prior in resp.history:
                    if prior.url.host and (not _hostname_is_public(str(prior.url.host))):
                        raise ValueError("Blocked redirect hostname")
                if resp.url.host and (not _hostname_is_public(str(resp.url.host))):
                    raise ValueError("Blocked final hostname")

                resp.raise_for_status()
                content = _read_limited(resp, limit_bytes=_MAX_FETCH_BYTES)
                mime_type = _content_type_to_mime(resp.headers.get("content-type"))
                return {"string": content, "mime_type": mime_type, "redirected_url": str(resp.url)}
    except Exception as e:  # noqa: BLE001
        logger.warning("weasyprint.fetch_failed", extra={"url": url, "error": str(e)})
        return {"string": b"", "mime_type": "application/octet-stream", "redirected_url": url}


def _read_limited(resp: httpx.Response, *, limit_bytes: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    for chunk in resp.iter_bytes():
        if not chunk:
            continue
        size += len(chunk)
        if size > limit_bytes:
            remaining = max(0, limit_bytes - (size - len(chunk)))
            if remaining:
                chunks.append(chunk[:remaining])
            break
        chunks.append(chunk)
    return b"".join(chunks)


def _fetch_data_url(url: str) -> dict:
    if not url.lower().startswith("data:"):
        raise ValueError("Not a data: URL")
    try:
        header, data = url.split(",", 1)
    except ValueError as e:
        raise ValueError("Invalid data: URL") from e

    meta = header[5:]
    is_base64 = ";base64" in meta.lower()
    mime = meta.split(";", 1)[0].strip() or "text/plain"

    raw = unquote_to_bytes(data)
    if is_base64:
        payload = base64.b64decode(raw, validate=False)
    else:
        payload = raw
    return {"string": payload, "mime_type": mime, "redirected_url": url}


def _hostname_is_public(hostname: str) -> bool:
    host = str(hostname or "").strip().strip("[]").lower()
    if not host:
        return False
    if host in {"localhost", "localhost."}:
        return False
    try:
        ip = ipaddress.ip_address(host)
        return _ip_is_public(ip)
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host, None)
    except Exception:
        return False

    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        if not _ip_is_public(ip):
            return False
    return True


def _ip_is_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _content_type_to_mime(content_type: str | None) -> str:
    if not content_type:
        return "application/octet-stream"
    return content_type.split(";", 1)[0].strip() or "application/octet-stream"
