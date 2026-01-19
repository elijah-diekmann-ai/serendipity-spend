from __future__ import annotations

import re
from html import unescape

_URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)
_DOMAIN_PATH_RE = re.compile(r"\b[A-Za-z0-9.-]+\.[A-Za-z]{2,}/\S+")


def decode_text_bytes(
    *,
    body: bytes,
    filename: str,
    content_type: str | None,
    preserve_blank_lines: bool = False,
) -> str:
    ctype = (content_type or "").lower()
    is_html = ctype.startswith("text/html") or filename.lower().endswith((".html", ".htm"))
    try:
        text = body.decode("utf-8", errors="replace")
    except Exception:
        text = body.decode("latin-1", errors="replace")
    if is_html or looks_like_html(text):
        text = html_to_text(text, preserve_blank_lines=preserve_blank_lines)
    return text


def looks_like_html(text: str) -> bool:
    t = (text or "").lstrip().lower()
    if not t:
        return False
    if t.startswith("<!doctype html") or t.startswith("<html"):
        return True
    head = t[:2000]
    return bool(re.search(r"<(html|body|div|p|br|table|tr|td|span)(\s|>)", head, re.I))


def html_to_text(html: str, *, preserve_blank_lines: bool = False) -> str:
    html = re.sub(r"(?is)<(script|style).*?>.*?</\1>", "", html)
    html = re.sub(r"(?i)<br\s*/?>", "\n", html)
    html = re.sub(r"(?i)</p\s*>", "\n\n", html)
    html = re.sub(r"(?i)</div\s*>", "\n", html)
    html = re.sub(r"(?s)<[^>]+>", "", html)
    html = unescape(html)

    lines = [re.sub(r"\s+", " ", ln).strip() for ln in html.splitlines()]
    if not preserve_blank_lines:
        return "\n".join([ln for ln in lines if ln])

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


def is_url_heavy_text(text: str) -> bool:
    t = str(text or "").strip()
    if not t:
        return False

    urls = list(_URL_RE.finditer(t))
    url_count = len(urls)
    if url_count == 0:
        return False

    nonspace_len = len(re.sub(r"\s+", "", t))
    url_chars = sum(len(m.group(0)) for m in urls)
    url_ratio = url_chars / max(1, nonspace_len)
    urls_per_1000_chars = url_count / max(1.0, len(t) / 1000.0)

    lines = [ln.strip() for ln in t.splitlines() if ln.strip()]
    url_only_lines = sum(1 for ln in lines if _line_is_only_urls(ln))
    url_only_ratio = url_only_lines / max(1, len(lines))

    if url_count >= 10:
        return True
    if urls_per_1000_chars >= 3.0 and url_count >= 3:
        return True
    if url_only_lines >= 3 or (url_only_ratio >= 0.25 and url_only_lines >= 2):
        return True
    return url_ratio >= 0.2 and url_count >= 3


def clean_email_body_text_for_export(text: str) -> str:
    lines_in = (text or "").replace("\u202f", " ").replace("\xa0", " ").splitlines()
    lines_out: list[str] = []

    for raw in lines_in:
        ln = raw.strip()
        if not ln:
            lines_out.append("")
            continue
        if re.match(r"(?i)^EmailDate:\s*\d{4}-\d{2}-\d{2}\b", ln):
            continue
        if _line_is_only_urls(ln):
            continue

        cleaned = _strip_urls_from_line(ln)
        if not cleaned:
            continue
        if _line_is_known_email_footer(cleaned) or _line_is_known_email_footer(ln):
            continue
        if _line_is_mostly_url_spam(ln) and (not _cleaned_line_is_meaningful(cleaned)):
            continue
        lines_out.append(cleaned)

    return _collapse_blank_lines(lines_out)


def _collapse_blank_lines(lines: list[str]) -> str:
    out: list[str] = []
    last_blank = False
    for ln in lines:
        if not ln:
            if last_blank:
                continue
            out.append("")
            last_blank = True
            continue
        out.append(ln)
        last_blank = False
    return "\n".join(out).strip()


def _line_is_only_urls(line: str) -> bool:
    candidate = line.strip()
    if not candidate:
        return True

    parts = re.split(r"\s+", candidate)
    for part in parts:
        p = part.strip().strip("<>").strip()
        if not p:
            continue
        if not re.match(r"(?i)^https?://\S+$", p):
            return False
    return True


def _line_is_mostly_url_spam(line: str) -> bool:
    urls = list(_URL_RE.finditer(line))
    if not urls:
        return False

    nonspace_len = len(re.sub(r"\s+", "", line))
    url_chars = sum(len(m.group(0)) for m in urls)
    url_ratio = url_chars / max(1, nonspace_len)
    has_very_long_url = any(len(m.group(0)) >= 120 for m in urls)

    lower = line.lower()
    has_tracking_tokens = any(
        token in lower
        for token in (
            "_ri_=",
            "utm_",
            "tracking.",
            "email.mgt.",
            "click.",
            "wifionboard.com",
        )
    )

    if url_ratio >= 0.7 and (len(urls) >= 2 or nonspace_len >= 120):
        return True
    if has_very_long_url and url_ratio >= 0.5:
        return True
    return has_tracking_tokens and nonspace_len >= 80 and url_ratio >= 0.4


def _line_is_known_email_footer(line: str) -> bool:
    lower = line.lower().strip()
    if lower in {
        "privacy policy",
        "terms and conditions",
        "my account",
        "manage my account",
        "report lost item",
    }:
        return True

    keywords = (
        "privacy policy",
        "terms and conditions",
        "my account",
        "report lost item",
        "unsubscribe",
        "do not reply",
    )
    hits = sum(1 for k in keywords if k in lower)
    if hits >= 2:
        return True
    return hits >= 1 and bool(_URL_RE.search(lower)) and len(lower) <= 160


def _strip_urls_from_line(line: str) -> str:
    without_urls = _URL_RE.sub(" ", line)
    without_urls = _DOMAIN_PATH_RE.sub(" ", without_urls)
    without_urls = without_urls.replace("<", " ").replace(">", " ")
    return re.sub(r"\s+", " ", without_urls).strip()


def _cleaned_line_is_meaningful(line: str) -> bool:
    if not line:
        return False
    if re.search(r"\d", line):
        return True
    return len(re.findall(r"[A-Za-z]", line)) >= 5
