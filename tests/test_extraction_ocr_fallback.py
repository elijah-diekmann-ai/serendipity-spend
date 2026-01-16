from __future__ import annotations


def test_extract_pdf_pages_uses_ocr_fallback(monkeypatch):
    from serendipity_spend.modules.extraction import service as extraction_service

    class _Page:
        def __init__(self, text: str) -> None:
            self._text = text

        def extract_text(self) -> str:
            return self._text

    class _Reader:
        def __init__(self, _stream) -> None:
            self.pages = [_Page(""), _Page("hello")]

    ocr_calls: list[object] = []

    def _ocr(page) -> str:
        ocr_calls.append(page)
        return "ocr text"

    monkeypatch.setattr(extraction_service, "PdfReader", _Reader)
    monkeypatch.setattr(extraction_service, "_ocr_pdf_page", _ocr)

    pages = extraction_service._extract_pdf_pages(b"%PDF-1.4 stub")
    assert pages == ["ocr text", "hello"]
    assert len(ocr_calls) == 1


def test_extract_pdf_pages_keeps_empty_when_ocr_empty(monkeypatch):
    from serendipity_spend.modules.extraction import service as extraction_service

    class _Page:
        def __init__(self, text: str) -> None:
            self._text = text

        def extract_text(self) -> str:
            return self._text

    class _Reader:
        def __init__(self, _stream) -> None:
            self.pages = [_Page("")]

    monkeypatch.setattr(extraction_service, "PdfReader", _Reader)
    monkeypatch.setattr(extraction_service, "_ocr_pdf_page", lambda _page: "")

    pages = extraction_service._extract_pdf_pages(b"%PDF-1.4 stub")
    assert pages == [""]

