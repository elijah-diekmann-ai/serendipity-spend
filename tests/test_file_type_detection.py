from __future__ import annotations


def test_detect_file_kind_rejects_non_pdf_bytes_for_pdf_extension():
    from serendipity_spend.modules.extraction import service as extraction_service

    kind = extraction_service._detect_file_kind(
        filename="receipt.pdf",
        content_type="application/pdf",
        body=b"\x00\x01\x02\x03",
    )
    assert kind == "bad_pdf_upload"


def test_detect_file_kind_treats_text_bytes_as_text_even_when_named_pdf():
    from serendipity_spend.modules.extraction import service as extraction_service

    kind = extraction_service._detect_file_kind(
        filename="receipt.pdf",
        content_type="application/pdf",
        body=b"Example Hotel\nTotal USD 10.00\n",
    )
    assert kind == "text"


def test_decode_text_bytes_detects_html_without_relying_on_filename():
    from serendipity_spend.modules.extraction import service as extraction_service

    out = extraction_service._decode_text_bytes(
        body=b"<html><body><p>Hello</p><p>Total USD 10.00</p></body></html>",
        filename="receipt.pdf",
        content_type="application/pdf",
    )
    assert "Hello" in out
    assert "<html" not in out.lower()

