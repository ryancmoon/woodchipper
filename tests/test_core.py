"""Tests for core functionality."""

import tempfile
from pathlib import Path

import pytest

from woodchipper.core import validate_pdf, process, get_urls, ValidationError


def test_validate_pdf_file_not_found():
    with pytest.raises(ValidationError, match="File not found"):
        validate_pdf("/nonexistent/path/file.pdf")


def test_validate_pdf_not_a_file(tmp_path):
    with pytest.raises(ValidationError, match="Not a file"):
        validate_pdf(tmp_path)


def test_validate_pdf_wrong_file_type():
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
        f.write(b"This is not a PDF file")
        f.flush()
        with pytest.raises(ValidationError, match="Invalid file type.*only accepts PDF"):
            validate_pdf(f.name)


def test_validate_pdf_valid_pdf():
    # Minimal valid PDF
    pdf_content = b"""%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj
3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj
xref
0 4
0000000000 65535 f
0000000009 00000 n
0000000052 00000 n
0000000101 00000 n
trailer<</Size 4/Root 1 0 R>>
startxref
167
%%EOF"""
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        f.write(pdf_content)
        f.flush()
        result = validate_pdf(f.name)
        assert isinstance(result, Path)


def test_process_valid_pdf():
    pdf_content = b"""%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj
3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj
xref
0 4
0000000000 65535 f
0000000009 00000 n
0000000052 00000 n
0000000101 00000 n
trailer<</Size 4/Root 1 0 R>>
startxref
167
%%EOF"""
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        f.write(pdf_content)
        f.flush()
        report = process(f.name)

        # Verify all required fields are present
        assert "filename" in report
        assert "filesize" in report
        assert "md5" in report
        assert "sha1" in report
        assert "sha256" in report
        assert "urls" in report

        # Verify types
        assert isinstance(report["filename"], str)
        assert isinstance(report["filesize"], int)
        assert isinstance(report["md5"], str)
        assert isinstance(report["sha1"], str)
        assert isinstance(report["sha256"], str)
        assert isinstance(report["urls"], list)

        # Verify hash lengths
        assert len(report["md5"]) == 32
        assert len(report["sha1"]) == 40
        assert len(report["sha256"]) == 64


def test_get_urls_no_links():
    """Test get_urls with a PDF that has no links."""
    pdf_content = b"""%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Count 1/Kids[3 0 R]>>endobj
3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R>>endobj
xref
0 4
0000000000 65535 f
0000000009 00000 n
0000000052 00000 n
0000000101 00000 n
trailer<</Size 4/Root 1 0 R>>
startxref
167
%%EOF"""
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        f.write(pdf_content)
        f.flush()
        urls = get_urls(f.name)
        assert urls == []


def test_get_urls_with_links():
    """Test get_urls with a PDF containing link annotations."""
    from pypdf import PdfWriter
    from pypdf.generic import (
        ArrayObject,
        DictionaryObject,
        NameObject,
        NumberObject,
        TextStringObject,
    )

    writer = PdfWriter()
    page = writer.add_blank_page(width=612, height=792)

    # Create link annotations with URLs
    link1 = DictionaryObject({
        NameObject("/Type"): NameObject("/Annot"),
        NameObject("/Subtype"): NameObject("/Link"),
        NameObject("/Rect"): ArrayObject([
            NumberObject(100), NumberObject(700),
            NumberObject(200), NumberObject(720),
        ]),
        NameObject("/A"): DictionaryObject({
            NameObject("/Type"): NameObject("/Action"),
            NameObject("/S"): NameObject("/URI"),
            NameObject("/URI"): TextStringObject("https://example.com"),
        }),
    })

    link2 = DictionaryObject({
        NameObject("/Type"): NameObject("/Annot"),
        NameObject("/Subtype"): NameObject("/Link"),
        NameObject("/Rect"): ArrayObject([
            NumberObject(100), NumberObject(650),
            NumberObject(200), NumberObject(670),
        ]),
        NameObject("/A"): DictionaryObject({
            NameObject("/Type"): NameObject("/Action"),
            NameObject("/S"): NameObject("/URI"),
            NameObject("/URI"): TextStringObject("https://test.org/page"),
        }),
    })

    page[NameObject("/Annots")] = ArrayObject([link1, link2])

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        urls = get_urls(f.name)
        assert "https://example.com" in urls
        assert "https://test.org/page" in urls
        assert len(urls) == 2


def test_get_urls_invalid_file():
    """Test get_urls with an invalid file."""
    with pytest.raises(ValidationError):
        get_urls("/nonexistent/file.pdf")
