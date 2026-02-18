"""Tests for core functionality."""

import tempfile
from pathlib import Path

import pytest

from woodchipper.core import validate_pdf, process, get_urls, get_pdf_metadata, check_anomalies, detect_additionalactions, detect_external_actions, detect_javascript, detect_embedded_file, detect_acroform, detect_xmlforms, extract_forms, ValidationError, _get_object_offset, _read_raw_bytes_hex, _get_decoded_bytes_hex, _make_action_detail


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
        assert "metadata" in report

        # Verify types
        assert isinstance(report["filename"], str)
        assert isinstance(report["filesize"], int)
        assert isinstance(report["md5"], str)
        assert isinstance(report["sha1"], str)
        assert isinstance(report["sha256"], str)
        assert isinstance(report["urls"], list)
        assert isinstance(report["metadata"], dict)

        # Verify hash lengths
        assert len(report["md5"]) == 32
        assert len(report["sha1"]) == 40
        assert len(report["sha256"]) == 64

        # Verify metadata structure
        metadata = report["metadata"]
        assert "author" in metadata
        assert "creator" in metadata
        assert "producer" in metadata
        assert "spoofing_indicators" in metadata
        assert isinstance(metadata["spoofing_indicators"], list)

        # Verify anomalies structure
        assert "anomalies" in report
        anomalies_section = report["anomalies"]
        assert "anomalies_present" in anomalies_section
        assert "anomalies" in anomalies_section
        assert "additional_actions_detected" in anomalies_section
        assert "external_actions" in anomalies_section
        assert "javascript_detected" in anomalies_section
        assert "embedded_files" in anomalies_section
        assert isinstance(anomalies_section["anomalies_present"], bool)
        assert isinstance(anomalies_section["anomalies"], list)
        assert isinstance(anomalies_section["additional_actions_detected"], list)
        assert isinstance(anomalies_section["external_actions"], list)
        assert isinstance(anomalies_section["javascript_detected"], list)
        assert isinstance(anomalies_section["embedded_files"], list)

        # Verify forms structure
        assert "forms" in report
        forms = report["forms"]
        assert "forms_present" in forms
        assert "form_submission_targets" in forms
        assert isinstance(forms["forms_present"], bool)
        assert isinstance(forms["form_submission_targets"], list)


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


def test_get_pdf_metadata_basic():
    """Test get_pdf_metadata returns expected structure."""
    from pypdf import PdfWriter

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    writer.add_metadata({
        "/Author": "Test Author",
        "/Creator": "Test Creator",
        "/Producer": "Test Producer",
        "/Title": "Test Title",
        "/Subject": "Test Subject",
        "/CreationDate": "D:20240101120000Z",
        "/ModDate": "D:20240102120000Z",
    })

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        metadata = get_pdf_metadata(f.name)

        assert metadata["author"] == "Test Author"
        assert metadata["creator"] == "Test Creator"
        assert metadata["producer"] == "Test Producer"
        assert metadata["title"] == "Test Title"
        assert metadata["subject"] == "Test Subject"
        assert metadata["creation_date"] is not None
        assert metadata["modification_date"] is not None
        assert isinstance(metadata["spoofing_indicators"], list)


def test_get_pdf_metadata_no_metadata():
    """Test get_pdf_metadata with a PDF that has no metadata."""
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
        metadata = get_pdf_metadata(f.name)

        assert metadata["author"] is None
        assert metadata["creator"] is None
        assert metadata["producer"] is None
        assert isinstance(metadata["spoofing_indicators"], list)


def test_get_pdf_metadata_spoofing_creator_producer_mismatch():
    """Test spoofing detection for creator/producer mismatch."""
    from pypdf import PdfWriter

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    writer.add_metadata({
        "/Creator": "Microsoft Word",
        "/Producer": "LibreOffice 7.0",
    })

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        metadata = get_pdf_metadata(f.name)

        # Should detect Microsoft/LibreOffice mismatch
        assert len(metadata["spoofing_indicators"]) > 0
        assert any("Microsoft" in ind for ind in metadata["spoofing_indicators"])


def test_get_pdf_metadata_spoofing_date_order():
    """Test spoofing detection for creation date after modification date."""
    from pypdf import PdfWriter

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    writer.add_metadata({
        "/CreationDate": "D:20240201120000Z",  # Feb 1
        "/ModDate": "D:20240101120000Z",       # Jan 1 (before creation)
    })

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        metadata = get_pdf_metadata(f.name)

        assert any(
            "Creation date is after modification date" in ind
            for ind in metadata["spoofing_indicators"]
        )


def test_get_pdf_metadata_invalid_file():
    """Test get_pdf_metadata with an invalid file."""
    with pytest.raises(ValidationError):
        get_pdf_metadata("/nonexistent/file.pdf")


def test_check_anomalies_valid_pdf():
    """Test check_anomalies with a well-formed PDF."""
    from pypdf import PdfWriter

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        anomalies = check_anomalies(f.name)

        assert isinstance(anomalies["anomalies_present"], bool)
        assert isinstance(anomalies["anomalies"], list)


def test_check_anomalies_invalid_version():
    """Test check_anomalies detects invalid PDF version."""
    # Create a PDF with an invalid version
    pdf_content = b"""%PDF-9.9
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
        anomalies = check_anomalies(f.name)

        assert anomalies["anomalies_present"] is True
        assert any("Invalid PDF version" in a for a in anomalies["anomalies"])


def test_check_anomalies_header_not_at_start():
    """Test check_anomalies detects header not at byte 0."""
    # Create a PDF with garbage before the header
    pdf_content = b"""GARBAGE DATA HERE
%PDF-1.4
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
        anomalies = check_anomalies(f.name)

        assert anomalies["anomalies_present"] is True
        assert any("not at byte 0" in a for a in anomalies["anomalies"])


def test_check_anomalies_missing_eof():
    """Test check_anomalies detects missing %%EOF marker."""
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
"""
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        f.write(pdf_content)
        f.flush()
        anomalies = check_anomalies(f.name)

        assert anomalies["anomalies_present"] is True
        assert any("%%EOF" in a for a in anomalies["anomalies"])


def test_check_anomalies_invalid_file():
    """Test check_anomalies with an invalid file."""
    with pytest.raises(ValidationError):
        check_anomalies("/nonexistent/file.pdf")


def test_extract_forms_no_forms():
    """Test extract_forms with a PDF that has no forms."""
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
        forms = extract_forms(f.name)

        assert forms["forms_present"] is False
        assert forms["form_submission_targets"] == []


def test_extract_forms_with_acroform():
    """Test extract_forms with a PDF containing an AcroForm."""
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

    # Create a text field widget annotation
    widget = DictionaryObject({
        NameObject("/Type"): NameObject("/Annot"),
        NameObject("/Subtype"): NameObject("/Widget"),
        NameObject("/FT"): NameObject("/Tx"),  # Text field
        NameObject("/T"): TextStringObject("name"),
        NameObject("/Rect"): ArrayObject([
            NumberObject(100), NumberObject(700),
            NumberObject(300), NumberObject(720),
        ]),
    })

    page[NameObject("/Annots")] = ArrayObject([widget])

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        forms = extract_forms(f.name)

        assert forms["forms_present"] is True
        assert isinstance(forms["form_submission_targets"], list)


def test_extract_forms_with_submit_action():
    """Test extract_forms extracts submission target URLs."""
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

    # Create a submit button widget with SubmitForm action
    submit_button = DictionaryObject({
        NameObject("/Type"): NameObject("/Annot"),
        NameObject("/Subtype"): NameObject("/Widget"),
        NameObject("/FT"): NameObject("/Btn"),  # Button field
        NameObject("/T"): TextStringObject("submit"),
        NameObject("/Rect"): ArrayObject([
            NumberObject(100), NumberObject(650),
            NumberObject(200), NumberObject(670),
        ]),
        NameObject("/A"): DictionaryObject({
            NameObject("/Type"): NameObject("/Action"),
            NameObject("/S"): NameObject("/SubmitForm"),
            NameObject("/F"): TextStringObject("https://example.com/submit"),
        }),
    })

    page[NameObject("/Annots")] = ArrayObject([submit_button])

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        forms = extract_forms(f.name)

        assert forms["forms_present"] is True
        assert "https://example.com/submit" in forms["form_submission_targets"]


def test_extract_forms_invalid_file():
    """Test extract_forms with an invalid file."""
    with pytest.raises(ValidationError):
        extract_forms("/nonexistent/file.pdf")


def test_process_defangs_urls():
    """Test that process() defangs URLs in the output."""
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

    # Create a link annotation with a URL
    link = DictionaryObject({
        NameObject("/Type"): NameObject("/Annot"),
        NameObject("/Subtype"): NameObject("/Link"),
        NameObject("/Rect"): ArrayObject([
            NumberObject(100), NumberObject(700),
            NumberObject(200), NumberObject(720),
        ]),
        NameObject("/A"): DictionaryObject({
            NameObject("/Type"): NameObject("/Action"),
            NameObject("/S"): NameObject("/URI"),
            NameObject("/URI"): TextStringObject("https://malicious.com/phish"),
        }),
    })

    # Create a submit button with a form submission URL
    submit_button = DictionaryObject({
        NameObject("/Type"): NameObject("/Annot"),
        NameObject("/Subtype"): NameObject("/Widget"),
        NameObject("/FT"): NameObject("/Btn"),
        NameObject("/T"): TextStringObject("submit"),
        NameObject("/Rect"): ArrayObject([
            NumberObject(100), NumberObject(650),
            NumberObject(200), NumberObject(670),
        ]),
        NameObject("/A"): DictionaryObject({
            NameObject("/Type"): NameObject("/Action"),
            NameObject("/S"): NameObject("/SubmitForm"),
            NameObject("/F"): TextStringObject("http://evil.org/collect"),
        }),
    })

    page[NameObject("/Annots")] = ArrayObject([link, submit_button])

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        report = process(f.name)

        # Verify URLs are defanged (hXXp/hXXps and [.])
        assert len(report["urls"]) == 1
        assert "hXXps://malicious[.]com/phish" in report["urls"]
        assert "https://malicious.com" not in report["urls"]

        # Verify form submission targets are defanged
        assert len(report["forms"]["form_submission_targets"]) == 1
        assert "hXXp://evil[.]org/collect" in report["forms"]["form_submission_targets"]
        assert "http://evil.org" not in report["forms"]["form_submission_targets"]


def test_detect_additionalactions_no_actions():
    """Test detect_additionalactions with a PDF that has no actions."""
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
        result = detect_additionalactions(f.name)

        assert result == []


def test_detect_additionalactions_with_openaction():
    """Test detect_additionalactions with a PDF containing OpenAction."""
    from pypdf import PdfWriter
    from pypdf.generic import (
        DictionaryObject,
        NameObject,
        TextStringObject,
        IndirectObject,
    )

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)

    # Add an OpenAction with JavaScript
    js_action = DictionaryObject({
        NameObject("/Type"): NameObject("/Action"),
        NameObject("/S"): NameObject("/JavaScript"),
        NameObject("/JS"): TextStringObject("app.alert('Hello');"),
    })

    # Add to document catalog
    writer._root_object[NameObject("/OpenAction")] = js_action

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        result = detect_additionalactions(f.name)

        assert len(result) > 0
        assert any("Document Open" in action["description"] for action in result)
        assert any("JavaScript" in action["description"] for action in result)


def test_detect_additionalactions_with_uri_action():
    """Test detect_additionalactions with a PDF containing OpenAction URI."""
    from pypdf import PdfWriter
    from pypdf.generic import (
        DictionaryObject,
        NameObject,
        TextStringObject,
    )

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)

    # Add an OpenAction with URI
    uri_action = DictionaryObject({
        NameObject("/Type"): NameObject("/Action"),
        NameObject("/S"): NameObject("/URI"),
        NameObject("/URI"): TextStringObject("https://malicious.com"),
    })

    writer._root_object[NameObject("/OpenAction")] = uri_action

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        result = detect_additionalactions(f.name)

        assert len(result) > 0
        assert any("Document Open" in action["description"] for action in result)
        assert any("URL" in action["description"] for action in result)


def test_detect_additionalactions_invalid_file():
    """Test detect_additionalactions with an invalid file."""
    with pytest.raises(ValidationError):
        detect_additionalactions("/nonexistent/file.pdf")


def test_check_anomalies_includes_additional_actions():
    """Test that check_anomalies includes additional_actions_detected."""
    from pypdf import PdfWriter
    from pypdf.generic import (
        DictionaryObject,
        NameObject,
        TextStringObject,
    )

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)

    # Add an OpenAction with JavaScript
    js_action = DictionaryObject({
        NameObject("/Type"): NameObject("/Action"),
        NameObject("/S"): NameObject("/JavaScript"),
        NameObject("/JS"): TextStringObject("app.alert('Malicious');"),
    })

    writer._root_object[NameObject("/OpenAction")] = js_action

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        anomalies = check_anomalies(f.name)

        # Should have anomalies_present=True due to additional actions
        assert anomalies["anomalies_present"] is True
        assert "additional_actions_detected" in anomalies
        assert len(anomalies["additional_actions_detected"]) > 0

        # Verify ActionDetail structure
        action = anomalies["additional_actions_detected"][0]
        assert "description" in action
        assert "offset" in action
        assert "raw_bytes" in action
        assert isinstance(action["description"], str)


def test_detect_external_actions_no_actions():
    """Test detect_external_actions with a PDF that has no external actions."""
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
        result = detect_external_actions(f.name)

        assert result == []


def test_detect_external_actions_with_uri():
    """Test detect_external_actions with a PDF containing /URI action."""
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

    # Create a link annotation with URI action
    link = DictionaryObject({
        NameObject("/Type"): NameObject("/Annot"),
        NameObject("/Subtype"): NameObject("/Link"),
        NameObject("/Rect"): ArrayObject([
            NumberObject(100), NumberObject(700),
            NumberObject(200), NumberObject(720),
        ]),
        NameObject("/A"): DictionaryObject({
            NameObject("/Type"): NameObject("/Action"),
            NameObject("/S"): NameObject("/URI"),
            NameObject("/URI"): TextStringObject("https://example.com/test"),
        }),
    })

    page[NameObject("/Annots")] = ArrayObject([link])

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        result = detect_external_actions(f.name)

        assert len(result) > 0
        assert any("/URI" in action["description"] for action in result)
        assert any("https://example.com/test" in action["description"] for action in result)


def test_detect_external_actions_with_launch():
    """Test detect_external_actions with a PDF containing /Launch action."""
    from pypdf import PdfWriter
    from pypdf.generic import (
        DictionaryObject,
        NameObject,
        TextStringObject,
    )

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)

    # Add an OpenAction with Launch
    launch_action = DictionaryObject({
        NameObject("/Type"): NameObject("/Action"),
        NameObject("/S"): NameObject("/Launch"),
        NameObject("/F"): TextStringObject("cmd.exe"),
    })

    writer._root_object[NameObject("/OpenAction")] = launch_action

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        result = detect_external_actions(f.name)

        assert len(result) > 0
        assert any("/Launch" in action["description"] for action in result)
        assert any("cmd.exe" in action["description"] for action in result)


def test_detect_external_actions_with_gotor():
    """Test detect_external_actions with a PDF containing /GoToR action."""
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

    # Create a link annotation with GoToR action
    link = DictionaryObject({
        NameObject("/Type"): NameObject("/Annot"),
        NameObject("/Subtype"): NameObject("/Link"),
        NameObject("/Rect"): ArrayObject([
            NumberObject(100), NumberObject(700),
            NumberObject(200), NumberObject(720),
        ]),
        NameObject("/A"): DictionaryObject({
            NameObject("/Type"): NameObject("/Action"),
            NameObject("/S"): NameObject("/GoToR"),
            NameObject("/F"): TextStringObject("remote.pdf"),
        }),
    })

    page[NameObject("/Annots")] = ArrayObject([link])

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        result = detect_external_actions(f.name)

        assert len(result) > 0
        assert any("/GoToR" in action["description"] for action in result)
        assert any("remote.pdf" in action["description"] for action in result)


def test_detect_external_actions_with_gotoe():
    """Test detect_external_actions with a PDF containing /GoToE action."""
    from pypdf import PdfWriter
    from pypdf.generic import (
        DictionaryObject,
        NameObject,
        TextStringObject,
    )

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)

    # Add an OpenAction with GoToE
    gotoe_action = DictionaryObject({
        NameObject("/Type"): NameObject("/Action"),
        NameObject("/S"): NameObject("/GoToE"),
        NameObject("/F"): TextStringObject("embedded.pdf"),
        NameObject("/T"): TextStringObject("target"),
    })

    writer._root_object[NameObject("/OpenAction")] = gotoe_action

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        result = detect_external_actions(f.name)

        assert len(result) > 0
        assert any("/GoToE" in action["description"] for action in result)
        assert any("embedded" in action["description"] for action in result)


def test_detect_external_actions_invalid_file():
    """Test detect_external_actions with an invalid file."""
    with pytest.raises(ValidationError):
        detect_external_actions("/nonexistent/file.pdf")


def test_check_anomalies_includes_external_actions():
    """Test that check_anomalies includes external_actions."""
    from pypdf import PdfWriter
    from pypdf.generic import (
        DictionaryObject,
        NameObject,
        TextStringObject,
    )

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)

    # Add an OpenAction with Launch
    launch_action = DictionaryObject({
        NameObject("/Type"): NameObject("/Action"),
        NameObject("/S"): NameObject("/Launch"),
        NameObject("/F"): TextStringObject("malware.exe"),
    })

    writer._root_object[NameObject("/OpenAction")] = launch_action

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        anomalies = check_anomalies(f.name)

        # Should have anomalies_present=True due to external actions
        assert anomalies["anomalies_present"] is True
        assert "external_actions" in anomalies
        assert len(anomalies["external_actions"]) > 0
        assert any("/Launch" in action["description"] for action in anomalies["external_actions"])


def test_detect_javascript_no_js():
    """Test detect_javascript with a PDF that has no JavaScript."""
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
        result = detect_javascript(f.name)

        assert result == []


def test_detect_javascript_with_alert():
    """Test detect_javascript with a PDF containing JavaScript alert."""
    from pypdf import PdfWriter
    from pypdf.generic import (
        DictionaryObject,
        NameObject,
        TextStringObject,
    )

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)

    # Add an OpenAction with JavaScript
    js_action = DictionaryObject({
        NameObject("/Type"): NameObject("/Action"),
        NameObject("/S"): NameObject("/JavaScript"),
        NameObject("/JS"): TextStringObject("app.alert('Hello World');"),
    })

    writer._root_object[NameObject("/OpenAction")] = js_action

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        result = detect_javascript(f.name)

        assert len(result) > 0
        assert any("displays alert" in js["description"] for js in result)
        assert any("app.alert" in js["description"] for js in result)


def test_detect_javascript_with_url_launch():
    """Test detect_javascript with a PDF containing JavaScript that launches URL."""
    from pypdf import PdfWriter
    from pypdf.generic import (
        DictionaryObject,
        NameObject,
        TextStringObject,
    )

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)

    # Add an OpenAction with JavaScript that launches URL
    js_action = DictionaryObject({
        NameObject("/Type"): NameObject("/Action"),
        NameObject("/S"): NameObject("/JavaScript"),
        NameObject("/JS"): TextStringObject("app.launchURL('http://malicious.com');"),
    })

    writer._root_object[NameObject("/OpenAction")] = js_action

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        result = detect_javascript(f.name)

        assert len(result) > 0
        assert any("launches URL" in js["description"] for js in result)


def test_detect_javascript_with_eval():
    """Test detect_javascript with a PDF containing JavaScript eval."""
    from pypdf import PdfWriter
    from pypdf.generic import (
        DictionaryObject,
        NameObject,
        TextStringObject,
    )

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)

    # Add an OpenAction with JavaScript using eval
    js_action = DictionaryObject({
        NameObject("/Type"): NameObject("/Action"),
        NameObject("/S"): NameObject("/JavaScript"),
        NameObject("/JS"): TextStringObject("var x = eval(someCode);"),
    })

    writer._root_object[NameObject("/OpenAction")] = js_action

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        result = detect_javascript(f.name)

        assert len(result) > 0
        assert any("evaluates dynamic code" in js["description"] for js in result)


def test_detect_javascript_with_obfuscation():
    """Test detect_javascript detects obfuscated code patterns."""
    from pypdf import PdfWriter
    from pypdf.generic import (
        DictionaryObject,
        NameObject,
        TextStringObject,
    )

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)

    # Add JavaScript with obfuscation patterns
    js_action = DictionaryObject({
        NameObject("/Type"): NameObject("/Action"),
        NameObject("/S"): NameObject("/JavaScript"),
        NameObject("/JS"): TextStringObject("var s = unescape('%41%42%43');"),
    })

    writer._root_object[NameObject("/OpenAction")] = js_action

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        result = detect_javascript(f.name)

        assert len(result) > 0
        assert any("decodes obfuscated content" in js["description"] for js in result)


def test_detect_javascript_invalid_file():
    """Test detect_javascript with an invalid file."""
    with pytest.raises(ValidationError):
        detect_javascript("/nonexistent/file.pdf")


def test_check_anomalies_includes_javascript():
    """Test that check_anomalies includes javascript_detected."""
    from pypdf import PdfWriter
    from pypdf.generic import (
        DictionaryObject,
        NameObject,
        TextStringObject,
    )

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)

    # Add an OpenAction with JavaScript
    js_action = DictionaryObject({
        NameObject("/Type"): NameObject("/Action"),
        NameObject("/S"): NameObject("/JavaScript"),
        NameObject("/JS"): TextStringObject("app.alert('Malicious');"),
    })

    writer._root_object[NameObject("/OpenAction")] = js_action

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        anomalies = check_anomalies(f.name)

        # Should have anomalies_present=True due to JavaScript
        assert anomalies["anomalies_present"] is True
        assert "javascript_detected" in anomalies
        assert len(anomalies["javascript_detected"]) > 0
        assert any("alert" in js["description"] for js in anomalies["javascript_detected"])


def test_detect_embedded_file_no_embedded():
    """Test detect_embedded_file with a PDF that has no embedded files."""
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
        result = detect_embedded_file(f.name)

        assert result == []


def test_detect_embedded_file_with_attachment():
    """Test detect_embedded_file with a PDF containing an embedded file."""
    from pypdf import PdfWriter
    from pypdf.generic import (
        ArrayObject,
        DictionaryObject,
        NameObject,
        TextStringObject,
        NumberObject,
        ByteStringObject,
        StreamObject,
        DecodedStreamObject,
        create_string_object,
    )

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)

    # Create embedded file content
    file_content = b"This is a test file content."

    # Create the embedded file stream
    ef_stream = DecodedStreamObject()
    ef_stream.set_data(file_content)
    ef_stream[NameObject("/Type")] = NameObject("/EmbeddedFile")
    ef_stream[NameObject("/Params")] = DictionaryObject({
        NameObject("/Size"): NumberObject(len(file_content)),
    })

    # Create the filespec dictionary
    filespec = DictionaryObject({
        NameObject("/Type"): NameObject("/Filespec"),
        NameObject("/F"): TextStringObject("test.txt"),
        NameObject("/UF"): TextStringObject("test.txt"),
        NameObject("/Desc"): TextStringObject("A test text file"),
        NameObject("/EF"): DictionaryObject({
            NameObject("/F"): ef_stream,
        }),
    })

    # Create the Names dictionary with EmbeddedFiles
    names_dict = DictionaryObject({
        NameObject("/EmbeddedFiles"): DictionaryObject({
            NameObject("/Names"): ArrayObject([
                TextStringObject("test.txt"),
                filespec,
            ]),
        }),
    })

    writer._root_object[NameObject("/Names")] = names_dict

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        result = detect_embedded_file(f.name)

        assert len(result) > 0
        assert result[0]["name"] == "test.txt"
        assert result[0]["description"] == "A test text file"


def test_detect_embedded_file_invalid_file():
    """Test detect_embedded_file with an invalid file."""
    with pytest.raises(ValidationError):
        detect_embedded_file("/nonexistent/file.pdf")


def test_check_anomalies_includes_embedded_files():
    """Test that check_anomalies includes embedded_files."""
    from pypdf import PdfWriter
    from pypdf.generic import (
        ArrayObject,
        DictionaryObject,
        NameObject,
        TextStringObject,
        NumberObject,
        DecodedStreamObject,
    )

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)

    # Create embedded file content
    file_content = b"MZ\x90\x00"  # Fake PE header

    # Create the embedded file stream
    ef_stream = DecodedStreamObject()
    ef_stream.set_data(file_content)
    ef_stream[NameObject("/Type")] = NameObject("/EmbeddedFile")

    # Create the filespec dictionary
    filespec = DictionaryObject({
        NameObject("/Type"): NameObject("/Filespec"),
        NameObject("/F"): TextStringObject("malware.exe"),
        NameObject("/EF"): DictionaryObject({
            NameObject("/F"): ef_stream,
        }),
    })

    # Create the Names dictionary with EmbeddedFiles
    names_dict = DictionaryObject({
        NameObject("/EmbeddedFiles"): DictionaryObject({
            NameObject("/Names"): ArrayObject([
                TextStringObject("malware.exe"),
                filespec,
            ]),
        }),
    })

    writer._root_object[NameObject("/Names")] = names_dict

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        anomalies = check_anomalies(f.name)

        # Should have anomalies_present=True due to embedded files
        assert anomalies["anomalies_present"] is True
        assert "embedded_files" in anomalies
        assert len(anomalies["embedded_files"]) > 0
        assert anomalies["embedded_files"][0]["name"] == "malware.exe"


# ---------------------------------------------------------------------------
# ActionDetail / offset / raw_bytes tests
# ---------------------------------------------------------------------------


def test_read_raw_bytes_hex_returns_hex():
    """Test _read_raw_bytes_hex returns correct hex encoding."""
    data = b"\x00\x01\x02\xff"
    assert _read_raw_bytes_hex(data, 0, length=4) == "00 01 02 ff"


def test_read_raw_bytes_hex_respects_length():
    """Test _read_raw_bytes_hex slices to at most *length* bytes."""
    data = b"A" * 1000
    result = _read_raw_bytes_hex(data, 0, length=10)
    # 10 bytes = 20 hex chars + 9 spaces
    assert len(result) == 29


def test_read_raw_bytes_hex_none_on_none_offset():
    """Test _read_raw_bytes_hex returns None when offset is None."""
    assert _read_raw_bytes_hex(b"data", None) is None


def test_get_object_offset_returns_none_for_plain_object():
    """Test _get_object_offset returns None when obj has no indirect_reference."""
    from pypdf import PdfReader
    from pypdf.generic import DictionaryObject, NameObject

    # A plain DictionaryObject built in-memory has no indirect_reference
    obj = DictionaryObject({NameObject("/S"): NameObject("/JavaScript")})

    # We still need a reader; use a minimal PDF
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
        reader = PdfReader(f.name)
        assert _get_object_offset(reader, obj) is None


def test_get_object_offset_returns_int_for_indirect_object():
    """Test _get_object_offset returns an int for an object in the xref table."""
    from pypdf import PdfWriter, PdfReader
    from pypdf.generic import DictionaryObject, NameObject, TextStringObject

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    js_action = DictionaryObject({
        NameObject("/Type"): NameObject("/Action"),
        NameObject("/S"): NameObject("/JavaScript"),
        NameObject("/JS"): TextStringObject("app.alert('test');"),
    })
    # Register as indirect object so it gets its own xref entry
    indirect_ref = writer._add_object(js_action)
    writer._root_object[NameObject("/OpenAction")] = indirect_ref

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        reader = PdfReader(f.name)
        root = reader.trailer["/Root"].get_object()
        open_action = root["/OpenAction"]
        offset = _get_object_offset(reader, open_action)
        assert offset is not None
        assert isinstance(offset, int)
        assert offset >= 0


def test_make_action_detail_with_indirect_object():
    """Test _make_action_detail populates offset and raw_bytes for indirect objects."""
    from pypdf import PdfWriter, PdfReader
    from pypdf.generic import DictionaryObject, NameObject, TextStringObject

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    js_action = DictionaryObject({
        NameObject("/Type"): NameObject("/Action"),
        NameObject("/S"): NameObject("/JavaScript"),
        NameObject("/JS"): TextStringObject("app.alert('test');"),
    })
    indirect_ref = writer._add_object(js_action)
    writer._root_object[NameObject("/OpenAction")] = indirect_ref

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        reader = PdfReader(f.name)
        pdf_bytes = Path(f.name).read_bytes()
        root = reader.trailer["/Root"].get_object()
        open_action = root["/OpenAction"]

        detail = _make_action_detail("test desc", reader, pdf_bytes, open_action)

        assert detail["description"] == "test desc"
        assert detail["offset"] is not None
        assert isinstance(detail["offset"], int)
        assert detail["raw_bytes"] is not None
        assert isinstance(detail["raw_bytes"], str)
        # raw_bytes should be valid hex
        bytes.fromhex(detail["raw_bytes"])


def test_make_action_detail_parent_fallback():
    """Test _make_action_detail falls back to parent_obj offset for inline actions."""
    from pypdf import PdfWriter, PdfReader
    from pypdf.generic import (
        ArrayObject,
        DictionaryObject,
        NameObject,
        NumberObject,
        TextStringObject,
    )

    writer = PdfWriter()
    page = writer.add_blank_page(width=612, height=792)

    # Create annotation with an inline /A action dict (no indirect reference).
    # The annotation itself is registered as an indirect object.
    link = DictionaryObject({
        NameObject("/Type"): NameObject("/Annot"),
        NameObject("/Subtype"): NameObject("/Link"),
        NameObject("/Rect"): ArrayObject([
            NumberObject(0), NumberObject(0),
            NumberObject(100), NumberObject(100),
        ]),
        NameObject("/A"): DictionaryObject({
            NameObject("/Type"): NameObject("/Action"),
            NameObject("/S"): NameObject("/URI"),
            NameObject("/URI"): TextStringObject("https://example.com"),
        }),
    })
    annot_ref = writer._add_object(link)
    page[NameObject("/Annots")] = ArrayObject([annot_ref])

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        reader = PdfReader(f.name)
        pdf_bytes = Path(f.name).read_bytes()

        page0 = reader.pages[0]
        annot = page0["/Annots"][0].get_object()
        action = annot["/A"]

        # The inline action itself should have no offset
        assert _get_object_offset(reader, action) is None

        # But the parent annotation should
        parent_offset = _get_object_offset(reader, annot)
        assert parent_offset is not None

        # _make_action_detail with parent should inherit the annotation offset
        detail = _make_action_detail("test", reader, pdf_bytes, action, parent_obj=annot)
        assert detail["offset"] == parent_offset
        assert detail["raw_bytes"] is not None


def test_detect_additionalactions_actiondetail_structure():
    """Test detect_additionalactions returns ActionDetail dicts with offset and raw_bytes."""
    from pypdf import PdfWriter
    from pypdf.generic import DictionaryObject, NameObject, TextStringObject

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    js_action = DictionaryObject({
        NameObject("/Type"): NameObject("/Action"),
        NameObject("/S"): NameObject("/JavaScript"),
        NameObject("/JS"): TextStringObject("app.alert('test');"),
    })
    indirect_ref = writer._add_object(js_action)
    writer._root_object[NameObject("/OpenAction")] = indirect_ref

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        result = detect_additionalactions(f.name)

        assert len(result) >= 1
        for action in result:
            assert set(action.keys()) == {"description", "offset", "raw_bytes", "decoded_bytes"}
            assert isinstance(action["description"], str)
            assert action["offset"] is not None
            assert isinstance(action["offset"], int)
            assert action["raw_bytes"] is not None
            bytes.fromhex(action["raw_bytes"])


def test_detect_external_actions_actiondetail_with_offset():
    """Test detect_external_actions returns ActionDetail with offset for annotation actions."""
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

    link = DictionaryObject({
        NameObject("/Type"): NameObject("/Annot"),
        NameObject("/Subtype"): NameObject("/Link"),
        NameObject("/Rect"): ArrayObject([
            NumberObject(0), NumberObject(0),
            NumberObject(100), NumberObject(100),
        ]),
        NameObject("/A"): DictionaryObject({
            NameObject("/Type"): NameObject("/Action"),
            NameObject("/S"): NameObject("/URI"),
            NameObject("/URI"): TextStringObject("https://example.com"),
        }),
    })
    # Annotation as indirect object; action is inline within it
    annot_ref = writer._add_object(link)
    page[NameObject("/Annots")] = ArrayObject([annot_ref])

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        result = detect_external_actions(f.name)

        assert len(result) >= 1
        for action in result:
            assert set(action.keys()) == {"description", "offset", "raw_bytes", "decoded_bytes"}
            assert isinstance(action["description"], str)
            # Annotation parent fallback should provide an offset
            assert action["offset"] is not None
            assert isinstance(action["offset"], int)
            assert action["raw_bytes"] is not None
            bytes.fromhex(action["raw_bytes"])


def test_detect_javascript_actiondetail_with_offset():
    """Test detect_javascript returns ActionDetail with offset and raw_bytes."""
    from pypdf import PdfWriter
    from pypdf.generic import DictionaryObject, NameObject, TextStringObject

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    js_action = DictionaryObject({
        NameObject("/Type"): NameObject("/Action"),
        NameObject("/S"): NameObject("/JavaScript"),
        NameObject("/JS"): TextStringObject("app.alert('test');"),
    })
    indirect_ref = writer._add_object(js_action)
    writer._root_object[NameObject("/OpenAction")] = indirect_ref

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        result = detect_javascript(f.name)

        assert len(result) >= 1
        for action in result:
            assert set(action.keys()) == {"description", "offset", "raw_bytes", "decoded_bytes"}
            assert isinstance(action["description"], str)
            assert action["offset"] is not None
            assert isinstance(action["offset"], int)
            assert action["raw_bytes"] is not None
            bytes.fromhex(action["raw_bytes"])


def test_detect_external_actions_launch_actiondetail_with_offset():
    """Test detect_external_actions returns ActionDetail with offset for /Launch via OpenAction."""
    from pypdf import PdfWriter
    from pypdf.generic import DictionaryObject, NameObject, TextStringObject

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    launch_action = DictionaryObject({
        NameObject("/Type"): NameObject("/Action"),
        NameObject("/S"): NameObject("/Launch"),
        NameObject("/F"): TextStringObject("cmd.exe"),
    })
    indirect_ref = writer._add_object(launch_action)
    writer._root_object[NameObject("/OpenAction")] = indirect_ref

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        result = detect_external_actions(f.name)

        assert len(result) >= 1
        action = result[0]
        assert "/Launch" in action["description"]
        assert action["offset"] is not None
        assert isinstance(action["offset"], int)
        assert action["raw_bytes"] is not None


def test_raw_bytes_contain_object_data():
    """Test that raw_bytes at the offset actually contain PDF object data."""
    from pypdf import PdfWriter
    from pypdf.generic import DictionaryObject, NameObject, TextStringObject

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    js_action = DictionaryObject({
        NameObject("/Type"): NameObject("/Action"),
        NameObject("/S"): NameObject("/JavaScript"),
        NameObject("/JS"): TextStringObject("app.alert('forensic');"),
    })
    indirect_ref = writer._add_object(js_action)
    writer._root_object[NameObject("/OpenAction")] = indirect_ref

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        result = detect_additionalactions(f.name)

        assert len(result) >= 1
        action = result[0]
        raw = bytes.fromhex(action["raw_bytes"])
        # The raw bytes at the offset should contain a PDF object marker
        # (e.g., "N 0 obj" pattern) since we point to the start of the object
        assert b"obj" in raw


def test_process_actiondetail_fields_survive_defang():
    """Test that process() preserves ActionDetail structure through defanging."""
    from pypdf import PdfWriter
    from pypdf.generic import DictionaryObject, NameObject, TextStringObject

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    js_action = DictionaryObject({
        NameObject("/Type"): NameObject("/Action"),
        NameObject("/S"): NameObject("/JavaScript"),
        NameObject("/JS"): TextStringObject("app.alert('test');"),
    })
    indirect_ref = writer._add_object(js_action)
    writer._root_object[NameObject("/OpenAction")] = indirect_ref

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        report = process(f.name)

        for field in ["additional_actions_detected", "javascript_detected"]:
            items = report["anomalies"][field]
            assert len(items) >= 1
            for item in items:
                assert set(item.keys()) == {"description", "offset", "raw_bytes", "decoded_bytes"}
                assert isinstance(item["description"], str)
                # offset is int (not defanged to string) and raw_bytes is hex str
                assert isinstance(item["offset"], int)
                assert isinstance(item["raw_bytes"], str)
                bytes.fromhex(item["raw_bytes"])


# ---------------------------------------------------------------------------
# EmbeddedFile offset / raw_bytes tests
# ---------------------------------------------------------------------------


def test_detect_embedded_file_has_offset_and_raw_bytes():
    """Test that detect_embedded_file returns offset and raw_bytes fields."""
    from pypdf import PdfWriter
    from pypdf.generic import (
        ArrayObject,
        DictionaryObject,
        NameObject,
        TextStringObject,
        NumberObject,
        DecodedStreamObject,
    )

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)

    file_content = b"Embedded test content."
    ef_stream = DecodedStreamObject()
    ef_stream.set_data(file_content)
    ef_stream[NameObject("/Type")] = NameObject("/EmbeddedFile")
    ef_stream[NameObject("/Params")] = DictionaryObject({
        NameObject("/Size"): NumberObject(len(file_content)),
    })

    filespec = DictionaryObject({
        NameObject("/Type"): NameObject("/Filespec"),
        NameObject("/F"): TextStringObject("payload.bin"),
        NameObject("/EF"): DictionaryObject({
            NameObject("/F"): ef_stream,
        }),
    })
    filespec_ref = writer._add_object(filespec)

    names_dict = DictionaryObject({
        NameObject("/EmbeddedFiles"): DictionaryObject({
            NameObject("/Names"): ArrayObject([
                TextStringObject("payload.bin"),
                filespec_ref,
            ]),
        }),
    })
    writer._root_object[NameObject("/Names")] = names_dict

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        result = detect_embedded_file(f.name)

        assert len(result) > 0
        ef = result[0]
        assert "offset" in ef
        assert "raw_bytes" in ef
        assert ef["name"] == "payload.bin"
        assert ef["offset"] is not None
        assert isinstance(ef["offset"], int)
        assert ef["raw_bytes"] is not None
        bytes.fromhex(ef["raw_bytes"])


def test_check_anomalies_embedded_files_have_offset():
    """Test that embedded_files through check_anomalies include offset/raw_bytes."""
    from pypdf import PdfWriter
    from pypdf.generic import (
        ArrayObject,
        DictionaryObject,
        NameObject,
        TextStringObject,
        DecodedStreamObject,
    )

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)

    ef_stream = DecodedStreamObject()
    ef_stream.set_data(b"MZ\x90\x00")
    ef_stream[NameObject("/Type")] = NameObject("/EmbeddedFile")

    filespec = DictionaryObject({
        NameObject("/Type"): NameObject("/Filespec"),
        NameObject("/F"): TextStringObject("malware.exe"),
        NameObject("/EF"): DictionaryObject({
            NameObject("/F"): ef_stream,
        }),
    })
    filespec_ref = writer._add_object(filespec)

    names_dict = DictionaryObject({
        NameObject("/EmbeddedFiles"): DictionaryObject({
            NameObject("/Names"): ArrayObject([
                TextStringObject("malware.exe"),
                filespec_ref,
            ]),
        }),
    })
    writer._root_object[NameObject("/Names")] = names_dict

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        anomalies = check_anomalies(f.name)

        ef = anomalies["embedded_files"][0]
        assert ef["name"] == "malware.exe"
        assert "offset" in ef
        assert "raw_bytes" in ef


# ---------------------------------------------------------------------------
# detect_acroform ActionDetail tests
# ---------------------------------------------------------------------------


def test_detect_acroform_returns_actiondetail():
    """Test that detect_acroform returns ActionDetail dicts."""
    from pypdf import PdfWriter
    from pypdf.generic import (
        ArrayObject,
        DictionaryObject,
        NameObject,
        TextStringObject,
        NumberObject,
    )

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)

    # Create a text field
    field = DictionaryObject({
        NameObject("/FT"): NameObject("/Tx"),
        NameObject("/T"): TextStringObject("username"),
        NameObject("/Ff"): NumberObject(0),
    })
    field_ref = writer._add_object(field)

    acro_form = DictionaryObject({
        NameObject("/Fields"): ArrayObject([field_ref]),
    })
    acro_form_ref = writer._add_object(acro_form)
    writer._root_object[NameObject("/AcroForm")] = acro_form_ref

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        result = detect_acroform(f.name)

        assert len(result) >= 1
        # First entry should be "AcroForm detected in document catalog"
        assert "AcroForm detected" in result[0]["description"]
        for item in result:
            assert set(item.keys()) == {"description", "offset", "raw_bytes", "decoded_bytes"}
            assert isinstance(item["description"], str)


def test_detect_acroform_field_has_offset():
    """Test that acroform field details include offset when field is indirect."""
    from pypdf import PdfWriter
    from pypdf.generic import (
        ArrayObject,
        DictionaryObject,
        NameObject,
        TextStringObject,
        NumberObject,
    )

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)

    field = DictionaryObject({
        NameObject("/FT"): NameObject("/Tx"),
        NameObject("/T"): TextStringObject("email"),
        NameObject("/Ff"): NumberObject(0),
    })
    field_ref = writer._add_object(field)

    acro_form = DictionaryObject({
        NameObject("/Fields"): ArrayObject([field_ref]),
    })
    acro_form_ref = writer._add_object(acro_form)
    writer._root_object[NameObject("/AcroForm")] = acro_form_ref

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        result = detect_acroform(f.name)

        # Find the field entry
        field_items = [r for r in result if "Field" in r["description"]]
        assert len(field_items) >= 1
        fi = field_items[0]
        assert fi["offset"] is not None
        assert isinstance(fi["offset"], int)
        assert fi["raw_bytes"] is not None
        raw = bytes.fromhex(fi["raw_bytes"])
        assert b"obj" in raw


def test_check_anomalies_acroform_details_actiondetail():
    """Test that check_anomalies acroform_details are ActionDetail dicts."""
    from pypdf import PdfWriter
    from pypdf.generic import (
        ArrayObject,
        DictionaryObject,
        NameObject,
        TextStringObject,
        NumberObject,
    )

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)

    field = DictionaryObject({
        NameObject("/FT"): NameObject("/Tx"),
        NameObject("/T"): TextStringObject("name"),
        NameObject("/Ff"): NumberObject(0),
    })
    field_ref = writer._add_object(field)

    acro_form = DictionaryObject({
        NameObject("/Fields"): ArrayObject([field_ref]),
    })
    acro_form_ref = writer._add_object(acro_form)
    writer._root_object[NameObject("/AcroForm")] = acro_form_ref

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        anomalies = check_anomalies(f.name)

        assert anomalies["anomalies_present"] is True
        for item in anomalies["acroform_details"]:
            assert "description" in item
            assert "offset" in item
            assert "raw_bytes" in item


# ---------------------------------------------------------------------------
# detect_xmlforms ActionDetail tests
# ---------------------------------------------------------------------------


def test_detect_xmlforms_returns_actiondetail():
    """Test that detect_xmlforms returns ActionDetail dicts."""
    from pypdf import PdfWriter
    from pypdf.generic import (
        DictionaryObject,
        NameObject,
        DecodedStreamObject,
    )

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)

    # Create a single-stream XFA with a script
    xfa_content = b"""<?xml version="1.0"?>
<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">
<script contentType="application/x-javascript">app.alert("xfa test");</script>
</xdp:xdp>"""
    xfa_stream = DecodedStreamObject()
    xfa_stream.set_data(xfa_content)
    xfa_stream_ref = writer._add_object(xfa_stream)

    acro_form = DictionaryObject({
        NameObject("/XFA"): xfa_stream_ref,
    })
    acro_form_ref = writer._add_object(acro_form)
    writer._root_object[NameObject("/AcroForm")] = acro_form_ref

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        result = detect_xmlforms(f.name)

        assert len(result) >= 1
        # First item should be "XFA (XML Forms Architecture) detected"
        assert "XFA" in result[0]["description"]
        for item in result:
            assert set(item.keys()) == {"description", "offset", "raw_bytes", "decoded_bytes"}
            assert isinstance(item["description"], str)


def test_detect_xmlforms_has_offset():
    """Test that detect_xmlforms returns offsets for XFA entries."""
    from pypdf import PdfWriter
    from pypdf.generic import (
        DictionaryObject,
        NameObject,
        DecodedStreamObject,
    )

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)

    xfa_content = b"""<?xml version="1.0"?>
<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">
<script>xfa.host.messageBox("test");</script>
</xdp:xdp>"""
    xfa_stream = DecodedStreamObject()
    xfa_stream.set_data(xfa_content)
    xfa_stream_ref = writer._add_object(xfa_stream)

    acro_form = DictionaryObject({
        NameObject("/XFA"): xfa_stream_ref,
    })
    acro_form_ref = writer._add_object(acro_form)
    writer._root_object[NameObject("/AcroForm")] = acro_form_ref

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        result = detect_xmlforms(f.name)

        # At least one item should have a non-null offset
        offsets = [item["offset"] for item in result if item["offset"] is not None]
        assert len(offsets) >= 1


def test_check_anomalies_xfa_details_actiondetail():
    """Test that check_anomalies xfa_details are ActionDetail dicts."""
    from pypdf import PdfWriter
    from pypdf.generic import (
        DictionaryObject,
        NameObject,
        DecodedStreamObject,
    )

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)

    xfa_content = b"""<?xml version="1.0"?>
<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/">
<script>app.alert("hello");</script>
</xdp:xdp>"""
    xfa_stream = DecodedStreamObject()
    xfa_stream.set_data(xfa_content)
    xfa_stream_ref = writer._add_object(xfa_stream)

    acro_form = DictionaryObject({
        NameObject("/XFA"): xfa_stream_ref,
    })
    acro_form_ref = writer._add_object(acro_form)
    writer._root_object[NameObject("/AcroForm")] = acro_form_ref

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        anomalies = check_anomalies(f.name)

        assert anomalies["anomalies_present"] is True
        for item in anomalies["xfa_details"]:
            assert "description" in item
            assert "offset" in item
            assert "raw_bytes" in item
            assert "decoded_bytes" in item


# ---------------------------------------------------------------------------
# decoded_bytes tests
# ---------------------------------------------------------------------------


def test_get_decoded_bytes_hex_returns_none_for_dict():
    """Test _get_decoded_bytes_hex returns None for plain dict objects (no stream)."""
    from pypdf.generic import DictionaryObject, NameObject, TextStringObject

    d = DictionaryObject({
        NameObject("/S"): NameObject("/JavaScript"),
        NameObject("/JS"): TextStringObject("app.alert(1);"),
    })
    assert _get_decoded_bytes_hex(d) is None


def test_get_decoded_bytes_hex_returns_content_for_stream():
    """Test _get_decoded_bytes_hex returns decompressed hex for stream objects."""
    from pypdf.generic import DecodedStreamObject

    stream = DecodedStreamObject()
    stream.set_data(b"Hello stream content")
    result = _get_decoded_bytes_hex(stream)
    assert result is not None
    assert bytes.fromhex(result) == b"Hello stream content"


def test_get_decoded_bytes_hex_respects_length():
    """Test _get_decoded_bytes_hex truncates to length."""
    from pypdf.generic import DecodedStreamObject

    stream = DecodedStreamObject()
    stream.set_data(b"A" * 2000)
    result = _get_decoded_bytes_hex(stream, length=10)
    assert result is not None
    assert bytes.fromhex(result) == b"A" * 10


def test_embedded_file_decoded_bytes_contains_file_content():
    """Test that EmbeddedFile decoded_bytes contains the decompressed file content."""
    from pypdf import PdfWriter
    from pypdf.generic import (
        ArrayObject,
        DictionaryObject,
        NameObject,
        TextStringObject,
        NumberObject,
        DecodedStreamObject,
    )

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)

    file_content = b"MZ\x90\x00\x03\x00\x00\x00"  # PE header bytes
    ef_stream = DecodedStreamObject()
    ef_stream.set_data(file_content)
    ef_stream[NameObject("/Type")] = NameObject("/EmbeddedFile")

    filespec = DictionaryObject({
        NameObject("/Type"): NameObject("/Filespec"),
        NameObject("/F"): TextStringObject("malware.exe"),
        NameObject("/EF"): DictionaryObject({NameObject("/F"): ef_stream}),
    })
    fs_ref = writer._add_object(filespec)
    names = DictionaryObject({
        NameObject("/EmbeddedFiles"): DictionaryObject({
            NameObject("/Names"): ArrayObject([TextStringObject("malware.exe"), fs_ref]),
        }),
    })
    writer._root_object[NameObject("/Names")] = names

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        result = detect_embedded_file(f.name)

        assert len(result) > 0
        ef = result[0]
        assert ef["decoded_bytes"] is not None
        decoded = bytes.fromhex(ef["decoded_bytes"])
        assert decoded == file_content


def test_xfa_decoded_bytes_contains_xml():
    """Test that XFA ActionDetail decoded_bytes contains decompressed XML."""
    from pypdf import PdfWriter
    from pypdf.generic import (
        DictionaryObject,
        NameObject,
        DecodedStreamObject,
    )

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)

    xfa_content = b'<?xml version="1.0"?><xdp><script>app.alert("xfa");</script></xdp>'
    xfa_stream = DecodedStreamObject()
    xfa_stream.set_data(xfa_content)
    xfa_ref = writer._add_object(xfa_stream)

    acro = DictionaryObject({NameObject("/XFA"): xfa_ref})
    acro_ref = writer._add_object(acro)
    writer._root_object[NameObject("/AcroForm")] = acro_ref

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        result = detect_xmlforms(f.name)

        # Find an item with decoded_bytes (stream-backed entries)
        decoded_items = [r for r in result if r["decoded_bytes"] is not None]
        assert len(decoded_items) >= 1
        decoded = bytes.fromhex(decoded_items[0]["decoded_bytes"])
        assert b"app.alert" in decoded


def test_acroform_decoded_bytes_is_none():
    """Test that AcroForm ActionDetail decoded_bytes is None for dict objects."""
    from pypdf import PdfWriter
    from pypdf.generic import (
        ArrayObject,
        DictionaryObject,
        NameObject,
        TextStringObject,
    )

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)

    field = DictionaryObject({
        NameObject("/FT"): NameObject("/Tx"),
        NameObject("/T"): TextStringObject("name"),
    })
    field_ref = writer._add_object(field)
    acro = DictionaryObject({NameObject("/Fields"): ArrayObject([field_ref])})
    acro_ref = writer._add_object(acro)
    writer._root_object[NameObject("/AcroForm")] = acro_ref

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        result = detect_acroform(f.name)

        # All items should have decoded_bytes=None since AcroForm uses dicts, not streams
        for item in result:
            assert item["decoded_bytes"] is None


def test_javascript_action_decoded_bytes_is_none():
    """Test that JS action ActionDetail decoded_bytes is None for dict-based actions."""
    from pypdf import PdfWriter
    from pypdf.generic import DictionaryObject, NameObject, TextStringObject

    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    js_action = DictionaryObject({
        NameObject("/Type"): NameObject("/Action"),
        NameObject("/S"): NameObject("/JavaScript"),
        NameObject("/JS"): TextStringObject("app.alert('test');"),
    })
    indirect_ref = writer._add_object(js_action)
    writer._root_object[NameObject("/OpenAction")] = indirect_ref

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        result = detect_additionalactions(f.name)

        assert len(result) >= 1
        # Dict-based JS actions have no stream to decode
        for item in result:
            assert item["decoded_bytes"] is None


def test_decoded_bytes_for_object_in_objstm():
    """Test that decoded_bytes returns decompressed ObjStm content for objects stored in object streams."""
    from pypdf import PdfWriter, PdfReader
    from pypdf.generic import (
        DictionaryObject,
        NameObject,
        TextStringObject,
    )

    # Create a normal PDF with an indirect JS action
    writer = PdfWriter()
    writer.add_blank_page(width=612, height=792)
    js_action = DictionaryObject({
        NameObject("/Type"): NameObject("/Action"),
        NameObject("/S"): NameObject("/JavaScript"),
        NameObject("/JS"): TextStringObject("app.alert('objstm');"),
    })
    js_ref = writer._add_object(js_action)
    writer._root_object[NameObject("/OpenAction")] = js_ref

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        writer.write(f)
        f.flush()
        reader = PdfReader(f.name)
        pdf_bytes = Path(f.name).read_bytes()

        # Resolve the OpenAction to get the action object
        root = reader.trailer["/Root"].get_object()
        action_obj = root["/OpenAction"]
        if hasattr(action_obj, "get_object"):
            action_obj = action_obj.get_object()

        ref = action_obj.indirect_reference
        assert ref is not None

        # In a normal PDF, the object is NOT in xref_objStm, so decoded_bytes is None
        assert ref.idnum not in reader.xref_objStm
        result = _get_decoded_bytes_hex(action_obj, reader=reader)
        assert result is None  # dict object, not in ObjStm

        # Now simulate ObjStm storage: move the xref entry to xref_objStm
        # pointing to an existing stream object (the page content stream)
        # Find a stream object to use as the fake ObjStm container
        page = reader.pages[0].get_object()
        contents = page.get("/Contents")
        if hasattr(contents, "get_object"):
            contents = contents.get_object()

        if hasattr(contents, "get_data"):
            contents_ref = contents.indirect_reference
            if contents_ref is not None:
                # Move the action into xref_objStm pointing to the content stream
                gen = ref.generation
                # Remove from traditional xref
                if gen in reader.xref and ref.idnum in reader.xref[gen]:
                    del reader.xref[gen][ref.idnum]
                # Add to xref_objStm: maps idnum -> (stream_obj_number, index)
                reader.xref_objStm[ref.idnum] = (contents_ref.idnum, 0)

                # Now _get_decoded_bytes_hex should decode the content stream
                result = _get_decoded_bytes_hex(action_obj, reader=reader)
                assert result is not None
                decoded = bytes.fromhex(result)
                assert len(decoded) > 0
