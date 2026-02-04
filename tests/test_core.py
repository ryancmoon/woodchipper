"""Tests for core functionality."""

import tempfile
from pathlib import Path

import pytest

from woodchipper.core import validate_pdf, process, get_urls, get_pdf_metadata, check_anomalies, detect_additionalactions, detect_external_actions, detect_javascript, extract_forms, ValidationError


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
        assert isinstance(anomalies_section["anomalies_present"], bool)
        assert isinstance(anomalies_section["anomalies"], list)
        assert isinstance(anomalies_section["additional_actions_detected"], list)
        assert isinstance(anomalies_section["external_actions"], list)
        assert isinstance(anomalies_section["javascript_detected"], list)

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
        assert any("Document Open" in action for action in result)
        assert any("JavaScript" in action for action in result)


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
        assert any("Document Open" in action for action in result)
        assert any("URL" in action for action in result)


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
        assert any("/URI" in action for action in result)
        assert any("https://example.com/test" in action for action in result)


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
        assert any("/Launch" in action for action in result)
        assert any("cmd.exe" in action for action in result)


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
        assert any("/GoToR" in action for action in result)
        assert any("remote.pdf" in action for action in result)


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
        assert any("/GoToE" in action for action in result)
        assert any("embedded" in action for action in result)


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
        assert any("/Launch" in action for action in anomalies["external_actions"])


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
        assert any("displays alert" in js for js in result)
        assert any("app.alert" in js for js in result)


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
        assert any("launches URL" in js for js in result)


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
        assert any("evaluates dynamic code" in js for js in result)


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
        assert any("decodes obfuscated content" in js for js in result)


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
        assert any("alert" in js for js in anomalies["javascript_detected"])
