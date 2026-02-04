"""Tests for CLI."""

import json
import subprocess
import sys
import tempfile


def test_cli_version():
    result = subprocess.run(
        [sys.executable, "-m", "woodchipper", "--version"],
        capture_output=True,
        text=True,
    )
    assert "0.1.0" in result.stdout


def test_cli_help():
    result = subprocess.run(
        [sys.executable, "-m", "woodchipper", "--help"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "PDF" in result.stdout


def test_cli_missing_file():
    result = subprocess.run(
        [sys.executable, "-m", "woodchipper", "/nonexistent/file.pdf"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert "File not found" in result.stderr


def test_cli_invalid_file_type():
    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as f:
        f.write(b"Not a PDF")
        f.flush()
        result = subprocess.run(
            [sys.executable, "-m", "woodchipper", f.name],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 1
        assert "only accepts PDF" in result.stderr


def test_cli_valid_pdf():
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
        result = subprocess.run(
            [sys.executable, "-m", "woodchipper", f.name],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0

        # Verify output is valid JSON with required fields
        report = json.loads(result.stdout)
        assert "filename" in report
        assert "filesize" in report
        assert "md5" in report
        assert "sha1" in report
        assert "sha256" in report
        assert "urls" in report
