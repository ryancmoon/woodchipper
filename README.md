# Woodchipper

All PDF files must be fed to the woodchipper.

A Python library and CLI tool for analyzing PDF files. Extracts metadata, computes file hashes, finds embedded URLs, detects forms, and identifies suspicious actions and anomalies. All URLs in output are automatically defanged for safe handling.

## Installation

```bash
pip install woodchipper
```

Or from source:

```bash
pip install -r requirements.txt
pip install -e .
```

**Note:** Requires `libmagic` for file type detection:
- Debian/Ubuntu: `apt install libmagic1`
- macOS: `brew install libmagic`
- Fedora: `dnf install file-libs`

## CLI Usage

```bash
woodchipper <path-to-pdf>
```

Output is JSON with defanged URLs:

```json
{
  "filename": "suspicious.pdf",
  "filesize": 142857,
  "md5": "d41d8cd98f00b204e9800998ecf8427e",
  "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "urls": [
    "hXXps://example[.]com",
    "hXXps://test[.]org/page"
  ],
  "metadata": {
    "author": "John Doe",
    "creator": "Microsoft Word",
    "producer": "Microsoft: Print To PDF",
    "subject": null,
    "title": "Important Document",
    "creation_date": "2024-01-15 12:00:00+00:00",
    "modification_date": "2024-01-16 09:00:00+00:00",
    "spoofing_indicators": []
  },
  "anomalies": {
    "anomalies_present": true,
    "anomalies": [
      "PDF header not at byte 0 (found at byte 18)"
    ],
    "additional_actions_detected": [
      "Document Open: JavaScript execution (code: app.alert('Hello');...)"
    ]
  },
  "forms": {
    "forms_present": true,
    "form_submission_targets": [
      "hXXps://collect[.]malicious[.]com/submit"
    ]
  }
}
```

Exit codes:
- `0` - Success
- `1` - Validation error (file not found, not readable, or not a PDF)

## Library API

### `process(file_path) -> PdfReport`

Process a PDF file and return a full report with all analysis.

```python
from woodchipper import process

report = process("document.pdf")
print(report["sha256"])
print(report["urls"])  # Defanged URLs
print(report["metadata"]["spoofing_indicators"])
print(report["anomalies"]["additional_actions_detected"])
```

**Note:** All URLs in the returned report are defanged for safe handling.

### `get_urls(file_path) -> list[str]`

Extract URLs from a PDF file (returns raw URLs, not defanged).

```python
from woodchipper import get_urls

urls = get_urls("document.pdf")
for url in urls:
    print(url)
```

Extracts URLs from `/Link` annotations and `/A` (Action) dictionaries with `/URI` entries.

### `get_pdf_metadata(file_path) -> PdfMetadata`

Extract document metadata with spoofing detection.

```python
from woodchipper import get_pdf_metadata

metadata = get_pdf_metadata("document.pdf")
print(f"Author: {metadata['author']}")
print(f"Creator: {metadata['creator']}")

if metadata["spoofing_indicators"]:
    print("Potential spoofing detected:")
    for indicator in metadata["spoofing_indicators"]:
        print(f"  - {indicator}")
```

**Spoofing detection includes:**
- Creation date after modification date
- Timestamps in the future
- Creator/producer mismatches (e.g., claims Microsoft Word but produced by LibreOffice)
- Creation date before PDF format existed (pre-1993)

### `check_anomalies(file_path) -> PdfAnomalies`

Check for PDF structural anomalies.

```python
from woodchipper import check_anomalies

anomalies = check_anomalies("document.pdf")
if anomalies["anomalies_present"]:
    for anomaly in anomalies["anomalies"]:
        print(f"Anomaly: {anomaly}")
    for action in anomalies["additional_actions_detected"]:
        print(f"Action: {action}")
```

**Detects:**
- PDF header not at byte 0 (embedded content)
- Invalid PDF version
- Missing or malformed binary marker
- Missing %%EOF marker
- Data after %%EOF (appended content)
- `/OpenAction` and `/AA` (Additional Actions) triggers

### `detect_additionalactions(file_path) -> list[str]`

Detect automatic actions triggered by PDF events.

```python
from woodchipper import detect_additionalactions

actions = detect_additionalactions("document.pdf")
for action in actions:
    print(action)
```

**Detects actions triggered by:**
- Document Open, Close, Save, Print
- Page Open, Close

**Action types identified:**
- JavaScript execution
- Launch external application
- Open URL
- Submit form data
- And more

### `extract_forms(file_path) -> PdfForms`

Detect PDF forms and extract submission targets.

```python
from woodchipper import extract_forms

forms = extract_forms("document.pdf")
if forms["forms_present"]:
    print("Form submission targets:")
    for target in forms["form_submission_targets"]:
        print(f"  {target}")
```

### `validate_pdf(file_path) -> Path`

Validate that a file exists, is readable, and is a PDF.

```python
from woodchipper import validate_pdf, ValidationError

try:
    path = validate_pdf("document.pdf")
except ValidationError as e:
    print(f"Invalid: {e}")
```

### `ValidationError`

Exception raised when file validation fails:
- File not found
- Path is not a file
- File is not readable
- File is not a PDF (based on magic bytes)

## Output Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "filename": { "type": "string" },
    "filesize": { "type": "integer" },
    "md5": { "type": "string" },
    "sha1": { "type": "string" },
    "sha256": { "type": "string" },
    "urls": {
      "type": "array",
      "items": { "type": "string" }
    },
    "metadata": {
      "type": "object",
      "properties": {
        "author": { "type": ["string", "null"] },
        "creator": { "type": ["string", "null"] },
        "producer": { "type": ["string", "null"] },
        "subject": { "type": ["string", "null"] },
        "title": { "type": ["string", "null"] },
        "creation_date": { "type": ["string", "null"] },
        "modification_date": { "type": ["string", "null"] },
        "spoofing_indicators": {
          "type": "array",
          "items": { "type": "string" }
        }
      }
    },
    "anomalies": {
      "type": "object",
      "properties": {
        "anomalies_present": { "type": "boolean" },
        "anomalies": {
          "type": "array",
          "items": { "type": "string" }
        },
        "additional_actions_detected": {
          "type": "array",
          "items": { "type": "string" }
        }
      }
    },
    "forms": {
      "type": "object",
      "properties": {
        "forms_present": { "type": "boolean" },
        "form_submission_targets": {
          "type": "array",
          "items": { "type": "string" }
        }
      }
    }
  },
  "required": ["filename", "filesize", "md5", "sha1", "sha256", "urls", "metadata", "anomalies", "forms"]
}
```

## Development

Install in editable mode with dev dependencies:

```bash
pip install -e ".[dev]"
```

Run tests:

```bash
pytest
```

## License

MIT
