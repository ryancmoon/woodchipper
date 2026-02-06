# Woodchipper

All PDF files must be fed to the woodchipper.

__description__ = 'A Python library, CLI tool, and HTTP API for analyzing PDF files. Extracts metadata, computes file hashes, finds embedded URLs, detects forms, AcroForms, XFA, JavaScript, embedded files, rich media, and identifies suspicious actions and anomalies. All output is automatically defanged for safe handling.'  
__author__ = 'Ryan C. Moon'  
__version__ = '1.0.0'  
__date__ = '2026-02-06'  

To report a bug, please open an issue or submit a PR.


## Installation

```bash
pip install woodchipper
```

With HTTP server support:

```bash
pip install woodchipper[server]
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

Output is JSON with all string fields defanged:

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
      "PDF header not at byte 0 (found at byte 18)",
      "Rich media detected: /3D (3D content). Rich media includes 3D or Flash streams which are no longer supported by modern OS or in common usage. This is suspicious.",
      "Stream length mismatches detected (1 stream(s)). Mismatched stream lengths may indicate PDF tampering, corruption, or malicious manipulation."
    ],
    "additional_actions_detected": [
      "Document Open: JavaScript execution (code: app.alert('Hello');...)"
    ],
    "external_actions": [
      "/Launch at Document OpenAction: Launches external application (file: cmd.exe)",
      "/URI at Page 1 Annotation 1: Opens URL (hXXps://malicious[.]com)"
    ],
    "javascript_detected": [
      "Document OpenAction: displays alert (code: app.alert('Hello');)"
    ],
    "embedded_files": [
      {
        "name": "malware.exe",
        "file_type": "PE32 executable (GUI) Intel 80386",
        "mime_type": "application/x-dosexec",
        "size": 45056,
        "description": "Click to open"
      }
    ],
    "acroform_details": [
      "AcroForm detected in document catalog",
      "Form contains 3 top-level field(s)",
      "Field 'username': type=Text, flags=[Required]"
    ],
    "xfa_details": [
      "XFA (XML Forms Architecture) detected",
      "XFA JavaScript script in template - behaviors: contains URL: var url = 'http://...'..."
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

## HTTP API

Woodchipper includes a FastAPI-based HTTP server for remote PDF analysis.

### Running the Server

```bash
# Install with server dependencies
pip install woodchipper[server]

# Run with the built-in command
woodchipper-server

# Or run directly with uvicorn
uvicorn woodchipper.server:app --host 0.0.0.0 --port 8080

# Or with auto-reload for development
uvicorn woodchipper.server:app --host 0.0.0.0 --port 8080 --reload
```

### Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| POST | `/analyze` | Upload PDF as multipart form |
| POST | `/analyze/raw` | Send raw PDF bytes in body |
| GET | `/docs` | Interactive Swagger UI documentation |

### Usage Examples

```bash
# Multipart upload
curl -X POST -F "file=@suspicious.pdf" http://localhost:8080/analyze

# Raw bytes
curl -X POST -H "Content-Type: application/pdf" \
  --data-binary @suspicious.pdf \
  http://localhost:8080/analyze/raw

# Health check
curl http://localhost:8080/health
```

### Response

Both `/analyze` and `/analyze/raw` return the same JSON report as the CLI:

```json
{
  "filename": "suspicious.pdf",
  "filesize": 142857,
  "md5": "...",
  "sha256": "...",
  "urls": ["hXXps://example[.]com"],
  "metadata": { ... },
  "anomalies": { ... },
  "forms": { ... }
}
```

### Error Handling

- `400 Bad Request` - Invalid file, empty body, or not a PDF
- `200 OK` - Analysis successful, returns JSON report

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
print(report["anomalies"]["external_actions"])
print(report["anomalies"]["javascript_detected"])
print(report["anomalies"]["embedded_files"])
print(report["anomalies"]["acroform_details"])
print(report["anomalies"]["xfa_details"])
```

**Note:** All string fields in the returned report are defanged for safe handling.

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

Check for PDF structural anomalies and suspicious content.

```python
from woodchipper import check_anomalies

anomalies = check_anomalies("document.pdf")
if anomalies["anomalies_present"]:
    for anomaly in anomalies["anomalies"]:
        print(f"Anomaly: {anomaly}")
    for action in anomalies["additional_actions_detected"]:
        print(f"Action: {action}")
    for external in anomalies["external_actions"]:
        print(f"External: {external}")
    for js in anomalies["javascript_detected"]:
        print(f"JavaScript: {js}")
    for ef in anomalies["embedded_files"]:
        print(f"Embedded: {ef['name']} ({ef['mime_type']})")
    for form in anomalies["acroform_details"]:
        print(f"AcroForm: {form}")
    for xfa in anomalies["xfa_details"]:
        print(f"XFA: {xfa}")
```

**Detects:**
- PDF header not at byte 0 (embedded content)
- Invalid PDF version
- Missing or malformed binary marker
- Missing %%EOF marker
- Data after %%EOF (appended content)
- Rich media (3D, Flash) - no longer supported, suspicious
- Stream length mismatches (tampering indicator)
- `/OpenAction` and `/AA` (Additional Actions) triggers
- External actions (`/Launch`, `/URI`, `/GoToR`, `/GoToE`)
- Embedded JavaScript with behavior analysis
- Embedded files with file type detection
- AcroForm details (field types, flags, actions)
- XFA (XML Forms Architecture) with script extraction

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

### `detect_external_actions(file_path) -> list[str]`

Detect external action tags that access resources outside the PDF.

```python
from woodchipper import detect_external_actions

actions = detect_external_actions("document.pdf")
for action in actions:
    print(action)
```

**Detects:**
- `/Launch` - Launches external applications (e.g., `cmd.exe`, executables)
- `/URI` - Opens URLs in browser
- `/GoToR` - Opens remote PDF documents
- `/GoToE` - Opens embedded documents

### `detect_javascript(file_path) -> list[str]`

Detect JavaScript code embedded in a PDF with behavior analysis.

```python
from woodchipper import detect_javascript

scripts = detect_javascript("document.pdf")
for script in scripts:
    print(script)
```

**Detects `/JavaScript` and `/JS` tags in:**
- Document OpenAction
- Document and page Additional Actions (/AA)
- Named JavaScript in the Names tree
- Annotation actions

**Behavior analysis identifies:**
- `displays alert` - app.alert() calls
- `launches URL` - app.launchURL() calls
- `submits form data` - this.submitForm() calls
- `exports data` - exportDataAsObject() calls
- `evaluates dynamic code` - eval() usage
- `decodes obfuscated content` - unescape(), fromCharCode()
- `makes network request` - XMLHttp, SOAP calls
- `accesses form fields` - this.getField() calls
- `sets timer/delayed execution` - setInterval/setTimeout
- `potential heap spray` - Collab.getIcon exploit pattern

### `detect_embedded_file(file_path) -> list[EmbeddedFile]`

Detect files embedded or attached to a PDF.

```python
from woodchipper import detect_embedded_file

files = detect_embedded_file("document.pdf")
for f in files:
    print(f"Name: {f['name']}")
    print(f"Type: {f['file_type']}")
    print(f"MIME: {f['mime_type']}")
    print(f"Size: {f['size']} bytes")
```

**Detects embedded files in:**
- `/Names` tree `/EmbeddedFiles` entries
- `/FileSpec` dictionaries with `/EF` streams
- `/FileAttachment` annotations

**Returns `EmbeddedFile` dict with:**
- `name` - Filename from the PDF
- `file_type` - File type description (from magic bytes)
- `mime_type` - MIME type (from magic bytes)
- `size` - File size in bytes
- `description` - Description from PDF metadata

### `detect_acroform(file_path) -> list[str]`

Detect and analyze AcroForm structures in a PDF.

```python
from woodchipper import detect_acroform

details = detect_acroform("document.pdf")
for detail in details:
    print(detail)
```

**Detects:**
- Presence of AcroForm in document catalog
- XFA forms (XML Forms Architecture)
- NeedAppearances flag (dynamic appearance generation)
- Signature flags (SignaturesExist, AppendOnly)
- Calculation Order (/CO) - automatic calculation scripts
- Form field details:
  - Field types (Text, Button, Choice, Signature)
  - Field flags (ReadOnly, Required, Password, Multiline, etc.)
  - Actions attached to fields
  - JavaScript in field actions

### `detect_xmlforms(file_path) -> list[str]`

Detect and analyze XFA (XML Forms Architecture) in a PDF.

```python
from woodchipper import detect_xmlforms

details = detect_xmlforms("document.pdf")
for detail in details:
    print(detail)
```

**Detects:**
- XFA presence and structure (array or single stream)
- XFA components (template, config, datasets, localeSet, etc.)
- Embedded scripts (JavaScript and FormCalc)
- Event handlers (onClick, onEnter, onChange, etc.)
- Submit actions and URL targets
- Dangerous operations:
  - `xfa.host.messageBox` - message display
  - `xfa.host.exportData` / `importData` - data operations
  - `xfa.host.gotoURL` - URL navigation
  - `app.launchURL`, `app.execMenuItem` - application actions
  - `ADBC.*` - database connectivity
  - `Net.HTTP`, `SOAP.*` - network operations

### `detect_richmedia(file_path) -> list[str]`

Detect rich media content (3D, Flash, multimedia) in a PDF.

```python
from woodchipper import detect_richmedia

findings = detect_richmedia("document.pdf")
for finding in findings:
    print(finding)
```

**Detects:**
- `/RichMedia` annotations and related tags
- `/3D`, `/3DD`, `/3DA`, `/3DV`, `/3DI` - 3D content
- `/U3D` (Universal 3D), `/PRC` (Product Representation Compact)
- `/Flash`, `/Movie`, `/Sound`, `/Screen` - multimedia
- `/Rendition`, `/GoTo3DView` - multimedia actions

**Note:** Rich media like 3D and Flash are no longer supported by modern OS and PDF readers, making their presence suspicious.

### `detect_stream_mismatches(file_path) -> list[str]`

Detect mismatches between declared and actual PDF stream lengths.

```python
from woodchipper import detect_stream_mismatches

mismatches = detect_stream_mismatches("document.pdf")
for mismatch in mismatches:
    print(mismatch)
```

**Detects:**
- Missing `endstream` markers (malformed structure)
- Declared length exceeds actual (truncated/tampered data)
- Actual length exceeds declared (injected data/buffer overflow attempt)
- Indirect length reference mismatches

**Note:** Mismatched stream lengths may indicate PDF tampering, corruption, or malicious manipulation to hide content or exploit PDF parsers.

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
          "items": { "type": "string" },
          "description": "Structural anomalies, rich media findings, and stream length mismatches"
        },
        "additional_actions_detected": {
          "type": "array",
          "items": { "type": "string" }
        },
        "external_actions": {
          "type": "array",
          "items": { "type": "string" }
        },
        "javascript_detected": {
          "type": "array",
          "items": { "type": "string" }
        },
        "embedded_files": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "name": { "type": ["string", "null"] },
              "file_type": { "type": ["string", "null"] },
              "mime_type": { "type": ["string", "null"] },
              "size": { "type": ["integer", "null"] },
              "description": { "type": ["string", "null"] }
            }
          }
        },
        "acroform_details": {
          "type": "array",
          "items": { "type": "string" },
          "description": "AcroForm field details, types, flags, and actions"
        },
        "xfa_details": {
          "type": "array",
          "items": { "type": "string" },
          "description": "XFA (XML Forms Architecture) components and scripts"
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

Install in editable mode with all dependencies:

```bash
pip install -e ".[all]"
```

Or just dev dependencies:

```bash
pip install -e ".[dev]"
```

Run tests:

```bash
pytest
```

## License

MIT
