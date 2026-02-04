# Woodchipper

All PDF files must be fed to the woodchipper.

A Python library and CLI tool for analyzing PDF files. Extracts metadata, computes file hashes, and finds embedded URLs.

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

Output is JSON:

```bash
$ woodchipper document.pdf
{
  "filename": "document.pdf",
  "filesize": 142857,
  "md5": "d41d8cd98f00b204e9800998ecf8427e",
  "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
  "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "urls": [
    "https://example.com",
    "https://test.org/page"
  ]
}
```

Exit codes:
- `0` - Success
- `1` - Validation error (file not found, not readable, or not a PDF)

## Library API

### `process(file_path) -> PdfReport`

Process a PDF file and return a full report.

```python
from woodchipper import process

report = process("document.pdf")
print(report["sha256"])
print(report["urls"])
```

**Returns:** `PdfReport` dict with keys:
- `filename` (str): Base filename
- `filesize` (int): Size in bytes
- `md5` (str): MD5 hash
- `sha1` (str): SHA1 hash
- `sha256` (str): SHA256 hash
- `urls` (list[str]): URLs extracted from PDF link annotations

**Raises:** `ValidationError` if file is invalid.

### `get_urls(file_path) -> list[str]`

Extract URLs from a PDF file.

```python
from woodchipper import get_urls

urls = get_urls("document.pdf")
for url in urls:
    print(url)
```

Extracts URLs from `/Link` annotations and `/A` (Action) dictionaries with `/URI` entries.

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

Exception raised when file validation fails. Possible reasons:
- File not found
- Path is not a file
- File is not readable
- File is not a PDF (based on magic bytes)

### `PdfReport`

TypedDict for type hints:

```python
from woodchipper import PdfReport

def analyze(path: str) -> PdfReport:
    return process(path)
```

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
    }
  },
  "required": ["filename", "filesize", "md5", "sha1", "sha256", "urls"]
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
