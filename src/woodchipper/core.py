"""Core library functionality."""

import hashlib
import os
from pathlib import Path
from typing import TypedDict

import magic
from pypdf import PdfReader
from pypdf.generic import ArrayObject, DictionaryObject


class PdfReport(TypedDict):
    """Report structure for processed PDF files."""

    filename: str
    filesize: int
    md5: str
    sha1: str
    sha256: str
    urls: list[str]


class ValidationError(Exception):
    """Raised when file validation fails."""


def validate_pdf(file_path: str | Path) -> Path:
    """Validate that a file path points to a readable PDF file.

    Args:
        file_path: Path to the file to validate.

    Returns:
        The validated Path object.

    Raises:
        ValidationError: If the file doesn't exist, isn't readable, or isn't a PDF.
    """
    path = Path(file_path)

    if not path.exists():
        raise ValidationError(f"File not found: {path}")

    if not path.is_file():
        raise ValidationError(f"Not a file: {path}")

    if not os.access(path, os.R_OK):
        raise ValidationError(f"File not readable: {path}")

    mime_type = magic.from_file(str(path), mime=True)
    if mime_type != "application/pdf":
        raise ValidationError(
            f"Invalid file type: expected PDF, got {mime_type}. "
            "Woodchipper only accepts PDF files."
        )

    return path


def get_urls(file_path: str | Path) -> list[str]:
    """Extract all URLs from a PDF file.

    Extracts URLs from /Link annotations and /A (Action) dictionaries,
    including /URI actions.

    Args:
        file_path: Path to the PDF file.

    Returns:
        List of unique URLs found in the PDF.

    Raises:
        ValidationError: If the file isn't a valid, readable PDF.
    """
    path = validate_pdf(file_path)
    urls: set[str] = set()

    reader = PdfReader(str(path))

    for page in reader.pages:
        annotations = page.get("/Annots")
        if annotations is None:
            continue

        if isinstance(annotations, ArrayObject):
            annot_list = annotations
        else:
            annot_list = [annotations]

        for annot_ref in annot_list:
            annot = annot_ref.get_object() if hasattr(annot_ref, "get_object") else annot_ref

            if not isinstance(annot, DictionaryObject):
                continue

            # Check if this is a Link annotation
            subtype = annot.get("/Subtype")
            if subtype != "/Link":
                continue

            # Extract URL from /A (Action) dictionary
            action = annot.get("/A")
            if action:
                action_obj = action.get_object() if hasattr(action, "get_object") else action
                if isinstance(action_obj, DictionaryObject):
                    uri = action_obj.get("/URI")
                    if uri:
                        url = str(uri)
                        urls.add(url)

    return sorted(urls)


def compute_hashes(file_path: Path) -> tuple[str, str, str]:
    """Compute MD5, SHA1, and SHA256 hashes of a file.

    Args:
        file_path: Path to the file.

    Returns:
        Tuple of (md5, sha1, sha256) hex digests.
    """
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return md5.hexdigest(), sha1.hexdigest(), sha256.hexdigest()


def process(file_path: str | Path) -> PdfReport:
    """Process a PDF file and generate a report.

    Args:
        file_path: Path to the PDF file to process.

    Returns:
        PdfReport containing file metadata, hashes, and extracted URLs.

    Raises:
        ValidationError: If the file isn't a valid, readable PDF.
    """
    path = validate_pdf(file_path)

    md5, sha1, sha256 = compute_hashes(path)
    urls = get_urls(path)

    return PdfReport(
        filename=path.name,
        filesize=path.stat().st_size,
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        urls=urls,
    )
