"""Woodchipper - A Python library for processing PDF files."""

__version__ = "0.1.0"

from .core import (
    process,
    validate_pdf,
    get_urls,
    get_pdf_metadata,
    check_anomalies,
    detect_additionalactions,
    extract_forms,
    ValidationError,
    PdfReport,
    PdfMetadata,
    PdfAnomalies,
    PdfForms,
)

__all__ = [
    "process",
    "validate_pdf",
    "get_urls",
    "get_pdf_metadata",
    "check_anomalies",
    "detect_additionalactions",
    "extract_forms",
    "ValidationError",
    "PdfReport",
    "PdfMetadata",
    "PdfAnomalies",
    "PdfForms",
    "__version__",
]
