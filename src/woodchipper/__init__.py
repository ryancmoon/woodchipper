"""Woodchipper - A Python library for processing PDF files."""

from importlib.metadata import version

__version__ = version("woodchipper")

from .core import (
    process,
    validate_pdf,
    get_urls,
    get_pdf_metadata,
    check_anomalies,
    detect_additionalactions,
    detect_external_actions,
    detect_javascript,
    detect_embedded_file,
    detect_acroform,
    detect_xmlforms,
    detect_richmedia,
    detect_stream_mismatches,
    extract_forms,
    ValidationError,
    PdfReport,
    PdfMetadata,
    PdfAnomalies,
    PdfForms,
    EmbeddedFile,
    ActionDetail,
)

__all__ = [
    "process",
    "validate_pdf",
    "get_urls",
    "get_pdf_metadata",
    "check_anomalies",
    "detect_additionalactions",
    "detect_external_actions",
    "detect_javascript",
    "detect_embedded_file",
    "detect_acroform",
    "detect_xmlforms",
    "detect_richmedia",
    "detect_stream_mismatches",
    "extract_forms",
    "ValidationError",
    "PdfReport",
    "PdfMetadata",
    "PdfAnomalies",
    "PdfForms",
    "EmbeddedFile",
    "ActionDetail",
    "__version__",
]
