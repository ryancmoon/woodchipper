"""Core library functionality."""

import hashlib
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import TypedDict

import defang
import magic
from pypdf import PdfReader
from pypdf.generic import ArrayObject, DictionaryObject


class PdfMetadata(TypedDict):
    """Metadata extracted from a PDF file."""

    author: str | None
    creator: str | None
    producer: str | None
    subject: str | None
    title: str | None
    creation_date: str | None
    modification_date: str | None
    spoofing_indicators: list[str]


class EmbeddedFile(TypedDict):
    """Information about an embedded file in a PDF."""

    name: str | None
    file_type: str | None
    mime_type: str | None
    size: int | None
    description: str | None


class PdfAnomalies(TypedDict):
    """Anomaly detection results for a PDF file."""

    anomalies_present: bool
    anomalies: list[str]
    additional_actions_detected: list[str]
    external_actions: list[str]
    javascript_detected: list[str]
    embedded_files: list[EmbeddedFile]
    acroform_details: list[str]
    xfa_details: list[str]


class PdfForms(TypedDict):
    """Form detection results for a PDF file."""

    forms_present: bool
    form_submission_targets: list[str]


class PdfReport(TypedDict):
    """Report structure for processed PDF files."""

    filename: str
    filesize: int
    md5: str
    sha1: str
    sha256: str
    urls: list[str]
    metadata: PdfMetadata
    anomalies: PdfAnomalies
    forms: PdfForms


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


def _parse_pdf_date(date_str: str | None) -> datetime | None:
    """Parse a PDF date string to datetime.

    PDF dates are in format: D:YYYYMMDDHHmmSSOHH'mm'
    where O is the timezone offset direction (+/-/Z).
    """
    if not date_str:
        return None

    # Remove the D: prefix if present
    if date_str.startswith("D:"):
        date_str = date_str[2:]

    # Try to parse various PDF date formats
    patterns = [
        (r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})([+-])(\d{2})'(\d{2})'?$", True),
        (r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z", False),
        (r"^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})$", False),
        (r"^(\d{4})(\d{2})(\d{2})$", False),
    ]

    for pattern, has_tz in patterns:
        match = re.match(pattern, date_str)
        if match:
            groups = match.groups()
            try:
                year = int(groups[0])
                month = int(groups[1])
                day = int(groups[2])
                hour = int(groups[3]) if len(groups) > 3 else 0
                minute = int(groups[4]) if len(groups) > 4 else 0
                second = int(groups[5]) if len(groups) > 5 else 0

                return datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
            except (ValueError, IndexError):
                continue

    return None


def get_pdf_metadata(file_path: str | Path) -> PdfMetadata:
    """Extract metadata from a PDF file with spoofing indicators.

    Args:
        file_path: Path to the PDF file.

    Returns:
        PdfMetadata containing author, creator, producer, timestamps,
        and a list of potential spoofing indicators.

    Raises:
        ValidationError: If the file isn't a valid, readable PDF.
    """
    path = validate_pdf(file_path)
    reader = PdfReader(str(path))
    meta = reader.metadata

    spoofing_indicators: list[str] = []

    # Extract metadata fields
    author = str(meta.author) if meta and meta.author else None
    creator = str(meta.creator) if meta and meta.creator else None
    producer = str(meta.producer) if meta and meta.producer else None
    subject = str(meta.subject) if meta and meta.subject else None
    title = str(meta.title) if meta and meta.title else None

    # Extract dates - pypdf returns datetime objects directly
    creation_dt: datetime | None = None
    modification_dt: datetime | None = None

    if meta:
        if meta.creation_date:
            if isinstance(meta.creation_date, datetime):
                creation_dt = meta.creation_date
                # Ensure timezone-aware for comparison
                if creation_dt.tzinfo is None:
                    creation_dt = creation_dt.replace(tzinfo=timezone.utc)
            else:
                creation_dt = _parse_pdf_date(str(meta.creation_date))
        elif hasattr(meta, "get") and meta.get("/CreationDate"):
            creation_dt = _parse_pdf_date(str(meta.get("/CreationDate")))

        if meta.modification_date:
            if isinstance(meta.modification_date, datetime):
                modification_dt = meta.modification_date
                # Ensure timezone-aware for comparison
                if modification_dt.tzinfo is None:
                    modification_dt = modification_dt.replace(tzinfo=timezone.utc)
            else:
                modification_dt = _parse_pdf_date(str(meta.modification_date))
        elif hasattr(meta, "get") and meta.get("/ModDate"):
            modification_dt = _parse_pdf_date(str(meta.get("/ModDate")))

    # Format dates as strings for output
    creation_date = str(creation_dt) if creation_dt else None
    modification_date = str(modification_dt) if modification_dt else None

    now = datetime.now(timezone.utc)

    # Spoofing detection checks

    # Check for creation date after modification date
    if creation_dt and modification_dt and creation_dt > modification_dt:
        spoofing_indicators.append(
            "Creation date is after modification date"
        )

    # Check for future timestamps
    if creation_dt and creation_dt > now:
        spoofing_indicators.append(
            f"Creation date is in the future: {creation_date}"
        )

    if modification_dt and modification_dt > now:
        spoofing_indicators.append(
            f"Modification date is in the future: {modification_date}"
        )

    # Check for creator/producer mismatches that suggest spoofing
    if creator and producer:
        creator_lower = creator.lower()
        producer_lower = producer.lower()

        # Microsoft Office should produce with Microsoft
        if "microsoft" in creator_lower and "microsoft" not in producer_lower:
            if "libreoffice" in producer_lower or "openoffice" in producer_lower:
                spoofing_indicators.append(
                    f"Creator claims Microsoft but producer is {producer}"
                )

        # Adobe products should generally match
        if "adobe" in creator_lower and "adobe" not in producer_lower:
            if "libreoffice" in producer_lower or "openoffice" in producer_lower:
                spoofing_indicators.append(
                    f"Creator claims Adobe but producer is {producer}"
                )

        # Check for known PDF generator mismatches
        if "word" in creator_lower and "writer" in producer_lower:
            spoofing_indicators.append(
                f"Creator claims Word but producer suggests LibreOffice Writer"
            )

    # Check for suspiciously empty metadata when producer exists
    if producer and not author and not creator and not title:
        spoofing_indicators.append(
            "Producer set but author, creator, and title are all empty"
        )

    # Check for very old creation dates (before PDF existed - 1993)
    if creation_dt and creation_dt.year < 1993:
        spoofing_indicators.append(
            f"Creation date predates PDF format: {creation_date}"
        )

    return PdfMetadata(
        author=author,
        creator=creator,
        producer=producer,
        subject=subject,
        title=title,
        creation_date=creation_date,
        modification_date=modification_date,
        spoofing_indicators=spoofing_indicators,
    )


# Valid PDF versions per ISO 32000
_VALID_PDF_VERSIONS = {"1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7", "2.0"}


def check_anomalies(file_path: str | Path) -> PdfAnomalies:
    """Check for malformed PDF headers and version anomalies.

    Args:
        file_path: Path to the PDF file.

    Returns:
        PdfAnomalies with anomalies_present flag and description of issues found.

    Raises:
        ValidationError: If the file isn't a valid, readable PDF.
    """
    path = validate_pdf(file_path)
    anomalies: list[str] = []

    with open(path, "rb") as f:
        # Read first 1024 bytes for header analysis
        header_bytes = f.read(1024)

        # Check if PDF header starts at byte 0
        if not header_bytes.startswith(b"%PDF-"):
            # Search for header within first 1024 bytes
            header_pos = header_bytes.find(b"%PDF-")
            if header_pos == -1:
                anomalies.append("PDF header not found in first 1024 bytes")
            elif header_pos > 0:
                anomalies.append(
                    f"PDF header not at byte 0 (found at byte {header_pos}); "
                    "data before header may indicate embedded content or manipulation"
                )

        # Extract and validate version
        header_match = re.search(rb"%PDF-(\d+\.\d+)", header_bytes)
        if header_match:
            version = header_match.group(1).decode("ascii")
            if version not in _VALID_PDF_VERSIONS:
                anomalies.append(
                    f"Invalid PDF version '{version}'; "
                    f"valid versions are: {', '.join(sorted(_VALID_PDF_VERSIONS))}"
                )
        else:
            anomalies.append("Could not parse PDF version from header")

        # Check for binary marker (second line should have high-byte chars)
        # Per PDF spec, line after header should contain at least 4 chars > 127
        lines = header_bytes.split(b"\n", 2)
        if len(lines) >= 2:
            second_line = lines[1]
            # Check if it's a comment with binary characters
            if second_line.startswith(b"%"):
                high_bytes = sum(1 for b in second_line if b > 127)
                if high_bytes < 4:
                    anomalies.append(
                        "Binary marker line missing or malformed; "
                        "PDF may not be recognized as binary by some tools"
                    )

        # Check for %%EOF marker
        f.seek(0, 2)  # Seek to end
        file_size = f.tell()
        # Read last 1024 bytes to find EOF
        read_size = min(1024, file_size)
        f.seek(-read_size, 2)
        tail_bytes = f.read(read_size)

        if b"%%EOF" not in tail_bytes:
            anomalies.append("%%EOF marker not found at end of file")
        else:
            # Check if there's significant data after %%EOF
            eof_pos = tail_bytes.rfind(b"%%EOF")
            after_eof = tail_bytes[eof_pos + 5:].strip()
            if len(after_eof) > 10:
                anomalies.append(
                    f"Data found after %%EOF marker ({len(after_eof)} bytes); "
                    "may indicate appended content"
                )

    # Detect rich media (3D, Flash, etc.) - adds to anomalies list
    richmedia = detect_richmedia(path)
    anomalies.extend(richmedia)

    # Detect stream length mismatches - adds to anomalies list
    stream_mismatches = detect_stream_mismatches(path)
    anomalies.extend(stream_mismatches)

    # Detect additional actions
    additional_actions = detect_additionalactions(path)

    # Detect external actions
    external_actions = detect_external_actions(path)

    # Detect JavaScript
    javascript = detect_javascript(path)

    # Detect embedded files
    embedded = detect_embedded_file(path)

    # Detect AcroForm details
    acroform = detect_acroform(path)

    # Detect XFA (XML Forms Architecture) details
    xfa = detect_xmlforms(path)

    has_anomalies = (
        bool(anomalies)
        or bool(additional_actions)
        or bool(external_actions)
        or bool(javascript)
        or bool(embedded)
        or bool(acroform)
        or bool(xfa)
    )

    return PdfAnomalies(
        anomalies_present=has_anomalies,
        anomalies=anomalies,
        additional_actions_detected=additional_actions,
        external_actions=external_actions,
        javascript_detected=javascript,
        embedded_files=embedded,
        acroform_details=acroform,
        xfa_details=xfa,
    )


def detect_additionalactions(file_path: str | Path) -> list[str]:
    """Detect /AA (Additional Actions) and /OpenAction tags in a PDF.

    Identifies automatic actions triggered on document open, close, or page view.

    Args:
        file_path: Path to the PDF file.

    Returns:
        List of detected actions and their triggers.

    Raises:
        ValidationError: If the file isn't a valid, readable PDF.
    """
    path = validate_pdf(file_path)
    actions_found: list[str] = []

    try:
        reader = PdfReader(str(path))
    except Exception:
        # PDF is too malformed to parse for actions
        return []

    # Check document catalog for /OpenAction
    if reader.trailer and "/Root" in reader.trailer:
        root = reader.trailer["/Root"]
        if hasattr(root, "get_object"):
            root = root.get_object()

        if isinstance(root, DictionaryObject):
            # Check /OpenAction (action on document open)
            if "/OpenAction" in root:
                open_action = root["/OpenAction"]
                if hasattr(open_action, "get_object"):
                    open_action = open_action.get_object()
                action_desc = _describe_action(open_action, "Document Open")
                if action_desc:
                    actions_found.append(action_desc)

            # Check /AA (Additional Actions) at document level
            if "/AA" in root:
                aa = root["/AA"]
                if hasattr(aa, "get_object"):
                    aa = aa.get_object()
                if isinstance(aa, DictionaryObject):
                    _extract_additional_actions(aa, "Document", actions_found)

    # Check each page for /AA (Additional Actions)
    for i, page in enumerate(reader.pages, start=1):
        page_dict = page.get_object() if hasattr(page, "get_object") else page
        if isinstance(page_dict, DictionaryObject) and "/AA" in page_dict:
            aa = page_dict["/AA"]
            if hasattr(aa, "get_object"):
                aa = aa.get_object()
            if isinstance(aa, DictionaryObject):
                _extract_additional_actions(aa, f"Page {i}", actions_found)

    return actions_found


def detect_external_actions(file_path: str | Path) -> list[str]:
    """Detect external action tags (/Launch, /URI, /GoToR, /GoToE) in a PDF.

    These actions can cause the PDF reader to access external resources,
    launch applications, or navigate to remote documents.

    Args:
        file_path: Path to the PDF file.

    Returns:
        List of detected external actions with descriptions of what they do.

    Raises:
        ValidationError: If the file isn't a valid, readable PDF.
    """
    path = validate_pdf(file_path)
    external_actions: list[str] = []

    try:
        reader = PdfReader(str(path))
    except Exception:
        # PDF is too malformed to parse
        return []

    def _scan_for_external_actions(obj: DictionaryObject, location: str) -> None:
        """Recursively scan a dictionary for external action types."""
        action_type = obj.get("/S")
        if action_type:
            action_type_str = str(action_type)

            if action_type_str == "/Launch":
                details = []
                if "/F" in obj:
                    details.append(f"file: {obj['/F']}")
                if "/Win" in obj:
                    win = obj["/Win"]
                    if hasattr(win, "get_object"):
                        win = win.get_object()
                    if isinstance(win, DictionaryObject):
                        if "/F" in win:
                            details.append(f"file: {win['/F']}")
                        if "/P" in win:
                            details.append(f"params: {win['/P']}")
                detail_str = f" ({', '.join(details)})" if details else ""
                external_actions.append(
                    f"/Launch at {location}: Launches external application{detail_str}"
                )

            elif action_type_str == "/URI":
                uri = obj.get("/URI", "unknown")
                external_actions.append(
                    f"/URI at {location}: Opens URL ({uri})"
                )

            elif action_type_str == "/GoToR":
                details = []
                if "/F" in obj:
                    f_val = obj["/F"]
                    if hasattr(f_val, "get_object"):
                        f_val = f_val.get_object()
                    if isinstance(f_val, DictionaryObject):
                        if "/F" in f_val:
                            details.append(f"file: {f_val['/F']}")
                        elif "/UF" in f_val:
                            details.append(f"file: {f_val['/UF']}")
                    else:
                        details.append(f"file: {f_val}")
                detail_str = f" ({', '.join(details)})" if details else ""
                external_actions.append(
                    f"/GoToR at {location}: Opens remote PDF document{detail_str}"
                )

            elif action_type_str == "/GoToE":
                details = []
                if "/F" in obj:
                    f_val = obj["/F"]
                    if hasattr(f_val, "get_object"):
                        f_val = f_val.get_object()
                    if isinstance(f_val, DictionaryObject):
                        if "/F" in f_val:
                            details.append(f"file: {f_val['/F']}")
                        elif "/UF" in f_val:
                            details.append(f"file: {f_val['/UF']}")
                    else:
                        details.append(f"file: {f_val}")
                if "/T" in obj:
                    details.append(f"target: {obj['/T']}")
                detail_str = f" ({', '.join(details)})" if details else ""
                external_actions.append(
                    f"/GoToE at {location}: Opens embedded document{detail_str}"
                )

        # Check /Next for chained actions
        if "/Next" in obj:
            next_action = obj["/Next"]
            if hasattr(next_action, "get_object"):
                next_action = next_action.get_object()
            if isinstance(next_action, DictionaryObject):
                _scan_for_external_actions(next_action, f"{location} (chained)")
            elif isinstance(next_action, ArrayObject):
                for i, item in enumerate(next_action):
                    item_obj = item.get_object() if hasattr(item, "get_object") else item
                    if isinstance(item_obj, DictionaryObject):
                        _scan_for_external_actions(item_obj, f"{location} (chained {i+1})")

    def _check_action_dict(action, location: str) -> None:
        """Check an action object for external actions."""
        if hasattr(action, "get_object"):
            action = action.get_object()
        if isinstance(action, DictionaryObject):
            _scan_for_external_actions(action, location)

    # Check document catalog for /OpenAction
    if reader.trailer and "/Root" in reader.trailer:
        root = reader.trailer["/Root"]
        if hasattr(root, "get_object"):
            root = root.get_object()

        if isinstance(root, DictionaryObject):
            if "/OpenAction" in root:
                _check_action_dict(root["/OpenAction"], "Document OpenAction")

            # Check document-level /AA
            if "/AA" in root:
                aa = root["/AA"]
                if hasattr(aa, "get_object"):
                    aa = aa.get_object()
                if isinstance(aa, DictionaryObject):
                    for key, trigger in [
                        ("/WC", "Will Close"),
                        ("/WS", "Will Save"),
                        ("/DS", "Did Save"),
                        ("/WP", "Will Print"),
                        ("/DP", "Did Print"),
                    ]:
                        if key in aa:
                            _check_action_dict(aa[key], f"Document AA {trigger}")

    # Check each page
    for page_num, page in enumerate(reader.pages, start=1):
        page_dict = page.get_object() if hasattr(page, "get_object") else page
        if not isinstance(page_dict, DictionaryObject):
            continue

        # Check page-level /AA
        if "/AA" in page_dict:
            aa = page_dict["/AA"]
            if hasattr(aa, "get_object"):
                aa = aa.get_object()
            if isinstance(aa, DictionaryObject):
                for key, trigger in [("/O", "Open"), ("/C", "Close")]:
                    if key in aa:
                        _check_action_dict(aa[key], f"Page {page_num} AA {trigger}")

        # Check annotations
        annotations = page_dict.get("/Annots")
        if annotations is None:
            continue

        if hasattr(annotations, "get_object"):
            annotations = annotations.get_object()

        if isinstance(annotations, ArrayObject):
            annot_list = annotations
        else:
            annot_list = [annotations]

        for annot_idx, annot_ref in enumerate(annot_list, start=1):
            annot = annot_ref.get_object() if hasattr(annot_ref, "get_object") else annot_ref
            if not isinstance(annot, DictionaryObject):
                continue

            location = f"Page {page_num} Annotation {annot_idx}"

            # Check /A (action)
            if "/A" in annot:
                _check_action_dict(annot["/A"], location)

            # Check /AA (additional actions)
            if "/AA" in annot:
                aa = annot["/AA"]
                if hasattr(aa, "get_object"):
                    aa = aa.get_object()
                if isinstance(aa, DictionaryObject):
                    for key, trigger in [
                        ("/E", "Enter"),
                        ("/X", "Exit"),
                        ("/D", "MouseDown"),
                        ("/U", "MouseUp"),
                        ("/Fo", "Focus"),
                        ("/Bl", "Blur"),
                    ]:
                        if key in aa:
                            _check_action_dict(aa[key], f"{location} AA {trigger}")

    return external_actions


def detect_javascript(file_path: str | Path) -> list[str]:
    """Detect JavaScript code embedded in a PDF.

    Scans for /JavaScript and /JS tags and extracts information about
    the scripts found, including a summary of what they do.

    Args:
        file_path: Path to the PDF file.

    Returns:
        List of detected JavaScript with descriptions of what they do.

    Raises:
        ValidationError: If the file isn't a valid, readable PDF.
    """
    path = validate_pdf(file_path)
    javascript_found: list[str] = []

    try:
        reader = PdfReader(str(path))
    except Exception:
        # PDF is too malformed to parse
        return []

    def _summarize_js(js_code: str) -> str:
        """Generate a brief summary of what the JavaScript does."""
        js_lower = js_code.lower()
        behaviors = []

        # Detect common malicious/suspicious patterns
        if "app.launchurl" in js_lower or "launchurl" in js_lower:
            behaviors.append("launches URL")
        if "app.alert" in js_lower or "alert(" in js_lower:
            behaviors.append("displays alert")
        if "this.submitform" in js_lower or "submitform" in js_lower:
            behaviors.append("submits form data")
        if "exportdataasobject" in js_lower or "exportdata" in js_lower:
            behaviors.append("exports data")
        if "app.openfile" in js_lower or "openfile" in js_lower:
            behaviors.append("opens file")
        if "util.printf" in js_lower and ("%" in js_code):
            behaviors.append("format string operation")
        if "eval(" in js_lower:
            behaviors.append("evaluates dynamic code")
        if "unescape(" in js_lower or "fromcharcode" in js_lower:
            behaviors.append("decodes obfuscated content")
        if "xmlhttp" in js_lower or "soap" in js_lower:
            behaviors.append("makes network request")
        if "this.getfield" in js_lower or "getfield" in js_lower:
            behaviors.append("accesses form fields")
        if "spell.customdictionaryopen" in js_lower:
            behaviors.append("accesses spell check dictionary")
        if "app.setinterval" in js_lower or "settimeout" in js_lower:
            behaviors.append("sets timer/delayed execution")
        if "collab.geticon" in js_lower:
            behaviors.append("potential heap spray (Collab.getIcon)")
        if "util.printd" in js_lower:
            behaviors.append("date formatting")
        if "media.newplayer" in js_lower:
            behaviors.append("creates media player")
        if "annot" in js_lower and ("destroy" in js_lower or "hidden" in js_lower):
            behaviors.append("manipulates annotations")

        if not behaviors:
            # Check for general patterns if no specific ones found
            if "http" in js_lower or "https" in js_lower:
                behaviors.append("contains URL reference")
            if "function" in js_lower:
                behaviors.append("defines function")
            if len(js_code) > 500:
                behaviors.append("large script block")

        if behaviors:
            return "; ".join(behaviors)
        return "unknown behavior"

    def _extract_js_code(action: DictionaryObject) -> str | None:
        """Extract JavaScript code from an action dictionary."""
        js = action.get("/JS")
        if js is None:
            return None

        if hasattr(js, "get_object"):
            js = js.get_object()

        # Handle stream objects
        if hasattr(js, "get_data"):
            try:
                return js.get_data().decode("utf-8", errors="replace")
            except Exception:
                return str(js)

        return str(js)

    def _process_js_action(action: DictionaryObject, location: str) -> None:
        """Process an action that may contain JavaScript."""
        action_type = action.get("/S")
        if action_type and str(action_type) in ("/JavaScript", "/JS"):
            js_code = _extract_js_code(action)
            if js_code:
                # Truncate for display
                code_preview = js_code[:150].replace("\n", " ").replace("\r", " ")
                if len(js_code) > 150:
                    code_preview += "..."

                summary = _summarize_js(js_code)
                javascript_found.append(
                    f"{location}: {summary} (code: {code_preview})"
                )

        # Check for chained /Next actions
        if "/Next" in action:
            next_action = action["/Next"]
            if hasattr(next_action, "get_object"):
                next_action = next_action.get_object()
            if isinstance(next_action, DictionaryObject):
                _process_js_action(next_action, f"{location} (chained)")
            elif isinstance(next_action, ArrayObject):
                for i, item in enumerate(next_action):
                    item_obj = item.get_object() if hasattr(item, "get_object") else item
                    if isinstance(item_obj, DictionaryObject):
                        _process_js_action(item_obj, f"{location} (chained {i+1})")

    def _check_action(action, location: str) -> None:
        """Check an action object for JavaScript."""
        if hasattr(action, "get_object"):
            action = action.get_object()
        if isinstance(action, DictionaryObject):
            _process_js_action(action, location)

    # Check for document-level JavaScript in Names tree
    if reader.trailer and "/Root" in reader.trailer:
        root = reader.trailer["/Root"]
        if hasattr(root, "get_object"):
            root = root.get_object()

        if isinstance(root, DictionaryObject):
            # Check /OpenAction
            if "/OpenAction" in root:
                _check_action(root["/OpenAction"], "Document OpenAction")

            # Check document-level /AA
            if "/AA" in root:
                aa = root["/AA"]
                if hasattr(aa, "get_object"):
                    aa = aa.get_object()
                if isinstance(aa, DictionaryObject):
                    for key, trigger in [
                        ("/WC", "Document Will Close"),
                        ("/WS", "Document Will Save"),
                        ("/DS", "Document Did Save"),
                        ("/WP", "Document Will Print"),
                        ("/DP", "Document Did Print"),
                    ]:
                        if key in aa:
                            _check_action(aa[key], trigger)

            # Check /Names dictionary for JavaScript
            if "/Names" in root:
                names = root["/Names"]
                if hasattr(names, "get_object"):
                    names = names.get_object()
                if isinstance(names, DictionaryObject) and "/JavaScript" in names:
                    js_names = names["/JavaScript"]
                    if hasattr(js_names, "get_object"):
                        js_names = js_names.get_object()
                    if isinstance(js_names, DictionaryObject) and "/Names" in js_names:
                        js_array = js_names["/Names"]
                        if hasattr(js_array, "get_object"):
                            js_array = js_array.get_object()
                        if isinstance(js_array, ArrayObject):
                            # Names array is [name1, obj1, name2, obj2, ...]
                            for i in range(0, len(js_array), 2):
                                if i + 1 < len(js_array):
                                    name = str(js_array[i])
                                    action = js_array[i + 1]
                                    if hasattr(action, "get_object"):
                                        action = action.get_object()
                                    if isinstance(action, DictionaryObject):
                                        _process_js_action(action, f"Named JavaScript '{name}'")

    # Check each page
    for page_num, page in enumerate(reader.pages, start=1):
        page_dict = page.get_object() if hasattr(page, "get_object") else page
        if not isinstance(page_dict, DictionaryObject):
            continue

        # Check page-level /AA
        if "/AA" in page_dict:
            aa = page_dict["/AA"]
            if hasattr(aa, "get_object"):
                aa = aa.get_object()
            if isinstance(aa, DictionaryObject):
                for key, trigger in [("/O", "Page Open"), ("/C", "Page Close")]:
                    if key in aa:
                        _check_action(aa[key], f"Page {page_num} {trigger}")

        # Check annotations
        annotations = page_dict.get("/Annots")
        if annotations is None:
            continue

        if hasattr(annotations, "get_object"):
            annotations = annotations.get_object()

        if isinstance(annotations, ArrayObject):
            annot_list = annotations
        else:
            annot_list = [annotations]

        for annot_idx, annot_ref in enumerate(annot_list, start=1):
            annot = annot_ref.get_object() if hasattr(annot_ref, "get_object") else annot_ref
            if not isinstance(annot, DictionaryObject):
                continue

            location = f"Page {page_num} Annotation {annot_idx}"

            # Check /A (action)
            if "/A" in annot:
                _check_action(annot["/A"], location)

            # Check /AA (additional actions)
            if "/AA" in annot:
                aa = annot["/AA"]
                if hasattr(aa, "get_object"):
                    aa = aa.get_object()
                if isinstance(aa, DictionaryObject):
                    for key, trigger in [
                        ("/E", "Mouse Enter"),
                        ("/X", "Mouse Exit"),
                        ("/D", "Mouse Down"),
                        ("/U", "Mouse Up"),
                        ("/Fo", "Focus"),
                        ("/Bl", "Blur"),
                        ("/K", "Keystroke"),
                        ("/F", "Format"),
                        ("/V", "Validate"),
                        ("/C", "Calculate"),
                    ]:
                        if key in aa:
                            _check_action(aa[key], f"{location} {trigger}")

    return javascript_found


def detect_embedded_file(file_path: str | Path) -> list[EmbeddedFile]:
    """Detect embedded files in a PDF.

    Scans for /EmbeddedFile, /FileSpec, and related tags to find
    files attached or embedded within the PDF.

    Args:
        file_path: Path to the PDF file.

    Returns:
        List of EmbeddedFile dicts with name, file_type, mime_type, size, description.

    Raises:
        ValidationError: If the file isn't a valid, readable PDF.
    """
    path = validate_pdf(file_path)
    embedded_files: list[EmbeddedFile] = []

    try:
        reader = PdfReader(str(path))
    except Exception:
        # PDF is too malformed to parse
        return []

    def _get_mime_from_data(data: bytes) -> str | None:
        """Determine MIME type from file data using magic bytes."""
        try:
            return magic.from_buffer(data, mime=True)
        except Exception:
            return None

    def _get_file_type_from_data(data: bytes) -> str | None:
        """Determine file type description from file data."""
        try:
            return magic.from_buffer(data)
        except Exception:
            return None

    def _process_filespec(filespec: DictionaryObject, location: str) -> None:
        """Process a FileSpec dictionary to extract embedded file info."""
        # Get the filename
        name = None
        for key in ["/UF", "/F", "/Unix", "/DOS", "/Mac"]:
            if key in filespec:
                name = str(filespec[key])
                break

        # Get description if available
        description = None
        if "/Desc" in filespec:
            description = str(filespec["/Desc"])

        # Check for embedded file stream in /EF dictionary
        if "/EF" in filespec:
            ef = filespec["/EF"]
            if hasattr(ef, "get_object"):
                ef = ef.get_object()

            if isinstance(ef, DictionaryObject):
                # Try different keys for the embedded file stream
                for key in ["/UF", "/F", "/Unix", "/DOS", "/Mac"]:
                    if key in ef:
                        stream = ef[key]
                        if hasattr(stream, "get_object"):
                            stream = stream.get_object()

                        # Extract file data and metadata
                        size = None
                        mime_type = None
                        file_type = None

                        # Get size from Params if available
                        if hasattr(stream, "get") and "/Params" in stream:
                            params = stream["/Params"]
                            if hasattr(params, "get_object"):
                                params = params.get_object()
                            if isinstance(params, DictionaryObject):
                                if "/Size" in params:
                                    try:
                                        size = int(params["/Size"])
                                    except (ValueError, TypeError):
                                        pass

                        # Try to get actual data for magic detection
                        if hasattr(stream, "get_data"):
                            try:
                                data = stream.get_data()
                                if size is None:
                                    size = len(data)
                                mime_type = _get_mime_from_data(data)
                                file_type = _get_file_type_from_data(data)
                            except Exception:
                                pass

                        embedded_files.append(EmbeddedFile(
                            name=name,
                            file_type=file_type,
                            mime_type=mime_type,
                            size=size,
                            description=description,
                        ))
                        break
        else:
            # FileSpec without embedded data (external reference)
            embedded_files.append(EmbeddedFile(
                name=name,
                file_type=None,
                mime_type=None,
                size=None,
                description=description or "External file reference",
            ))

    def _process_annotation_filespec(annot: DictionaryObject, location: str) -> None:
        """Process file attachment annotations."""
        if "/FS" in annot:
            fs = annot["/FS"]
            if hasattr(fs, "get_object"):
                fs = fs.get_object()
            if isinstance(fs, DictionaryObject):
                _process_filespec(fs, location)

    # Check Names tree for EmbeddedFiles
    if reader.trailer and "/Root" in reader.trailer:
        root = reader.trailer["/Root"]
        if hasattr(root, "get_object"):
            root = root.get_object()

        if isinstance(root, DictionaryObject):
            # Check /Names dictionary
            if "/Names" in root:
                names = root["/Names"]
                if hasattr(names, "get_object"):
                    names = names.get_object()

                if isinstance(names, DictionaryObject):
                    # Check for /EmbeddedFiles name tree
                    if "/EmbeddedFiles" in names:
                        ef_tree = names["/EmbeddedFiles"]
                        if hasattr(ef_tree, "get_object"):
                            ef_tree = ef_tree.get_object()

                        if isinstance(ef_tree, DictionaryObject):
                            # Process /Names array
                            if "/Names" in ef_tree:
                                names_array = ef_tree["/Names"]
                                if hasattr(names_array, "get_object"):
                                    names_array = names_array.get_object()
                                if isinstance(names_array, ArrayObject):
                                    # Names array: [name1, filespec1, name2, filespec2, ...]
                                    for i in range(0, len(names_array), 2):
                                        if i + 1 < len(names_array):
                                            filespec = names_array[i + 1]
                                            if hasattr(filespec, "get_object"):
                                                filespec = filespec.get_object()
                                            if isinstance(filespec, DictionaryObject):
                                                _process_filespec(filespec, "EmbeddedFiles Name Tree")

                            # Process /Kids array (for large name trees)
                            if "/Kids" in ef_tree:
                                kids = ef_tree["/Kids"]
                                if hasattr(kids, "get_object"):
                                    kids = kids.get_object()
                                if isinstance(kids, ArrayObject):
                                    for kid in kids:
                                        kid_obj = kid.get_object() if hasattr(kid, "get_object") else kid
                                        if isinstance(kid_obj, DictionaryObject) and "/Names" in kid_obj:
                                            names_array = kid_obj["/Names"]
                                            if hasattr(names_array, "get_object"):
                                                names_array = names_array.get_object()
                                            if isinstance(names_array, ArrayObject):
                                                for i in range(0, len(names_array), 2):
                                                    if i + 1 < len(names_array):
                                                        filespec = names_array[i + 1]
                                                        if hasattr(filespec, "get_object"):
                                                            filespec = filespec.get_object()
                                                        if isinstance(filespec, DictionaryObject):
                                                            _process_filespec(filespec, "EmbeddedFiles Name Tree")

    # Check page annotations for file attachments
    for page_num, page in enumerate(reader.pages, start=1):
        page_dict = page.get_object() if hasattr(page, "get_object") else page
        if not isinstance(page_dict, DictionaryObject):
            continue

        annotations = page_dict.get("/Annots")
        if annotations is None:
            continue

        if hasattr(annotations, "get_object"):
            annotations = annotations.get_object()

        if isinstance(annotations, ArrayObject):
            annot_list = annotations
        else:
            annot_list = [annotations]

        for annot_idx, annot_ref in enumerate(annot_list, start=1):
            annot = annot_ref.get_object() if hasattr(annot_ref, "get_object") else annot_ref
            if not isinstance(annot, DictionaryObject):
                continue

            subtype = annot.get("/Subtype")
            location = f"Page {page_num} Annotation {annot_idx}"

            # FileAttachment annotation
            if subtype == "/FileAttachment":
                _process_annotation_filespec(annot, location)

    return embedded_files


def detect_acroform(file_path: str | Path) -> list[str]:
    """Detect and analyze AcroForm structures in a PDF.

    Scans for /AcroForm tags and provides detailed analysis of form fields,
    their types, flags, and any potentially suspicious characteristics.

    Args:
        file_path: Path to the PDF file.

    Returns:
        List of descriptions of AcroForm features found.

    Raises:
        ValidationError: If the file isn't a valid, readable PDF.
    """
    path = validate_pdf(file_path)
    acroform_details: list[str] = []

    try:
        reader = PdfReader(str(path))
    except Exception:
        # PDF is too malformed to parse
        return []

    # Field type mapping
    field_types = {
        "/Tx": "Text",
        "/Btn": "Button",
        "/Ch": "Choice",
        "/Sig": "Signature",
    }

    # Field flag bits (Ff field)
    field_flag_bits = {
        0: "ReadOnly",
        1: "Required",
        2: "NoExport",
        # Text field specific (bit 12-14, 20-21, 23, 25)
        12: "Multiline",
        13: "Password",
        20: "FileSelect",
        21: "DoNotSpellCheck",
        22: "DoNotScroll",
        23: "Comb",
        24: "RichText",
        # Button specific (bit 14-16)
        14: "NoToggleToOff",
        15: "Radio",
        16: "Pushbutton",
        25: "RadiosInUnison",
        # Choice specific (bit 17-19, 21-22)
        17: "Combo",
        18: "Edit",
        19: "Sort",
        26: "CommitOnSelChange",
    }

    def _get_field_flags(ff_value: int) -> list[str]:
        """Extract human-readable flags from field flags bitmask."""
        flags = []
        for bit, name in field_flag_bits.items():
            if ff_value & (1 << bit):
                flags.append(name)
        return flags

    def _analyze_field(field: DictionaryObject, field_path: str) -> None:
        """Analyze a form field and its children recursively."""
        # Get field type
        field_type = field.get("/FT")
        field_type_str = field_types.get(str(field_type), str(field_type)) if field_type else "Unknown"

        # Get field name
        field_name = field.get("/T")
        name_str = str(field_name) if field_name else "unnamed"
        current_path = f"{field_path}.{name_str}" if field_path else name_str

        # Get field flags
        ff = field.get("/Ff")
        flags = []
        if ff:
            try:
                ff_int = int(ff)
                flags = _get_field_flags(ff_int)
            except (ValueError, TypeError):
                pass

        # Check for actions that could be suspicious
        has_action = "/A" in field
        has_aa = "/AA" in field

        # Build description
        details = []
        if field_type:
            details.append(f"type={field_type_str}")
        if flags:
            details.append(f"flags=[{', '.join(flags)}]")
        if has_action:
            action = field["/A"]
            if hasattr(action, "get_object"):
                action = action.get_object()
            if isinstance(action, DictionaryObject):
                action_type = action.get("/S")
                if action_type:
                    details.append(f"action={action_type}")
        if has_aa:
            details.append("has_additional_actions")

        # Check for JavaScript in field actions
        if has_action or has_aa:
            js_found = _check_field_for_js(field)
            if js_found:
                details.append("contains_javascript")

        if details:
            acroform_details.append(f"Field '{current_path}': {', '.join(details)}")

        # Process child fields (/Kids array)
        if "/Kids" in field:
            kids = field["/Kids"]
            if hasattr(kids, "get_object"):
                kids = kids.get_object()
            if isinstance(kids, ArrayObject):
                for kid in kids:
                    kid_obj = kid.get_object() if hasattr(kid, "get_object") else kid
                    if isinstance(kid_obj, DictionaryObject):
                        _analyze_field(kid_obj, current_path)

    def _check_field_for_js(field: DictionaryObject) -> bool:
        """Check if a field contains JavaScript actions."""
        # Check /A action
        if "/A" in field:
            action = field["/A"]
            if hasattr(action, "get_object"):
                action = action.get_object()
            if isinstance(action, DictionaryObject):
                action_type = action.get("/S")
                if action_type and str(action_type) in ("/JavaScript", "/JS"):
                    return True

        # Check /AA additional actions
        if "/AA" in field:
            aa = field["/AA"]
            if hasattr(aa, "get_object"):
                aa = aa.get_object()
            if isinstance(aa, DictionaryObject):
                for key in ["/K", "/F", "/V", "/C", "/E", "/X"]:  # Keystroke, Format, Validate, Calculate, Enter, Exit
                    if key in aa:
                        action = aa[key]
                        if hasattr(action, "get_object"):
                            action = action.get_object()
                        if isinstance(action, DictionaryObject):
                            action_type = action.get("/S")
                            if action_type and str(action_type) in ("/JavaScript", "/JS"):
                                return True
        return False

    # Check document catalog for /AcroForm
    if reader.trailer and "/Root" in reader.trailer:
        root = reader.trailer["/Root"]
        if hasattr(root, "get_object"):
            root = root.get_object()

        if isinstance(root, DictionaryObject) and "/AcroForm" in root:
            acro_form = root["/AcroForm"]
            if hasattr(acro_form, "get_object"):
                acro_form = acro_form.get_object()

            if isinstance(acro_form, DictionaryObject):
                acroform_details.append("AcroForm detected in document catalog")

                # Check for XFA (XML Forms Architecture) - can be used for malicious purposes
                if "/XFA" in acro_form:
                    acroform_details.append(
                        "XFA forms detected: XML Forms Architecture present "
                        "(can contain active content and scripts)"
                    )

                # Check NeedAppearances flag
                if "/NeedAppearances" in acro_form:
                    need_app = acro_form["/NeedAppearances"]
                    if str(need_app).lower() == "true":
                        acroform_details.append(
                            "NeedAppearances=true: Form appearance may be generated dynamically"
                        )

                # Check SigFlags (signature-related flags)
                if "/SigFlags" in acro_form:
                    sig_flags = acro_form["/SigFlags"]
                    try:
                        sig_int = int(sig_flags)
                        sig_details = []
                        if sig_int & 1:
                            sig_details.append("SignaturesExist")
                        if sig_int & 2:
                            sig_details.append("AppendOnly")
                        if sig_details:
                            acroform_details.append(f"Signature flags: {', '.join(sig_details)}")
                    except (ValueError, TypeError):
                        pass

                # Check for document-level scripts in /CO (calculation order)
                if "/CO" in acro_form:
                    acroform_details.append(
                        "Calculation Order (/CO) defined: Fields have automatic calculation scripts"
                    )

                # Process form fields
                if "/Fields" in acro_form:
                    fields = acro_form["/Fields"]
                    if hasattr(fields, "get_object"):
                        fields = fields.get_object()
                    if isinstance(fields, ArrayObject):
                        field_count = len(fields)
                        acroform_details.append(f"Form contains {field_count} top-level field(s)")

                        for field_ref in fields:
                            field = field_ref.get_object() if hasattr(field_ref, "get_object") else field_ref
                            if isinstance(field, DictionaryObject):
                                _analyze_field(field, "")

    return acroform_details


def detect_xmlforms(file_path: str | Path) -> list[str]:
    """Detect and analyze XFA (XML Forms Architecture) in a PDF.

    XFA forms can contain embedded scripts (JavaScript, FormCalc) and
    active content that may be used for malicious purposes.

    Args:
        file_path: Path to the PDF file.

    Returns:
        List of descriptions of XFA features and extracted scripts found.

    Raises:
        ValidationError: If the file isn't a valid, readable PDF.
    """
    path = validate_pdf(file_path)
    xfa_details: list[str] = []

    try:
        reader = PdfReader(str(path))
    except Exception:
        # PDF is too malformed to parse
        return []

    def _extract_stream_data(obj) -> str | None:
        """Extract text data from a stream object."""
        if hasattr(obj, "get_object"):
            obj = obj.get_object()
        if hasattr(obj, "get_data"):
            try:
                data = obj.get_data()
                return data.decode("utf-8", errors="replace")
            except Exception:
                return None
        return str(obj) if obj else None

    def _analyze_xfa_xml(xml_content: str, component_name: str) -> None:
        """Analyze XFA XML content for scripts and form structure."""
        # Check for script tags
        script_patterns = [
            (r"<script[^>]*>(.*?)</script>", "JavaScript"),
            (r"<script\s+contentType=['\"]application/x-formcalc['\"][^>]*>(.*?)</script>", "FormCalc"),
            (r"<script\s+contentType=['\"]application/x-javascript['\"][^>]*>(.*?)</script>", "JavaScript"),
        ]

        for pattern, script_type in script_patterns:
            matches = re.findall(pattern, xml_content, re.DOTALL | re.IGNORECASE)
            for match in matches:
                script_content = match.strip()
                if script_content:
                    # Truncate long scripts for display
                    preview = script_content[:200].replace("\n", " ").replace("\r", " ")
                    if len(script_content) > 200:
                        preview += "..."

                    # Analyze script behavior
                    behaviors = _analyze_script_behavior(script_content, script_type)
                    behavior_str = f" - behaviors: {behaviors}" if behaviors else ""

                    xfa_details.append(
                        f"XFA {script_type} script in {component_name}{behavior_str}: {preview}"
                    )

        # Check for event handlers
        event_patterns = [
            (r'<event\s+activity=["\']([^"\']+)["\'][^>]*>', "event handler"),
            (r'on(Click|Enter|Exit|Change|Full|Ready|Initialize|Calculate|Validate|IndexChange)\s*=', "inline event"),
        ]

        for pattern, event_type in event_patterns:
            matches = re.findall(pattern, xml_content, re.IGNORECASE)
            if matches:
                unique_events = set(matches) if isinstance(matches[0], str) else set(m[0] if isinstance(m, tuple) else m for m in matches)
                xfa_details.append(
                    f"XFA {event_type}s in {component_name}: {', '.join(sorted(unique_events))}"
                )

        # Check for submit actions
        submit_patterns = [
            r'<submit[^>]*target=["\']([^"\']+)["\']',
            r'<submit[^>]*url=["\']([^"\']+)["\']',
            r'xfa\.host\.exportData\([^)]*\)',
            r'xfa\.host\.gotoURL\([^)]*["\']([^"\']+)["\']',
        ]

        for pattern in submit_patterns:
            matches = re.findall(pattern, xml_content, re.IGNORECASE)
            for match in matches:
                if match:
                    xfa_details.append(f"XFA submit/URL action in {component_name}: {match}")

        # Check for potentially dangerous operations
        dangerous_patterns = [
            (r"xfa\.host\.messageBox", "displays message box"),
            (r"xfa\.host\.exportData", "exports form data"),
            (r"xfa\.host\.importData", "imports data"),
            (r"xfa\.host\.gotoURL", "navigates to URL"),
            (r"xfa\.host\.openList", "opens list"),
            (r"xfa\.host\.print", "triggers print"),
            (r"xfa\.host\.response", "prompts for user input"),
            (r"app\.launchURL", "launches URL"),
            (r"app\.execMenuItem", "executes menu item"),
            (r"util\.printd", "date formatting (potential exploit)"),
            (r"Collab\.", "collaboration features"),
            (r"ADBC\.", "database connectivity"),
            (r"Net\.HTTP", "network operations"),
            (r"SOAP\.", "SOAP web services"),
        ]

        for pattern, description in dangerous_patterns:
            if re.search(pattern, xml_content, re.IGNORECASE):
                xfa_details.append(f"XFA {description} detected in {component_name}")

    def _analyze_script_behavior(script: str, script_type: str) -> str:
        """Analyze script content for suspicious behaviors."""
        behaviors = []
        script_lower = script.lower()

        if script_type == "FormCalc":
            # FormCalc-specific patterns
            if "url(" in script_lower or "get(" in script_lower or "post(" in script_lower:
                behaviors.append("network request")
            if "put(" in script_lower:
                behaviors.append("file write")
            if "exists(" in script_lower:
                behaviors.append("file system access")
            if "encode(" in script_lower or "decode(" in script_lower:
                behaviors.append("encoding operations")
            if "eval(" in script_lower:
                behaviors.append("dynamic evaluation")
        else:
            # JavaScript patterns
            if "eval(" in script_lower:
                behaviors.append("eval")
            if "xmlhttp" in script_lower or "fetch(" in script_lower:
                behaviors.append("network request")
            if "unescape(" in script_lower or "fromcharcode" in script_lower:
                behaviors.append("decoding/obfuscation")
            if "document.write" in script_lower:
                behaviors.append("document modification")

        # Common patterns
        if "http://" in script_lower or "https://" in script_lower:
            behaviors.append("contains URL")
        if "base64" in script_lower:
            behaviors.append("base64 operations")
        if re.search(r"\\x[0-9a-f]{2}", script_lower):
            behaviors.append("hex-encoded strings")
        if len(script) > 1000:
            behaviors.append("large script block")

        return "; ".join(behaviors) if behaviors else ""

    # Check document catalog for /AcroForm with /XFA
    if reader.trailer and "/Root" in reader.trailer:
        root = reader.trailer["/Root"]
        if hasattr(root, "get_object"):
            root = root.get_object()

        if isinstance(root, DictionaryObject) and "/AcroForm" in root:
            acro_form = root["/AcroForm"]
            if hasattr(acro_form, "get_object"):
                acro_form = acro_form.get_object()

            if isinstance(acro_form, DictionaryObject) and "/XFA" in acro_form:
                xfa = acro_form["/XFA"]
                if hasattr(xfa, "get_object"):
                    xfa = xfa.get_object()

                xfa_details.append("XFA (XML Forms Architecture) detected")

                # XFA can be a stream or an array of name/stream pairs
                if isinstance(xfa, ArrayObject):
                    # Array format: [name1, stream1, name2, stream2, ...]
                    xfa_details.append(f"XFA structure: array with {len(xfa)} elements")

                    # Known XFA component names
                    xfa_components = {
                        "preamble": "XML preamble",
                        "config": "form configuration",
                        "template": "form template/layout",
                        "localeSet": "locale settings",
                        "datasets": "form data",
                        "stylesheet": "CSS styling",
                        "xmpmeta": "XMP metadata",
                        "xfdf": "forms data format",
                        "postamble": "XML postamble",
                    }

                    for i in range(0, len(xfa), 2):
                        if i + 1 < len(xfa):
                            component_name = str(xfa[i])
                            component_stream = xfa[i + 1]

                            # Describe the component
                            component_desc = xfa_components.get(
                                component_name, f"unknown component"
                            )
                            xfa_details.append(
                                f"XFA component '{component_name}': {component_desc}"
                            )

                            # Extract and analyze content
                            content = _extract_stream_data(component_stream)
                            if content:
                                _analyze_xfa_xml(content, component_name)

                else:
                    # Single stream containing entire XFA
                    xfa_details.append("XFA structure: single stream")
                    content = _extract_stream_data(xfa)
                    if content:
                        # Try to identify what's in the stream
                        if "<?xml" in content:
                            xfa_details.append("XFA contains XML content")
                        _analyze_xfa_xml(content, "main XFA stream")

    return xfa_details


def detect_richmedia(file_path: str | Path) -> list[str]:
    """Detect rich media content (/RichMedia, /3D, Flash) in a PDF.

    Rich media such as 3D content and Flash are no longer supported by
    modern operating systems and PDF readers, making their presence suspicious.

    Args:
        file_path: Path to the PDF file.

    Returns:
        List of anomaly descriptions for rich media found.

    Raises:
        ValidationError: If the file isn't a valid, readable PDF.
    """
    path = validate_pdf(file_path)
    richmedia_findings: list[str] = []

    try:
        reader = PdfReader(str(path))
    except Exception:
        # PDF is too malformed to parse
        return []

    # Tags to search for
    richmedia_tags = {
        "/RichMedia": "RichMedia annotation (embedded multimedia)",
        "/3D": "3D content",
        "/3DD": "3D data dictionary",
        "/3DA": "3D activation dictionary",
        "/3DV": "3D view dictionary",
        "/3DI": "3D interactive",
        "/Flash": "Flash content",
        "/Movie": "Movie/video content",
        "/Sound": "Sound content",
        "/Screen": "Screen annotation (multimedia)",
        "/RichMediaContent": "RichMedia content stream",
        "/RichMediaSettings": "RichMedia settings",
        "/RichMediaActivation": "RichMedia activation",
        "/RichMediaDeactivation": "RichMedia deactivation",
        "/RichMediaAnimation": "RichMedia animation",
        "/RichMediaPresentation": "RichMedia presentation",
        "/U3D": "Universal 3D format",
        "/PRC": "Product Representation Compact (3D)",
    }

    found_tags: set[str] = set()

    def _scan_dict_for_richmedia(obj: DictionaryObject, location: str) -> None:
        """Recursively scan a dictionary for rich media tags."""
        for tag, description in richmedia_tags.items():
            if tag in obj:
                found_tags.add(tag)

        # Check /Subtype for rich media annotation types
        subtype = obj.get("/Subtype")
        if subtype:
            subtype_str = str(subtype)
            if subtype_str in ("/RichMedia", "/3D", "/Movie", "/Sound", "/Screen"):
                found_tags.add(subtype_str)

        # Check /S (action type) for multimedia actions
        action_type = obj.get("/S")
        if action_type:
            action_str = str(action_type)
            if action_str in ("/Rendition", "/Movie", "/Sound", "/GoTo3DView"):
                found_tags.add(action_str)

    # Check document catalog
    if reader.trailer and "/Root" in reader.trailer:
        root = reader.trailer["/Root"]
        if hasattr(root, "get_object"):
            root = root.get_object()

        if isinstance(root, DictionaryObject):
            _scan_dict_for_richmedia(root, "Document Catalog")

            # Check /Names dictionary for embedded files that might be rich media
            if "/Names" in root:
                names = root["/Names"]
                if hasattr(names, "get_object"):
                    names = names.get_object()
                if isinstance(names, DictionaryObject):
                    _scan_dict_for_richmedia(names, "Names Dictionary")

    # Check each page for rich media annotations
    for page_num, page in enumerate(reader.pages, start=1):
        page_dict = page.get_object() if hasattr(page, "get_object") else page
        if not isinstance(page_dict, DictionaryObject):
            continue

        _scan_dict_for_richmedia(page_dict, f"Page {page_num}")

        # Check annotations
        annotations = page_dict.get("/Annots")
        if annotations is None:
            continue

        if hasattr(annotations, "get_object"):
            annotations = annotations.get_object()

        if isinstance(annotations, ArrayObject):
            annot_list = annotations
        else:
            annot_list = [annotations]

        for annot_idx, annot_ref in enumerate(annot_list, start=1):
            annot = annot_ref.get_object() if hasattr(annot_ref, "get_object") else annot_ref
            if not isinstance(annot, DictionaryObject):
                continue

            _scan_dict_for_richmedia(annot, f"Page {page_num} Annotation {annot_idx}")

            # Check action dictionaries within annotations
            if "/A" in annot:
                action = annot["/A"]
                if hasattr(action, "get_object"):
                    action = action.get_object()
                if isinstance(action, DictionaryObject):
                    _scan_dict_for_richmedia(action, f"Page {page_num} Annotation {annot_idx} Action")

    # Build anomaly message if any rich media was found
    if found_tags:
        tag_descriptions = []
        for tag in sorted(found_tags):
            desc = richmedia_tags.get(tag, tag)
            tag_descriptions.append(f"{tag} ({desc})")

        richmedia_findings.append(
            f"Rich media detected: {', '.join(tag_descriptions)}. "
            "Rich media includes 3D or Flash streams which are no longer supported "
            "by modern OS or in common usage. This is suspicious."
        )

    return richmedia_findings


def detect_stream_mismatches(file_path: str | Path) -> list[str]:
    """Detect mismatches between declared and actual PDF stream lengths.

    PDF streams have a /Length key that declares the expected size. If the
    actual stream data differs from this declared length, it may indicate
    the PDF has been tampered with, corrupted, or maliciously crafted.

    Args:
        file_path: Path to the PDF file.

    Returns:
        List of anomaly descriptions for stream length mismatches found.

    Raises:
        ValidationError: If the file isn't a valid, readable PDF.
    """
    path = validate_pdf(file_path)
    mismatches: list[str] = []

    # Read raw PDF content to analyze streams
    with open(path, "rb") as f:
        pdf_content = f.read()

    # Find all stream objects by looking for "stream" and "endstream" markers
    # PDF streams are structured as: << /Length N >> stream\n...data...\nendstream
    stream_pattern = rb"/Length\s+(\d+)(?:\s+\d+\s+R|\s*(?:/[A-Za-z]+\s*[^>]*)*)\s*>>[\r\n\s]*stream[\r\n]"

    mismatched_count = 0
    total_streams = 0

    for match in re.finditer(stream_pattern, pdf_content):
        total_streams += 1
        declared_length = int(match.group(1))
        stream_start = match.end()

        # Find the endstream marker
        endstream_pos = pdf_content.find(b"endstream", stream_start)
        if endstream_pos == -1:
            mismatches.append(
                f"Stream at offset {match.start()}: Missing 'endstream' marker. "
                "This indicates a malformed or corrupted PDF structure."
            )
            mismatched_count += 1
            continue

        # Calculate actual stream length (accounting for possible trailing whitespace)
        actual_data = pdf_content[stream_start:endstream_pos]

        # PDF spec allows for optional EOL before endstream
        # Strip trailing \r\n or \n if present
        if actual_data.endswith(b"\r\n"):
            actual_length = len(actual_data) - 2
        elif actual_data.endswith(b"\n") or actual_data.endswith(b"\r"):
            actual_length = len(actual_data) - 1
        else:
            actual_length = len(actual_data)

        # Check for mismatch
        if declared_length != actual_length:
            # Allow small tolerance for EOL variations
            diff = abs(declared_length - actual_length)
            if diff > 2:  # More than just EOL difference
                mismatched_count += 1
                if declared_length > actual_length:
                    mismatches.append(
                        f"Stream at offset {match.start()}: Declared length ({declared_length}) "
                        f"exceeds actual length ({actual_length}) by {diff} bytes. "
                        "May indicate truncated or tampered stream data."
                    )
                else:
                    mismatches.append(
                        f"Stream at offset {match.start()}: Actual length ({actual_length}) "
                        f"exceeds declared length ({declared_length}) by {diff} bytes. "
                        "May indicate injected data or buffer overflow attempt."
                    )

    # Also check for streams using indirect /Length references
    # Pattern: /Length N 0 R (indirect reference)
    indirect_pattern = rb"/Length\s+(\d+)\s+(\d+)\s+R"
    indirect_refs = list(re.finditer(indirect_pattern, pdf_content))

    if indirect_refs:
        # Try to resolve indirect length references and check them
        for match in indirect_refs:
            obj_num = int(match.group(1))
            gen_num = int(match.group(2))

            # Find the object definition: N G obj ... endobj
            obj_pattern = rf"{obj_num}\\s+{gen_num}\\s+obj\\s*(\\d+)\\s*endobj".encode()
            obj_match = re.search(obj_pattern, pdf_content)

            if obj_match:
                try:
                    declared_length = int(obj_match.group(1))
                    # Find corresponding stream
                    stream_start_search = pdf_content.find(b"stream", match.end())
                    if stream_start_search != -1 and stream_start_search < match.end() + 200:
                        # Find actual start after "stream\n"
                        newline_pos = pdf_content.find(b"\n", stream_start_search)
                        if newline_pos != -1:
                            actual_start = newline_pos + 1
                            endstream_pos = pdf_content.find(b"endstream", actual_start)
                            if endstream_pos != -1:
                                actual_data = pdf_content[actual_start:endstream_pos]
                                if actual_data.endswith(b"\r\n"):
                                    actual_length = len(actual_data) - 2
                                elif actual_data.endswith(b"\n") or actual_data.endswith(b"\r"):
                                    actual_length = len(actual_data) - 1
                                else:
                                    actual_length = len(actual_data)

                                diff = abs(declared_length - actual_length)
                                if diff > 2:
                                    mismatched_count += 1
                                    mismatches.append(
                                        f"Stream with indirect length ref ({obj_num} {gen_num} R): "
                                        f"Declared {declared_length} bytes, actual {actual_length} bytes "
                                        f"(diff: {diff}). Indirect length references with mismatches "
                                        "are suspicious."
                                    )
                except (ValueError, IndexError):
                    pass

    # Add summary if mismatches found
    if mismatched_count > 0:
        mismatches.insert(
            0,
            f"Stream length mismatches detected ({mismatched_count} stream(s)). "
            "Mismatched stream lengths may indicate PDF tampering, corruption, "
            "or malicious manipulation to hide content or exploit PDF parsers."
        )

    return mismatches


def _extract_additional_actions(
    aa: DictionaryObject, context: str, actions_found: list[str]
) -> None:
    """Extract actions from an Additional Actions (/AA) dictionary.

    Args:
        aa: The /AA dictionary object.
        context: Description of where the /AA was found (e.g., "Document", "Page 1").
        actions_found: List to append action descriptions to.
    """
    # Document-level triggers
    trigger_map = {
        "/WC": "Document Will Close",
        "/WS": "Document Will Save",
        "/DS": "Document Did Save",
        "/WP": "Document Will Print",
        "/DP": "Document Did Print",
        # Page-level triggers
        "/O": "Page Open",
        "/C": "Page Close",
    }

    for key, trigger_name in trigger_map.items():
        if key in aa:
            action = aa[key]
            if hasattr(action, "get_object"):
                action = action.get_object()
            action_desc = _describe_action(action, f"{context} - {trigger_name}")
            if action_desc:
                actions_found.append(action_desc)


def _describe_action(action: DictionaryObject | ArrayObject, trigger: str) -> str | None:
    """Describe a PDF action for reporting.

    Args:
        action: The action object (dictionary or array).
        trigger: Description of what triggers this action.

    Returns:
        Human-readable description of the action, or None if not an action.
    """
    # Handle array (could be a destination array)
    if isinstance(action, ArrayObject):
        return f"{trigger}: GoTo destination"

    if not isinstance(action, DictionaryObject):
        return None

    action_type = action.get("/S")
    if not action_type:
        # Might be a destination dictionary
        if "/D" in action:
            return f"{trigger}: GoTo destination"
        return None

    action_type_str = str(action_type)

    # Map action types to descriptions
    action_descriptions = {
        "/JavaScript": "JavaScript execution",
        "/JS": "JavaScript execution",
        "/Launch": "Launch external application",
        "/URI": "Open URL",
        "/GoTo": "GoTo destination",
        "/GoToR": "GoTo remote document",
        "/GoToE": "GoTo embedded document",
        "/SubmitForm": "Submit form data",
        "/ImportData": "Import data",
        "/Rendition": "Play multimedia",
        "/Sound": "Play sound",
        "/Movie": "Play movie",
        "/Hide": "Hide/show annotation",
        "/Named": "Execute named action",
        "/SetOCGState": "Change layer visibility",
    }

    action_name = action_descriptions.get(action_type_str, f"Unknown action ({action_type_str})")

    # Add extra detail for certain action types
    details = []

    if action_type_str in ("/JavaScript", "/JS"):
        js = action.get("/JS")
        if js:
            js_str = str(js)[:100]  # Truncate long JS
            if len(str(js)) > 100:
                js_str += "..."
            details.append(f"code: {js_str}")

    elif action_type_str == "/URI":
        uri = action.get("/URI")
        if uri:
            details.append(f"target: {uri}")

    elif action_type_str == "/Launch":
        if "/F" in action:
            details.append(f"file: {action['/F']}")
        if "/Win" in action:
            win = action["/Win"]
            if hasattr(win, "get_object"):
                win = win.get_object()
            if isinstance(win, DictionaryObject):
                if "/F" in win:
                    details.append(f"file: {win['/F']}")
                if "/P" in win:
                    details.append(f"params: {win['/P']}")

    elif action_type_str == "/Named":
        name = action.get("/N")
        if name:
            details.append(f"name: {name}")

    detail_str = f" ({', '.join(details)})" if details else ""
    return f"{trigger}: {action_name}{detail_str}"


def extract_forms(file_path: str | Path) -> PdfForms:
    """Extract form information from a PDF file.

    Detects AcroForms and extracts form submission target URLs.

    Args:
        file_path: Path to the PDF file.

    Returns:
        PdfForms with forms_present flag and list of submission target URLs.

    Raises:
        ValidationError: If the file isn't a valid, readable PDF.
    """
    path = validate_pdf(file_path)
    submission_targets: set[str] = set()

    reader = PdfReader(str(path))

    # Check for AcroForm in the document catalog
    has_acroform = False
    if reader.trailer and "/Root" in reader.trailer:
        root = reader.trailer["/Root"]
        if hasattr(root, "get_object"):
            root = root.get_object()
        if isinstance(root, DictionaryObject) and "/AcroForm" in root:
            has_acroform = True
            acro_form = root["/AcroForm"]
            if hasattr(acro_form, "get_object"):
                acro_form = acro_form.get_object()

            # Extract form fields
            if isinstance(acro_form, DictionaryObject):
                _extract_form_actions(acro_form, submission_targets)

                # Check /Fields array for form fields
                if "/Fields" in acro_form:
                    fields = acro_form["/Fields"]
                    if hasattr(fields, "get_object"):
                        fields = fields.get_object()
                    if isinstance(fields, ArrayObject):
                        for field_ref in fields:
                            field = field_ref.get_object() if hasattr(field_ref, "get_object") else field_ref
                            if isinstance(field, DictionaryObject):
                                _extract_form_actions(field, submission_targets)

    # Also check page annotations for widget annotations with actions
    for page in reader.pages:
        annotations = page.get("/Annots")
        if annotations is None:
            continue

        if hasattr(annotations, "get_object"):
            annotations = annotations.get_object()

        if isinstance(annotations, ArrayObject):
            annot_list = annotations
        else:
            annot_list = [annotations]

        for annot_ref in annot_list:
            annot = annot_ref.get_object() if hasattr(annot_ref, "get_object") else annot_ref

            if not isinstance(annot, DictionaryObject):
                continue

            # Check if this is a Widget annotation (form field)
            subtype = annot.get("/Subtype")
            if subtype == "/Widget":
                has_acroform = True
                _extract_form_actions(annot, submission_targets)

    return PdfForms(
        forms_present=has_acroform,
        form_submission_targets=sorted(submission_targets),
    )


def _extract_form_actions(obj: DictionaryObject, targets: set[str]) -> None:
    """Extract submission URLs from form field actions.

    Args:
        obj: Dictionary object that may contain form actions.
        targets: Set to add discovered submission URLs to.
    """
    # Check /A (action) dictionary
    if "/A" in obj:
        action = obj["/A"]
        if hasattr(action, "get_object"):
            action = action.get_object()
        if isinstance(action, DictionaryObject):
            _process_action(action, targets)

    # Check /AA (additional actions) dictionary
    if "/AA" in obj:
        aa = obj["/AA"]
        if hasattr(aa, "get_object"):
            aa = aa.get_object()
        if isinstance(aa, DictionaryObject):
            # Check various trigger actions
            for key in ["/F", "/K", "/V", "/C"]:  # Format, Keystroke, Validate, Calculate
                if key in aa:
                    action = aa[key]
                    if hasattr(action, "get_object"):
                        action = action.get_object()
                    if isinstance(action, DictionaryObject):
                        _process_action(action, targets)


def _process_action(action: DictionaryObject, targets: set[str]) -> None:
    """Process an action dictionary to extract submission URLs.

    Args:
        action: Action dictionary object.
        targets: Set to add discovered submission URLs to.
    """
    action_type = action.get("/S")

    # SubmitForm action
    if action_type == "/SubmitForm":
        # /F contains the URL or file specification
        if "/F" in action:
            f_value = action["/F"]
            if hasattr(f_value, "get_object"):
                f_value = f_value.get_object()

            if isinstance(f_value, str):
                targets.add(f_value)
            elif isinstance(f_value, DictionaryObject):
                # File specification dictionary
                if "/F" in f_value:
                    targets.add(str(f_value["/F"]))
                elif "/UF" in f_value:
                    targets.add(str(f_value["/UF"]))

    # URI action (can also be used for form submission)
    elif action_type == "/URI":
        if "/URI" in action:
            targets.add(str(action["/URI"]))

    # Check for chained /Next actions
    if "/Next" in action:
        next_action = action["/Next"]
        if hasattr(next_action, "get_object"):
            next_action = next_action.get_object()
        if isinstance(next_action, DictionaryObject):
            _process_action(next_action, targets)
        elif isinstance(next_action, ArrayObject):
            for item in next_action:
                item_obj = item.get_object() if hasattr(item, "get_object") else item
                if isinstance(item_obj, DictionaryObject):
                    _process_action(item_obj, targets)


def _defang_value(value):
    """Recursively defang all string values in a data structure.

    Args:
        value: A value that may be a string, list, dict, or primitive.

    Returns:
        The value with all strings defanged.
    """
    if value is None:
        return None
    elif isinstance(value, str):
        return defang.defang(value)
    elif isinstance(value, list):
        return [_defang_value(item) for item in value]
    elif isinstance(value, dict):
        return {key: _defang_value(val) for key, val in value.items()}
    else:
        # int, bool, float, etc. - return as-is
        return value


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

    All string fields in the output are defanged for safe handling.

    Args:
        file_path: Path to the PDF file to process.

    Returns:
        PdfReport containing file metadata, hashes, extracted URLs,
        document metadata, anomaly detection results, and form information.

    Raises:
        ValidationError: If the file isn't a valid, readable PDF.
    """
    path = validate_pdf(file_path)

    md5, sha1, sha256 = compute_hashes(path)
    urls = get_urls(path)
    metadata = get_pdf_metadata(path)
    anomalies = check_anomalies(path)
    forms = extract_forms(path)

    # Build the report
    report = PdfReport(
        filename=path.name,
        filesize=path.stat().st_size,
        md5=md5,
        sha1=sha1,
        sha256=sha256,
        urls=urls,
        metadata=metadata,
        anomalies=anomalies,
        forms=forms,
    )

    # Defang all string fields for safe handling
    return _defang_value(report)
