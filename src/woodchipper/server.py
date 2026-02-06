"""FastAPI HTTP server for woodchipper PDF analysis."""

import os
import tempfile
from typing import Annotated

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import JSONResponse

from .core import ValidationError, process

app = FastAPI(
    title="Woodchipper API",
    description="PDF analysis API - extracts metadata, URLs, detects anomalies, JavaScript, embedded files, and more.",
    version="1.0.0",
)


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok"}


@app.post("/analyze")
async def analyze_pdf(file: Annotated[UploadFile, File(description="PDF file to analyze")]):
    """Analyze a PDF file and return a full report.

    Upload a PDF file to receive a JSON report containing:
    - File hashes (MD5, SHA1, SHA256)
    - Extracted URLs (defanged)
    - Document metadata with spoofing detection
    - Structural anomalies
    - Detected actions (OpenAction, Additional Actions)
    - External actions (Launch, URI, GoToR, GoToE)
    - JavaScript with behavior analysis
    - Embedded files with type detection
    - Form submission targets

    All string fields in the response are defanged for safe handling.
    """
    # Validate content type
    if file.content_type and file.content_type != "application/pdf":
        # Allow through anyway - we'll validate with magic bytes
        pass

    # Read file content
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Empty file")

    # Save to temp file for processing
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        f.write(content)
        temp_path = f.name

    try:
        report = process(temp_path)
        return JSONResponse(content=report)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        # Clean up temp file
        os.unlink(temp_path)


@app.post("/analyze/raw")
async def analyze_pdf_raw(
    body: Annotated[bytes, File(description="Raw PDF bytes")],
):
    """Analyze raw PDF bytes sent directly in the request body.

    Send raw PDF bytes with Content-Type: application/pdf to receive
    the same analysis report as /analyze.
    """
    if not body:
        raise HTTPException(status_code=400, detail="Empty body")

    # Save to temp file for processing
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as f:
        f.write(body)
        temp_path = f.name

    try:
        report = process(temp_path)
        return JSONResponse(content=report)
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    finally:
        # Clean up temp file
        os.unlink(temp_path)


def main(host: str = "0.0.0.0", port: int = 8080):
    """Run the server."""
    import uvicorn

    uvicorn.run(app, host=host, port=port, limit_max_request_size=1024 * 1024 * 1024)


if __name__ == "__main__":
    main()
