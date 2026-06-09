"""Document text extraction for TXT and PDF uploads."""

from __future__ import annotations

from io import BytesIO


def extract_document_text(filename: str, content: bytes) -> str:
    """Extract text from an uploaded TXT/MD/PDF document.

    PDF support requires the optional pypdf package. The frontend catches the
    raised ValueError and shows a friendly message when the dependency is absent.
    """
    lower_name = filename.lower()
    if lower_name.endswith((".txt", ".md", ".eml", ".log")):
        return content.decode("utf-8", errors="replace")
    if lower_name.endswith(".pdf"):
        return _extract_pdf_text(content)
    raise ValueError("Unsupported upload type. Use TXT, MD, EML, LOG, or PDF.")


def _extract_pdf_text(content: bytes) -> str:
    """Extract PDF text with pypdf when it is installed."""
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise ValueError("PDF upload requires the optional pypdf dependency.") from exc

    reader = PdfReader(BytesIO(content))
    pages = [(page.extract_text() or "") for page in reader.pages]
    text = "\n".join(page.strip() for page in pages if page.strip())
    if not text:
        raise ValueError("No selectable text was found in the PDF.")
    return text
