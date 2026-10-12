"""Document text extraction for TXT and PDF uploads."""

from __future__ import annotations

import math
import multiprocessing
from io import BytesIO
from multiprocessing.connection import Connection

ALLOWED_UPLOAD_TYPES = {
    ".txt": {"text/plain"},
    ".md": {"text/markdown", "text/plain"},
    ".eml": {"message/rfc822", "text/plain"},
    ".log": {"text/plain"},
    ".pdf": {"application/pdf"},
}


class DocumentParseError(ValueError):
    """Safe parser failure with a stable machine-readable code."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def validate_upload_type(filename: str, content_type: str | None, content_prefix: bytes) -> None:
    """Require an allow-listed extension, MIME type, and matching file signature."""
    suffix = next((suffix for suffix in ALLOWED_UPLOAD_TYPES if filename.lower().endswith(suffix)), None)
    if suffix is None:
        raise DocumentParseError("unsupported_file_type", "Use TXT, MD, EML, LOG, or PDF files only.")
    normalized_mime = (content_type or "").split(";", 1)[0].strip().lower()
    if normalized_mime not in ALLOWED_UPLOAD_TYPES[suffix]:
        raise DocumentParseError(
            "invalid_mime_type", f"MIME type {normalized_mime or 'missing'} is not valid for {suffix}."
        )
    if suffix == ".pdf" and not content_prefix.startswith(b"%PDF-"):
        raise DocumentParseError("invalid_file_signature", "The file does not have a valid PDF signature.")
    if suffix != ".pdf" and (b"\x00" in content_prefix or content_prefix.startswith(b"%PDF-")):
        raise DocumentParseError("invalid_file_signature", "The file signature does not match a text document.")


def extract_document_text(
    filename: str,
    content: bytes,
    *,
    max_pages: int = 50,
    max_chars: int = 20000,
) -> str:
    """Extract text from an uploaded TXT/MD/PDF document.

    PDF support requires the optional pypdf package. The frontend catches the
    raised ValueError and shows a friendly message when the dependency is absent.
    """
    lower_name = filename.lower()
    if lower_name.endswith((".txt", ".md", ".eml", ".log")):
        return _limit_text(content.decode("utf-8", errors="replace"), max_chars)
    if lower_name.endswith(".pdf"):
        return _extract_pdf_text(content, max_pages=max_pages, max_chars=max_chars)
    raise DocumentParseError("unsupported_file_type", "Unsupported upload type. Use TXT, MD, EML, LOG, or PDF.")


def extract_document_text_controlled(
    filename: str,
    content: bytes,
    *,
    max_pages: int,
    max_chars: int,
    timeout_seconds: float,
    memory_limit_mb: int,
) -> str:
    """Parse in a disposable subprocess with wall-clock, CPU, and memory limits."""
    context = multiprocessing.get_context("spawn")
    parent, child = context.Pipe(duplex=False)
    process = context.Process(
        target=_parser_worker,
        args=(child, filename, content, max_pages, max_chars, timeout_seconds, memory_limit_mb),
        daemon=True,
    )
    process.start()
    child.close()
    process.join(timeout_seconds)
    if process.is_alive():
        process.terminate()
        process.join(1)
        if process.is_alive():
            process.kill()
            process.join(1)
        parent.close()
        raise DocumentParseError("parser_timeout", "Document parsing exceeded the configured time limit.")
    if not parent.poll():
        parent.close()
        raise DocumentParseError("parser_failed", "The document parser stopped unexpectedly.")
    ok, code, payload = parent.recv()
    parent.close()
    if not ok:
        raise DocumentParseError(code, payload)
    return str(payload)


def _parser_worker(
    connection: Connection,
    filename: str,
    content: bytes,
    max_pages: int,
    max_chars: int,
    timeout_seconds: float,
    memory_limit_mb: int,
) -> None:
    try:
        _apply_resource_limits(timeout_seconds, memory_limit_mb)
        text = extract_document_text(filename, content, max_pages=max_pages, max_chars=max_chars)
        connection.send((True, "", text))
    except DocumentParseError as exc:
        connection.send((False, exc.code, str(exc)))
    except ValueError as exc:
        connection.send((False, "invalid_document", str(exc)))
    except BaseException:
        connection.send((False, "parser_failed", "Document parsing failed safely."))
    finally:
        connection.close()


def _apply_resource_limits(timeout_seconds: float, memory_limit_mb: int) -> None:
    """Apply POSIX resource limits when supported by the host."""
    try:
        import resource
    except ImportError:
        return
    cpu_seconds = max(1, math.ceil(timeout_seconds))
    memory_bytes = memory_limit_mb * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
    resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))


def _extract_pdf_text(content: bytes, *, max_pages: int, max_chars: int) -> str:
    """Extract PDF text with pypdf when it is installed."""
    try:
        from pypdf import PdfReader
    except ImportError as exc:
        raise DocumentParseError("pdf_support_unavailable", "PDF upload support is unavailable.") from exc

    try:
        reader = PdfReader(BytesIO(content), strict=True)
    except Exception as exc:
        raise DocumentParseError("malformed_pdf", "The uploaded PDF is malformed or cannot be parsed safely.") from exc
    if reader.is_encrypted:
        raise DocumentParseError("encrypted_pdf", "Encrypted PDF files are not supported.")
    if len(reader.pages) > max_pages:
        raise DocumentParseError("pdf_page_limit", f"PDF exceeds the {max_pages}-page limit.")
    try:
        pages: list[str] = []
        extracted_chars = 0
        for page in reader.pages:
            page_text = (page.extract_text() or "").strip()
            extracted_chars += len(page_text)
            if extracted_chars > max_chars:
                raise DocumentParseError(
                    "extracted_text_limit", f"Extracted text exceeds the {max_chars}-character limit."
                )
            if page_text:
                pages.append(page_text)
    except DocumentParseError:
        raise
    except Exception as exc:
        raise DocumentParseError("pdf_extraction_failed", "Text could not be extracted from the PDF safely.") from exc
    text = "\n".join(pages)
    if not text:
        raise DocumentParseError("no_extractable_text", "No selectable text was found in the PDF.")
    return _limit_text(text, max_chars)


def _limit_text(text: str, max_chars: int) -> str:
    """Reject documents whose extracted text would exceed the analysis limit."""
    if len(text) > max_chars:
        raise DocumentParseError("extracted_text_limit", f"Extracted text exceeds the {max_chars}-character limit.")
    return text
