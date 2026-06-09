"""PDF export utilities for SOC reports."""

from __future__ import annotations

from io import BytesIO

from reportlab.lib.pagesizes import LETTER
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer


def markdown_to_pdf_bytes(title: str, markdown_text: str) -> bytes:
    """Convert a plain Markdown report into a simple readable PDF."""
    buffer = BytesIO()
    document = SimpleDocTemplate(buffer, pagesize=LETTER, title=title)
    styles = getSampleStyleSheet()
    story = [Paragraph(_escape(title), styles["Title"]), Spacer(1, 12)]

    for line in markdown_text.splitlines():
        if not line.strip():
            story.append(Spacer(1, 8))
            continue
        style = styles["Normal"]
        text = line
        if line.startswith("# "):
            style = styles["Heading1"]
            text = line[2:]
        elif line.startswith("## "):
            style = styles["Heading2"]
            text = line[3:]
        elif line.startswith("- "):
            text = f"&bull; {line[2:]}"
        story.append(Paragraph(_escape(text), style))

    document.build(story)
    return buffer.getvalue()


def _escape(text: str) -> str:
    """Escape text for ReportLab Paragraph markup."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
