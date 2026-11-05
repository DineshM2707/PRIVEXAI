import csv
from dataclasses import dataclass
from io import BytesIO, StringIO

from pypdf import PdfReader
from pypdf.errors import PdfReadError


MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
MAX_EXTRACTED_CHARACTERS = 20_000
MAX_PDF_PAGES = 50
SUPPORTED_EXTENSIONS = {".txt", ".csv", ".pdf"}


class DocumentReadError(ValueError):
    pass


@dataclass(frozen=True)
class ExtractedDocument:
    filename: str
    text: str
    extraction_method: str
    truncated: bool


def extract_document_text(filename: str, content: bytes) -> ExtractedDocument:
    safe_filename = filename.replace("\\", "/").rsplit("/", 1)[-1].strip()
    extension = "." + safe_filename.rsplit(".", 1)[-1].lower() if "." in safe_filename else ""
    if extension not in SUPPORTED_EXTENSIONS:
        raise DocumentReadError("Unsupported file type. Upload a TXT, CSV, or PDF document.")
    if not content:
        raise DocumentReadError("The uploaded document is empty.")
    if len(content) > MAX_DOCUMENT_BYTES:
        raise DocumentReadError("The document exceeds the 2 MB upload limit.")

    if extension in {".txt", ".csv"}:
        try:
            decoded = content.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise DocumentReadError("The document must use UTF-8 text encoding.") from exc
        if extension == ".csv":
            try:
                rows = csv.reader(StringIO(decoded), strict=True)
                decoded = "\n".join("\t".join(row) for row in rows)
            except csv.Error as exc:
                raise DocumentReadError("The CSV document could not be parsed.") from exc
        method = "UTF-8 text" if extension == ".txt" else "CSV text"
    else:
        if not content.startswith(b"%PDF-"):
            raise DocumentReadError("The uploaded file does not have a valid PDF signature.")
        try:
            reader = PdfReader(BytesIO(content), strict=False)
            if reader.is_encrypted:
                raise DocumentReadError("Encrypted PDFs cannot be scanned; upload an unencrypted PDF.")
            if len(reader.pages) > MAX_PDF_PAGES:
                raise DocumentReadError("PDFs are limited to 50 pages.")
            decoded = "\n".join(page.extract_text() or "" for page in reader.pages)
        except PdfReadError as exc:
            raise DocumentReadError("The PDF is unreadable or damaged.") from exc
        method = "PDF text extraction"
        if not decoded.strip():
            raise DocumentReadError("No readable text was found in the PDF; OCR is not supported.")

    if not decoded.strip():
        raise DocumentReadError("No readable text was found in the document.")
    truncated = len(decoded) > MAX_EXTRACTED_CHARACTERS
    return ExtractedDocument(
        filename=safe_filename[:160],
        text=decoded[:MAX_EXTRACTED_CHARACTERS],
        extraction_method=method,
        truncated=truncated,
    )
