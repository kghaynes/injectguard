"""Pick the right extractor for a file based on its name and first bytes."""
from __future__ import annotations

import io
import zipfile
from pathlib import PurePath
from typing import List, Tuple

from ..models import Segment

EXT_KIND = {
    ".pdf": "pdf", ".docx": "docx", ".docm": "docx", ".dotx": "docx", ".xlsx": "xlsx", ".xlsm": "xlsx",
    ".pptx": "pptx", ".pptm": "pptx", ".html": "html", ".htm": "html", ".xhtml": "html", ".svg": "html",
    ".md": "markdown", ".markdown": "markdown", ".txt": "text", ".csv": "text", ".json": "text", ".xml": "text",
    ".yaml": "text", ".yml": "text", ".rtf": "text", ".eml": "eml", ".msg": "msg", ".zip": "zip",
}
SUPPORTED = set(EXT_KIND)
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"   # Microsoft compound file (old Office, encrypted Office)
LOCK_PREFIXES = ("~$", ".~lock.")                    # Office / LibreOffice owner files left next to open documents


def detect_kind(name: str, data: bytes) -> str:
    ext = PurePath(name).suffix.lower()
    head = data[:8]
    if head.startswith(b"%PDF"):
        return "pdf"
    if head.startswith(b"\xd0\xcf\x11\xe0") and ext == ".msg":
        return "msg"
    if head.startswith(b"PK"):
        if ext in EXT_KIND and EXT_KIND[ext] in ("docx", "xlsx", "pptx"):
            return EXT_KIND[ext]
        try:
            names = zipfile.ZipFile(io.BytesIO(data)).namelist()
            if "word/document.xml" in names:
                return "docx"
            if "xl/workbook.xml" in names:
                return "xlsx"
            if "ppt/presentation.xml" in names:
                return "pptx"
        except zipfile.BadZipFile:
            pass
        return "zip"
    if ext in EXT_KIND:
        return EXT_KIND[ext]
    sniff = data[:512].lstrip().lower()
    if sniff.startswith(b"<!doctype html") or sniff.startswith(b"<html"):
        return "html"
    try:
        data[:4096].decode("utf-8")
        return "text"
    except UnicodeDecodeError:
        return "unknown"


def extract(name: str, data: bytes) -> Tuple[str, List[Segment], List[Tuple[str, bytes]], List[str]]:
    """Returns (kind, segments, child_files, notes)."""
    kind = detect_kind(name, data)
    loc = PurePath(name).name or name
    if kind in ("docx", "xlsx", "pptx") and data[:8] == OLE_MAGIC:
        from ..engine import Unreadable
        if "EncryptedPackage".encode("utf-16-le") in data:   # directory entries can sit anywhere in the file
            raise Unreadable("Password-protected or rights-managed Office file; its contents can't be checked")
        raise Unreadable("Older Office format (.doc/.xls/.ppt) saved with a newer extension; not supported yet")
    children: List[Tuple[str, bytes]] = []
    notes: List[str] = []
    if kind == "pdf":
        from .pdf import extract_pdf
        segs, children, notes = extract_pdf(data, loc)
    elif kind == "docx":
        from .office import extract_docx
        segs = extract_docx(data, loc)
    elif kind == "xlsx":
        from .office import extract_xlsx
        segs = extract_xlsx(data, loc)
    elif kind == "pptx":
        from .office import extract_pptx
        segs = extract_pptx(data, loc)
    elif kind == "html":
        from .html import extract_html
        from .email_text import _decode
        segs = extract_html(_decode(data), loc)
    elif kind in ("markdown", "text"):
        from .email_text import extract_text
        segs = extract_text(data, loc, markdown=(kind == "markdown"))
    elif kind == "eml":
        from .email_text import extract_eml
        segs, children = extract_eml(data, loc)
    elif kind == "msg":
        from .email_text import extract_msg
        segs, children = extract_msg(data, loc)
    elif kind == "zip":
        segs = []
        z = zipfile.ZipFile(io.BytesIO(data))
        total = 0
        for info in z.infolist():
            if info.is_dir():
                continue
            total += info.file_size
            if total > 200 * 1024 * 1024:
                notes.append("Archive stopped at 200 MB uncompressed (possible zip bomb)")
                break
            if PurePath(info.filename).suffix.lower() in SUPPORTED:
                children.append((info.filename, z.read(info)))
    else:
        raise ValueError("Unsupported file type")
    return kind, segs, children, notes
