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
ALIAS_MAGIC = b"book\x00\x00\x00\x00mark\x00\x00\x00\x00"   # macOS Finder alias / bookmark file
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"   # Microsoft compound file (old Office, encrypted Office)
LOCK_PREFIXES = ("~$", ".~lock.")                    # Office / LibreOffice owner files left next to open documents


OFFICE = ("docx", "xlsx", "pptx")


def _sniff(data: bytes) -> str:
    """What the bytes actually are, ignoring the file name."""
    head = data[:8]
    if data[:16] == ALIAS_MAGIC:
        return "alias"
    if head.startswith(b"%PDF") or b"%PDF-" in data[:1024]:   # PDF spec allows junk before the header
        return "pdf"
    if head == OLE_MAGIC:
        return "ole"
    if head.startswith(b"PK"):
        return "zip"
    body = data[:4096].lstrip(b"\xef\xbb\xbf \t\r\n").lower()
    if body.startswith((b"<!doctype html", b"<html", b"<table", b"<meta", b"<head")) or b"<html" in body[:1024]:
        return "html"
    if body.startswith(b"<?xml"):
        return "xml"
    return "text" if _looks_like_text(data[:4096]) else "binary"


def _looks_like_text(chunk: bytes) -> bool:
    if chunk[:2] in (b"\xff\xfe", b"\xfe\xff"):            # UTF-16 only with its byte-order mark
        try:
            t = chunk.decode("utf-16")
        except UnicodeDecodeError:
            return False
    else:
        try:
            t = chunk.decode("utf-8")
        except UnicodeDecodeError as e:
            if e.start < len(chunk) - 4:                     # allow a multi-byte character cut at the end
                return False
            t = chunk[:e.start].decode("utf-8")
    if not t:
        return False
    printable = sum(1 for c in t if c.isprintable() or c in "\t\r\n")
    return printable / len(t) >= 0.95


def detect_kind(name: str, data: bytes) -> str:
    ext = PurePath(name).suffix.lower()
    real = _sniff(data)
    if real == "alias":
        return "alias"
    if real == "pdf":
        return "pdf"
    if real == "ole" and ext == ".msg":
        return "msg"
    if real == "zip":
        if ext in EXT_KIND and EXT_KIND[ext] in OFFICE:
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
    if ext in EXT_KIND and EXT_KIND[ext] in OFFICE:
        # Named like a new Office file but isn't one: go by what the content really is.
        return {"ole": "office-ole", "html": "html", "xml": "text", "text": "text"}.get(real, "office-unknown")
    if ext == ".pdf":
        return {"html": "html", "xml": "text", "text": "text"}.get(real, "misnamed")
    if ext in EXT_KIND:
        return EXT_KIND[ext]
    if real == "html":
        return "html"
    if real in ("text", "xml"):
        return "text"
    return "unknown"   # unsupported binary with an unknown name


def extract(name: str, data: bytes) -> Tuple[str, List[Segment], List[Tuple[str, bytes]], List[str]]:
    """Returns (kind, segments, child_files, notes)."""
    kind = detect_kind(name, data)
    loc = PurePath(name).name or name
    if kind == "alias":
        from ..engine import Unreadable
        raise Unreadable("Finder alias (a shortcut to a file stored elsewhere); the original is scanned where it lives")
    if kind == "misnamed":
        from ..engine import Unreadable
        raise Unreadable(f"Named {PurePath(name).suffix} but isn't one (starts with {data[:8].hex(' ')}); not scanned")
    if kind in ("office-ole", "office-unknown"):
        from ..engine import Unreadable
        if kind == "office-ole" and "EncryptedPackage".encode("utf-16-le") in data:
            raise Unreadable("Password-protected or rights-managed Office file; its contents can't be checked")
        if kind == "office-ole":
            raise Unreadable("Older Office format (.doc/.xls/.ppt) saved with a newer extension; not supported yet")
        raise Unreadable(f"Named {PurePath(name).suffix} but isn't an Office file (starts with {data[:8].hex(' ')}); "
                         "not scanned")
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
