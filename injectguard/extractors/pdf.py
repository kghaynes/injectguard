"""PDF extractor (PyMuPDF). Uses the low-level text trace so it sees color, size, opacity, render mode and position
for every character - the things attackers use to hide text."""
from __future__ import annotations

import re
from typing import List, Tuple

from ..models import Segment, VISIBLE, HIDDEN, COMMENT, METADATA

try:
    import pymupdf as fitz  # PyMuPDF >= 1.24
except ImportError:  # pragma: no cover
    import fitz


def _span_reason(span, page_rect) -> str | None:
    if span.get("type") == 3:
        return "invisible render mode"
    if span.get("opacity", 1) <= 0.05:
        return "fully transparent"
    if span.get("size", 12) < 2:
        return f"tiny font ({span.get('size', 0):.1f} pt)"
    col = span.get("color") or (0, 0, 0)
    if len(col) == 3 and all(c >= 0.92 for c in col):
        return "white text"
    if len(col) == 1 and col[0] >= 0.92:
        return "white text"
    if len(col) == 4 and all(c <= 0.08 for c in col):  # CMYK white
        return "white text"
    x0, y0, x1, y1 = span["bbox"]
    pr = page_rect
    if x1 < pr.x0 - 1 or x0 > pr.x1 + 1 or y1 < pr.y0 - 1 or y0 > pr.y1 + 1:
        return "placed outside the page"
    return None


def _white_text_on_dark(page, span) -> bool:
    """White text is only hidden if it sits on a white area. Check for a dark filled shape behind it."""
    try:
        r = fitz.Rect(span["bbox"])
        for d in page.get_drawings():
            fill = d.get("fill")
            if fill and d["rect"].intersects(r) and sum(fill[:3]) / 3 < 0.6:
                return True
    except Exception:
        pass
    return False


def extract_pdf(data: bytes, location: str = "PDF") -> Tuple[List[Segment], List[Tuple[str, bytes]], List[str]]:
    """Returns (segments, embedded_files, notes)."""
    segs: List[Segment] = []
    embedded: List[Tuple[str, bytes]] = []
    notes: List[str] = []
    doc = fitz.open(stream=data, filetype="pdf")
    if doc.needs_pass:
        raise ValueError("PDF is password-protected")

    for k, v in (doc.metadata or {}).items():
        if v and isinstance(v, str) and len(v) > 3:
            segs.append(Segment(v, f"{location}: metadata '{k}'", METADATA, "document metadata"))
    try:
        xmp = doc.get_xml_metadata()
        if xmp and len(xmp) > 50:
            txt = re.sub(r"<[^>]+>", " ", xmp)
            segs.append(Segment(txt, f"{location}: XMP metadata", METADATA, "XMP metadata"))
    except Exception:
        pass

    # JavaScript / auto-actions
    try:
        for xref in range(1, doc.xref_length()):
            obj = doc.xref_object(xref, compressed=False) or ""
            if "/JS" in obj or "/JavaScript" in obj:
                notes.append("PDF contains JavaScript")
                m = re.search(r"/JS\s*\((.*?)\)\s*[/>]", obj, re.S)
                if m:
                    segs.append(Segment(m.group(1), f"{location}: embedded JavaScript", HIDDEN, "PDF JavaScript"))
                break
    except Exception:
        pass

    for pno, page in enumerate(doc, start=1):
        visible_parts: List[str] = []
        hidden_runs: dict = {}
        try:
            trace = page.get_texttrace()
        except Exception:
            trace = []
        for span in trace:
            text = "".join(chr(c[0]) for c in span.get("chars", []) if c[0] > 0)
            if not text.strip() and not text:
                continue
            reason = _span_reason(span, page.rect)
            if reason == "white text" and _white_text_on_dark(page, span):
                reason = None
            if reason:
                hidden_runs.setdefault(reason, []).append(text)
            else:
                visible_parts.append(text)
        if visible_parts:
            segs.append(Segment(" ".join(visible_parts), f"{location}: page {pno} visible text", VISIBLE))
        for reason, parts in hidden_runs.items():
            segs.append(Segment(" ".join(parts), f"{location}: page {pno}", HIDDEN, reason))

        for annot in page.annots() or []:
            info = annot.info or {}
            txt = " ".join(x for x in (info.get("title"), info.get("subject"), info.get("content")) if x)
            if txt.strip():
                segs.append(Segment(txt, f"{location}: page {pno} annotation ({annot.type[1]})", COMMENT, "annotation"))
        for w in page.widgets() or []:
            txt = " ".join(str(x) for x in (w.field_name, w.field_value, w.field_label) if x)
            if txt.strip():
                segs.append(Segment(txt, f"{location}: page {pno} form field", METADATA, "form field"))

    try:
        for name in doc.embfile_names():
            embedded.append((name, doc.embfile_get(name)))
    except Exception:
        pass
    doc.close()
    return segs, embedded, notes
