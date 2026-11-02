"""Office extractors: DOCX (raw XML), XLSX (openpyxl), PPTX (python-pptx). Never runs macros."""
from __future__ import annotations

import io
import re
import zipfile
from typing import List

from lxml import etree

from ..models import Segment, VISIBLE, HIDDEN, COMMENT, METADATA

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
NS = {"w": W}
WHITE = {"FFFFFF", "FEFEFE", "FDFDFD", "FCFCFC", "FAFAFA", "F8F8F8", "F5F5F5"}
MAX_XML = 40 * 1024 * 1024


def _xml(z: zipfile.ZipFile, name: str):
    info = z.getinfo(name)
    if info.file_size > MAX_XML:
        raise ValueError(f"{name} too large")
    parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False)
    return etree.fromstring(z.read(name), parser)


def _props(z: zipfile.ZipFile, location: str) -> List[Segment]:
    segs = []
    for name in ("docProps/core.xml", "docProps/app.xml", "docProps/custom.xml"):
        if name in z.namelist():
            root = _xml(z, name)
            for el in root.iter():
                if el.text and len(el.text.strip()) > 3 and not el.text.strip().isdigit():
                    tag = etree.QName(el).localname
                    segs.append(Segment(el.text.strip(), f"{location}: property '{tag}'", METADATA, "document property"))
    for name in z.namelist():
        if name.startswith("customXml/") and name.endswith(".xml") and "itemProps" not in name:
            txt = " ".join(t.strip() for t in _xml(z, name).itertext() if t.strip())
            if txt:
                segs.append(Segment(txt, f"{location}: {name}", METADATA, "custom XML part"))
    return segs


# ------------------------------------------------------------------ DOCX
def _docx_hidden_styles(z) -> dict:
    out = {}
    if "word/styles.xml" not in z.namelist():
        return out
    root = _xml(z, "word/styles.xml")
    for st in root.iterfind(".//w:style", NS):
        sid = st.get(f"{{{W}}}styleId")
        rpr = st.find("w:rPr", NS)
        if rpr is not None:
            r = _rpr_reason(rpr)
            if r:
                out[sid] = r
    return out


def _rpr_reason(rpr) -> str | None:
    if rpr is None:
        return None
    for tag in ("vanish", "specVanish", "webHidden"):
        el = rpr.find(f"w:{tag}", NS)
        if el is not None and el.get(f"{{{W}}}val", "true") not in ("0", "false"):
            return "hidden text (Word 'Hidden' font setting)"
    col = rpr.find("w:color", NS)
    shd = rpr.find("w:shd", NS)
    hl = rpr.find("w:highlight", NS)
    if col is not None and (col.get(f"{{{W}}}val", "").upper() in WHITE):
        dark_bg = (shd is not None and shd.get(f"{{{W}}}fill", "auto").upper() not in ("AUTO", "FFFFFF")) or \
                  (hl is not None and hl.get(f"{{{W}}}val", "none") not in ("none", "white"))
        if not dark_bg:
            return "white text"
    sz = rpr.find("w:sz", NS)
    if sz is not None:
        try:
            if int(sz.get(f"{{{W}}}val", "24")) < 4:  # half-points
                return "tiny font (under 2 pt)"
        except ValueError:
            pass
    return None


def _docx_part(z, name, location, hidden_styles) -> List[Segment]:
    root = _xml(z, name)
    visible, hidden = [], {}
    for p in root.iterfind(".//w:p", NS):
        pstyle = p.find("w:pPr/w:pStyle", NS)
        p_reason = hidden_styles.get(pstyle.get(f"{{{W}}}val")) if pstyle is not None else None
        p_vis = []
        for r in p.iterfind(".//w:r", NS):
            text = "".join((t.text or "") for t in r.iterfind("w:t", NS)) + \
                   "".join((t.text or "") for t in r.iterfind("w:instrText", NS))
            if not text:
                continue
            rpr = r.find("w:rPr", NS)
            reason = _rpr_reason(rpr)
            if not reason and rpr is not None:
                rs = rpr.find("w:rStyle", NS)
                if rs is not None:
                    reason = hidden_styles.get(rs.get(f"{{{W}}}val"))
            reason = reason or p_reason
            if reason:
                hidden.setdefault(reason, []).append(text)
            else:
                p_vis.append(text)
        if p_vis:
            visible.append("".join(p_vis))
    segs = []
    if visible:
        segs.append(Segment("\n".join(visible), f"{location}: {name} visible text", VISIBLE))
    for reason, parts in hidden.items():
        segs.append(Segment(" ".join(parts), f"{location}: {name}", HIDDEN, reason))
    return segs


def extract_docx(data: bytes, location="DOCX") -> List[Segment]:
    z = zipfile.ZipFile(io.BytesIO(data))
    hs = _docx_hidden_styles(z)
    segs: List[Segment] = []
    for name in z.namelist():
        if re.fullmatch(r"word/(document|header\d*|footer\d*|footnotes|endnotes)\.xml", name):
            segs += _docx_part(z, name, location, hs)
    if "word/comments.xml" in z.namelist():
        txt = " ".join(t.strip() for t in _xml(z, "word/comments.xml").itertext() if t.strip())
        if txt:
            segs.append(Segment(txt, f"{location}: reviewer comments", COMMENT, "Word comment"))
    segs += _props(z, location)
    return segs


# ------------------------------------------------------------------ XLSX
def extract_xlsx(data: bytes, location="XLSX") -> List[Segment]:
    import openpyxl
    wb = openpyxl.load_workbook(io.BytesIO(data), data_only=False, read_only=False)
    segs: List[Segment] = []
    for ws in wb.worksheets:
        sheet_hidden = ws.sheet_state != "visible"
        vis, hid = [], {}
        hidden_rows = {i for i, d in ws.row_dimensions.items() if d.hidden}
        hidden_cols = {k for k, d in ws.column_dimensions.items() if d.hidden}
        for row in ws.iter_rows():
            for c in row:
                if c.value is None:
                    continue
                v = str(c.value)
                if c.comment and c.comment.text:
                    segs.append(Segment(c.comment.text, f"{location}: sheet '{ws.title}' {c.coordinate} comment",
                                        COMMENT, "cell comment"))
                reason = None
                if sheet_hidden:
                    reason = f"sheet is {ws.sheet_state}"
                elif c.row in hidden_rows:
                    reason = "hidden row"
                elif c.column_letter in hidden_cols:
                    reason = "hidden column"
                elif c.number_format and re.fullmatch(r";;;?", c.number_format.strip()):
                    reason = "number format ';;;' hides the value"
                else:
                    col = c.font.color if c.font else None
                    rgb = getattr(col, "rgb", None) if col is not None else None
                    if isinstance(rgb, str) and rgb[-6:].upper() in WHITE:
                        fill = c.fill.fgColor.rgb if c.fill and c.fill.fill_type else None
                        if not (isinstance(fill, str) and fill[-6:].upper() not in WHITE and fill != "00000000"):
                            reason = "white text"
                    if not reason and c.font and c.font.sz and c.font.sz < 2:
                        reason = "tiny font"
                if reason:
                    hid.setdefault(reason, []).append(v)
                else:
                    vis.append(v)
        if vis:
            segs.append(Segment(" ".join(vis), f"{location}: sheet '{ws.title}' visible cells", VISIBLE))
        for reason, parts in hid.items():
            segs.append(Segment(" ".join(parts), f"{location}: sheet '{ws.title}'", HIDDEN, reason))
    try:
        for name, dn in wb.defined_names.items():
            if dn.value and len(str(dn.value)) > 25:
                segs.append(Segment(str(dn.value), f"{location}: defined name '{name}'", METADATA, "defined name"))
    except Exception:
        pass
    z = zipfile.ZipFile(io.BytesIO(data))
    segs += _props(z, location)
    return segs


# ------------------------------------------------------------------ PPTX
def extract_pptx(data: bytes, location="PPTX") -> List[Segment]:
    from pptx import Presentation
    from pptx.util import Pt
    prs = Presentation(io.BytesIO(data))
    sw, sh = prs.slide_width or 0, prs.slide_height or 0
    segs: List[Segment] = []
    for i, slide in enumerate(prs.slides, start=1):
        slide_hidden = slide._element.get("show") == "0"
        vis, hid = [], {}

        def walk(shapes):
            for shp in shapes:
                if shp.shape_type == 6 and hasattr(shp, "shapes"):  # group
                    walk(shp.shapes)
                    continue
                descr = shp._element.xpath("./*[1]/p:cNvPr/@descr") if hasattr(shp, "_element") else []
                if descr and len(descr[0]) > 20:
                    segs.append(Segment(descr[0], f"{location}: slide {i} alt text on '{shp.name}'", METADATA, "alt text"))
                if not shp.has_text_frame:
                    continue
                off = False
                try:
                    l, t, w, h = shp.left or 0, shp.top or 0, shp.width or 0, shp.height or 0
                    off = (l + w <= 0) or (t + h <= 0) or (sw and l >= sw) or (sh and t >= sh)
                except Exception:
                    pass
                for p in shp.text_frame.paragraphs:
                    for r in p.runs:
                        if not r.text:
                            continue
                        reason = None
                        if slide_hidden:
                            reason = "hidden slide"
                        elif off:
                            reason = "shape placed off the slide"
                        else:
                            try:
                                if r.font.color and r.font.color.type is not None and r.font.color.rgb is not None \
                                        and str(r.font.color.rgb).upper() in WHITE:
                                    reason = "white text"
                            except Exception:
                                pass
                            if not reason and r.font.size is not None and r.font.size < Pt(2):
                                reason = "tiny font"
                        if reason:
                            hid.setdefault(reason, []).append(r.text)
                        else:
                            vis.append(r.text)
        walk(slide.shapes)
        if vis:
            segs.append(Segment(" ".join(vis), f"{location}: slide {i} visible text", VISIBLE))
        for reason, parts in hid.items():
            segs.append(Segment(" ".join(parts), f"{location}: slide {i}", HIDDEN, reason))
        if slide.has_notes_slide:
            notes = slide.notes_slide.notes_text_frame.text if slide.notes_slide.notes_text_frame else ""
            if notes.strip():
                segs.append(Segment(notes, f"{location}: slide {i} speaker notes", COMMENT, "speaker notes"))
    z = zipfile.ZipFile(io.BytesIO(data))
    segs += _props(z, location)
    return segs
