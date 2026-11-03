"""Email (.eml/.msg), Markdown and plain-text extractors."""
from __future__ import annotations

import email
import re
from email import policy
from typing import List, Tuple

from ..models import Segment, VISIBLE, HIDDEN, COMMENT, METADATA
from .html import extract_html

HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.S)
MD_REFDEF = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*\S+(?:\s+[\"'(](.+?)[\"')])?\s*$", re.M)
MD_FENCE = re.compile(r"^(```|~~~)[^\n]*\n.*?^\1[ \t]*$", re.M | re.S)
MD_INLINE_CODE = re.compile(r"`[^`\n]+`")
MD_IMG_ALT = re.compile(r"!\[([^\]]{20,})\]\(")
HAS_TAG = re.compile(r"<(div|span|p|font|section|details|a|img|style)\b", re.I)


def extract_text(data: bytes, location="Text", markdown=False) -> List[Segment]:
    """Plain text: everything is on screen, so it is all 'visible' (invisible Unicode is still caught by the rules).
    Markdown: comments, reference lines, alt text and hidden inline HTML disappear when rendered."""
    text = _decode(data)
    segs: List[Segment] = []
    body = text
    if markdown:
        for m in HTML_COMMENT.finditer(text):
            if m.group(1).strip():
                segs.append(Segment(m.group(1), f"{location}: HTML comment", COMMENT,
                                    "HTML comment (not shown when rendered)"))
        body = HTML_COMMENT.sub(" ", text)
        code = [m.group(0) for m in MD_FENCE.finditer(body)]
        body = MD_FENCE.sub(" ", body)
        code += MD_INLINE_CODE.findall(body)
        body = MD_INLINE_CODE.sub(" ", body)
        if code:
            from ..rules import CODE_MARK
            segs.append(Segment("\n".join(code), f"{location}: {CODE_MARK}", VISIBLE))
        for m in MD_REFDEF.finditer(body):
            segs.append(Segment(m.group(0), f"{location}: link reference definition", HIDDEN,
                                "Markdown reference line (not shown when rendered)"))
        for m in MD_IMG_ALT.finditer(body):
            segs.append(Segment(m.group(1), f"{location}: image alt text", METADATA, "image alt text"))
        if HAS_TAG.search(body):
            segs += [s for s in extract_html(body, location) if s.visibility != VISIBLE]
    segs.append(Segment(body, f"{location}: text", VISIBLE))
    return segs


def _decode(data: bytes) -> str:
    for enc in ("utf-8-sig", "utf-16"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1", errors="replace")


def extract_eml(data: bytes, location="Email") -> Tuple[List[Segment], List[Tuple[str, bytes]]]:
    msg = email.message_from_bytes(data, policy=policy.default)
    segs: List[Segment] = []
    attachments: List[Tuple[str, bytes]] = []
    for h in ("Subject", "From", "Reply-To", "X-Mailer"):
        v = msg.get(h)
        if v:
            segs.append(Segment(str(v), f"{location}: {h} header", METADATA if h != "Subject" else VISIBLE, None if h == "Subject" else "email header"))
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        disp = part.get_content_disposition()
        fname = part.get_filename()
        if disp == "attachment" or (fname and disp != "inline"):
            payload = part.get_payload(decode=True) or b""
            attachments.append((fname or "attachment.bin", payload))
            continue
        try:
            content = part.get_content()
        except Exception:
            payload = part.get_payload(decode=True) or b""
            content = _decode(payload)
        if isinstance(content, bytes):
            continue
        if ctype == "text/html":
            segs += extract_html(content, f"{location} HTML body")
        elif ctype.startswith("text/"):
            segs.append(Segment(content, f"{location}: plain-text body", VISIBLE))
    return segs, attachments


def extract_msg(data: bytes, location="Outlook MSG") -> Tuple[List[Segment], List[Tuple[str, bytes]]]:
    import io
    import extract_msg  # optional dependency
    m = extract_msg.openMsg(io.BytesIO(data))
    segs: List[Segment] = []
    attachments: List[Tuple[str, bytes]] = []
    try:
        if m.subject:
            segs.append(Segment(m.subject, f"{location}: subject", VISIBLE))
        html = None
        try:
            html = m.htmlBody
        except Exception:
            pass
        if html:
            if isinstance(html, bytes):
                html = _decode(html)
            segs += extract_html(html, f"{location} HTML body")
        elif m.body:
            segs.append(Segment(m.body, f"{location}: body", VISIBLE))
        for a in m.attachments:
            d = getattr(a, "data", None)
            if isinstance(d, (bytes, bytearray)):
                attachments.append((a.longFilename or a.shortFilename or "attachment.bin", bytes(d)))
    finally:
        m.close()
    return segs, attachments
