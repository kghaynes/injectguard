"""HTML extractor: separates text a person sees from text hidden by CSS, attributes, or comments.

Works on static HTML (files, emails, fetched URLs). The Chrome extension does the live-page version
with real computed styles.
"""
from __future__ import annotations

import re
from typing import List, Optional

from bs4 import BeautifulSoup, Comment, Tag

from ..models import Segment, VISIBLE, HIDDEN, COMMENT, METADATA

SKIP_TAGS = {"script", "style", "svg", "math"}
HIDDEN_CONTAINERS = {"noscript": "inside <noscript>", "template": "inside <template>"}
TEXT_ATTRS = ("alt", "title", "aria-label", "aria-description", "placeholder", "data-prompt", "data-instructions")

NAMED_COLORS = {"white": (255, 255, 255), "black": (0, 0, 0), "transparent": None,
                "snow": (255, 250, 250), "ivory": (255, 255, 240), "whitesmoke": (245, 245, 245)}


def _parse_style(s: str) -> dict:
    out = {}
    for part in (s or "").split(";"):
        if ":" in part:
            k, v = part.split(":", 1)
            out[k.strip().lower()] = v.strip().lower().replace("!important", "").strip()
    return out


def _color(v: Optional[str]):
    if not v:
        return None
    v = v.strip().lower()
    if v in NAMED_COLORS:
        return NAMED_COLORS[v]
    m = re.match(r"#([0-9a-f]{3}|[0-9a-f]{6})\b", v)
    if m:
        h = m.group(1)
        if len(h) == 3:
            h = "".join(c * 2 for c in h)
        return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))
    m = re.match(r"rgba?\(\s*(\d+)[ ,]+(\d+)[ ,]+(\d+)(?:[ ,/]+([\d.]+))?", v)
    if m:
        if m.group(4) is not None and float(m.group(4)) == 0:
            return None
        return tuple(int(m.group(i)) for i in (1, 2, 3))
    return None


def _close(a, b, tol=24):
    return a is not None and b is not None and all(abs(x - y) <= tol for x, y in zip(a, b))


def _px(v: str) -> Optional[float]:
    m = re.match(r"(-?[\d.]+)\s*(px|pt|em|rem|%)?", v or "")
    if not m:
        return None
    n = float(m.group(1))
    unit = m.group(2) or "px"
    return n * {"px": 1, "pt": 1.33, "em": 16, "rem": 16, "%": 0.16}[unit]


def _style_hidden(st: dict) -> Optional[str]:
    if st.get("display") == "none":
        return "display:none"
    if st.get("visibility") in ("hidden", "collapse"):
        return "visibility:hidden"
    op = 1.0
    if "opacity" in st:
        try:
            op = float(st["opacity"])
        except ValueError:
            pass
    if op <= 0.05:
        return "opacity:0"
    if op <= 0.15:
        return f"nearly transparent (opacity {op})"
    fs = _px(st.get("font-size", ""))
    if fs is not None and fs < 4:
        return "font-size near 0"
    if fs is not None and fs < 7 and op < 0.5:
        return f"micro text ({fs:g}px, opacity {op})"
    for side in ("left", "top", "text-indent", "margin-left", "right"):
        v = _px(st.get(side, ""))
        if v is not None and v <= -999:
            return f"moved off-screen ({side})"
    if "clip" in st and re.search(r"rect\(\s*0", st["clip"]):
        return "clipped to nothing"
    if "clip-path" in st and re.search(r"inset\(\s*(50|100)%|circle\(\s*0", st["clip-path"]):
        return "clipped to nothing"
    w, h = _px(st.get("width", "")), _px(st.get("height", ""))
    if (w == 0 or h == 0) and st.get("overflow") == "hidden":
        return "zero-size box"
    if st.get("transform", "").startswith("scale(0"):
        return "scaled to 0"
    if st.get("color") and _color(st.get("color")) is None and st.get("color") == "transparent":
        return "transparent text"
    return None


def _css_class_rules(soup) -> dict:
    """Very small CSS reader: maps simple selectors (.cls, #id, tag) in <style> blocks to hiding reasons."""
    rules = {}
    for st in soup.find_all("style"):
        css = st.get_text() or ""
        css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
        for sel, body in re.findall(r"([^{}]+)\{([^{}]*)\}", css):
            props = _parse_style(body)
            reason = _style_hidden(props)
            col = _color(props.get("color"))
            bg = _color(props.get("background-color") or props.get("background"))
            for s in sel.split(","):
                s = s.strip()
                if re.fullmatch(r"[.#]?[A-Za-z][\w-]*", s):
                    rules[s] = {"reason": reason, "color": col, "bg": bg}
    return rules


def extract_html(html: str, location: str = "HTML", base_bg=(255, 255, 255)) -> List[Segment]:
    soup = BeautifulSoup(html, "lxml")
    segs: List[Segment] = []
    css = _css_class_rules(soup)

    # 1. Comments
    for c in soup.find_all(string=lambda s: isinstance(s, Comment)):
        txt = str(c).strip()
        if txt:
            segs.append(Segment(txt, f"{location}: HTML comment", COMMENT, "HTML comment"))
        c.extract()

    # 2. Metadata and attributes
    for m in soup.find_all("meta"):
        content = m.get("content")
        if content and len(content) > 20:
            name = m.get("name") or m.get("property") or m.get("http-equiv") or "meta"
            segs.append(Segment(content, f"{location}: <meta {name}>", METADATA, "meta tag"))
    for s in soup.find_all("script", attrs={"type": "application/ld+json"}):
        segs.append(Segment(s.get_text(), f"{location}: JSON-LD data", METADATA, "structured data"))
    if soup.title and soup.title.string:
        segs.append(Segment(soup.title.string, f"{location}: <title>", VISIBLE))
    for el in soup.find_all(True):
        for a in TEXT_ATTRS:
            v = el.get(a)
            if isinstance(v, str) and len(v) > 25:
                segs.append(Segment(v, f"{location}: {a} attribute on <{el.name}>", METADATA, f"{a} attribute"))
        for a, v in list(el.attrs.items()):
            if a.startswith("data-") and a not in TEXT_ATTRS and isinstance(v, str) and len(v) > 40 and " " in v:
                segs.append(Segment(v, f"{location}: {a} attribute on <{el.name}>", METADATA, f"{a} attribute"))

    for s in soup.find_all(list(SKIP_TAGS)):
        s.decompose()

    # 3. Hidden elements (walk top-down, carry inherited text and background color)
    hidden_tops = []

    def visit(el: Tag, inherited_color, inherited_bg):
        if not isinstance(el, Tag):
            return
        reason = None
        if el.name in HIDDEN_CONTAINERS:
            reason = HIDDEN_CONTAINERS[el.name]
        elif el.has_attr("hidden"):
            reason = "hidden attribute"
        elif str(el.get("aria-hidden", "")).lower() == "true" and el.get_text(strip=True):
            reason = "aria-hidden"
        if el.name == "input" and str(el.get("type", "")).lower() == "hidden":
            v = el.get("value")
            if v and len(v) > 20:
                segs.append(Segment(v, f"{location}: hidden form field", HIDDEN, "hidden input"))
        st = _parse_style(el.get("style", ""))
        color, bg = inherited_color, inherited_bg
        for key in [el.name] + ["." + c for c in (el.get("class") or [])] + (["#" + el["id"]] if el.get("id") else []):
            r = css.get(key)
            if r:
                reason = reason or r["reason"]
                color = r["color"] or color
                bg = r["bg"] or bg
        reason = reason or _style_hidden(st)
        color = _color(st.get("color")) or color
        bg = _color(st.get("background-color") or st.get("background")) or bg
        if not reason and color is not None and _close(color, bg) and el.find(string=True, recursive=False):
            own = "".join(t for t in el.find_all(string=True, recursive=False)).strip()
            if own:
                reason = "text color matches background"
        if reason:
            txt = el.get_text(" ", strip=True)
            if txt:
                hidden_tops.append((el, reason, txt))
            return
        for ch in list(el.children):
            visit(ch, color, bg)

    root = soup.body or soup
    visit(root, (0, 0, 0), base_bg)
    for el, reason, txt in hidden_tops:
        tag = el.name + (("#" + el["id"]) if el.get("id") else "") + (("." + ".".join(el["class"])) if el.get("class") else "")
        segs.append(Segment(txt, f"{location}: <{tag}>", HIDDEN, reason))
        el.decompose()

    # 4. Code examples (<pre>, <code>) are shown to people as examples, not instructions
    from ..rules import CODE_MARK
    code = []
    for el in (root.find_all(["pre", "code"]) if root else []):
        if el.find_parent(["pre", "code"]):
            continue
        t = el.get_text(" ", strip=True)
        if t:
            code.append(t)
        el.decompose()
    if code:
        segs.append(Segment("\n".join(code), f"{location}: {CODE_MARK}", VISIBLE))

    # 5. What is left is what a person sees
    visible = root.get_text(" ", strip=True) if root else ""
    if visible:
        segs.append(Segment(visible, f"{location}: visible text", VISIBLE))
    return segs
