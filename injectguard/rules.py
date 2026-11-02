"""Rule engine: turns text segments into scored findings.

Phrase rules live in rules.json so the Chrome extension can use the exact same list
(tools/sync_rules.py writes extension/rules.js from it).
"""
from __future__ import annotations

import base64
import binascii
import json
import math
import re
import unicodedata
from pathlib import Path
from typing import Iterable, List, Tuple

from .models import Finding, Segment, HIDDEN, VISIBLE

RULES_PATH = Path(__file__).with_name("rules.json")
RULESET = json.loads(RULES_PATH.read_text(encoding="utf-8"))
MULT = RULESET["visibility_multiplier"]
TH_SUSPICIOUS = RULESET["thresholds"]["suspicious"]
TH_MALICIOUS = RULESET["thresholds"]["malicious"]
REASON_TIERS = RULESET.get("hidden_reason_multiplier", [])
DUP_MIN = RULESET.get("duplicate_min_chars", 20)


def multiplier(visibility: str, reason) -> float:
    """Hidden text scores x2, except hiding that normal web pages use all the time."""
    if visibility == "hidden" and reason:
        r = reason.lower()
        for tier in REASON_TIERS:
            if any(r.startswith(p) for p in tier["prefixes"]):
                return tier["mult"]
    return MULT.get(visibility, 1.0)


def _compile(rule):
    flags = re.S | re.I
    if "m" in rule.get("flags", ""):
        flags |= re.M
    return re.compile(rule["pattern"], flags)


PHRASE_RULES = [(r, _compile(r)) for r in RULESET["phrase_rules"]]

# ---------------------------------------------------------------- invisible characters
ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E, 0x00AD, 0x034F, 0x2061, 0x2062, 0x2063, 0x2064}
BIDI = set(range(0x202A, 0x202F)) | set(range(0x2066, 0x206A)) | {0x200E, 0x200F, 0x061C}
TAG_RANGE = range(0xE0000, 0xE0080)
VARIATION = set(range(0xFE00, 0xFE10)) | set(range(0xE0100, 0xE01F0))


def is_invisible(cp: int) -> bool:
    return cp in ZERO_WIDTH or cp in BIDI or cp in TAG_RANGE or cp in VARIATION


# Common look-alike letters (Cyrillic / Greek) mapped to Latin.
HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "ԛ": "q", "ԝ": "w", "ν": "v", "ο": "o", "α": "a", "ε": "e",
    "ι": "i", "κ": "k", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "А": "a", "В": "b", "Е": "e", "К": "k",
    "М": "m", "Н": "h", "О": "o", "Р": "p", "С": "c", "Т": "t", "Х": "x", "І": "i", "Α": "a", "Β": "b",
    "Ε": "e", "Η": "h", "Ι": "i", "Κ": "k", "Μ": "m", "Ν": "n", "Ο": "o", "Ρ": "p", "Τ": "t", "Χ": "x",
}


def normalize(raw: str) -> Tuple[str, List[int]]:
    """Lower-case, NFKC, strip invisible chars, fold look-alikes, collapse whitespace.

    Returns the normalized text and a map from each normalized index back to the raw index,
    so excerpts can be shown in the original wording.
    """
    out: List[str] = []
    idx: List[int] = []
    prev_space = True
    for i, ch in enumerate(raw):
        cp = ord(ch)
        if is_invisible(cp):
            continue
        n = unicodedata.normalize("NFKC", ch)
        for c in n:
            c = HOMOGLYPHS.get(c, c).lower()
            if c.isspace():
                if prev_space:
                    continue
                c = " "
                prev_space = True
            else:
                prev_space = False
            out.append(c)
            idx.append(i)
    return "".join(out), idx


def _excerpt(raw: str, start: int, end: int, ctx: int = 60) -> str:
    a = max(0, start - ctx)
    b = min(len(raw), end + ctx)
    s = raw[a:b]
    s = "".join(ch for ch in s if not is_invisible(ord(ch)))
    s = re.sub(r"\s+", " ", s).strip()
    if a > 0:
        s = "…" + s
    if b < len(raw):
        s = s + "…"
    return s[:300]


QUOTES = "\"'“”‘’«»`"


def _is_quoted(raw: str, start: int, end: int, span: int = 300) -> bool:
    """True when the match sits inside an open quotation (someone quoting the attack, not making it)."""
    before = raw[max(0, start - span):start]
    after = raw[end:end + span]
    if before.count('"') % 2 == 1 and '"' in after:
        return True
    for o, c in (("“", "”"), ("‘", "’"), ("«", "»")):
        if before.rfind(o) > before.rfind(c) and c in after:
            return True
    qb = before.rfind("'")   # single straight quote: only right next to the phrase (apostrophes are common)
    return qb >= len(before) - 3 and "'" in after[:120]


def _score(weight: int, visibility: str, reason=None) -> int:
    return int(min(100, math.floor(weight * multiplier(visibility, reason) + 0.5)))  # same rounding as JS Math.round


def run_phrase_rules(raw: str, seg: Segment, *, extra_weight: int = 0, rule_prefix: str = "",
                     family_override: str = None, title_prefix: str = "") -> List[Finding]:
    norm, idx = normalize(raw)
    found: List[Finding] = []
    for rule, rx in PHRASE_RULES:
        text = raw if rule.get("raw") else norm
        m = rx.search(text)
        if not m:
            continue
        if rule.get("raw"):
            rs, re_ = m.start(), m.end()
        else:
            rs = idx[m.start()] if m.start() < len(idx) else 0
            re_ = (idx[m.end() - 1] + 1) if m.end() - 1 < len(idx) else len(raw)
        weight = rule["weight"] + extra_weight
        title = title_prefix + rule["title"]
        explain = rule["explain"]
        # Evasion: the phrase only matched after invisible characters were removed.
        if not rule.get("raw") and any(is_invisible(ord(c)) for c in raw[rs:re_]):
            weight += 20
            title += " (split with invisible characters)"
            explain += " Invisible characters were inserted inside the words to slip past filters."
        # Discussion: visible text that puts the phrase in quotes is usually an article about injection.
        elif seg.visibility == VISIBLE and _is_quoted(raw, rs, re_):
            weight = int(weight * 0.4)
            title += " (quoted - likely a discussion)"
        found.append(Finding(
            rule_id=rule_prefix + rule["id"],
            family=family_override or rule["family"],
            title=title,
            explain=explain,
            score=_score(weight, seg.visibility, seg.hidden_reason),
            excerpt=_excerpt(raw, rs, re_),
            location=seg.location,
            visibility=seg.visibility,
            hidden_reason=seg.hidden_reason,
        ))
    return found


# ---------------------------------------------------------------- special checks
B64_RX = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
SCRIPT_CYR = re.compile(r"[Ѐ-ӿ]")
SCRIPT_GRK = re.compile(r"[Ͱ-Ͽ]")
LATIN = re.compile(r"[A-Za-z]")
WORD_RX = re.compile(r"[^\W\d_]{3,}", re.U)


def check_unicode(raw: str, seg: Segment) -> Tuple[List[Finding], List[Segment]]:
    """Find invisible characters. Unicode tag characters are decoded and returned as a new hidden segment."""
    findings: List[Finding] = []
    extra: List[Segment] = []
    body = raw[1:] if raw[:1] == "﻿" else raw   # a leading byte-order mark is normal
    zw = sum(1 for ch in body if ord(ch) in ZERO_WIDTH)
    bidi = sum(1 for ch in raw if ord(ch) in BIDI)
    tags = [ch for ch in raw if ord(ch) in TAG_RANGE]

    if tags:
        decoded = "".join(chr(ord(c) - 0xE0000) for c in tags if 0x20 <= ord(c) - 0xE0000 <= 0x7E)
        pos = next(i for i, ch in enumerate(raw) if ord(ch) in TAG_RANGE)
        findings.append(Finding(
            rule_id="UNI-TAG", family="invisible_unicode",
            title="Hidden message in invisible Unicode tag characters",
            explain="Unicode tag characters (U+E0000 block) show nothing on screen but many AI models read them as normal "
                    "letters. This is called ASCII smuggling.",
            score=min(100, 50 + (20 if len(decoded) > 10 else 0)),
            excerpt=("Decoded: " + decoded[:250]) if decoded else _excerpt(raw, pos, pos + 1),
            location=seg.location, visibility=seg.visibility, hidden_reason="invisible Unicode tags"))
        if decoded.strip():
            extra.append(Segment(decoded, seg.location + " (decoded tag characters)", HIDDEN, "invisible Unicode tags"))
    if zw >= 3:
        pos = next(i for i, ch in enumerate(raw) if ord(ch) in ZERO_WIDTH)
        findings.append(Finding(
            rule_id="UNI-ZW", family="invisible_unicode",
            title=f"{zw} zero-width characters",
            explain="Zero-width characters are invisible. They are used to split banned words so filters miss them, "
                    "or to watermark text.",
            score=20 if zw < 20 else 30, excerpt=_excerpt(raw, pos, pos + 1),
            location=seg.location, visibility=seg.visibility, hidden_reason=seg.hidden_reason))
    if bidi:
        pos = next(i for i, ch in enumerate(raw) if ord(ch) in BIDI)
        findings.append(Finding(
            rule_id="UNI-BIDI", family="invisible_unicode",
            title=f"{bidi} text-direction override characters",
            explain="Bidirectional override characters make text display in a different order than the AI reads it.",
            score=25, excerpt=_excerpt(raw, pos, pos + 1),
            location=seg.location, visibility=seg.visibility, hidden_reason=seg.hidden_reason))
    return findings, extra


def check_base64(raw: str, seg: Segment) -> List[Finding]:
    out: List[Finding] = []
    for m in B64_RX.finditer(raw):
        blob = m.group(0)
        if len(blob) > 20000:
            continue
        try:
            dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
        except (binascii.Error, ValueError):
            continue
        try:
            txt = dec.decode("utf-8")
        except UnicodeDecodeError:
            continue
        printable = sum(1 for c in txt if c.isprintable() or c.isspace())
        if not txt or printable / len(txt) < 0.9 or not re.search(r"[A-Za-z]{3,} [A-Za-z]{2,}", txt):
            continue
        sub = Segment(txt, seg.location + " (decoded Base64)", seg.visibility, seg.hidden_reason)
        hits = run_phrase_rules(txt, sub, extra_weight=10, rule_prefix="B64:", family_override="encoded_payload",
                                title_prefix="Base64-encoded: ")
        out.extend(hits)
    return out


def check_homoglyphs(raw: str, seg: Segment) -> List[Finding]:
    mixed = []
    for w in WORD_RX.findall(raw):
        if LATIN.search(w) and (SCRIPT_CYR.search(w) or SCRIPT_GRK.search(w)):
            mixed.append(w)
    if len(mixed) >= 2:
        return [Finding(
            rule_id="HOM-001", family="homoglyph",
            title=f"{len(mixed)} words mix Latin with look-alike letters",
            explain="Words that mix English letters with Cyrillic or Greek look-alikes are a trick to slip past "
                    "keyword filters.",
            score=15 if len(mixed) < 5 else 25,
            excerpt=", ".join(mixed[:8]), location=seg.location, visibility=seg.visibility,
            hidden_reason=seg.hidden_reason)]
    return []


def _demote_duplicates(segments: List[Segment]) -> List[Segment]:
    """Hidden text that also appears on screen is a layout copy (mobile menu, responsive duplicate), not camouflage.
    Treat it as visible."""
    visible = " ".join(normalize(s.text or "")[0] for s in segments if s.visibility == VISIBLE)
    if not visible:
        return segments
    out = []
    for s in segments:
        if s.visibility == HIDDEN:
            n = normalize(s.text or "")[0].strip()
            if len(n) >= DUP_MIN and n in visible:
                s = Segment(s.text, s.location, VISIBLE, None)
        out.append(s)
    return out


def scan_segments(segments: Iterable[Segment]) -> Tuple[List[Finding], int]:
    """Run every check on every segment. Returns findings and number of segments scanned."""
    findings: List[Finding] = []
    queue = _demote_duplicates(list(segments))
    n = 0
    while queue:
        seg = queue.pop(0)
        raw = seg.text or ""
        if not raw.strip():
            continue
        n += 1
        uni, extra = check_unicode(raw, seg)
        findings.extend(uni)
        queue.extend(extra)
        seg_hits = run_phrase_rules(raw, seg)
        seg_hits += check_base64(raw, seg)
        seg_hits += check_homoglyphs(raw, seg)
        findings.extend(seg_hits)
        # Hidden text with no other hit: list it as info so the user knows it exists.
        if seg.visibility == HIDDEN and not seg_hits and not uni:
            norm, _ = normalize(raw)
            if len(norm) >= 40:
                findings.append(Finding(
                    rule_id="HID-INFO", family="hidden_text", title="Hidden text (no instructions found)",
                    explain="This text is hidden from people but readable by AI tools. Nothing in it matched an "
                            "injection rule.",
                    score=8, excerpt=_excerpt(raw, 0, min(len(raw), 200), 0), location=seg.location,
                    visibility=seg.visibility, hidden_reason=seg.hidden_reason))
    return dedupe(findings), n


def dedupe(findings: List[Finding]) -> List[Finding]:
    best = {}
    for f in findings:
        key = (f.rule_id, f.location, f.excerpt[:80])
        if key not in best or f.score > best[key].score:
            best[key] = f
    return sorted(best.values(), key=lambda f: -f.score)


def overall(findings: List[Finding]) -> Tuple[int, str]:
    if not findings:
        return 0, "clean"
    scores = sorted((f.score for f in findings), reverse=True)
    extra = sum(1 for s in scores[1:] if s >= TH_SUSPICIOUS)
    score = min(100, scores[0] + 8 * min(extra, 6))
    if score >= TH_MALICIOUS:
        return score, "malicious"
    if score >= TH_SUSPICIOUS:
        return score, "suspicious"
    return score, "clean"
