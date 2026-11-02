"""Data types shared across the engine, API, GUI and CLI."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List, Optional

VISIBLE = "visible"
HIDDEN = "hidden"
COMMENT = "comment"
METADATA = "metadata"


@dataclass
class Segment:
    """A run of text pulled out of a file or page, tagged with where it was and whether a person can see it."""
    text: str
    location: str = ""
    visibility: str = VISIBLE           # visible | hidden | comment | metadata
    hidden_reason: Optional[str] = None  # e.g. "white text", "display:none"


@dataclass
class Finding:
    rule_id: str
    family: str
    title: str
    explain: str
    score: int
    excerpt: str
    location: str
    visibility: str
    hidden_reason: Optional[str] = None
    llm_verdict: Optional[str] = None   # "injection" | "benign" | None
    llm_reason: Optional[str] = None

    def to_dict(self):
        return asdict(self)


@dataclass
class ScanResult:
    target: str
    kind: str                    # pdf, docx, html, page, text, ...
    verdict: str = "clean"       # clean | suspicious | malicious | error | skipped
    score: int = 0
    findings: List[Finding] = field(default_factory=list)
    segments_scanned: int = 0
    errors: List[str] = field(default_factory=list)
    duration_ms: int = 0
    scanned_at: str = ""
    sha256: str = ""
    children: List["ScanResult"] = field(default_factory=list)  # attachments / archive members

    def to_dict(self):
        d = asdict(self)
        return d

    @staticmethod
    def from_dict(d: dict) -> "ScanResult":
        d = dict(d)
        d["findings"] = [Finding(**f) for f in d.get("findings", [])]
        d["children"] = [ScanResult.from_dict(c) for c in d.get("children", [])]
        return ScanResult(**d)
