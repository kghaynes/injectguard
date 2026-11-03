"""Top-level scan functions used by the CLI, API, background service and GUI."""
from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import os
import socket
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Iterator, List, Optional

from . import llm
from .config import Settings
from .extractors import SUPPORTED, extract
from .models import Finding, ScanResult, Segment
from .rules import overall, scan_segments


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _finish(res: ScanResult, findings: List[Finding], settings: Optional[Settings], t0: float) -> ScanResult:
    if settings and settings.get("llm_enabled") and findings:
        res.errors += llm.review(findings, settings["llm_url"], settings["llm_model"])
        findings.sort(key=lambda f: -f.score)
    res.findings = findings
    child_scores = [c.score for c in res.children]
    res.score, res.verdict = overall(findings)
    if child_scores and max(child_scores) > res.score:
        worst = max(res.children, key=lambda c: c.score)
        res.score, res.verdict = worst.score, worst.verdict
    res.duration_ms = int((time.perf_counter() - t0) * 1000)
    res.scanned_at = _now()
    return res


def scan_bytes(name: str, data: bytes, settings: Optional[Settings] = None, depth: int = 0) -> ScanResult:
    t0 = time.perf_counter()
    res = ScanResult(target=name, kind="unknown", sha256=hashlib.sha256(data).hexdigest())
    max_depth = (settings or {}).get("max_depth", 3)
    try:
        kind, segs, children, notes = extract(name, data)
        res.kind = kind
    except Exception as e:  # noqa: BLE001
        res.verdict = "error"
        res.errors.append(f"Could not read file: {e}")
        res.scanned_at = _now()
        res.duration_ms = int((time.perf_counter() - t0) * 1000)
        return res
    findings, n = scan_segments(segs)
    res.segments_scanned = n
    for note in notes:
        if "JavaScript" in note:
            findings.append(Finding("PDF-JS", "tool_abuse", "PDF contains JavaScript",
                                    "Scripts in a PDF can change what a viewer or AI tool sees. Rare in normal documents.",
                                    15, note, name, "hidden"))
        else:
            res.errors.append(note)
    if depth < max_depth:
        for cname, cdata in children[:200]:
            res.children.append(scan_bytes(f"{name} › {cname}", cdata, settings, depth + 1))
    elif children:
        res.errors.append(f"Skipped {len(children)} nested items (depth limit)")
    return _finish(res, findings, settings, t0)


def scan_file(path: str | os.PathLike, settings: Optional[Settings] = None) -> ScanResult:
    p = Path(path)
    max_mb = (settings or {}).get("max_file_mb", 50)
    try:
        size = p.stat().st_size
    except OSError as e:
        return ScanResult(target=str(p), kind="unknown", verdict="error", errors=[str(e)], scanned_at=_now())
    if size > max_mb * 1024 * 1024:
        return ScanResult(target=str(p), kind="unknown", verdict="skipped",
                          errors=[f"File is {size // (1024 * 1024)} MB, over the {max_mb} MB limit"], scanned_at=_now())
    data = p.read_bytes()
    res = scan_bytes(str(p), data, settings)
    return res


def scan_segments_result(target: str, kind: str, segments: List[Segment],
                         settings: Optional[Settings] = None) -> ScanResult:
    """Used by the browser extension: the page is already split into visible/hidden segments."""
    t0 = time.perf_counter()
    res = ScanResult(target=target, kind=kind)
    findings, n = scan_segments(segments)
    res.segments_scanned = n
    return _finish(res, findings, settings, t0)


def scan_text(text: str, label: str = "Pasted text", settings: Optional[Settings] = None) -> ScanResult:
    return scan_segments_result(label, "text", [Segment(text, label)], settings)


class BlockedAddress(ValueError):
    pass


def _check_url(url: str, allow_private: bool) -> None:
    """Only http(s). Unless allowed, refuse addresses inside this computer or the local network
    (loopback, private ranges, link-local such as cloud metadata at 169.254.169.254)."""
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https") or not u.hostname:
        raise BlockedAddress("only http(s) addresses can be scanned")
    if allow_private:
        return
    try:
        infos = socket.getaddrinfo(u.hostname, u.port or (443 if u.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise BlockedAddress(f"cannot resolve {u.hostname}: {e}") from None
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
                or ip.is_unspecified or (ip.version == 6 and ip.ipv4_mapped and not ip.ipv4_mapped.is_global)):
            raise BlockedAddress(f"{u.hostname} points to a local or private address ({ip}); not scanned")


def _opener(allow_private: bool):
    class Redirects(urllib.request.HTTPRedirectHandler):
        max_redirections = 5

        def redirect_request(self, req, fp, code, msg, headers, newurl):
            _check_url(newurl, allow_private)   # every hop is checked, not just the first
            return super().redirect_request(req, fp, code, msg, headers, newurl)
    return urllib.request.build_opener(Redirects)


def scan_url(url: str, settings: Optional[Settings] = None, timeout: float = 20.0,
             allow_private: bool = True) -> ScanResult:
    """Fetch and scan a page or linked file. allow_private=False for requests that come from the browser
    (a web page must not be able to steer the scanner at the local network)."""
    try:
        _check_url(url, allow_private)
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 InjectGuard/1.0"})
        with _opener(allow_private).open(req, timeout=timeout) as r:
            data = r.read(20 * 1024 * 1024)
            ctype = r.headers.get("Content-Type", "")
    except Exception as e:  # noqa: BLE001
        return ScanResult(target=url, kind="url", verdict="error", errors=[f"Could not fetch: {e}"], scanned_at=_now())
    name = url.split("?")[0]
    if "html" in ctype and not name.lower().endswith((".html", ".htm")):
        name += ".html"
    elif "pdf" in ctype and not name.lower().endswith(".pdf"):
        name += ".pdf"
    res = scan_bytes(name, data, settings)
    res.target = url
    return res


def is_excluded(path: str, patterns: Iterable[str]) -> bool:
    p = path.replace("\\", "/")
    return any(fnmatch.fnmatch(p, pat) for pat in patterns)


def iter_files(roots: Iterable[str], exclusions: Iterable[str] = ()) -> Iterator[Path]:
    excl = list(exclusions)
    for root in roots:
        r = Path(root).expanduser()
        if r.is_file():
            yield r
            continue
        if not r.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(r):
            dirnames[:] = [d for d in dirnames if not d.startswith(".") and not is_excluded(os.path.join(dirpath, d) + "/", excl)]
            for f in filenames:
                fp = os.path.join(dirpath, f)
                if Path(f).suffix.lower() in SUPPORTED and not is_excluded(fp, excl):
                    yield Path(fp)


def scan_tree(roots: Iterable[str], settings: Optional[Settings] = None,
              progress: Optional[Callable[[int, int, str], None]] = None,
              cancel: Optional[Callable[[], bool]] = None,
              skip_unchanged: Optional[Callable[[Path], bool]] = None) -> Iterator[ScanResult]:
    files = list(iter_files(roots, (settings or {}).get("exclusions", [])))
    for i, f in enumerate(files, start=1):
        if cancel and cancel():
            break
        if progress:
            progress(i, len(files), str(f))
        if skip_unchanged and skip_unchanged(f):
            continue
        yield scan_file(f, settings)
