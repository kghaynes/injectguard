"""Export scan results as a standalone HTML report (or JSON)."""
from __future__ import annotations

import html
import json
from datetime import datetime
from typing import List

from .models import ScanResult

COLORS = {"malicious": "#c62828", "suspicious": "#ef6c00", "clean": "#2e7d32", "error": "#616161", "skipped": "#616161"}


def flatten(results: List[ScanResult]):
    for r in results:
        yield r
        yield from flatten(r.children)


def to_json(results: List[ScanResult]) -> str:
    return json.dumps([r.to_dict() for r in results], indent=2)


def to_html(results: List[ScanResult], title="InjectGuard scan report") -> str:
    e = html.escape
    rows = []
    allr = list(flatten(results))
    counts = {}
    for r in allr:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    for r in sorted(allr, key=lambda r: -r.score):
        if not r.findings and r.verdict in ("clean",):
            continue
        fl = "".join(
            f"<tr><td>{f.score}</td><td><b>{e(f.title)}</b><br><small>{e(f.explain)}</small>"
            f"{'<br><small>Local AI: ' + e(f.llm_verdict) + ' - ' + e(f.llm_reason or '') + '</small>' if f.llm_verdict else ''}</td>"
            f"<td>{e(f.location)}<br><small>{e(f.visibility)}{' - ' + e(f.hidden_reason) if f.hidden_reason else ''}</small></td>"
            f"<td><code>{e(f.excerpt)}</code></td></tr>" for f in r.findings)
        errs = "".join(f"<div class='err'>{e(x)}</div>" for x in r.errors)
        rows.append(f"""<section><h2><span class="v" style="background:{COLORS.get(r.verdict, '#555')}">{e(r.verdict)}</span>
{e(r.target)} <small>score {r.score} · {e(r.kind)}</small></h2>{errs}
{'<table><tr><th>Score</th><th>Finding</th><th>Where</th><th>Text</th></tr>' + fl + '</table>' if fl else ''}</section>""")
    summary = " · ".join(f"{k}: {v}" for k, v in sorted(counts.items()))
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>{e(title)}</title><style>
body{{font:14px/1.45 system-ui,sans-serif;margin:32px;color:#222;max-width:1200px}}
h1{{font-size:22px}} h2{{font-size:15px;margin:24px 0 8px}} .v{{color:#fff;padding:2px 8px;border-radius:4px;
text-transform:uppercase;font-size:12px;margin-right:8px}} table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ddd;padding:6px;vertical-align:top;text-align:left}} code{{white-space:pre-wrap;word-break:break-word}}
small{{color:#666}} .err{{color:#a00}}</style></head><body><h1>{e(title)}</h1>
<p>Generated {datetime.now():%Y-%m-%d %H:%M} · {len(allr)} item(s) · {e(summary)}</p>{''.join(rows) or '<p>No findings.</p>'}
</body></html>"""
