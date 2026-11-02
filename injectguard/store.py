"""Local history (SQLite) and quarantine. Shared by the GUI, CLI, API and background service."""
from __future__ import annotations

import json
import shutil
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from .config import app_dir
from .models import ScanResult

_lock = threading.Lock()


def _db() -> sqlite3.Connection:
    con = sqlite3.connect(app_dir() / "history.db", timeout=10)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("""CREATE TABLE IF NOT EXISTS scans(
        id INTEGER PRIMARY KEY, ts TEXT, target TEXT, kind TEXT, source TEXT, verdict TEXT, score INTEGER,
        n_findings INTEGER, result TEXT)""")
    con.execute("CREATE INDEX IF NOT EXISTS scans_ts ON scans(ts)")
    con.execute("""CREATE TABLE IF NOT EXISTS file_index(path TEXT PRIMARY KEY, mtime REAL, size INTEGER,
        verdict TEXT, ts TEXT)""")
    con.execute("""CREATE TABLE IF NOT EXISTS quarantine(id TEXT PRIMARY KEY, original TEXT, stored TEXT,
        ts TEXT, verdict TEXT, score INTEGER)""")
    return con


def _trim(res: ScanResult) -> dict:
    d = res.to_dict()

    def cut(r):
        for f in r["findings"]:
            f["excerpt"] = f["excerpt"][:300]
        for c in r["children"]:
            cut(c)
    cut(d)
    return d


def record(res: ScanResult, source: str = "manual") -> int:
    with _lock, _db() as con:
        cur = con.execute(
            "INSERT INTO scans(ts,target,kind,source,verdict,score,n_findings,result) VALUES(?,?,?,?,?,?,?,?)",
            (res.scanned_at or datetime.now(timezone.utc).isoformat(timespec="seconds"), res.target, res.kind, source,
             res.verdict, res.score, len(res.findings) + sum(len(c.findings) for c in res.children),
             json.dumps(_trim(res))))
        return cur.lastrowid


def history(limit: int = 500, verdicts: Optional[List[str]] = None, since: Optional[str] = None) -> List[dict]:
    q = "SELECT id,ts,target,kind,source,verdict,score,n_findings FROM scans"
    cond, args = [], []
    if verdicts:
        cond.append("verdict IN (%s)" % ",".join("?" * len(verdicts)))
        args += verdicts
    if since:
        cond.append("ts >= ?")
        args.append(since)
    if cond:
        q += " WHERE " + " AND ".join(cond)
    q += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    with _db() as con:
        cols = ["id", "ts", "target", "kind", "source", "verdict", "score", "n_findings"]
        return [dict(zip(cols, r)) for r in con.execute(q, args)]


def get_result(scan_id: int) -> Optional[ScanResult]:
    with _db() as con:
        row = con.execute("SELECT result FROM scans WHERE id=?", (scan_id,)).fetchone()
    return ScanResult.from_dict(json.loads(row[0])) if row else None


def clear_history():
    with _lock, _db() as con:
        con.execute("DELETE FROM scans")
        con.execute("DELETE FROM file_index")


def stats(since: str) -> dict:
    with _db() as con:
        rows = con.execute("SELECT verdict, COUNT(*) FROM scans WHERE ts >= ? GROUP BY verdict", (since,)).fetchall()
        last = con.execute("SELECT ts FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    d = {v: n for v, n in rows}
    d["last_scan"] = last[0] if last else None
    return d


# ---------------------------------------------------------------- unchanged-file cache (scheduled scans)
def unchanged(path: Path) -> bool:
    try:
        st = path.stat()
    except OSError:
        return True
    with _db() as con:
        row = con.execute("SELECT mtime,size FROM file_index WHERE path=?", (str(path),)).fetchone()
    return bool(row and row[0] == st.st_mtime and row[1] == st.st_size)


def mark_indexed(path: Path, verdict: str):
    try:
        st = path.stat()
    except OSError:
        return
    with _lock, _db() as con:
        con.execute("INSERT OR REPLACE INTO file_index VALUES(?,?,?,?,?)",
                    (str(path), st.st_mtime, st.st_size, verdict, datetime.now(timezone.utc).isoformat()))


# ---------------------------------------------------------------- quarantine
def qdir() -> Path:
    p = app_dir() / "quarantine"
    p.mkdir(exist_ok=True)
    return p


def quarantine(path: str, verdict: str = "", score: int = 0) -> str:
    src = Path(path)
    qid = uuid.uuid4().hex[:12]
    dst = qdir() / f"{qid}_{src.name}.quarantined"
    shutil.move(str(src), dst)
    meta = {"id": qid, "original": str(src), "stored": str(dst), "ts": datetime.now(timezone.utc).isoformat(),
            "verdict": verdict, "score": score}
    (qdir() / f"{qid}.json").write_text(json.dumps(meta, indent=2))
    with _lock, _db() as con:
        con.execute("INSERT INTO quarantine VALUES(?,?,?,?,?,?)", (qid, str(src), str(dst), meta["ts"], verdict, score))
    return qid


def quarantined() -> List[dict]:
    with _db() as con:
        cols = ["id", "original", "stored", "ts", "verdict", "score"]
        return [dict(zip(cols, r)) for r in con.execute("SELECT * FROM quarantine ORDER BY ts DESC")]


def restore(qid: str) -> str:
    with _db() as con:
        row = con.execute("SELECT original, stored FROM quarantine WHERE id=?", (qid,)).fetchone()
    if not row:
        raise KeyError(qid)
    original, stored = Path(row[0]), Path(row[1])
    dest = original
    if dest.exists():
        dest = dest.with_name(dest.stem + ".restored" + dest.suffix)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(stored), dest)
    _forget(qid)
    return str(dest)


def delete_quarantined(qid: str):
    with _db() as con:
        row = con.execute("SELECT stored FROM quarantine WHERE id=?", (qid,)).fetchone()
    if row:
        Path(row[0]).unlink(missing_ok=True)
    _forget(qid)


def _forget(qid: str):
    (qdir() / f"{qid}.json").unlink(missing_ok=True)
    with _lock, _db() as con:
        con.execute("DELETE FROM quarantine WHERE id=?", (qid,))
