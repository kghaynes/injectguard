"""Settings, app-data folder, and the pairing token for the Chrome extension."""
from __future__ import annotations

import json
import os
import secrets
import sys
import threading
from pathlib import Path

DEFAULTS = {
    "watch_folders": [str(Path.home() / d) for d in ("Downloads", "Desktop", "Documents")],
    "realtime_enabled": True,
    "schedule_enabled": True,
    "schedule_time": "02:00",
    "api_enabled": True,
    "api_port": 47321,
    "llm_enabled": False,
    "llm_url": "http://127.0.0.1:11434",
    "llm_model": "llama3.2:3b",
    "notify": True,
    "notify_min_verdict": "malicious",       # suspicious | malicious
    "settings_version": 2,
    "auto_quarantine": False,
    "quarantine_min_score": 80,
    "max_file_mb": 50,
    "max_depth": 3,
    "exclusions": ["*/node_modules/*", "*/.git/*", "*/Library/*", "*/AppData/*", "*.tmp", "*.crdownload", "*.part"],
}


def app_dir() -> Path:
    env = os.environ.get("INJECTGUARD_HOME")
    if env:
        p = Path(env)
    elif sys.platform == "win32":
        p = Path(os.environ.get("APPDATA", Path.home())) / "InjectGuard"
    elif sys.platform == "darwin":
        p = Path.home() / "Library" / "Application Support" / "InjectGuard"
    else:
        p = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "injectguard"
    p.mkdir(parents=True, exist_ok=True)
    return p


_lock = threading.Lock()


class Settings(dict):
    path: Path

    @classmethod
    def load(cls) -> "Settings":
        s = cls(DEFAULTS)
        s.path = app_dir() / "settings.json"
        if s.path.exists():
            try:
                saved = json.loads(s.path.read_text(encoding="utf-8"))
                s.update(saved)
                if saved.get("settings_version", 1) < 2:
                    # 0.0.8: background alerts only for "malicious" (visible-only findings now top out at suspicious)
                    if saved.get("notify_min_verdict") == "suspicious":
                        s["notify_min_verdict"] = "malicious"
                    s["settings_version"] = 2
                    s.save()
            except json.JSONDecodeError:
                pass
        return s

    def save(self):
        with _lock:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self, indent=2), encoding="utf-8")
            tmp.replace(self.path)


def api_token(regenerate: bool = False) -> str:
    p = app_dir() / "api_token"
    if regenerate or not p.exists():
        p.write_text(secrets.token_urlsafe(24), encoding="utf-8")
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
    return p.read_text(encoding="utf-8").strip()
