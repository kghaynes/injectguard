"""Desktop notifications without extra dependencies. The GUI uses its own tray balloon instead."""
from __future__ import annotations

import shutil
import subprocess
import sys


def notify(title: str, message: str) -> bool:
    title, message = title[:80], message[:240]
    try:
        if sys.platform == "darwin":
            esc = lambda s: s.replace("\\", "\\\\").replace('"', '\\"')  # noqa: E731
            subprocess.run(["osascript", "-e", f'display notification "{esc(message)}" with title "{esc(title)}"'],
                           check=False, timeout=5)
            return True
        if sys.platform == "win32":
            ps = (
                "Add-Type -AssemblyName System.Windows.Forms;"
                "$n=New-Object System.Windows.Forms.NotifyIcon;$n.Icon=[System.Drawing.SystemIcons]::Warning;"
                "$n.Visible=$true;$n.ShowBalloonTip(8000,$args[0],$args[1],'Warning');Start-Sleep 9;$n.Dispose()"
            )
            subprocess.Popen(["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps, title, message],
                             creationflags=0x08000000)
            return True
        if shutil.which("notify-send"):
            subprocess.run(["notify-send", "-a", "InjectGuard", "-u", "critical", title, message], check=False, timeout=5)
            return True
    except Exception:  # noqa: BLE001
        pass
    return False


def should_alert(verdict: str, min_verdict: str) -> bool:
    order = {"clean": 0, "skipped": 0, "error": 0, "suspicious": 1, "malicious": 2}
    return order.get(verdict, 0) >= order.get(min_verdict, 1) and order.get(verdict, 0) > 0
