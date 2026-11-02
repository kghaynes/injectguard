"""Register the background service to start at login (per-user, no admin rights needed)."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from xml.sax.saxutils import escape

LABEL = "tech.cybercloudai.injectguard"


def _cmd():
    return [sys.executable, "-m", "injectguard", "service"]


def plan() -> dict:
    """Returns {'path': file to write, 'content': text, 'load': [command], 'unload': [command]}."""
    cmd = _cmd()
    if sys.platform == "darwin":
        path = Path.home() / "Library/LaunchAgents" / f"{LABEL}.plist"
        args = "".join(f"<string>{escape(a)}</string>" for a in cmd)
        logdir = Path.home() / "Library/Logs"
        content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key><array>{args}</array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>{logdir}/injectguard.out.log</string>
  <key>StandardErrorPath</key><string>{logdir}/injectguard.err.log</string>
</dict></plist>
"""
        return {"path": path, "content": content,
                "load": ["launchctl", "load", "-w", str(path)], "unload": ["launchctl", "unload", "-w", str(path)]}
    if sys.platform == "win32":
        path = Path.home() / "AppData/Local/InjectGuard/injectguard-task.xml"
        pyw = Path(sys.executable).with_name("pythonw.exe")
        exe = pyw if pyw.exists() else Path(sys.executable)
        content = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>InjectGuard background protection</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Principals><Principal id="Author"><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>
  </Settings>
  <Actions Context="Author"><Exec><Command>{escape(str(exe))}</Command><Arguments>-m injectguard service</Arguments></Exec></Actions>
</Task>
"""
        return {"path": path, "content": content,
                "load": ["schtasks", "/Create", "/TN", "InjectGuard", "/XML", str(path), "/F"],
                "unload": ["schtasks", "/Delete", "/TN", "InjectGuard", "/F"]}
    path = Path.home() / ".config/systemd/user/injectguard.service"
    content = f"""[Unit]
Description=InjectGuard background protection (prompt-injection scanner)
After=graphical-session.target

[Service]
ExecStart={' '.join(cmd)}
Restart=on-failure
RestartSec=10
Nice=10
IOSchedulingClass=idle

[Install]
WantedBy=default.target
"""
    return {"path": path, "content": content,
            "load": ["systemctl", "--user", "enable", "--now", "injectguard.service"],
            "unload": ["systemctl", "--user", "disable", "--now", "injectguard.service"]}


def install(load: bool = True) -> str:
    p = plan()
    p["path"].parent.mkdir(parents=True, exist_ok=True)
    enc = "utf-16" if sys.platform == "win32" else "utf-8"
    p["path"].write_text(p["content"], encoding=enc)
    msg = f"Wrote {p['path']}"
    if load:
        if sys.platform.startswith("linux"):
            subprocess.run(["systemctl", "--user", "daemon-reload"], check=False)
        r = subprocess.run(p["load"], capture_output=True, text=True)
        msg += f"\nRan: {' '.join(p['load'])} -> exit {r.returncode} {r.stderr.strip()}"
    else:
        msg += f"\nTo start it: {' '.join(p['load'])}"
    return msg


def uninstall() -> str:
    p = plan()
    r = subprocess.run(p["unload"], capture_output=True, text=True)
    p["path"].unlink(missing_ok=True)
    return f"Ran: {' '.join(p['unload'])} -> exit {r.returncode}; removed {p['path']}"
